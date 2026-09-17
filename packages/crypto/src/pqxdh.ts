/**
 * PQXDH: post-quantum-hybrid initial key agreement.
 *
 * This is X3DH with an ML-KEM encapsulation mixed into the same KDF. The
 * hybrid construction is the point: the session secret is safe if *either*
 * X25519 *or* ML-KEM-1024 holds. Elliptic-curve DH alone is vulnerable to
 * "harvest now, decrypt later" — an adversary recording traffic today and
 * breaking it on a future quantum computer — and ML-KEM alone is a much
 * younger assumption than Curve25519. Requiring both to fail is strictly
 * stronger than trusting either.
 *
 * The four DH terms each do a specific job:
 *   DH1 = DH(IK_a, SPK_b)  authenticates Alice to Bob   (only Alice has IK_a)
 *   DH2 = DH(EK_a, IK_b)   authenticates Bob to Alice   (only Bob has IK_b)
 *   DH3 = DH(EK_a, SPK_b)  forward secrecy from the medium-term prekey
 *   DH4 = DH(EK_a, OPK_b)  forward secrecy from a single-use prekey (optional)
 *
 * Dropping any one of them costs a real property, so DH4 is the only optional
 * term and its absence is recorded in the transcript rather than ignored.
 */

import {
  SHARED_SECRET_LEN,
  dh,
  generateDhKeyPair,
  kdf,
  kemDecapsulate,
  kemEncapsulate,
  wipe,
} from './primitives.js';
import { HANDSHAKE_PREFIX, LABELS } from './kdf.js';
import { MalformedInputError } from './errors.js';
import { Writer, concat, utf8 } from './wire.js';
import {
  verifyPreKeyBundle,
  type PreKeyBundle,
  type PrivateIdentity,
  type PublicIdentity,
} from './identity.js';

/** Identifies which of Bob's published keys a handshake consumed. */
export interface HandshakeKeyIds {
  readonly signedPreKeyId: number;
  readonly signedKemPreKeyId: number;
  readonly oneTimePreKeyId?: number;
  readonly oneTimeKemPreKeyId?: number;
}

/** Alice's side of the handshake: the secret plus what Bob needs to replay it. */
export interface InitiatorHandshake {
  /** 32-byte root secret that seeds the Double Ratchet. */
  readonly rootSecret: Uint8Array;
  /** Ephemeral X25519 public key, sent in the clear inside the sealed envelope. */
  readonly ephemeralPublicKey: Uint8Array;
  /** ML-KEM ciphertext Bob decapsulates. */
  readonly kemCiphertext: Uint8Array;
  readonly keyIds: HandshakeKeyIds;
  /** Bound into every AEAD on this session; see `associatedData`. */
  readonly associatedData: Uint8Array;
}

/** What Bob needs to reconstruct the same secret, taken from the prekey message. */
export interface ResponderHandshakeInput {
  readonly initiatorIdentity: PublicIdentity;
  readonly ephemeralPublicKey: Uint8Array;
  readonly kemCiphertext: Uint8Array;
  readonly keyIds: HandshakeKeyIds;
  /** Secret halves of the prekeys named by `keyIds`, looked up by the caller. */
  readonly signedPreKeySecret: Uint8Array;
  readonly signedKemPreKeySecret: Uint8Array;
  readonly oneTimePreKeySecret?: Uint8Array;
  readonly oneTimeKemPreKeySecret?: Uint8Array;
}

/**
 * Associated data bound into every AEAD operation of the session.
 *
 * Contains both identity keys in a fixed order (initiator first). This is what
 * cryptographically ties ciphertext to a pair of identities: a relay that
 * re-addresses a message to a different recipient produces an AEAD failure
 * rather than a delivered message.
 */
export function associatedData(
  initiator: PublicIdentity,
  responder: PublicIdentity,
): Uint8Array {
  return new Writer()
    .fixed(utf8.encode('Veil/v1/AD'))
    .bytes(initiator.signingPublicKey)
    .bytes(initiator.exchangePublicKey)
    .bytes(responder.signingPublicKey)
    .bytes(responder.exchangePublicKey)
    .finish();
}

/**
 * Transcript mixed into the KDF alongside the raw secrets.
 *
 * Binding the key identifiers and the *presence* of the optional one-time keys
 * means the two sides derive different keys if they disagree about which keys
 * were used. That turns a key-substitution or prekey-downgrade attempt by the
 * server into an immediate decryption failure instead of a silent weakening.
 */
function handshakeTranscript(
  initiator: PublicIdentity,
  responder: PublicIdentity,
  ephemeralPublicKey: Uint8Array,
  kemCiphertext: Uint8Array,
  keyIds: HandshakeKeyIds,
): Uint8Array {
  return new Writer()
    .fixed(utf8.encode('Veil/v1/PQXDH/Transcript'))
    .bytes(initiator.signingPublicKey)
    .bytes(initiator.exchangePublicKey)
    .bytes(responder.signingPublicKey)
    .bytes(responder.exchangePublicKey)
    .bytes(ephemeralPublicKey)
    .bytes(kemCiphertext)
    .u32(keyIds.signedPreKeyId)
    .u32(keyIds.signedKemPreKeyId)
    .u8(keyIds.oneTimePreKeyId === undefined ? 0 : 1)
    .u32(keyIds.oneTimePreKeyId ?? 0)
    .u8(keyIds.oneTimeKemPreKeyId === undefined ? 0 : 1)
    .u32(keyIds.oneTimeKemPreKeyId ?? 0)
    .finish();
}

function deriveRootSecret(secrets: Uint8Array[], transcript: Uint8Array): Uint8Array {
  // HANDSHAKE_PREFIX (32 x 0xFF) matches the X3DH/PQXDH convention: it makes the
  // KDF input unambiguously not a raw curve point, which blocks cross-protocol
  // confusion with implementations that hash bare DH outputs.
  const ikm = concat(HANDSHAKE_PREFIX, ...secrets);
  try {
    return kdf(ikm, transcript, LABELS.handshake, SHARED_SECRET_LEN);
  } finally {
    wipe(ikm);
  }
}

/**
 * Alice: derive a session secret against Bob's published bundle.
 *
 * Verifies every signature in the bundle before performing any key agreement.
 */
export function initiateHandshake(
  self: PrivateIdentity,
  bundle: PreKeyBundle,
): InitiatorHandshake {
  verifyPreKeyBundle(bundle);

  const selfPublic: PublicIdentity = {
    signingPublicKey: self.signing.publicKey,
    exchangePublicKey: self.exchange.publicKey,
    exchangeKeySignature: self.exchangeKeySignature,
  };

  const ephemeral = generateDhKeyPair();

  // Post-quantum term. Prefer the one-time KEM prekey; fall back to the signed
  // ("last resort") one, which is still authenticated but is reused until rotation.
  const kemTarget = bundle.oneTimeKemPreKey ?? bundle.signedKemPreKey;
  const { ciphertext: kemCiphertext, sharedSecret: kemSecret } = kemEncapsulate(
    kemTarget.publicKey,
  );

  const dh1 = dh(self.exchange.secretKey, bundle.signedPreKey.publicKey);
  const dh2 = dh(ephemeral.secretKey, bundle.identity.exchangePublicKey);
  const dh3 = dh(ephemeral.secretKey, bundle.signedPreKey.publicKey);
  const dh4 = bundle.oneTimePreKey
    ? dh(ephemeral.secretKey, bundle.oneTimePreKey.publicKey)
    : undefined;

  const keyIds: HandshakeKeyIds = {
    signedPreKeyId: bundle.signedPreKey.id,
    signedKemPreKeyId: bundle.signedKemPreKey.id,
    ...(bundle.oneTimePreKey ? { oneTimePreKeyId: bundle.oneTimePreKey.id } : {}),
    ...(bundle.oneTimeKemPreKey ? { oneTimeKemPreKeyId: bundle.oneTimeKemPreKey.id } : {}),
  };

  const transcript = handshakeTranscript(
    selfPublic,
    bundle.identity,
    ephemeral.publicKey,
    kemCiphertext,
    keyIds,
  );

  const secrets = dh4 ? [dh1, dh2, dh3, dh4, kemSecret] : [dh1, dh2, dh3, kemSecret];
  const rootSecret = deriveRootSecret(secrets, transcript);

  // Retire every intermediate secret; only rootSecret survives this function.
  wipe(dh1, dh2, dh3, dh4, kemSecret, ephemeral.secretKey);

  return {
    rootSecret,
    ephemeralPublicKey: ephemeral.publicKey,
    kemCiphertext,
    keyIds,
    associatedData: associatedData(selfPublic, bundle.identity),
  };
}

/**
 * Bob: reconstruct the same session secret from Alice's prekey message.
 *
 * The one-time-key secrets must be present exactly when `keyIds` names them.
 * We check that explicitly instead of silently deriving a different (and
 * therefore useless) key, so a mismatch is a clear protocol error.
 */
export function respondToHandshake(
  self: PrivateIdentity,
  input: ResponderHandshakeInput,
): { rootSecret: Uint8Array; associatedData: Uint8Array } {
  const selfPublic: PublicIdentity = {
    signingPublicKey: self.signing.publicKey,
    exchangePublicKey: self.exchange.publicKey,
    exchangeKeySignature: self.exchangeKeySignature,
  };

  const wantsOneTime = input.keyIds.oneTimePreKeyId !== undefined;
  if (wantsOneTime !== (input.oneTimePreKeySecret !== undefined)) {
    throw new MalformedInputError(
      'one-time prekey id and secret must both be present or both absent',
    );
  }
  const wantsKemOneTime = input.keyIds.oneTimeKemPreKeyId !== undefined;
  if (wantsKemOneTime !== (input.oneTimeKemPreKeySecret !== undefined)) {
    throw new MalformedInputError(
      'one-time ML-KEM prekey id and secret must both be present or both absent',
    );
  }

  // Mirror of the initiator's choice: one-time KEM key if it was used, else the
  // signed last-resort key.
  const kemSecretKey = input.oneTimeKemPreKeySecret ?? input.signedKemPreKeySecret;
  const kemSecret = kemDecapsulate(input.kemCiphertext, kemSecretKey);

  const dh1 = dh(input.signedPreKeySecret, input.initiatorIdentity.exchangePublicKey);
  const dh2 = dh(self.exchange.secretKey, input.ephemeralPublicKey);
  const dh3 = dh(input.signedPreKeySecret, input.ephemeralPublicKey);
  const dh4 = input.oneTimePreKeySecret
    ? dh(input.oneTimePreKeySecret, input.ephemeralPublicKey)
    : undefined;

  const transcript = handshakeTranscript(
    input.initiatorIdentity,
    selfPublic,
    input.ephemeralPublicKey,
    input.kemCiphertext,
    input.keyIds,
  );

  const secrets = dh4 ? [dh1, dh2, dh3, dh4, kemSecret] : [dh1, dh2, dh3, kemSecret];
  const rootSecret = deriveRootSecret(secrets, transcript);

  wipe(dh1, dh2, dh3, dh4, kemSecret);

  return {
    rootSecret,
    associatedData: associatedData(input.initiatorIdentity, selfPublic),
  };
}

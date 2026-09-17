/**
 * Identities and prekey bundles.
 *
 * An identity is three long-term keys:
 *   - `signing`  (Ed25519)      the root of trust; what a safety number covers.
 *   - `exchange` (X25519)       the long-term DH key used by the handshake.
 *   - address                   a self-certifying name derived from `signing`.
 *
 * The exchange key is *bound* to the signing key by a signature, so a server
 * cannot swap in its own DH key while keeping a victim's real signing key.
 * There is no phone number and no email anywhere in this structure: an account
 * is a keypair, so the operator has no identifier to hand over or to leak.
 */

import {
  ED25519_PUBLIC_LEN,
  MLKEM_PUBLIC_LEN,
  X25519_PUBLIC_LEN,
  constantTimeEqual,
  dhPublicKey,
  generateDhKeyPair,
  generateKemKeyPair,
  generateSigningKeyPair,
  hash256,
  sign,
  signingPublicKey,
  verify,
  type KeyPair,
} from './primitives.js';
import { MalformedInputError, UntrustedBundleError } from './errors.js';
import { Writer, toBase32, utf8 } from './wire.js';

/** Bytes of address material taken from the identity-key hash. 16 bytes = 128-bit. */
const ADDRESS_BYTES = 16;

/** What we publish about ourselves. Safe to hand to anyone, including the server. */
export interface PublicIdentity {
  readonly signingPublicKey: Uint8Array;
  readonly exchangePublicKey: Uint8Array;
  /** Ed25519 signature over the exchange key, proving the two belong together. */
  readonly exchangeKeySignature: Uint8Array;
}

/** What never leaves the device's secure storage. */
export interface PrivateIdentity {
  readonly signing: KeyPair;
  readonly exchange: KeyPair;
  readonly exchangeKeySignature: Uint8Array;
}

/** A signed medium-term X25519 prekey, rotated on a schedule (days). */
export interface SignedPreKey {
  readonly id: number;
  readonly publicKey: Uint8Array;
  readonly signature: Uint8Array;
}

/** A signed medium-term ML-KEM prekey. Rotated like the classical one. */
export interface SignedKemPreKey {
  readonly id: number;
  readonly publicKey: Uint8Array;
  readonly signature: Uint8Array;
}

/** A single-use X25519 prekey. Consumed by one handshake, then deleted. */
export interface OneTimePreKey {
  readonly id: number;
  readonly publicKey: Uint8Array;
}

/** A single-use ML-KEM prekey, giving per-session PQ forward secrecy. */
export interface OneTimeKemPreKey {
  readonly id: number;
  readonly publicKey: Uint8Array;
}

/**
 * What a peer fetches to start a conversation with us.
 *
 * The server stores this and hands it out. Every field except the one-time keys
 * is signed, and the one-time keys are covered by the handshake transcript, so
 * a malicious server can at worst deny service or force reuse of the
 * last-resort keys — it cannot substitute keys it controls.
 */
export interface PreKeyBundle {
  readonly identity: PublicIdentity;
  readonly signedPreKey: SignedPreKey;
  readonly signedKemPreKey: SignedKemPreKey;
  readonly oneTimePreKey?: OneTimePreKey;
  readonly oneTimeKemPreKey?: OneTimeKemPreKey;
}

/** Secret halves of published prekeys, kept so we can complete handshakes. */
export interface PreKeyStoreState {
  readonly signedPreKeys: Map<number, KeyPair>;
  readonly signedKemPreKeys: Map<number, KeyPair>;
  readonly oneTimePreKeys: Map<number, KeyPair>;
  readonly oneTimeKemPreKeys: Map<number, KeyPair>;
}

// ---------------------------------------------------------------------------
// Signing transcripts
//
// Each signature covers a tagged, length-delimited encoding. The tag stops a
// signature made over one kind of key from being replayed as a signature over
// another kind — a real attack against naive "sign the raw public key" schemes.
// ---------------------------------------------------------------------------

const SIG_CONTEXT_EXCHANGE = 0x01;
const SIG_CONTEXT_SIGNED_PREKEY = 0x02;
const SIG_CONTEXT_KEM_PREKEY = 0x03;

function signingTranscript(
  context: number,
  signingPublicKey: Uint8Array,
  id: number,
  publicKey: Uint8Array,
): Uint8Array {
  return new Writer()
    .fixed(utf8.encode('Veil/v1/KeyBinding'))
    .u8(context)
    .bytes(signingPublicKey)
    .u32(id)
    .bytes(publicKey)
    .finish();
}

// ---------------------------------------------------------------------------
// Identity creation
// ---------------------------------------------------------------------------

export function createIdentity(): PrivateIdentity {
  const signing = generateSigningKeyPair();
  const exchange = generateDhKeyPair();
  const exchangeKeySignature = sign(
    signing.secretKey,
    signingTranscript(SIG_CONTEXT_EXCHANGE, signing.publicKey, 0, exchange.publicKey),
  );
  return { signing, exchange, exchangeKeySignature };
}

export function publicIdentityOf(identity: PrivateIdentity): PublicIdentity {
  return {
    signingPublicKey: identity.signing.publicKey,
    exchangePublicKey: identity.exchange.publicKey,
    exchangeKeySignature: identity.exchangeKeySignature,
  };
}

/**
 * Rebuild a private identity from stored secret keys.
 *
 * Recomputes both public halves rather than trusting the stored copies, then
 * re-verifies the binding signature. If the at-rest blob were tampered with in
 * a way the vault AEAD somehow missed, we refuse to load it rather than run on
 * an identity whose DH key may not belong to its signing key.
 */
export function restoreIdentity(
  signingSecretKey: Uint8Array,
  exchangeSecretKey: Uint8Array,
  exchangeKeySignature: Uint8Array,
): PrivateIdentity {
  const identity: PrivateIdentity = {
    signing: {
      secretKey: signingSecretKey,
      publicKey: signingPublicKey(signingSecretKey),
    },
    exchange: {
      secretKey: exchangeSecretKey,
      publicKey: dhPublicKey(exchangeSecretKey),
    },
    exchangeKeySignature,
  };
  if (!verifyIdentityBinding(publicIdentityOf(identity))) {
    throw new UntrustedBundleError('restored identity failed its own key-binding check');
  }
  return identity;
}

// ---------------------------------------------------------------------------
// Prekey generation
// ---------------------------------------------------------------------------

export function createSignedPreKey(
  identity: PrivateIdentity,
  id: number,
): { published: SignedPreKey; secret: KeyPair } {
  const pair = generateDhKeyPair();
  const signature = sign(
    identity.signing.secretKey,
    signingTranscript(
      SIG_CONTEXT_SIGNED_PREKEY,
      identity.signing.publicKey,
      id,
      pair.publicKey,
    ),
  );
  return { published: { id, publicKey: pair.publicKey, signature }, secret: pair };
}

export function createSignedKemPreKey(
  identity: PrivateIdentity,
  id: number,
): { published: SignedKemPreKey; secret: KeyPair } {
  const pair = generateKemKeyPair();
  const signature = sign(
    identity.signing.secretKey,
    signingTranscript(SIG_CONTEXT_KEM_PREKEY, identity.signing.publicKey, id, pair.publicKey),
  );
  return { published: { id, publicKey: pair.publicKey, signature }, secret: pair };
}

export function createOneTimePreKeys(
  startId: number,
  count: number,
): Array<{ published: OneTimePreKey; secret: KeyPair }> {
  const out: Array<{ published: OneTimePreKey; secret: KeyPair }> = [];
  for (let i = 0; i < count; i++) {
    const pair = generateDhKeyPair();
    out.push({ published: { id: startId + i, publicKey: pair.publicKey }, secret: pair });
  }
  return out;
}

export function createOneTimeKemPreKeys(
  startId: number,
  count: number,
): Array<{ published: OneTimeKemPreKey; secret: KeyPair }> {
  const out: Array<{ published: OneTimeKemPreKey; secret: KeyPair }> = [];
  for (let i = 0; i < count; i++) {
    const pair = generateKemKeyPair();
    out.push({ published: { id: startId + i, publicKey: pair.publicKey }, secret: pair });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export function verifyIdentityBinding(identity: PublicIdentity): boolean {
  if (identity.signingPublicKey.length !== ED25519_PUBLIC_LEN) return false;
  if (identity.exchangePublicKey.length !== X25519_PUBLIC_LEN) return false;
  return verify(
    identity.signingPublicKey,
    signingTranscript(
      SIG_CONTEXT_EXCHANGE,
      identity.signingPublicKey,
      0,
      identity.exchangePublicKey,
    ),
    identity.exchangeKeySignature,
  );
}

/**
 * Validate every signature in a bundle before any key agreement happens.
 *
 * This runs *first*, on untrusted server output, so malformed or hostile
 * bundles never reach the handshake. Throws rather than returning false: there
 * is no safe way to continue with an unverified bundle.
 */
export function verifyPreKeyBundle(bundle: PreKeyBundle): void {
  if (!verifyIdentityBinding(bundle.identity)) {
    throw new UntrustedBundleError('identity exchange-key binding signature is invalid');
  }

  const signingKey = bundle.identity.signingPublicKey;

  if (bundle.signedPreKey.publicKey.length !== X25519_PUBLIC_LEN) {
    throw new MalformedInputError('signed prekey has wrong length');
  }
  if (
    !verify(
      signingKey,
      signingTranscript(
        SIG_CONTEXT_SIGNED_PREKEY,
        signingKey,
        bundle.signedPreKey.id,
        bundle.signedPreKey.publicKey,
      ),
      bundle.signedPreKey.signature,
    )
  ) {
    throw new UntrustedBundleError('signed prekey signature is invalid');
  }

  if (bundle.signedKemPreKey.publicKey.length !== MLKEM_PUBLIC_LEN) {
    throw new MalformedInputError('signed ML-KEM prekey has wrong length');
  }
  if (
    !verify(
      signingKey,
      signingTranscript(
        SIG_CONTEXT_KEM_PREKEY,
        signingKey,
        bundle.signedKemPreKey.id,
        bundle.signedKemPreKey.publicKey,
      ),
      bundle.signedKemPreKey.signature,
    )
  ) {
    throw new UntrustedBundleError('signed ML-KEM prekey signature is invalid');
  }

  if (
    bundle.oneTimePreKey &&
    bundle.oneTimePreKey.publicKey.length !== X25519_PUBLIC_LEN
  ) {
    throw new MalformedInputError('one-time prekey has wrong length');
  }
  if (
    bundle.oneTimeKemPreKey &&
    bundle.oneTimeKemPreKey.publicKey.length !== MLKEM_PUBLIC_LEN
  ) {
    throw new MalformedInputError('one-time ML-KEM prekey has wrong length');
  }
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/**
 * A routing address derived from the identity key.
 *
 * Self-certifying: anyone holding the address can check that a claimed identity
 * key hashes to it, so the directory cannot point a name at the wrong key. The
 * server only ever sees this, never a phone number.
 */
export function addressOf(identity: PublicIdentity | Uint8Array): string {
  const signingKey = identity instanceof Uint8Array ? identity : identity.signingPublicKey;
  if (signingKey.length !== ED25519_PUBLIC_LEN) {
    throw new MalformedInputError('identity signing key has wrong length');
  }
  const digest = hash256(utf8.encode('Veil/v1/Address'), signingKey);
  return toBase32(digest.slice(0, ADDRESS_BYTES));
}

export function addressMatches(address: string, identity: PublicIdentity): boolean {
  const expected = utf8.encode(addressOf(identity));
  const actual = utf8.encode(address);
  return constantTimeEqual(expected, actual);
}

/**
 * Sealed sender.
 *
 * The ratchet protects message *content*. It does nothing about metadata, and
 * metadata is often the more sensitive half: who contacted a journalist, at
 * what time, how often. A plain E2EE messenger still hands its operator a
 * complete social graph.
 *
 * So the sender's identity is itself encrypted, to the recipient's long-term
 * exchange key, using a fresh ephemeral key per envelope. What the server sees
 * is only:
 *   - the recipient address (it must, in order to route)
 *   - an ephemeral public key that is unlinkable to any account
 *   - a uniform-looking ciphertext
 *
 * It cannot tell who sent the message, nor link two envelopes to one sender.
 *
 * Limits, stated plainly: the recipient is still visible to the server, and
 * traffic timing and volume still leak. Full sender *and* receiver anonymity
 * needs a mixnet or PIR-style delivery, which is out of scope here. This
 * removes the operator's ability to build a sender-side social graph; it is not
 * a traffic-analysis defence.
 */

import {
  AEAD_KEY_LEN,
  AEAD_NONCE_LEN,
  X25519_PUBLIC_LEN,
  dh,
  generateDhKeyPair,
  kdf,
  verify,
  wipe,
  aeadDecrypt,
  aeadEncrypt,
} from './primitives.js';
import { LABELS } from './kdf.js';
import { AuthenticationError, MalformedInputError } from './errors.js';
import { Reader, Writer, concat, utf8 } from './wire.js';
import { addressOf, verifyIdentityBinding, type PublicIdentity } from './identity.js';

/** Envelope payload kinds. The kind is inside the sealed layer, not on the wire. */
export const PAYLOAD_PREKEY = 0x01;
export const PAYLOAD_RATCHET = 0x02;

export interface SealedEnvelope {
  /** Routing address of the recipient. The only account identifier the server sees. */
  readonly recipientAddress: string;
  /** Per-envelope ephemeral X25519 public key. Unlinkable across envelopes. */
  readonly ephemeralPublicKey: Uint8Array;
  /** Encrypts { sender identity, proof of possession, inner payload }. */
  readonly ciphertext: Uint8Array;
}

export interface OpenedEnvelope {
  readonly senderIdentity: PublicIdentity;
  readonly payloadKind: number;
  readonly payload: Uint8Array;
}

function envelopeKeys(sharedSecret: Uint8Array, ephemeralPublicKey: Uint8Array, recipientExchangeKey: Uint8Array) {
  // Both public keys go into the salt, binding the derived key to this exact
  // (ephemeral, recipient) pair. Without that binding, an ephemeral key could
  // be lifted onto a different recipient's envelope.
  const salt = concat(ephemeralPublicKey, recipientExchangeKey);
  const derived = kdf(sharedSecret, salt, LABELS.sealedSender, AEAD_KEY_LEN + AEAD_NONCE_LEN);
  const keys = {
    key: derived.slice(0, AEAD_KEY_LEN),
    nonce: derived.slice(AEAD_KEY_LEN),
  };
  wipe(derived, salt);
  return keys;
}

/**
 * Bytes the sender signs to prove they really hold the identity they claim.
 *
 * Without this, anyone could put someone else's public identity in the sealed
 * layer and impersonate them at the envelope level. The signature covers the
 * ephemeral key and recipient address, so it cannot be replayed into a
 * different envelope or redirected to another recipient.
 */
function senderProofTranscript(
  ephemeralPublicKey: Uint8Array,
  recipientAddress: string,
  payloadKind: number,
  payload: Uint8Array,
): Uint8Array {
  return new Writer()
    .fixed(utf8.encode('Veil/v1/SenderProof'))
    .bytes(ephemeralPublicKey)
    .bytes(utf8.encode(recipientAddress))
    .u8(payloadKind)
    .bytes(payload)
    .finish();
}

/**
 * Seal a payload to a recipient.
 *
 * `sign` is passed in rather than the identity's secret key so callers holding
 * keys in a hardware keystore (Secure Enclave / StrongBox) can seal without the
 * private key ever entering JS memory.
 */
export function sealEnvelope(params: {
  senderIdentity: PublicIdentity;
  signWithIdentity: (message: Uint8Array) => Uint8Array;
  recipientIdentity: PublicIdentity;
  payloadKind: number;
  payload: Uint8Array;
}): SealedEnvelope {
  const { senderIdentity, recipientIdentity, payloadKind, payload } = params;

  if (!verifyIdentityBinding(recipientIdentity)) {
    throw new MalformedInputError('recipient identity binding is invalid; refusing to seal');
  }

  const recipientAddress = addressOf(recipientIdentity);
  const ephemeral = generateDhKeyPair();
  const sharedSecret = dh(ephemeral.secretKey, recipientIdentity.exchangePublicKey);
  const { key, nonce } = envelopeKeys(
    sharedSecret,
    ephemeral.publicKey,
    recipientIdentity.exchangePublicKey,
  );

  const proof = params.signWithIdentity(
    senderProofTranscript(ephemeral.publicKey, recipientAddress, payloadKind, payload),
  );

  const inner = new Writer()
    .bytes(senderIdentity.signingPublicKey)
    .bytes(senderIdentity.exchangePublicKey)
    .bytes(senderIdentity.exchangeKeySignature)
    .bytes(proof)
    .u8(payloadKind)
    .bytes(payload)
    .finish();

  try {
    return {
      recipientAddress,
      ephemeralPublicKey: ephemeral.publicKey,
      // No associated data: the recipient address is already bound via the
      // signed proof, and adding it here would let the server cause confusing
      // failures by rewriting it.
      ciphertext: aeadEncrypt(key, nonce, inner, new Uint8Array(0)),
    };
  } finally {
    wipe(key, nonce, sharedSecret, ephemeral.secretKey, inner);
  }
}

/**
 * Open an envelope addressed to us.
 *
 * Order matters: decrypt, then check the identity binding, then check the
 * sender's proof of possession. We return the sender identity only once all
 * three succeed, so callers can never act on an unauthenticated sender.
 *
 * `recipientAddress` is *our own* address, computed locally from our identity —
 * deliberately not read from `envelope.recipientAddress`, which is a
 * server-supplied routing field. Verifying the sender's proof against the
 * address we know to be ours means a relay that rewrites the routing field
 * cannot get a message accepted under a different binding; it can only cause a
 * clean verification failure.
 */
export function openEnvelope(params: {
  recipientExchangeSecretKey: Uint8Array;
  recipientExchangePublicKey: Uint8Array;
  recipientAddress: string;
  envelope: SealedEnvelope;
}): OpenedEnvelope {
  const { envelope } = params;

  if (envelope.ephemeralPublicKey.length !== X25519_PUBLIC_LEN) {
    throw new MalformedInputError('envelope ephemeral key has wrong length');
  }

  const sharedSecret = dh(params.recipientExchangeSecretKey, envelope.ephemeralPublicKey);
  const { key, nonce } = envelopeKeys(
    sharedSecret,
    envelope.ephemeralPublicKey,
    params.recipientExchangePublicKey,
  );

  let inner: Uint8Array;
  try {
    inner = aeadDecrypt(key, nonce, envelope.ciphertext, new Uint8Array(0));
  } finally {
    wipe(key, nonce, sharedSecret);
  }

  const reader = new Reader(inner);
  const senderIdentity: PublicIdentity = {
    signingPublicKey: reader.bytes(),
    exchangePublicKey: reader.bytes(),
    exchangeKeySignature: reader.bytes(),
  };
  const proof = reader.bytes();
  const payloadKind = reader.u8();
  const payload = reader.bytes();
  reader.end();
  wipe(inner);

  if (!verifyIdentityBinding(senderIdentity)) {
    throw new AuthenticationError('sealed sender identity binding is invalid');
  }

  const expectedProof = senderProofTranscript(
    envelope.ephemeralPublicKey,
    params.recipientAddress,
    payloadKind,
    payload,
  );
  if (!verify(senderIdentity.signingPublicKey, expectedProof, proof)) {
    throw new AuthenticationError('sealed sender proof of possession is invalid');
  }

  return { senderIdentity, payloadKind, payload };
}

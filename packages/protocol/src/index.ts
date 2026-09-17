/**
 * @veil/protocol — the client/relay wire contract.
 *
 * Everything here is transport framing. The one rule this package exists to
 * enforce: *no field in any message below may carry plaintext.* Bodies are
 * sealed envelopes produced by @veil/crypto, and the relay is expected to be
 * able to read every field defined here without learning anything it should
 * not. If a future field would break that, it belongs inside the envelope
 * instead.
 *
 * JSON with base64url for bytes, rather than a binary format: the relay's
 * parser is a place where a hostile client meets server code, so a boring,
 * well-tested parser is worth more than saved bytes. Size limits are enforced
 * before parsing (see the relay's body limit).
 */

// ---------------------------------------------------------------------------
// base64url helpers
//
// Unpadded base64url, so values are safe in URLs and headers without escaping.
// ---------------------------------------------------------------------------

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const base64 =
    typeof btoa === 'function'
      ? btoa(binary)
      : // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (globalThis as any).Buffer.from(bytes).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error('invalid base64url input');
  }
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  if (typeof atob === 'function') {
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return new Uint8Array((globalThis as any).Buffer.from(padded, 'base64'));
}

// ---------------------------------------------------------------------------
// Limits
//
// Enforced by the relay and asserted by its tests. They exist to bound what a
// hostile client can make the server allocate or store.
// ---------------------------------------------------------------------------

export const LIMITS = {
  /** Largest accepted request body. Generous for a padded message, far from unbounded. */
  maxBodyBytes: 256 * 1024,
  /** Largest single envelope ciphertext. */
  maxEnvelopeBytes: 128 * 1024,
  /** Queued messages retained per recipient before the oldest are dropped. */
  maxQueueLength: 2000,
  /** One-time prekeys a client may have stored server-side. */
  maxOneTimePreKeys: 500,
  /** How long an undelivered message is retained, in milliseconds. */
  messageTtlMs: 30 * 24 * 60 * 60 * 1000,
  /** Authentication challenge lifetime. Short, because it is single-use. */
  challengeTtlMs: 60 * 1000,
  /** Session token lifetime. */
  tokenTtlMs: 24 * 60 * 60 * 1000,
} as const;

// ---------------------------------------------------------------------------
// Registration and key distribution
// ---------------------------------------------------------------------------

/** Serialised public identity. All three fields are public by design. */
export interface WirePublicIdentity {
  readonly signingPublicKey: string;
  readonly exchangePublicKey: string;
  readonly exchangeKeySignature: string;
}

export interface WireSignedPreKey {
  readonly id: number;
  readonly publicKey: string;
  readonly signature: string;
}

export interface WireOneTimePreKey {
  readonly id: number;
  readonly publicKey: string;
}

/**
 * Registration request.
 *
 * Note what is absent: no phone number, no email, no username, no device
 * fingerprint. An account is a public key, so there is no personal identifier
 * for the operator to hold, log, sell, lose, or be compelled to hand over.
 */
export interface RegisterRequest {
  readonly identity: WirePublicIdentity;
  readonly signedPreKey: WireSignedPreKey;
  readonly signedKemPreKey: WireSignedPreKey;
  readonly oneTimePreKeys: WireOneTimePreKey[];
  readonly oneTimeKemPreKeys: WireOneTimePreKey[];
}

export interface RegisterResponse {
  readonly address: string;
}

/** A bundle handed to a peer who wants to start a conversation. */
export interface PreKeyBundleResponse {
  readonly identity: WirePublicIdentity;
  readonly signedPreKey: WireSignedPreKey;
  readonly signedKemPreKey: WireSignedPreKey;
  readonly oneTimePreKey?: WireOneTimePreKey;
  readonly oneTimeKemPreKey?: WireOneTimePreKey;
}

export interface UploadPreKeysRequest {
  readonly signedPreKey?: WireSignedPreKey;
  readonly signedKemPreKey?: WireSignedPreKey;
  readonly oneTimePreKeys?: WireOneTimePreKey[];
  readonly oneTimeKemPreKeys?: WireOneTimePreKey[];
}

// ---------------------------------------------------------------------------
// Authentication
//
// Challenge-response against the registered identity key. There is no password
// and no recovery flow, because there is nothing the server could recover: it
// holds no secret belonging to the user.
// ---------------------------------------------------------------------------

export interface ChallengeRequest {
  readonly address: string;
}

export interface ChallengeResponse {
  readonly challenge: string;
  readonly expiresAt: number;
}

export interface AuthenticateRequest {
  readonly address: string;
  readonly challenge: string;
  /** Ed25519 signature over the domain-separated challenge transcript. */
  readonly signature: string;
}

export interface AuthenticateResponse {
  readonly token: string;
  readonly expiresAt: number;
}

/**
 * Bytes a client signs to authenticate.
 *
 * Domain-separated and bound to the address, so a signature made here can
 * never be replayed as a key-binding signature or a sender proof — the same
 * identity key is used for all three.
 */
export function challengeTranscript(address: string, challenge: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(`Veil/v1/Auth:${address}:`);
  const out = new Uint8Array(prefix.length + challenge.length);
  out.set(prefix, 0);
  out.set(challenge, prefix.length);
  return out;
}

// ---------------------------------------------------------------------------
// Messaging
// ---------------------------------------------------------------------------

/**
 * A sealed envelope as it crosses the wire.
 *
 * This is the complete set of what the relay sees per message. `recipient` is
 * unavoidable — it is the routing address. Everything about the sender is
 * inside `ciphertext`.
 */
export interface WireEnvelope {
  readonly recipient: string;
  readonly ephemeralPublicKey: string;
  readonly ciphertext: string;
}

export interface SendMessageRequest {
  readonly envelope: WireEnvelope;
}

export interface SendMessageResponse {
  readonly accepted: true;
}

/** A queued message being delivered. `id` is for acknowledgement only. */
export interface DeliveredMessage {
  readonly id: string;
  readonly envelope: WireEnvelope;
  /**
   * Server receive time, used only for TTL expiry.
   *
   * Rounded to the hour on delivery: the client needs it for ordering
   * fallback, and an exact arrival timestamp is metadata worth blurring.
   */
  readonly receivedAtHour: number;
}

export interface FetchMessagesResponse {
  readonly messages: DeliveredMessage[];
}

export interface AcknowledgeRequest {
  /** Ids to delete. Deletion is immediate and unrecoverable. */
  readonly ids: string[];
}

// ---------------------------------------------------------------------------
// Realtime socket
//
// Call signalling rides the same sealed envelopes as messages, so the relay
// cannot read SDP, ICE candidates, or call state. It only sees that some
// envelope is bound for some address. That matters: readable SDP would expose
// IP addresses and call metadata even on an otherwise E2EE call.
// ---------------------------------------------------------------------------

export type ClientSocketMessage =
  | { readonly type: 'authenticate'; readonly token: string }
  | { readonly type: 'send'; readonly envelope: WireEnvelope }
  | { readonly type: 'acknowledge'; readonly ids: string[] }
  | { readonly type: 'ping' };

export type ServerSocketMessage =
  | { readonly type: 'authenticated'; readonly address: string }
  | { readonly type: 'deliver'; readonly message: DeliveredMessage }
  | { readonly type: 'accepted' }
  | { readonly type: 'pong' }
  | { readonly type: 'error'; readonly code: string; readonly message: string };

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

import type {
  OneTimeKemPreKey,
  OneTimePreKey,
  PreKeyBundle,
  PublicIdentity,
  SealedEnvelope,
  SignedKemPreKey,
  SignedPreKey,
} from '@veil/crypto';

export function encodeIdentity(identity: PublicIdentity): WirePublicIdentity {
  return {
    signingPublicKey: toBase64Url(identity.signingPublicKey),
    exchangePublicKey: toBase64Url(identity.exchangePublicKey),
    exchangeKeySignature: toBase64Url(identity.exchangeKeySignature),
  };
}

export function decodeIdentity(wire: WirePublicIdentity): PublicIdentity {
  return {
    signingPublicKey: fromBase64Url(wire.signingPublicKey),
    exchangePublicKey: fromBase64Url(wire.exchangePublicKey),
    exchangeKeySignature: fromBase64Url(wire.exchangeKeySignature),
  };
}

export function encodeSignedPreKey(key: SignedPreKey | SignedKemPreKey): WireSignedPreKey {
  return {
    id: key.id,
    publicKey: toBase64Url(key.publicKey),
    signature: toBase64Url(key.signature),
  };
}

export function decodeSignedPreKey(wire: WireSignedPreKey): SignedPreKey {
  return {
    id: wire.id,
    publicKey: fromBase64Url(wire.publicKey),
    signature: fromBase64Url(wire.signature),
  };
}

export function encodeOneTimePreKey(
  key: OneTimePreKey | OneTimeKemPreKey,
): WireOneTimePreKey {
  return { id: key.id, publicKey: toBase64Url(key.publicKey) };
}

export function decodeOneTimePreKey(wire: WireOneTimePreKey): OneTimePreKey {
  return { id: wire.id, publicKey: fromBase64Url(wire.publicKey) };
}

export function decodeBundle(wire: PreKeyBundleResponse): PreKeyBundle {
  return {
    identity: decodeIdentity(wire.identity),
    signedPreKey: decodeSignedPreKey(wire.signedPreKey),
    signedKemPreKey: decodeSignedPreKey(wire.signedKemPreKey),
    ...(wire.oneTimePreKey
      ? { oneTimePreKey: decodeOneTimePreKey(wire.oneTimePreKey) }
      : {}),
    ...(wire.oneTimeKemPreKey
      ? { oneTimeKemPreKey: decodeOneTimePreKey(wire.oneTimeKemPreKey) }
      : {}),
  };
}

export function encodeEnvelope(envelope: SealedEnvelope): WireEnvelope {
  return {
    recipient: envelope.recipientAddress,
    ephemeralPublicKey: toBase64Url(envelope.ephemeralPublicKey),
    ciphertext: toBase64Url(envelope.ciphertext),
  };
}

export function decodeEnvelope(wire: WireEnvelope): SealedEnvelope {
  return {
    recipientAddress: wire.recipient,
    ephemeralPublicKey: fromBase64Url(wire.ephemeralPublicKey),
    ciphertext: fromBase64Url(wire.ciphertext),
  };
}

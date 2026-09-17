/**
 * App-level domain types.
 *
 * Kept separate from the wire types in @veil/protocol: what the app stores and
 * shows is not what it transmits. Message *bodies* here are plaintext, because
 * this is the one layer where plaintext legitimately exists — inside the
 * unlocked app, after decryption. Everything persisted from these types goes
 * through the vault first.
 */

/** A contact's verification state, which drives what the UI must warn about. */
export type VerificationState =
  /** We have their key but nobody has checked it out-of-band. */
  | 'unverified'
  /** Safety number compared in person or over a trusted channel. */
  | 'verified'
  /** Previously verified, but the key changed. Highest-severity warning. */
  | 'changed';

export interface Contact {
  /** Self-certifying address, derived from the identity key. */
  readonly address: string;
  /** User-chosen local name. Never sent anywhere; purely a local label. */
  displayName: string;
  /**
   * Base64url identity signing key, as currently known.
   *
   * Mutable because accepting a peer's reinstall rewrites it - but only via
   * `acceptIdentityChange`, which also resets verification to 'unverified',
   * so a new key can never inherit the old key's verified status.
   */
  identityKey: string;
  verification: VerificationState;
  /** When the key last changed, for the UI to explain a warning. */
  identityChangedAt?: number;
}

export type MessageDirection = 'outgoing' | 'incoming';

export type MessageStatus =
  | 'pending'
  | 'sent'
  | 'delivered'
  | 'read'
  | 'failed';

export interface Message {
  readonly id: string;
  readonly conversationAddress: string;
  readonly direction: MessageDirection;
  readonly body: string;
  /** Local clock. We never trust a peer-supplied or server-supplied time. */
  readonly timestamp: number;
  status: MessageStatus;
  /** Set for a message that self-destructs; absolute local expiry time. */
  expiresAt?: number;
}

export interface Conversation {
  readonly address: string;
  lastMessageAt: number;
  lastMessagePreview: string;
  unreadCount: number;
  /** Disappearing-message timer in seconds; 0 means off. */
  disappearAfterSeconds: number;
}

/** Call lifecycle, as the UI needs to render it. */
export type CallState =
  | 'idle'
  | 'ringing-outgoing'
  | 'ringing-incoming'
  | 'connecting'
  | 'connected'
  | 'ended';

export interface CallInfo {
  readonly callId: string;
  readonly peerAddress: string;
  readonly direction: 'outgoing' | 'incoming';
  state: CallState;
  /**
   * The four words both parties read aloud to rule out an active MITM.
   * Undefined until media keys are derived.
   */
  sas?: string;
  sasDigits?: string;
  /** Set once the user confirms the words matched. */
  sasConfirmed?: boolean;
  startedAt?: number;
  endedAt?: number;
  endReason?: string;
}

/**
 * Message payloads exchanged inside the encrypted channel.
 *
 * Call signalling travels here, alongside chat, precisely so the relay cannot
 * read SDP or ICE candidates. Readable SDP would expose IP addresses and call
 * metadata even when the audio itself is encrypted.
 */
export type Payload =
  | {
      readonly kind: 'text';
      /**
       * Sender-assigned message id, carried so receipts can refer to it.
       *
       * Both sides store the message under this id. Without it, a receipt would
       * name an id only the receiver knows, and the sender could never match it
       * to the message it acknowledges.
       */
      readonly messageId: string;
      readonly body: string;
      readonly expiresInSeconds?: number;
    }
  | { readonly kind: 'receipt'; readonly messageIds: string[]; readonly receipt: 'delivered' | 'read' }
  | { readonly kind: 'typing'; readonly typing: boolean }
  | {
      readonly kind: 'call-offer';
      readonly callId: string;
      /** Base64url per-call media root secret. */
      readonly mediaSecret: string;
      readonly sdp: string;
      readonly dtlsFingerprint: string;
    }
  | {
      readonly kind: 'call-answer';
      readonly callId: string;
      readonly sdp: string;
      readonly dtlsFingerprint: string;
    }
  | {
      readonly kind: 'call-ice';
      readonly callId: string;
      readonly candidate: string;
    }
  | { readonly kind: 'call-hangup'; readonly callId: string; readonly reason: string };

export function encodePayload(payload: Payload): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(payload));
}

/**
 * Parse a decrypted payload.
 *
 * Runs on authenticated plaintext, so this is not an attack surface in the way
 * the relay's parser is — but a peer can still be buggy or malicious, so we
 * validate the discriminant rather than trusting the shape.
 */
export function decodePayload(bytes: Uint8Array): Payload {
  const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
  if (typeof parsed !== 'object' || parsed === null || !('kind' in parsed)) {
    throw new Error('payload is not an object with a kind');
  }
  const kind = (parsed as { kind: unknown }).kind;
  const known = [
    'text',
    'receipt',
    'typing',
    'call-offer',
    'call-answer',
    'call-ice',
    'call-hangup',
  ];
  if (typeof kind !== 'string' || !known.includes(kind)) {
    throw new Error(`unknown payload kind: ${String(kind)}`);
  }
  return parsed as Payload;
}

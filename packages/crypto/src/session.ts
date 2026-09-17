/**
 * The API the app actually calls.
 *
 * Everything below this file is protocol detail. A UI developer should be able
 * to send a secure message without knowing what a ratchet is, and — more
 * importantly — should not be *able* to construct an insecure one. So there is
 * no "encrypt without padding" option, no way to skip bundle verification, and
 * no way to obtain a plaintext that failed authentication.
 */

import {
  constantTimeEqual,
  sign,
  wipe,
  type KeyPair,
} from './primitives.js';
import { IdentityChangedError, MalformedInputError, SessionStateError } from './errors.js';
import { Reader, Writer } from './wire.js';
import { pad, unpad } from './padding.js';
import {
  addressOf,
  publicIdentityOf,
  type PreKeyBundle,
  type PrivateIdentity,
  type PublicIdentity,
} from './identity.js';
import {
  initiateHandshake,
  respondToHandshake,
  type HandshakeKeyIds,
} from './pqxdh.js';
import {
  destroyRatchet,
  initialiseInitiator,
  initialiseResponder,
  ratchetDecrypt,
  ratchetEncrypt,
  type RatchetMessage,
  type RatchetState,
} from './doubleRatchet.js';
import {
  PAYLOAD_PREKEY,
  PAYLOAD_RATCHET,
  openEnvelope,
  sealEnvelope,
  type SealedEnvelope,
} from './envelope.js';

/** A live conversation with one peer device. */
export interface Session {
  readonly peerIdentity: PublicIdentity;
  readonly ratchet: RatchetState;
  /**
   * Set while we still owe the peer the prekey preamble.
   *
   * Every message repeats it until we receive a reply, because our first
   * message may be dropped and the peer cannot build a session without it.
   */
  pendingPreKey?: PreKeyPreamble | undefined;
  /**
   * For a responder session: the initiator ephemeral key that created it.
   *
   * The initiator repeats its preamble on every message until we reply, so we
   * receive the same handshake many times. This lets us recognise "same
   * handshake, later message" and decrypt it with the session we already
   * built, instead of trying to redo a handshake whose one-time prekey is
   * already spent.
   */
  establishedBy?: Uint8Array | undefined;
}

/** The handshake material the initiator prepends to early messages. */
export interface PreKeyPreamble {
  readonly ephemeralPublicKey: Uint8Array;
  readonly kemCiphertext: Uint8Array;
  readonly keyIds: HandshakeKeyIds;
}

/** Resolves the secret half of a published prekey. Backed by the device vault. */
export interface PreKeyResolver {
  signedPreKey(id: number): KeyPair | undefined;
  signedKemPreKey(id: number): KeyPair | undefined;
  oneTimePreKey(id: number): KeyPair | undefined;
  oneTimeKemPreKey(id: number): KeyPair | undefined;
  /** Called after a successful handshake so single-use keys are never reused. */
  consumeOneTimePreKey(id: number): void;
  consumeOneTimeKemPreKey(id: number): void;
}

// ---------------------------------------------------------------------------
// Preamble encoding
// ---------------------------------------------------------------------------

function encodePreamble(preamble: PreKeyPreamble): Uint8Array {
  const writer = new Writer()
    .bytes(preamble.ephemeralPublicKey)
    .bytes(preamble.kemCiphertext)
    .u32(preamble.keyIds.signedPreKeyId)
    .u32(preamble.keyIds.signedKemPreKeyId)
    .u8(preamble.keyIds.oneTimePreKeyId === undefined ? 0 : 1)
    .u32(preamble.keyIds.oneTimePreKeyId ?? 0)
    .u8(preamble.keyIds.oneTimeKemPreKeyId === undefined ? 0 : 1)
    .u32(preamble.keyIds.oneTimeKemPreKeyId ?? 0);
  return writer.finish();
}

function decodePreamble(reader: Reader): PreKeyPreamble {
  const ephemeralPublicKey = reader.bytes();
  const kemCiphertext = reader.bytes();
  const signedPreKeyId = reader.u32();
  const signedKemPreKeyId = reader.u32();
  const hasOneTime = reader.u8() === 1;
  const oneTimePreKeyId = reader.u32();
  const hasKemOneTime = reader.u8() === 1;
  const oneTimeKemPreKeyId = reader.u32();
  return {
    ephemeralPublicKey,
    kemCiphertext,
    keyIds: {
      signedPreKeyId,
      signedKemPreKeyId,
      ...(hasOneTime ? { oneTimePreKeyId } : {}),
      ...(hasKemOneTime ? { oneTimeKemPreKeyId } : {}),
    },
  };
}

function encodeRatchetMessage(message: RatchetMessage): Uint8Array {
  return new Writer()
    .bytes(message.header.ratchetPublicKey)
    .u32(message.header.previousChainLength)
    .u32(message.header.messageNumber)
    .bytes(message.ciphertext)
    .finish();
}

function decodeRatchetMessage(reader: Reader): RatchetMessage {
  const ratchetPublicKey = reader.bytes();
  const previousChainLength = reader.u32();
  const messageNumber = reader.u32();
  const ciphertext = reader.bytes();
  return {
    header: { ratchetPublicKey, previousChainLength, messageNumber },
    ciphertext,
  };
}

// ---------------------------------------------------------------------------
// Starting a session
// ---------------------------------------------------------------------------

/**
 * Start a session as the initiator, from a bundle fetched for the peer.
 *
 * `expectedFingerprint` is how a previously verified contact is pinned. If the
 * server hands back a different identity key than the one the user verified in
 * person, we refuse rather than transparently re-keying: silent re-keying is
 * precisely how a compromised operator would mount an active MITM.
 */
export function startSession(
  self: PrivateIdentity,
  bundle: PreKeyBundle,
  expectedFingerprint?: Uint8Array,
): Session {
  if (expectedFingerprint) {
    if (!constantTimeEqual(expectedFingerprint, bundle.identity.signingPublicKey)) {
      throw new IdentityChangedError(
        'peer identity key does not match the verified fingerprint; refusing to start a session',
        addressOf(expectedFingerprint),
        addressOf(bundle.identity),
      );
    }
  }

  const handshake = initiateHandshake(self, bundle);

  // The initiator's first DH ratchet step targets the peer's signed prekey,
  // which is the one ratchet-capable key the responder is guaranteed to hold.
  const ratchet = initialiseInitiator(
    handshake.rootSecret,
    bundle.signedPreKey.publicKey,
    handshake.associatedData,
  );
  wipe(handshake.rootSecret);

  return {
    peerIdentity: bundle.identity,
    ratchet,
    pendingPreKey: {
      ephemeralPublicKey: handshake.ephemeralPublicKey,
      kemCiphertext: handshake.kemCiphertext,
      keyIds: handshake.keyIds,
    },
  };
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

/**
 * Encrypt an outgoing message and wrap it in a sealed envelope.
 *
 * Plaintext is padded first, so the envelope length reveals only a bucket.
 */
export function encryptMessage(
  self: PrivateIdentity,
  session: Session,
  plaintext: Uint8Array,
): SealedEnvelope {
  const padded = pad(plaintext);
  let message: RatchetMessage;
  try {
    message = ratchetEncrypt(session.ratchet, padded);
  } finally {
    wipe(padded);
  }

  const body = encodeRatchetMessage(message);
  const payload = session.pendingPreKey
    ? new Writer().fixed(encodePreamble(session.pendingPreKey)).bytes(body).finish()
    : body;

  return sealEnvelope({
    senderIdentity: publicIdentityOf(self),
    signWithIdentity: (bytes) => sign(self.signing.secretKey, bytes),
    recipientIdentity: session.peerIdentity,
    payloadKind: session.pendingPreKey ? PAYLOAD_PREKEY : PAYLOAD_RATCHET,
    payload,
  });
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

export interface DecryptedMessage {
  readonly senderIdentity: PublicIdentity;
  readonly plaintext: Uint8Array;
  /** The session to persist; either the existing one or a newly created one. */
  readonly session: Session;
  /** True when this message established the session (a prekey message). */
  readonly isNewSession: boolean;
}

/**
 * Decrypt an inbound envelope.
 *
 * `lookupSession` returns an existing session for a sender address, if any.
 * A prekey message for an address we already have a session with creates a
 * *new* session rather than disturbing the live one: the peer may have
 * reinstalled, and we must not let an attacker reset a healthy ratchet by
 * replaying a stale prekey message.
 */
export function decryptEnvelope(params: {
  self: PrivateIdentity;
  envelope: SealedEnvelope;
  lookupSession: (senderAddress: string) => Session | undefined;
  preKeys: PreKeyResolver;
  /** Pinned identity key for this sender, if the user has verified them. */
  pinnedIdentityKey?: (senderAddress: string) => Uint8Array | undefined;
}): DecryptedMessage {
  const { self, envelope, preKeys } = params;

  const opened = openEnvelope({
    recipientExchangeSecretKey: self.exchange.secretKey,
    recipientExchangePublicKey: self.exchange.publicKey,
    recipientAddress: addressOf(publicIdentityOf(self)),
    envelope,
  });

  const senderAddress = addressOf(opened.senderIdentity);

  // Pinning check happens before any ratchet work, so a substituted identity
  // never advances our state.
  const pinned = params.pinnedIdentityKey?.(senderAddress);
  if (pinned && !constantTimeEqual(pinned, opened.senderIdentity.signingPublicKey)) {
    throw new IdentityChangedError(
      'sender identity key does not match the pinned fingerprint',
      addressOf(pinned),
      senderAddress,
    );
  }

  const reader = new Reader(opened.payload);

  if (opened.payloadKind === PAYLOAD_PREKEY) {
    const preamble = decodePreamble(reader);
    const body = reader.bytes();
    reader.end();

    // The initiator resends the preamble until we reply, so a prekey message
    // for a handshake we have already completed is normal traffic, not an
    // attack. Route it to the session that handshake produced; its one-time
    // prekeys are gone, so redoing the handshake would (correctly) fail.
    const existing = params.lookupSession(senderAddress);
    if (
      existing?.establishedBy &&
      constantTimeEqual(existing.establishedBy, preamble.ephemeralPublicKey)
    ) {
      const repeated = decodeRatchetMessage(new Reader(body));
      const paddedRepeat = ratchetDecrypt(existing.ratchet, repeated);
      try {
        return {
          senderIdentity: opened.senderIdentity,
          plaintext: unpad(paddedRepeat),
          session: existing,
          isNewSession: false,
        };
      } finally {
        wipe(paddedRepeat);
      }
    }

    const signedPreKey = preKeys.signedPreKey(preamble.keyIds.signedPreKeyId);
    if (!signedPreKey) {
      throw new SessionStateError(
        `unknown signed prekey ${preamble.keyIds.signedPreKeyId}; it may have been rotated out`,
      );
    }
    const signedKemPreKey = preKeys.signedKemPreKey(preamble.keyIds.signedKemPreKeyId);
    if (!signedKemPreKey) {
      throw new SessionStateError(
        `unknown signed ML-KEM prekey ${preamble.keyIds.signedKemPreKeyId}`,
      );
    }

    const oneTimeId = preamble.keyIds.oneTimePreKeyId;
    const oneTime = oneTimeId === undefined ? undefined : preKeys.oneTimePreKey(oneTimeId);
    if (oneTimeId !== undefined && !oneTime) {
      // Already consumed: either a replay, or a message we have handled before.
      throw new SessionStateError(
        `one-time prekey ${oneTimeId} is already used; refusing to reuse it`,
      );
    }
    const kemOneTimeId = preamble.keyIds.oneTimeKemPreKeyId;
    const kemOneTime =
      kemOneTimeId === undefined ? undefined : preKeys.oneTimeKemPreKey(kemOneTimeId);
    if (kemOneTimeId !== undefined && !kemOneTime) {
      throw new SessionStateError(
        `one-time ML-KEM prekey ${kemOneTimeId} is already used; refusing to reuse it`,
      );
    }

    const { rootSecret, associatedData } = respondToHandshake(self, {
      initiatorIdentity: opened.senderIdentity,
      ephemeralPublicKey: preamble.ephemeralPublicKey,
      kemCiphertext: preamble.kemCiphertext,
      keyIds: preamble.keyIds,
      signedPreKeySecret: signedPreKey.secretKey,
      signedKemPreKeySecret: signedKemPreKey.secretKey,
      ...(oneTime ? { oneTimePreKeySecret: oneTime.secretKey } : {}),
      ...(kemOneTime ? { oneTimeKemPreKeySecret: kemOneTime.secretKey } : {}),
    });

    const ratchet = initialiseResponder(rootSecret, signedPreKey, associatedData);
    const session: Session = {
      peerIdentity: opened.senderIdentity,
      ratchet,
      establishedBy: preamble.ephemeralPublicKey,
    };

    const message = decodeRatchetMessage(new Reader(body));
    // Decrypt before consuming one-time keys: if this fails, the keys stay
    // available for the genuine message.
    const padded = ratchetDecrypt(session.ratchet, message);

    if (oneTimeId !== undefined) preKeys.consumeOneTimePreKey(oneTimeId);
    if (kemOneTimeId !== undefined) preKeys.consumeOneTimeKemPreKey(kemOneTimeId);

    try {
      return {
        senderIdentity: opened.senderIdentity,
        plaintext: unpad(padded),
        session,
        isNewSession: true,
      };
    } finally {
      wipe(padded);
    }
  }

  if (opened.payloadKind !== PAYLOAD_RATCHET) {
    throw new MalformedInputError(`unknown payload kind ${opened.payloadKind}`);
  }

  const session = params.lookupSession(senderAddress);
  if (!session) {
    throw new SessionStateError(
      'no session for this sender; a prekey message is required to establish one',
    );
  }

  const message = decodeRatchetMessage(reader);
  reader.end();
  const padded = ratchetDecrypt(session.ratchet, message);

  // A reply proves the peer has a working session, so we can stop resending
  // the handshake preamble.
  session.pendingPreKey = undefined;

  try {
    return {
      senderIdentity: opened.senderIdentity,
      plaintext: unpad(padded),
      session,
      isNewSession: false,
    };
  } finally {
    wipe(padded);
  }
}

/** Wipe a session's secrets. Call on "delete conversation" and on logout. */
export function destroySession(session: Session): void {
  destroyRatchet(session.ratchet);
}

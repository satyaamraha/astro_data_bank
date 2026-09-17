/**
 * The Double Ratchet.
 *
 * Two ratchets turning at once:
 *
 *  - The *symmetric* ratchet advances a chain key by one HMAC step per message.
 *    It is one-way, so a key recovered today cannot decrypt yesterday's
 *    messages. That is forward secrecy.
 *
 *  - The *DH* ratchet mixes a fresh Diffie-Hellman output into the root key
 *    every time the conversation changes direction. An attacker who steals the
 *    full session state loses it again as soon as the peer replies with a new
 *    ratchet key. That is break-in recovery (post-compromise security), and it
 *    is the property that makes a one-time device seizure non-permanent.
 *
 * Out-of-order and dropped messages are normal on mobile networks, so skipped
 * message keys are cached. That cache is the main abuse surface here, and it is
 * bounded on three axes (see MAX_SKIP_PER_CHAIN / MAX_SKIPPED_KEYS): an
 * attacker must not be able to make us derive unbounded keys or grow memory
 * without limit by claiming a huge counter.
 */

import {
  AEAD_KEY_LEN,
  AEAD_NONCE_LEN,
  SHARED_SECRET_LEN,
  aeadDecrypt,
  aeadEncrypt,
  dh,
  generateDhKeyPair,
  kdf,
  mac,
  wipe,
  type KeyPair,
} from './primitives.js';
import { CHAIN_MESSAGE_KEY_SEED, CHAIN_NEXT_KEY_SEED, LABELS } from './kdf.js';
import { MalformedInputError, SessionStateError } from './errors.js';
import { Reader, Writer, concat, toHex } from './wire.js';

/**
 * Most keys we will derive to catch up within a single chain.
 *
 * A peer legitimately gets a few hundred messages ahead during an outage. A
 * counter of 2^32-1 is an attempt to pin the CPU, so we refuse it outright.
 */
export const MAX_SKIP_PER_CHAIN = 1000;

/**
 * Most skipped keys retained across all chains.
 *
 * Bounded so a flood of gappy messages cannot grow session state without
 * limit. Eviction is oldest-first, which means a very old undelivered message
 * eventually becomes undecryptable — the deliberate trade of availability for
 * bounded memory and a bounded window of retained keys.
 */
export const MAX_SKIPPED_KEYS = 2000;

export interface RatchetHeader {
  /** Sender's current ratchet public key. */
  readonly ratchetPublicKey: Uint8Array;
  /** Number of messages in the *previous* sending chain, so gaps can be closed. */
  readonly previousChainLength: number;
  /** This message's index within the current sending chain. */
  readonly messageNumber: number;
}

interface SkippedKey {
  /** Insertion order, used for oldest-first eviction. */
  readonly sequence: number;
  readonly messageKey: Uint8Array;
}

export interface RatchetState {
  rootKey: Uint8Array;
  /** Our sending ratchet keypair. */
  sending: KeyPair;
  /** Peer's latest ratchet public key; undefined until we receive one. */
  receiving?: Uint8Array;
  sendingChainKey?: Uint8Array;
  receivingChainKey?: Uint8Array;
  /** Messages sent in the current sending chain. */
  sentCount: number;
  /** Messages received in the current receiving chain. */
  receivedCount: number;
  /** Length of the previous sending chain. */
  previousSentCount: number;
  /** Keyed by `${hex(ratchetPublicKey)}:${messageNumber}`. */
  skipped: Map<string, SkippedKey>;
  skippedSequence: number;
  /** Bound into every AEAD; comes from the handshake. */
  associatedData: Uint8Array;
}

// ---------------------------------------------------------------------------
// Key schedule
// ---------------------------------------------------------------------------

/** Root-chain step: absorb a DH output, emit a new root key and chain key. */
function advanceRootChain(
  rootKey: Uint8Array,
  dhOutput: Uint8Array,
): { rootKey: Uint8Array; chainKey: Uint8Array } {
  // rootKey is the HKDF salt and the DH output the IKM, so both must be known
  // to continue the chain.
  const derived = kdf(dhOutput, rootKey, LABELS.rootChain, SHARED_SECRET_LEN * 2);
  const next = {
    rootKey: derived.slice(0, SHARED_SECRET_LEN),
    chainKey: derived.slice(SHARED_SECRET_LEN),
  };
  wipe(derived);
  return next;
}

/**
 * Symmetric-ratchet step.
 *
 * Two HMACs under the same chain key with different one-byte seeds. The
 * message key and the next chain key are therefore independent: learning a
 * message key reveals nothing about the rest of the chain.
 */
function advanceChain(chainKey: Uint8Array): {
  messageKey: Uint8Array;
  nextChainKey: Uint8Array;
} {
  const messageKeyFull = mac(chainKey, CHAIN_MESSAGE_KEY_SEED);
  const nextChainKeyFull = mac(chainKey, CHAIN_NEXT_KEY_SEED);
  const result = {
    messageKey: messageKeyFull.slice(0, SHARED_SECRET_LEN),
    nextChainKey: nextChainKeyFull.slice(0, SHARED_SECRET_LEN),
  };
  wipe(messageKeyFull, nextChainKeyFull);
  return result;
}

/** Message key -> the (key, nonce) pair actually handed to the AEAD. */
function deriveMessageKeys(messageKey: Uint8Array): {
  key: Uint8Array;
  nonce: Uint8Array;
} {
  const derived = kdf(
    messageKey,
    new Uint8Array(0),
    LABELS.messageKey,
    AEAD_KEY_LEN + AEAD_NONCE_LEN,
  );
  const keys = {
    key: derived.slice(0, AEAD_KEY_LEN),
    nonce: derived.slice(AEAD_KEY_LEN),
  };
  wipe(derived);
  return keys;
}

// ---------------------------------------------------------------------------
// Header encoding
//
// The header travels authenticated-but-readable *inside* the sealed-sender
// envelope, so the transport never sees it. Encoding is deterministic because
// these exact bytes go into the AEAD's associated data.
// ---------------------------------------------------------------------------

export function encodeHeader(header: RatchetHeader): Uint8Array {
  return new Writer()
    .fixed(header.ratchetPublicKey)
    .u32(header.previousChainLength)
    .u32(header.messageNumber)
    .finish();
}

export function decodeHeader(bytes: Uint8Array): RatchetHeader {
  const reader = new Reader(bytes);
  const header: RatchetHeader = {
    ratchetPublicKey: reader.fixed(32),
    previousChainLength: reader.u32(),
    messageNumber: reader.u32(),
  };
  reader.end();
  return header;
}

function aeadAssociatedData(state: RatchetState, header: RatchetHeader): Uint8Array {
  // Session AD (both identities) plus this message's header. Binding the header
  // is what stops an attacker reordering or re-numbering ciphertexts.
  return concat(state.associatedData, encodeHeader(header));
}

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

/**
 * Initiator side. Alice knows Bob's signed prekey, so she can take the first
 * DH ratchet step immediately and send without waiting for a reply.
 */
export function initialiseInitiator(
  rootSecret: Uint8Array,
  peerRatchetPublicKey: Uint8Array,
  associatedData: Uint8Array,
): RatchetState {
  const sending = generateDhKeyPair();
  const dhOutput = dh(sending.secretKey, peerRatchetPublicKey);
  const { rootKey, chainKey } = advanceRootChain(rootSecret, dhOutput);
  wipe(dhOutput);

  return {
    rootKey,
    sending,
    receiving: peerRatchetPublicKey,
    sendingChainKey: chainKey,
    sentCount: 0,
    receivedCount: 0,
    previousSentCount: 0,
    skipped: new Map(),
    skippedSequence: 0,
    associatedData,
  };
}

/**
 * Responder side. Bob's ratchet keypair *is* his signed prekey pair, which is
 * how Alice's first DH step lands on a key he holds. He has no sending chain
 * until Alice's first message arrives.
 */
export function initialiseResponder(
  rootSecret: Uint8Array,
  signedPreKeyPair: KeyPair,
  associatedData: Uint8Array,
): RatchetState {
  return {
    rootKey: rootSecret,
    sending: signedPreKeyPair,
    sentCount: 0,
    receivedCount: 0,
    previousSentCount: 0,
    skipped: new Map(),
    skippedSequence: 0,
    associatedData,
  };
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

export interface RatchetMessage {
  readonly header: RatchetHeader;
  readonly ciphertext: Uint8Array;
}

export function ratchetEncrypt(state: RatchetState, plaintext: Uint8Array): RatchetMessage {
  if (!state.sendingChainKey) {
    throw new SessionStateError(
      'no sending chain: the responder must receive one message before sending',
    );
  }

  const { messageKey, nextChainKey } = advanceChain(state.sendingChainKey);
  wipe(state.sendingChainKey);
  state.sendingChainKey = nextChainKey;

  const header: RatchetHeader = {
    ratchetPublicKey: state.sending.publicKey,
    previousChainLength: state.previousSentCount,
    messageNumber: state.sentCount,
  };
  state.sentCount += 1;

  const { key, nonce } = deriveMessageKeys(messageKey);
  try {
    return {
      header,
      ciphertext: aeadEncrypt(key, nonce, plaintext, aeadAssociatedData(state, header)),
    };
  } finally {
    // The message key is never retained on the sending side: we cannot decrypt
    // our own sent messages, which is what forward secrecy requires.
    wipe(messageKey, key, nonce);
  }
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

function skippedKeyId(ratchetPublicKey: Uint8Array, messageNumber: number): string {
  return `${toHex(ratchetPublicKey)}:${messageNumber}`;
}

function rememberSkipped(
  state: RatchetState,
  ratchetPublicKey: Uint8Array,
  messageNumber: number,
  messageKey: Uint8Array,
): void {
  if (state.skipped.size >= MAX_SKIPPED_KEYS) {
    // Oldest-first eviction, and we wipe the key we drop.
    let oldestId: string | undefined;
    let oldestSequence = Number.POSITIVE_INFINITY;
    for (const [id, entry] of state.skipped) {
      if (entry.sequence < oldestSequence) {
        oldestSequence = entry.sequence;
        oldestId = id;
      }
    }
    if (oldestId !== undefined) {
      wipe(state.skipped.get(oldestId)?.messageKey);
      state.skipped.delete(oldestId);
    }
  }
  state.skipped.set(skippedKeyId(ratchetPublicKey, messageNumber), {
    sequence: state.skippedSequence++,
    messageKey,
  });
}

/** Derive and stash keys for messages we have not seen yet in the current chain. */
function skipReceivingKeys(state: RatchetState, until: number): void {
  if (!state.receivingChainKey || !state.receiving) return;
  if (until < state.receivedCount) return;

  if (until - state.receivedCount > MAX_SKIP_PER_CHAIN) {
    throw new SessionStateError(
      `message number ${until} skips more than ${MAX_SKIP_PER_CHAIN} keys; refusing`,
    );
  }

  while (state.receivedCount < until) {
    const { messageKey, nextChainKey } = advanceChain(state.receivingChainKey);
    wipe(state.receivingChainKey);
    state.receivingChainKey = nextChainKey;
    rememberSkipped(state, state.receiving, state.receivedCount, messageKey);
    state.receivedCount += 1;
  }
}

/** DH ratchet step: the peer moved to a new ratchet key, so re-key both chains. */
function performDhRatchet(state: RatchetState, header: RatchetHeader): void {
  // Close out the old receiving chain first so late messages stay decryptable.
  skipReceivingKeys(state, header.previousChainLength);

  state.previousSentCount = state.sentCount;
  state.sentCount = 0;
  state.receivedCount = 0;
  state.receiving = header.ratchetPublicKey;

  // Receiving chain from the peer's new key and our current key.
  {
    const dhOutput = dh(state.sending.secretKey, header.ratchetPublicKey);
    const { rootKey, chainKey } = advanceRootChain(state.rootKey, dhOutput);
    wipe(dhOutput, state.rootKey, state.receivingChainKey);
    state.rootKey = rootKey;
    state.receivingChainKey = chainKey;
  }

  // Then a brand-new sending key, so our next reply gives the peer fresh
  // entropy too. This is the step that delivers post-compromise security.
  {
    wipe(state.sending.secretKey);
    state.sending = generateDhKeyPair();
    const dhOutput = dh(state.sending.secretKey, header.ratchetPublicKey);
    const { rootKey, chainKey } = advanceRootChain(state.rootKey, dhOutput);
    wipe(dhOutput, state.rootKey, state.sendingChainKey);
    state.rootKey = rootKey;
    state.sendingChainKey = chainKey;
  }
}

function tryDecryptWithSkipped(
  state: RatchetState,
  message: RatchetMessage,
): Uint8Array | undefined {
  const id = skippedKeyId(message.header.ratchetPublicKey, message.header.messageNumber);
  const entry = state.skipped.get(id);
  if (!entry) return undefined;

  const { key, nonce } = deriveMessageKeys(entry.messageKey);
  try {
    const plaintext = aeadDecrypt(
      key,
      nonce,
      message.ciphertext,
      aeadAssociatedData(state, message.header),
    );
    // Consume on success only. A forged ciphertext must not burn a real key,
    // or an attacker could make a legitimate message permanently undecryptable.
    wipe(entry.messageKey);
    state.skipped.delete(id);
    return plaintext;
  } finally {
    wipe(key, nonce);
  }
}

export function ratchetDecrypt(state: RatchetState, message: RatchetMessage): Uint8Array {
  if (message.header.ratchetPublicKey.length !== 32) {
    throw new MalformedInputError('ratchet header public key has wrong length');
  }

  // 1. An out-of-order message we already derived a key for.
  const fromSkipped = tryDecryptWithSkipped(state, message);
  if (fromSkipped) return fromSkipped;

  // 2. A new ratchet key means the conversation turned around.
  const isNewRatchetKey =
    !state.receiving ||
    toHex(state.receiving) !== toHex(message.header.ratchetPublicKey);
  if (isNewRatchetKey) {
    performDhRatchet(state, message.header);
  }

  // 3. Catch up within the current chain, then derive this message's key.
  skipReceivingKeys(state, message.header.messageNumber);

  if (!state.receivingChainKey) {
    throw new SessionStateError('no receiving chain key after ratchet step');
  }
  if (message.header.messageNumber !== state.receivedCount) {
    // Only reachable for a replay of an already-consumed message: the key is
    // gone, so there is nothing to try.
    throw new SessionStateError(
      `message ${message.header.messageNumber} was already consumed (replay?)`,
    );
  }

  const { messageKey, nextChainKey } = advanceChain(state.receivingChainKey);
  const { key, nonce } = deriveMessageKeys(messageKey);
  try {
    const plaintext = aeadDecrypt(
      key,
      nonce,
      message.ciphertext,
      aeadAssociatedData(state, message.header),
    );
    // Commit the ratchet only after authentication succeeds, so unauthenticated
    // garbage cannot advance our state and desynchronise a live session.
    wipe(state.receivingChainKey);
    state.receivingChainKey = nextChainKey;
    state.receivedCount += 1;
    return plaintext;
  } catch (error) {
    // Authentication failed: discard the derived chain key and leave state
    // untouched so the session survives injected garbage.
    wipe(nextChainKey);
    throw error;
  } finally {
    wipe(messageKey, key, nonce);
  }
}

/** Wipe all secret material in a session. Called on logout and on deletion. */
export function destroyRatchet(state: RatchetState): void {
  wipe(state.rootKey, state.sending.secretKey, state.sendingChainKey, state.receivingChainKey);
  for (const entry of state.skipped.values()) wipe(entry.messageKey);
  state.skipped.clear();
}

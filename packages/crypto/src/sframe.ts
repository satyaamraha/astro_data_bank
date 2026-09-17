/**
 * SFrame-style media frame encryption.
 *
 * Voice frames have properties that make them unlike messages:
 *  - There are ~50 per second, so per-frame cost must be tiny.
 *  - They are sent over UDP and *will* be lost and reordered. A ratchet that
 *    breaks on a dropped frame would break the call.
 *  - The relay must read RTP routing headers but must not read the payload.
 *
 * So media uses a counter-based scheme rather than a ratchet: one call key, a
 * strictly increasing per-frame counter, and a nonce derived from that counter.
 * Frame loss is harmless because any frame can be decrypted independently.
 *
 * The critical invariant is nonce uniqueness. Reusing a (key, nonce) pair with
 * a stream cipher leaks the XOR of two plaintexts and destroys Poly1305's
 * integrity. Two things enforce it:
 *   - the sender's counter never repeats and never wraps silently — it refuses
 *     to encrypt past the counter limit rather than rolling over;
 *   - the receiver rejects replayed and too-old counters via a sliding window,
 *     so a relay cannot re-inject a captured frame.
 */

import {
  AEAD_KEY_LEN,
  AEAD_NONCE_LEN,
  aeadDecrypt,
  aeadEncrypt,
  kdf,
  wipe,
} from './primitives.js';
import { LABELS } from './kdf.js';
import { MalformedInputError, ReplayError } from './errors.js';
import { Writer } from './wire.js';

/**
 * Highest frame counter we will use.
 *
 * 2^48 frames is ~178,000 years at 50 frames/second, so this is never reached
 * in practice; the limit exists so that the counter *cannot* wrap and silently
 * repeat a nonce.
 */
export const MAX_FRAME_COUNTER = (1n << 48n) - 1n;

/** Replay window, in frames. 1024 at 50fps tolerates ~20s of reordering. */
export const REPLAY_WINDOW = 1024;

export interface SframeSender {
  readonly key: Uint8Array;
  counter: bigint;
}

export interface SframeReceiver {
  readonly key: Uint8Array;
  /** Highest counter accepted so far. */
  highestCounter: bigint;
  /** Counters seen within the window, for replay rejection. */
  readonly seen: Set<bigint>;
}

export function createSender(key: Uint8Array): SframeSender {
  if (key.length !== AEAD_KEY_LEN) {
    throw new MalformedInputError('SFrame key must be 32 bytes');
  }
  return { key, counter: 0n };
}

export function createReceiver(key: Uint8Array): SframeReceiver {
  if (key.length !== AEAD_KEY_LEN) {
    throw new MalformedInputError('SFrame key must be 32 bytes');
  }
  return { key, highestCounter: -1n, seen: new Set() };
}

/**
 * Per-frame (key, nonce) from the call key and the frame counter.
 *
 * Deriving a fresh subkey per frame rather than reusing one key with a counter
 * nonce costs one HKDF but removes any dependence on the AEAD's birthday bound
 * over a long call, and means a leaked single-frame key reveals nothing else.
 */
function frameKeys(key: Uint8Array, counter: bigint) {
  const info = new Writer().fixed(LABELS.sframeFrame).u64(counter).finish();
  const derived = kdf(key, new Uint8Array(0), info, AEAD_KEY_LEN + AEAD_NONCE_LEN);
  const keys = {
    frameKey: derived.slice(0, AEAD_KEY_LEN),
    nonce: derived.slice(AEAD_KEY_LEN),
  };
  wipe(derived);
  return keys;
}

/**
 * Frame header: the counter, in the clear but authenticated.
 *
 * The receiver needs the counter to derive the key, so it cannot be encrypted.
 * It is covered by the AEAD tag, so it cannot be altered. A relay therefore
 * learns only a frame index — no content, no speech activity beyond what packet
 * timing already reveals.
 */
export function encodeFrameHeader(counter: bigint): Uint8Array {
  return new Writer().u64(counter).finish();
}

export interface EncryptedFrame {
  readonly counter: bigint;
  readonly payload: Uint8Array;
}

/**
 * Encrypt one media frame.
 *
 * `additionalData` should carry any RTP header fields the relay may read but
 * must not modify, so tampering with them breaks authentication.
 */
export function encryptFrame(
  sender: SframeSender,
  frame: Uint8Array,
  additionalData: Uint8Array = new Uint8Array(0),
): EncryptedFrame {
  if (sender.counter > MAX_FRAME_COUNTER) {
    // Refuse rather than wrap: a repeated nonce would be catastrophic.
    throw new MalformedInputError('SFrame counter exhausted; the call must be re-keyed');
  }
  const counter = sender.counter;
  sender.counter += 1n;

  const { frameKey, nonce } = frameKeys(sender.key, counter);
  const associatedData = new Writer()
    .fixed(encodeFrameHeader(counter))
    .fixed(additionalData)
    .finish();
  try {
    return { counter, payload: aeadEncrypt(frameKey, nonce, frame, associatedData) };
  } finally {
    wipe(frameKey, nonce);
  }
}

/**
 * Decrypt one media frame, rejecting replays and stale counters.
 *
 * Replay checks run *before* the AEAD so a flood of replayed frames costs us
 * only a set lookup, and the `seen` set is committed *after* authentication so
 * forged frames cannot poison the window and lock out genuine frames.
 */
export function decryptFrame(
  receiver: SframeReceiver,
  frame: EncryptedFrame,
  additionalData: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const { counter } = frame;
  if (counter < 0n || counter > MAX_FRAME_COUNTER) {
    throw new MalformedInputError('SFrame counter out of range');
  }
  if (receiver.seen.has(counter)) {
    throw new ReplayError(`media frame ${counter} was already accepted`);
  }
  if (
    receiver.highestCounter >= 0n &&
    counter + BigInt(REPLAY_WINDOW) <= receiver.highestCounter
  ) {
    throw new ReplayError(`media frame ${counter} is outside the replay window`);
  }

  const { frameKey, nonce } = frameKeys(receiver.key, counter);
  const associatedData = new Writer()
    .fixed(encodeFrameHeader(counter))
    .fixed(additionalData)
    .finish();

  let plaintext: Uint8Array;
  try {
    plaintext = aeadDecrypt(frameKey, nonce, frame.payload, associatedData);
  } finally {
    wipe(frameKey, nonce);
  }

  receiver.seen.add(counter);
  if (counter > receiver.highestCounter) receiver.highestCounter = counter;

  // Drop counters that have fallen out of the window, so the set stays bounded.
  const cutoff = receiver.highestCounter - BigInt(REPLAY_WINDOW);
  if (cutoff > 0n) {
    for (const value of receiver.seen) {
      if (value <= cutoff) receiver.seen.delete(value);
    }
  }

  return plaintext;
}

export function destroySender(sender: SframeSender): void {
  wipe(sender.key);
}

export function destroyReceiver(receiver: SframeReceiver): void {
  wipe(receiver.key);
  receiver.seen.clear();
}

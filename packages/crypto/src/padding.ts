/**
 * Length-hiding padding.
 *
 * Ciphertext length leaks. "yes" and a 400-word paragraph are distinguishable
 * on the wire even under perfect encryption, and over a conversation that leaks
 * a surprising amount. We pad every plaintext up to a bucket boundary so many
 * different messages share one size.
 *
 * Buckets grow geometrically (~1.25x) rather than in fixed steps: fixed steps
 * either waste bandwidth on small messages or barely hide large ones, whereas
 * a multiplicative schedule keeps the *relative* uncertainty roughly constant
 * at every size. This is the same reasoning behind Signal's padding buckets.
 *
 * Scheme: append 0x80 then 0x00* to the bucket size. Unambiguous because the
 * terminator is a fixed non-zero byte scanned from the end.
 */

import { MalformedInputError } from './errors.js';

const PADDING_MARKER = 0x80;
const GROWTH = 1.25;
const MIN_BUCKET = 128;

/** Smallest bucket that fits `length` payload bytes plus the 1-byte marker. */
export function bucketSize(length: number): number {
  if (!Number.isInteger(length) || length < 0) {
    throw new MalformedInputError(`invalid plaintext length ${length}`);
  }
  const needed = length + 1;
  let bucket = MIN_BUCKET;
  while (bucket < needed) {
    bucket = Math.ceil(bucket * GROWTH);
  }
  return bucket;
}

export function pad(plaintext: Uint8Array): Uint8Array {
  const size = bucketSize(plaintext.length);
  const padded = new Uint8Array(size);
  padded.set(plaintext, 0);
  padded[plaintext.length] = PADDING_MARKER;
  // Remainder is already zero.
  return padded;
}

/**
 * Strip padding.
 *
 * Runs only on data that already passed its AEAD check, so the input is
 * authentic and a malformed structure means a bug rather than an attack. We
 * still validate instead of trusting the length byte.
 */
export function unpad(padded: Uint8Array): Uint8Array {
  for (let i = padded.length - 1; i >= 0; i--) {
    const byte = padded[i]!;
    if (byte === 0x00) continue;
    if (byte === PADDING_MARKER) return padded.slice(0, i);
    throw new MalformedInputError('padding is malformed: unexpected trailing byte');
  }
  throw new MalformedInputError('padding is malformed: no marker found');
}

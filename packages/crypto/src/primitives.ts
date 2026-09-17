/**
 * Thin, auditable wrappers over audited primitives.
 *
 * Policy: this file is the ONLY place in Veil that touches a cryptographic
 * library directly. Everything above it composes these functions. That keeps
 * the primitive choice reviewable in one screen and makes algorithm changes a
 * single-file diff.
 *
 * Choices and why:
 *  - X25519 for ECDH .......... small, fast, misuse-resistant, no invalid-curve zoo.
 *  - Ed25519 for signatures ... deterministic, no nonce-reuse foot-gun like ECDSA.
 *  - ML-KEM-1024 for KEM ...... FIPS 203; defends against harvest-now/decrypt-later.
 *  - XChaCha20-Poly1305 ....... 24-byte nonces, so random nonces are safe; no
 *                               AES timing concerns on phones without AES-NI.
 *  - SHA-512 / HKDF-SHA-512 ... wide margin, fast on 64-bit mobile cores.
 *  - Argon2id for passphrases . memory-hard, the only sane choice for at-rest keys.
 */

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { argon2id } from '@noble/hashes/argon2.js';
import { randomBytes } from '@noble/hashes/utils.js';

import { AuthenticationError, MalformedInputError } from './errors.js';

// ---------------------------------------------------------------------------
// Sizes. Exported so wire formats and tests share one source of truth.
// ---------------------------------------------------------------------------

export const X25519_PUBLIC_LEN = 32;
export const X25519_SECRET_LEN = 32;
export const ED25519_PUBLIC_LEN = 32;
export const ED25519_SECRET_LEN = 32;
export const ED25519_SIGNATURE_LEN = 64;
export const MLKEM_PUBLIC_LEN = 1568;
export const MLKEM_SECRET_LEN = 3168;
export const MLKEM_CIPHERTEXT_LEN = 1568;
export const AEAD_KEY_LEN = 32;
export const AEAD_NONCE_LEN = 24;
export const AEAD_TAG_LEN = 16;
export const SHARED_SECRET_LEN = 32;

// ---------------------------------------------------------------------------
// Randomness and memory hygiene
// ---------------------------------------------------------------------------

/**
 * CSPRNG bytes. Delegates to the platform RNG (`crypto.getRandomValues` in
 * React Native via a polyfill, `crypto.randomBytes` on Node).
 */
export function random(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw new MalformedInputError(`random() needs a positive integer length, got ${length}`);
  }
  return randomBytes(length);
}

/**
 * Overwrite secret material in place.
 *
 * Honest caveat: JS gives no guarantee the value was not already copied by the
 * GC, and this cannot scrub a compacted heap. It still meaningfully shortens
 * the window in which a key sits in a long-lived buffer, so we do it for every
 * ratchet key we retire.
 */
export function wipe(...buffers: Array<Uint8Array | undefined | null>): void {
  for (const buffer of buffers) {
    if (buffer) buffer.fill(0);
  }
}

/**
 * Constant-time equality. Used for every tag/fingerprint comparison so a
 * network attacker cannot learn a prefix by timing our rejection.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function expectLength(name: string, value: Uint8Array, expected: number): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new MalformedInputError(`${name} must be a Uint8Array`);
  }
  if (value.length !== expected) {
    throw new MalformedInputError(`${name} must be ${expected} bytes, got ${value.length}`);
  }
  return value;
}

// ---------------------------------------------------------------------------
// Hashing and key derivation
// ---------------------------------------------------------------------------

export function hash512(...parts: Uint8Array[]): Uint8Array {
  const h = sha512.create();
  for (const part of parts) h.update(part);
  return h.digest();
}

export function hash256(...parts: Uint8Array[]): Uint8Array {
  const h = sha256.create();
  for (const part of parts) h.update(part);
  return h.digest();
}

export function mac(key: Uint8Array, ...parts: Uint8Array[]): Uint8Array {
  const h = hmac.create(sha512, key);
  for (const part of parts) h.update(part);
  return h.digest();
}

/**
 * HKDF-SHA-512. `info` is always a domain-separation label (see kdf.ts) so two
 * different uses of the same input secret can never derive the same key.
 */
export function kdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return hkdf(sha512, ikm, salt, info, length);
}

/** Argon2id. Parameters are chosen by the caller; see vault.ts for the profile. */
export function passphraseKdf(
  passphrase: Uint8Array,
  salt: Uint8Array,
  opts: { memoryKiB: number; iterations: number; parallelism: number; length: number },
): Uint8Array {
  return argon2id(passphrase, salt, {
    m: opts.memoryKiB,
    t: opts.iterations,
    p: opts.parallelism,
    dkLen: opts.length,
  });
}

// ---------------------------------------------------------------------------
// X25519 (Diffie-Hellman)
// ---------------------------------------------------------------------------

export interface KeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
}

export function generateDhKeyPair(): KeyPair {
  const secretKey = x25519.utils.randomSecretKey();
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
}

export function dhPublicKey(secretKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(expectLength('x25519 secret key', secretKey, X25519_SECRET_LEN));
}

/**
 * X25519 shared secret.
 *
 * noble rejects all-zero outputs (low-order / small-subgroup public keys), which
 * is exactly the contributory-behaviour check we want: a peer cannot force a
 * predictable shared secret. We surface that as an error rather than proceeding.
 */
export function dh(secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
  expectLength('x25519 secret key', secretKey, X25519_SECRET_LEN);
  expectLength('x25519 public key', peerPublicKey, X25519_PUBLIC_LEN);
  try {
    return x25519.getSharedSecret(secretKey, peerPublicKey);
  } catch (cause) {
    throw new MalformedInputError(
      `X25519 agreement failed (degenerate or invalid peer public key): ${String(cause)}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Ed25519 (signatures)
// ---------------------------------------------------------------------------

export function generateSigningKeyPair(): KeyPair {
  const secretKey = ed25519.utils.randomSecretKey();
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}

/** Ed25519 public keys are a pure function of the secret key; recompute, never trust storage. */
export function signingPublicKey(secretKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(expectLength('ed25519 secret key', secretKey, ED25519_SECRET_LEN));
}

export function sign(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  expectLength('ed25519 secret key', secretKey, ED25519_SECRET_LEN);
  return ed25519.sign(message, secretKey);
}

/** Never throws on a bad signature — returns false, so callers must branch. */
export function verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== ED25519_PUBLIC_LEN) return false;
  if (signature.length !== ED25519_SIGNATURE_LEN) return false;
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// ML-KEM-1024 (post-quantum key encapsulation)
// ---------------------------------------------------------------------------

export function generateKemKeyPair(): KeyPair {
  const { publicKey, secretKey } = ml_kem1024.keygen();
  return { publicKey, secretKey };
}

export interface KemEncapsulation {
  readonly ciphertext: Uint8Array;
  readonly sharedSecret: Uint8Array;
}

export function kemEncapsulate(peerPublicKey: Uint8Array): KemEncapsulation {
  expectLength('ML-KEM public key', peerPublicKey, MLKEM_PUBLIC_LEN);
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(peerPublicKey);
  return { ciphertext: cipherText, sharedSecret };
}

/**
 * ML-KEM decapsulation.
 *
 * ML-KEM is implicitly rejecting: a corrupted ciphertext yields a pseudorandom
 * secret instead of an error. That is by design and safe here, because the
 * resulting secret feeds a KDF whose output must still authenticate an AEAD
 * tag — so a tampered ciphertext surfaces as an AuthenticationError one layer up.
 */
export function kemDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Uint8Array {
  expectLength('ML-KEM ciphertext', ciphertext, MLKEM_CIPHERTEXT_LEN);
  expectLength('ML-KEM secret key', secretKey, MLKEM_SECRET_LEN);
  return ml_kem1024.decapsulate(ciphertext, secretKey);
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

export function aeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array {
  expectLength('AEAD key', key, AEAD_KEY_LEN);
  expectLength('AEAD nonce', nonce, AEAD_NONCE_LEN);
  return xchacha20poly1305(key, nonce, associatedData).encrypt(plaintext);
}

export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array {
  expectLength('AEAD key', key, AEAD_KEY_LEN);
  expectLength('AEAD nonce', nonce, AEAD_NONCE_LEN);
  if (ciphertext.length < AEAD_TAG_LEN) {
    throw new MalformedInputError('ciphertext shorter than the authentication tag');
  }
  try {
    return xchacha20poly1305(key, nonce, associatedData).decrypt(ciphertext);
  } catch {
    // Deliberately opaque: never leak whether the key, nonce, or AD was wrong.
    throw new AuthenticationError('AEAD authentication failed');
  }
}

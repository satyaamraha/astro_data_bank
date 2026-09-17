/**
 * At-rest encryption.
 *
 * Transport encryption is pointless if a seized phone yields the whole message
 * history. This is the layer that makes "the app is private" true when the
 * device is in someone else's hands.
 *
 * Structure:
 *
 *   passphrase --Argon2id--> KEK --wraps--> DEK --per-record--> record keys
 *
 * Why the extra indirection instead of encrypting records under the KEK:
 *  - Changing the passphrase re-wraps one small blob instead of re-encrypting
 *    the entire database.
 *  - The expensive Argon2id derivation runs once at unlock, not per record.
 *  - The DEK can be held in a hardware keystore while the KEK stays derived,
 *    so on devices with a Secure Enclave / StrongBox the DEK never sits in JS.
 *
 * Honest limits: this protects data at rest while the app is locked. It cannot
 * protect a running, unlocked app from a compromised OS, and a short passphrase
 * remains brute-forceable no matter what Argon2id parameters we pick — which is
 * why the app should bind the DEK to hardware-backed key material as well.
 */

import {
  AEAD_KEY_LEN,
  AEAD_NONCE_LEN,
  aeadDecrypt,
  aeadEncrypt,
  constantTimeEqual,
  kdf,
  passphraseKdf,
  random,
  wipe,
} from './primitives.js';
import { LABELS } from './kdf.js';
import { AuthenticationError, MalformedInputError, VaultLockedError } from './errors.js';
import { Reader, Writer, utf8 } from './wire.js';

/**
 * Argon2id parameters.
 *
 * 64 MiB / 3 passes / 1 lane is the interactive profile: roughly 100-300ms on a
 * mid-range phone, which users tolerate at unlock, while costing an attacker
 * 64 MiB of memory per parallel guess. That memory cost is the point — it is
 * what makes GPU and ASIC cracking uneconomic, and it is why Argon2id is used
 * here rather than PBKDF2, which parallelises almost for free.
 *
 * Stored in the header so the parameters can be raised later without making
 * existing vaults unreadable.
 */
export const ARGON2_PROFILE = {
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 1,
} as const;

const SALT_LEN = 16;
const VAULT_MAGIC = utf8.encode('VEIL-VAULT-1');

/** The on-disk wrapper. Safe to back up: useless without the passphrase. */
export interface WrappedVault {
  readonly salt: Uint8Array;
  readonly memoryKiB: number;
  readonly iterations: number;
  readonly parallelism: number;
  /** DEK encrypted under the KEK. */
  readonly wrappedKey: Uint8Array;
}

/** An unlocked vault. Holds the DEK in memory; wipe on lock. */
export interface Vault {
  readonly dataKey: Uint8Array;
}

function deriveKek(
  passphrase: Uint8Array,
  salt: Uint8Array,
  profile: { memoryKiB: number; iterations: number; parallelism: number },
): Uint8Array {
  const raw = passphraseKdf(passphrase, salt, { ...profile, length: 32 });
  // One HKDF pass over the Argon2id output gives clean domain separation, so
  // the same passphrase+salt could serve another purpose without key reuse.
  const kek = kdf(raw, salt, LABELS.vaultKek, AEAD_KEY_LEN);
  wipe(raw);
  return kek;
}

function wrapNonce(salt: Uint8Array): Uint8Array {
  // Deterministic from the salt: the KEK is used for exactly one encryption
  // (wrapping the DEK), so a fresh random nonce would add nothing, and a
  // deterministic one removes the risk of storing a mismatched nonce.
  const derived = kdf(salt, VAULT_MAGIC, LABELS.vaultKek, AEAD_NONCE_LEN);
  return derived;
}

/** Create a new vault with a random DEK, protected by `passphrase`. */
export function createVault(passphrase: Uint8Array): {
  vault: Vault;
  wrapped: WrappedVault;
} {
  const salt = random(SALT_LEN);
  const dataKey = random(AEAD_KEY_LEN);
  const kek = deriveKek(passphrase, salt, ARGON2_PROFILE);
  const nonce = wrapNonce(salt);
  try {
    return {
      vault: { dataKey },
      wrapped: {
        salt,
        ...ARGON2_PROFILE,
        wrappedKey: aeadEncrypt(kek, nonce, dataKey, VAULT_MAGIC),
      },
    };
  } finally {
    wipe(kek, nonce);
  }
}

/**
 * Unlock a vault.
 *
 * A wrong passphrase surfaces as VaultLockedError, deliberately
 * indistinguishable from a tampered blob: telling the user which of the two it
 * was would tell an attacker the same thing.
 */
export function unlockVault(passphrase: Uint8Array, wrapped: WrappedVault): Vault {
  if (wrapped.salt.length !== SALT_LEN) {
    throw new MalformedInputError('vault salt has wrong length');
  }
  const kek = deriveKek(passphrase, wrapped.salt, {
    memoryKiB: wrapped.memoryKiB,
    iterations: wrapped.iterations,
    parallelism: wrapped.parallelism,
  });
  const nonce = wrapNonce(wrapped.salt);
  try {
    return { dataKey: aeadDecrypt(kek, nonce, wrapped.wrappedKey, VAULT_MAGIC) };
  } catch (error) {
    if (error instanceof AuthenticationError) {
      throw new VaultLockedError('incorrect passphrase, or the vault has been tampered with');
    }
    throw error;
  } finally {
    wipe(kek, nonce);
  }
}

/** Re-wrap the same DEK under a new passphrase; stored records stay valid. */
export function changePassphrase(
  vault: Vault,
  newPassphrase: Uint8Array,
): WrappedVault {
  const salt = random(SALT_LEN);
  const kek = deriveKek(newPassphrase, salt, ARGON2_PROFILE);
  const nonce = wrapNonce(salt);
  try {
    return {
      salt,
      ...ARGON2_PROFILE,
      wrappedKey: aeadEncrypt(kek, nonce, vault.dataKey, VAULT_MAGIC),
    };
  } finally {
    wipe(kek, nonce);
  }
}

/**
 * Per-record key from the DEK and the record's id.
 *
 * Binding the key to the record id means a stolen database cannot have its rows
 * swapped: a ciphertext moved to a different id fails to decrypt.
 */
function recordKey(dataKey: Uint8Array, recordId: string): Uint8Array {
  return kdf(
    dataKey,
    utf8.encode(recordId),
    LABELS.vaultRecord,
    AEAD_KEY_LEN,
  );
}

/** Encrypt one record. The nonce is random per write, so rewrites are safe. */
export function encryptRecord(
  vault: Vault,
  recordId: string,
  plaintext: Uint8Array,
): Uint8Array {
  const key = recordKey(vault.dataKey, recordId);
  const nonce = random(AEAD_NONCE_LEN);
  try {
    const ciphertext = aeadEncrypt(key, nonce, plaintext, utf8.encode(recordId));
    return new Writer().fixed(nonce).fixed(ciphertext).finish();
  } finally {
    wipe(key, nonce);
  }
}

export function decryptRecord(
  vault: Vault,
  recordId: string,
  stored: Uint8Array,
): Uint8Array {
  if (stored.length < AEAD_NONCE_LEN) {
    throw new MalformedInputError('stored record is too short to contain a nonce');
  }
  const nonce = stored.slice(0, AEAD_NONCE_LEN);
  const ciphertext = stored.slice(AEAD_NONCE_LEN);
  const key = recordKey(vault.dataKey, recordId);
  try {
    return aeadDecrypt(key, nonce, ciphertext, utf8.encode(recordId));
  } finally {
    wipe(key);
  }
}

/** Lock the vault: wipe the DEK from memory. */
export function lockVault(vault: Vault): void {
  wipe(vault.dataKey);
}

/** Serialise the wrapper for storage. */
export function encodeWrappedVault(wrapped: WrappedVault): Uint8Array {
  return new Writer()
    .fixed(VAULT_MAGIC)
    .bytes(wrapped.salt)
    .u32(wrapped.memoryKiB)
    .u32(wrapped.iterations)
    .u32(wrapped.parallelism)
    .bytes(wrapped.wrappedKey)
    .finish();
}

export function decodeWrappedVault(bytes: Uint8Array): WrappedVault {
  const reader = new Reader(bytes);
  const magic = reader.fixed(VAULT_MAGIC.length);
  if (!constantTimeEqual(magic, VAULT_MAGIC)) {
    throw new MalformedInputError('not a Veil vault');
  }
  const wrapped: WrappedVault = {
    salt: reader.bytes(),
    memoryKiB: reader.u32(),
    iterations: reader.u32(),
    parallelism: reader.u32(),
    wrappedKey: reader.bytes(),
  };
  reader.end();
  return wrapped;
}

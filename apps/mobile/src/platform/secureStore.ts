/**
 * Identity storage backed by the platform keystore.
 *
 * This holds the two things whose loss is unrecoverable: the identity secret
 * keys and the vault wrapper. Everything else the app stores is ciphertext that
 * is useless without them.
 *
 * Platform behaviour differs, and it is worth being precise rather than
 * hand-waving about "the keystore":
 *
 *  - **Android** (the primary target): values are encrypted with a key held in
 *    the Android Keystore, which on devices with a TEE or StrongBox is backed
 *    by hardware and cannot be exported even from a rooted device. Keeping the
 *    entry out of cloud backup is *not* done here — it is done by
 *    `allowBackup="false"` plus the backup rules in
 *    `plugins/withAndroidPrivacy.js`.
 *  - **iOS**: values go to the Keychain. `keychainAccessible` is an iOS-only
 *    option, and `WHEN_UNLOCKED_THIS_DEVICE_ONLY` is what stops the entry
 *    syncing to iCloud Keychain or migrating in an encrypted backup.
 *
 * `requireAuthentication` is requested when the device can honour it. That
 * binds reading the identity key to a biometric or device-credential prompt,
 * so a running-but-locked device cannot be made to hand it over. It is a
 * request, not a guarantee: a device with no passcode set cannot provide it,
 * and the app reports which mode is actually in force rather than assuming
 * the stronger one.
 */

import * as SecureStore from 'expo-secure-store';
import type { SecretStore } from '../core/storage.js';

/** How strongly the platform is actually protecting the stored secrets. */
export type KeystoreMode =
  /** Reads require a biometric or device-credential prompt. */
  | 'authenticated'
  /** Encrypted at rest by the keystore, but readable by the running app. */
  | 'unauthenticated';

const BASE_OPTIONS: SecureStore.SecureStoreOptions = {
  // iOS-only; ignored on Android. Prevents iCloud Keychain sync and backup
  // migration of the identity key.
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

const AUTHENTICATED_OPTIONS: SecureStore.SecureStoreOptions = {
  ...BASE_OPTIONS,
  requireAuthentication: true,
  authenticationPrompt: 'Unlock Veil',
};

/**
 * Whether the device can bind stored secrets to user authentication.
 *
 * Note this is genuinely a question about the *device credential*, not about
 * hardware key storage: a device with a TEE but no configured passcode returns
 * false. There is no API that reports whether the keystore is hardware-backed,
 * so the app must not claim that it is.
 */
export async function canRequireAuthentication(): Promise<boolean> {
  try {
    return await SecureStore.canUseBiometricAuthentication();
  } catch {
    return false;
  }
}

export class KeystoreSecretStore implements SecretStore {
  private constructor(
    private readonly options: SecureStore.SecureStoreOptions,
    readonly mode: KeystoreMode,
  ) {}

  /**
   * Open the keystore, preferring authentication-bound storage.
   *
   * Falls back rather than failing, because refusing to run on a device with
   * no passcode would push people to a messenger with no encryption at all.
   * The mode is exposed so the UI can tell the user which protection they have.
   */
  static async open(): Promise<KeystoreSecretStore> {
    if (await canRequireAuthentication()) {
      return new KeystoreSecretStore(AUTHENTICATED_OPTIONS, 'authenticated');
    }
    return new KeystoreSecretStore(BASE_OPTIONS, 'unauthenticated');
  }

  /**
   * Open without authentication binding.
   *
   * Used when migrating an existing install whose entries were written in the
   * weaker mode: a value stored without `requireAuthentication` cannot be read
   * back with it, so an unconditional upgrade would lock the user out of their
   * own identity.
   */
  static openUnauthenticated(): KeystoreSecretStore {
    return new KeystoreSecretStore(BASE_OPTIONS, 'unauthenticated');
  }

  async get(key: string): Promise<string | undefined> {
    const value = await SecureStore.getItemAsync(key, this.options);
    return value ?? undefined;
  }

  async set(key: string, value: string): Promise<void> {
    await SecureStore.setItemAsync(key, value, this.options);
  }

  async delete(key: string): Promise<void> {
    await SecureStore.deleteItemAsync(key, this.options);
  }
}

/**
 * Read a value written in either mode.
 *
 * Tries the authentication-bound store first, then the plain one. Needed
 * because an install predating the authenticated mode has entries that the
 * stronger options cannot open, and silently treating that as "no identity
 * found" would offer to create a new one and orphan the user's history.
 */
export async function readEitherMode(key: string): Promise<string | undefined> {
  const primary = await KeystoreSecretStore.open();
  try {
    const value = await primary.get(key);
    if (value !== undefined) return value;
  } catch {
    // Fall through to the weaker store.
  }
  if (primary.mode === 'unauthenticated') return undefined;
  try {
    return await KeystoreSecretStore.openUnauthenticated().get(key);
  } catch {
    return undefined;
  }
}

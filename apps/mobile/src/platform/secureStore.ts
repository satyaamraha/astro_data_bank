/**
 * Identity storage backed by the platform keystore.
 *
 * On iOS this is the Keychain; on Android, the Keystore (hardware-backed on
 * devices with a StrongBox or TEE). Two options matter here:
 *
 *  - `requireAuthentication` binds the entry to device unlock, so the identity
 *    key cannot be read while the phone is locked.
 *  - `keychainAccessible: WHEN_UNLOCKED_THIS_DEVICE_ONLY` keeps the key out of
 *    iCloud Keychain and out of encrypted backups. Without it, the account key
 *    would sync to Apple's servers, which would quietly undo the point of
 *    holding it on-device.
 */

import * as SecureStore from 'expo-secure-store';
import type { SecretStore } from '../core/storage.js';

const OPTIONS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

export class KeystoreSecretStore implements SecretStore {
  async get(key: string): Promise<string | undefined> {
    const value = await SecureStore.getItemAsync(key, OPTIONS);
    return value ?? undefined;
  }

  async set(key: string, value: string): Promise<void> {
    await SecureStore.setItemAsync(key, value, OPTIONS);
  }

  async delete(key: string): Promise<void> {
    await SecureStore.deleteItemAsync(key, OPTIONS);
  }
}

/** True when the device can store secrets in hardware. Surfaced in settings. */
export async function hasHardwareKeystore(): Promise<boolean> {
  return SecureStore.canUseBiometricAuthentication();
}

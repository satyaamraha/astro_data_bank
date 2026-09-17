/**
 * Encrypted local storage.
 *
 * Two distinct stores, because they have different threat models:
 *
 *  - `SecretStore` holds the identity key and the vault wrapper. It must be
 *    backed by the platform keystore (iOS Keychain / Android Keystore), where
 *    the OS can bind entries to device unlock and, on supported hardware, to a
 *    secure element that resists extraction even from a rooted device.
 *
 *  - `Database` holds messages and contacts. Large, queryable, and encrypted
 *    by us under the vault's data key rather than by the platform — so a
 *    database file copied off the device is opaque without the passphrase.
 *
 * Splitting them means a device backup that captures app files does not
 * capture the keys needed to read them.
 */

import {
  decryptRecord,
  encryptRecord,
  type Vault,
} from '@veil/crypto';

/** Platform keystore. Small values only; every entry is a secret. */
export interface SecretStore {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

/** Opaque blob store. Values are always ciphertext produced by this module. */
export interface Database {
  get(collection: string, id: string): Promise<Uint8Array | undefined>;
  put(collection: string, id: string, value: Uint8Array): Promise<void>;
  delete(collection: string, id: string): Promise<void>;
  list(collection: string): Promise<Array<{ id: string; value: Uint8Array }>>;
  clear(): Promise<void>;
}

/**
 * A typed, encrypted collection.
 *
 * Every value is encrypted under a key derived from the vault's data key and
 * the record id, so rows cannot be swapped between ids even by someone with
 * write access to the database file.
 */
export class EncryptedCollection<T> {
  constructor(
    private readonly database: Database,
    private readonly vault: Vault,
    private readonly name: string,
  ) {}

  private recordId(id: string): string {
    // The collection name is part of the key derivation, so a record cannot be
    // moved from one collection to another either.
    return `${this.name}/${id}`;
  }

  async get(id: string): Promise<T | undefined> {
    const stored = await this.database.get(this.name, id);
    if (!stored) return undefined;
    const plaintext = decryptRecord(this.vault, this.recordId(id), stored);
    return JSON.parse(new TextDecoder().decode(plaintext)) as T;
  }

  async put(id: string, value: T): Promise<void> {
    const plaintext = new TextEncoder().encode(JSON.stringify(value));
    const ciphertext = encryptRecord(this.vault, this.recordId(id), plaintext);
    await this.database.put(this.name, id, ciphertext);
  }

  async delete(id: string): Promise<void> {
    await this.database.delete(this.name, id);
  }

  /**
   * Read every record.
   *
   * A record that fails to decrypt is skipped rather than thrown, so one
   * corrupt row cannot make the whole conversation list unopenable. Corruption
   * is reported through `onCorrupt` so the app can surface it instead of
   * hiding data loss.
   */
  async all(onCorrupt?: (id: string, error: unknown) => void): Promise<Array<{ id: string; value: T }>> {
    const rows = await this.database.list(this.name);
    const out: Array<{ id: string; value: T }> = [];
    for (const row of rows) {
      try {
        const plaintext = decryptRecord(this.vault, this.recordId(row.id), row.value);
        out.push({
          id: row.id,
          value: JSON.parse(new TextDecoder().decode(plaintext)) as T,
        });
      } catch (error) {
        onCorrupt?.(row.id, error);
      }
    }
    return out;
  }
}

/** In-memory implementations, used by tests and by the app before unlock. */
export class InMemorySecretStore implements SecretStore {
  private readonly values = new Map<string, string>();

  async get(key: string): Promise<string | undefined> {
    return this.values.get(key);
  }

  async set(key: string, value: string): Promise<void> {
    this.values.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.values.delete(key);
  }
}

export class InMemoryDatabase implements Database {
  private readonly collections = new Map<string, Map<string, Uint8Array>>();

  private collection(name: string): Map<string, Uint8Array> {
    const existing = this.collections.get(name);
    if (existing) return existing;
    const created = new Map<string, Uint8Array>();
    this.collections.set(name, created);
    return created;
  }

  async get(collection: string, id: string): Promise<Uint8Array | undefined> {
    return this.collection(collection).get(id);
  }

  async put(collection: string, id: string, value: Uint8Array): Promise<void> {
    this.collection(collection).set(id, value);
  }

  async delete(collection: string, id: string): Promise<void> {
    this.collection(collection).delete(id);
  }

  async list(collection: string): Promise<Array<{ id: string; value: Uint8Array }>> {
    return [...this.collection(collection).entries()].map(([id, value]) => ({ id, value }));
  }

  async clear(): Promise<void> {
    this.collections.clear();
  }

  /** Test helper: raw stored bytes, for asserting nothing is stored in clear. */
  async raw(): Promise<string> {
    const parts: string[] = [];
    for (const [name, records] of this.collections) {
      parts.push(name);
      for (const [id, value] of records) {
        parts.push(id, Buffer.from(value).toString('binary'));
      }
    }
    return parts.join('|');
  }
}

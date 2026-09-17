/**
 * Message and contact storage on SQLite.
 *
 * Note what this layer does *not* do: it never sees plaintext. Values arrive
 * already encrypted by `EncryptedCollection` under a key derived from the
 * vault. So the database file is opaque on its own, and we do not depend on
 * SQLCipher or on the OS encrypting the file — a copied database is useless
 * without the passphrase either way.
 */

import * as SQLite from 'expo-sqlite';
import type { Database } from '../core/storage.js';

const DATABASE_NAME = 'veil.db';

export class SqliteDatabase implements Database {
  private constructor(private readonly db: SQLite.SQLiteDatabase) {}

  static async open(): Promise<SqliteDatabase> {
    const db = await SQLite.openDatabaseAsync(DATABASE_NAME);
    // A single blob table: the app's schema lives inside the encrypted values,
    // so the database structure itself reveals nothing beyond record counts.
    await db.execAsync(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS records (
        collection TEXT NOT NULL,
        id TEXT NOT NULL,
        value BLOB NOT NULL,
        PRIMARY KEY (collection, id)
      );
    `);
    return new SqliteDatabase(db);
  }

  async get(collection: string, id: string): Promise<Uint8Array | undefined> {
    const row = await this.db.getFirstAsync<{ value: Uint8Array }>(
      'SELECT value FROM records WHERE collection = ? AND id = ?',
      [collection, id],
    );
    return row ? new Uint8Array(row.value) : undefined;
  }

  async put(collection: string, id: string, value: Uint8Array): Promise<void> {
    await this.db.runAsync(
      'INSERT OR REPLACE INTO records (collection, id, value) VALUES (?, ?, ?)',
      [collection, id, value],
    );
  }

  async delete(collection: string, id: string): Promise<void> {
    await this.db.runAsync('DELETE FROM records WHERE collection = ? AND id = ?', [
      collection,
      id,
    ]);
  }

  async list(collection: string): Promise<Array<{ id: string; value: Uint8Array }>> {
    const rows = await this.db.getAllAsync<{ id: string; value: Uint8Array }>(
      'SELECT id, value FROM records WHERE collection = ?',
      [collection],
    );
    return rows.map((row) => ({ id: row.id, value: new Uint8Array(row.value) }));
  }

  async clear(): Promise<void> {
    await this.db.runAsync('DELETE FROM records');
    // Reclaim the pages so deleted ciphertext is not left in free space where
    // forensic recovery could reach it.
    await this.db.execAsync('VACUUM');
  }
}

/**
 * Relay storage.
 *
 * The interface is deliberately narrow, because the shape of the storage layer
 * *is* the privacy policy. What the relay can store is exactly what is
 * declared here, and there is no field for a phone number, an IP address, a
 * contact list, a read receipt, or a sender.
 *
 * The in-memory implementation is the reference. A production deployment swaps
 * in Redis or Postgres behind the same interface; the point is that a
 * different backend cannot widen what is retained without changing this file,
 * which makes the change visible in review.
 */

import { LIMITS, type WireEnvelope } from '@veil/protocol';

export interface AccountRecord {
  readonly address: string;
  /** Public identity, needed to verify auth signatures and serve bundles. */
  readonly identity: {
    signingPublicKey: string;
    exchangePublicKey: string;
    exchangeKeySignature: string;
  };
  signedPreKey: { id: number; publicKey: string; signature: string };
  signedKemPreKey: { id: number; publicKey: string; signature: string };
  oneTimePreKeys: Array<{ id: number; publicKey: string }>;
  oneTimeKemPreKeys: Array<{ id: number; publicKey: string }>;
}

export interface QueuedMessage {
  readonly id: string;
  readonly envelope: WireEnvelope;
  readonly receivedAt: number;
}

export interface RelayStore {
  createAccount(record: AccountRecord): Promise<void>;
  getAccount(address: string): Promise<AccountRecord | undefined>;
  updatePreKeys(
    address: string,
    update: Partial<
      Pick<
        AccountRecord,
        'signedPreKey' | 'signedKemPreKey' | 'oneTimePreKeys' | 'oneTimeKemPreKeys'
      >
    >,
  ): Promise<void>;
  /** Atomically take one one-time prekey of each kind, if any remain. */
  takeOneTimePreKeys(address: string): Promise<{
    oneTimePreKey?: { id: number; publicKey: string };
    oneTimeKemPreKey?: { id: number; publicKey: string };
  }>;
  enqueue(message: QueuedMessage): Promise<void>;
  /** Queued messages for a recipient, oldest first. */
  queued(address: string): Promise<QueuedMessage[]>;
  /** Delete by id. Returns how many were removed. */
  acknowledge(address: string, ids: string[]): Promise<number>;
  /** Drop messages past their TTL. Called on a timer. */
  expire(now: number): Promise<number>;
  countQueued(address: string): Promise<number>;
}

export class InMemoryRelayStore implements RelayStore {
  private readonly accounts = new Map<string, AccountRecord>();
  private readonly queues = new Map<string, QueuedMessage[]>();

  async createAccount(record: AccountRecord): Promise<void> {
    this.accounts.set(record.address, record);
  }

  async getAccount(address: string): Promise<AccountRecord | undefined> {
    return this.accounts.get(address);
  }

  async updatePreKeys(
    address: string,
    update: Partial<
      Pick<
        AccountRecord,
        'signedPreKey' | 'signedKemPreKey' | 'oneTimePreKeys' | 'oneTimeKemPreKeys'
      >
    >,
  ): Promise<void> {
    const account = this.accounts.get(address);
    if (!account) return;
    if (update.signedPreKey) account.signedPreKey = update.signedPreKey;
    if (update.signedKemPreKey) account.signedKemPreKey = update.signedKemPreKey;
    if (update.oneTimePreKeys) {
      // Cap the pool so a client cannot use the relay as free storage.
      account.oneTimePreKeys = [
        ...account.oneTimePreKeys,
        ...update.oneTimePreKeys,
      ].slice(0, LIMITS.maxOneTimePreKeys);
    }
    if (update.oneTimeKemPreKeys) {
      account.oneTimeKemPreKeys = [
        ...account.oneTimeKemPreKeys,
        ...update.oneTimeKemPreKeys,
      ].slice(0, LIMITS.maxOneTimePreKeys);
    }
  }

  async takeOneTimePreKeys(address: string): Promise<{
    oneTimePreKey?: { id: number; publicKey: string };
    oneTimeKemPreKey?: { id: number; publicKey: string };
  }> {
    const account = this.accounts.get(address);
    if (!account) return {};
    // shift() removes the key as it is handed out, so two peers never receive
    // the same one-time prekey. Reuse would cost a forward-secrecy term.
    const oneTimePreKey = account.oneTimePreKeys.shift();
    const oneTimeKemPreKey = account.oneTimeKemPreKeys.shift();
    return {
      ...(oneTimePreKey ? { oneTimePreKey } : {}),
      ...(oneTimeKemPreKey ? { oneTimeKemPreKey } : {}),
    };
  }

  async enqueue(message: QueuedMessage): Promise<void> {
    const address = message.envelope.recipient;
    const queue = this.queues.get(address) ?? [];
    queue.push(message);
    // Oldest-first overflow. Bounded so one recipient cannot be used to fill
    // the server's disk.
    while (queue.length > LIMITS.maxQueueLength) queue.shift();
    this.queues.set(address, queue);
  }

  async queued(address: string): Promise<QueuedMessage[]> {
    return [...(this.queues.get(address) ?? [])];
  }

  async acknowledge(address: string, ids: string[]): Promise<number> {
    const queue = this.queues.get(address);
    if (!queue) return 0;
    const wanted = new Set(ids);
    const kept = queue.filter((message) => !wanted.has(message.id));
    const removed = queue.length - kept.length;
    this.queues.set(address, kept);
    return removed;
  }

  async expire(now: number): Promise<number> {
    let removed = 0;
    for (const [address, queue] of this.queues) {
      const kept = queue.filter((m) => now - m.receivedAt < LIMITS.messageTtlMs);
      removed += queue.length - kept.length;
      this.queues.set(address, kept);
    }
    return removed;
  }

  async countQueued(address: string): Promise<number> {
    return this.queues.get(address)?.length ?? 0;
  }

  /** Test/ops helper: total queued messages across all recipients. */
  async totalQueued(): Promise<number> {
    let total = 0;
    for (const queue of this.queues.values()) total += queue.length;
    return total;
  }
}

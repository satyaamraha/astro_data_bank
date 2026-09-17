/**
 * An in-memory prekey store.
 *
 * This is the reference implementation of the key-management policy: which keys
 * exist, when they rotate, and — critically — that a one-time prekey is used
 * exactly once. The app wraps this with vault-backed persistence rather than
 * reimplementing the policy, so the "used exactly once" rule lives in one place.
 */

import { type KeyPair } from './primitives.js';
import {
  createOneTimeKemPreKeys,
  createOneTimePreKeys,
  createSignedKemPreKey,
  createSignedPreKey,
  type OneTimeKemPreKey,
  type OneTimePreKey,
  type PreKeyBundle,
  type PrivateIdentity,
  type PublicIdentity,
  type SignedKemPreKey,
  type SignedPreKey,
} from './identity.js';
import { type PreKeyResolver } from './session.js';

/**
 * How many one-time prekeys to keep published.
 *
 * Each one gives a fresh conversation its own single-use key. If the server
 * runs out it must hand out bundles without one, which still works but loses
 * one forward-secrecy term until we upload more — so the app refills well
 * before exhaustion.
 */
export const ONE_TIME_PREKEY_TARGET = 100;

/** Refill threshold: upload more once the published pool drops below this. */
export const ONE_TIME_PREKEY_LOW_WATER = 20;

/**
 * Retain rotated-out signed prekeys for a grace period.
 *
 * A peer may have fetched our bundle just before rotation and sent a message
 * against the old key. Dropping it immediately would make that message
 * permanently undecryptable; keeping a couple of generations closes that race
 * without retaining keys indefinitely.
 */
export const SIGNED_PREKEY_GENERATIONS = 3;

export interface PublishedPreKeys {
  readonly signedPreKey: SignedPreKey;
  readonly signedKemPreKey: SignedKemPreKey;
  readonly oneTimePreKeys: OneTimePreKey[];
  readonly oneTimeKemPreKeys: OneTimeKemPreKey[];
}

export class InMemoryPreKeyStore implements PreKeyResolver {
  private readonly signedPreKeys = new Map<number, KeyPair>();
  private readonly signedKemPreKeys = new Map<number, KeyPair>();
  private readonly oneTimePreKeys = new Map<number, KeyPair>();
  private readonly oneTimeKemPreKeys = new Map<number, KeyPair>();

  private signedPreKeyOrder: number[] = [];
  private signedKemPreKeyOrder: number[] = [];

  private currentSignedPreKey!: SignedPreKey;
  private currentSignedKemPreKey!: SignedKemPreKey;
  private publishedOneTime: OneTimePreKey[] = [];
  private publishedOneTimeKem: OneTimeKemPreKey[] = [];
  private nextId = 1;

  constructor(private readonly identity: PrivateIdentity) {
    this.rotateSignedPreKeys();
    this.replenishOneTimePreKeys(ONE_TIME_PREKEY_TARGET);
  }

  /** Rotate the medium-term keys. The app calls this on a schedule (~weekly). */
  rotateSignedPreKeys(): void {
    const spk = createSignedPreKey(this.identity, this.nextId++);
    this.signedPreKeys.set(spk.published.id, spk.secret);
    this.signedPreKeyOrder.push(spk.published.id);
    this.currentSignedPreKey = spk.published;

    const kem = createSignedKemPreKey(this.identity, this.nextId++);
    this.signedKemPreKeys.set(kem.published.id, kem.secret);
    this.signedKemPreKeyOrder.push(kem.published.id);
    this.currentSignedKemPreKey = kem.published;

    this.pruneGenerations(this.signedPreKeys, this.signedPreKeyOrder);
    this.pruneGenerations(this.signedKemPreKeys, this.signedKemPreKeyOrder);
  }

  private pruneGenerations(store: Map<number, KeyPair>, order: number[]): void {
    while (order.length > SIGNED_PREKEY_GENERATIONS) {
      const expired = order.shift();
      if (expired !== undefined) store.delete(expired);
    }
  }

  /** Generate more one-time prekeys for upload. */
  replenishOneTimePreKeys(count: number): {
    oneTimePreKeys: OneTimePreKey[];
    oneTimeKemPreKeys: OneTimeKemPreKey[];
  } {
    const classical = createOneTimePreKeys(this.nextId, count);
    this.nextId += count;
    const pq = createOneTimeKemPreKeys(this.nextId, count);
    this.nextId += count;

    for (const { published, secret } of classical) {
      this.oneTimePreKeys.set(published.id, secret);
      this.publishedOneTime.push(published);
    }
    for (const { published, secret } of pq) {
      this.oneTimeKemPreKeys.set(published.id, secret);
      this.publishedOneTimeKem.push(published);
    }

    return {
      oneTimePreKeys: classical.map((k) => k.published),
      oneTimeKemPreKeys: pq.map((k) => k.published),
    };
  }

  needsReplenishment(): boolean {
    return (
      this.publishedOneTime.length < ONE_TIME_PREKEY_LOW_WATER ||
      this.publishedOneTimeKem.length < ONE_TIME_PREKEY_LOW_WATER
    );
  }

  /** Everything we would upload to the relay. */
  published(): PublishedPreKeys {
    return {
      signedPreKey: this.currentSignedPreKey,
      signedKemPreKey: this.currentSignedKemPreKey,
      oneTimePreKeys: [...this.publishedOneTime],
      oneTimeKemPreKeys: [...this.publishedOneTimeKem],
    };
  }

  /**
   * Build the bundle a peer would receive.
   *
   * Models the relay's behaviour: hand out one one-time key of each kind and
   * remove it from the pool, so no two peers get the same one.
   */
  issueBundle(identity: PublicIdentity): PreKeyBundle {
    const oneTime = this.publishedOneTime.shift();
    const oneTimeKem = this.publishedOneTimeKem.shift();
    return {
      identity,
      signedPreKey: this.currentSignedPreKey,
      signedKemPreKey: this.currentSignedKemPreKey,
      ...(oneTime ? { oneTimePreKey: oneTime } : {}),
      ...(oneTimeKem ? { oneTimeKemPreKey: oneTimeKem } : {}),
    };
  }

  // --- PreKeyResolver ------------------------------------------------------

  signedPreKey(id: number): KeyPair | undefined {
    return this.signedPreKeys.get(id);
  }

  signedKemPreKey(id: number): KeyPair | undefined {
    return this.signedKemPreKeys.get(id);
  }

  oneTimePreKey(id: number): KeyPair | undefined {
    return this.oneTimePreKeys.get(id);
  }

  oneTimeKemPreKey(id: number): KeyPair | undefined {
    return this.oneTimeKemPreKeys.get(id);
  }

  /** Delete, never just mark used: a deleted key cannot be reused by a replay. */
  consumeOneTimePreKey(id: number): void {
    this.oneTimePreKeys.delete(id);
    this.publishedOneTime = this.publishedOneTime.filter((k) => k.id !== id);
  }

  consumeOneTimeKemPreKey(id: number): void {
    this.oneTimeKemPreKeys.delete(id);
    this.publishedOneTimeKem = this.publishedOneTimeKem.filter((k) => k.id !== id);
  }
}

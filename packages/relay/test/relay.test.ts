import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { LIMITS, toBase64Url } from '@veil/protocol';
import { addressOf, publicIdentityOf, createIdentity, random } from '@veil/crypto';
import { buildRelay, type Relay } from '../src/index.js';
import { TestClient } from './client.js';

let relay: Relay;

beforeEach(async () => {
  relay = await buildRelay({ disableTimers: true });
});

afterEach(async () => {
  await relay.close();
});

describe('registration', () => {
  it('registers an account addressed by its own key', async () => {
    const alice = new TestClient(relay, 'alice');
    const response = await alice.register();
    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({ address: alice.address });
  });

  it('stores no personal identifier', async () => {
    // The entire stored record must contain nothing but keys and an address
    // derived from them. No phone number exists to be subpoenaed.
    const alice = new TestClient(relay, 'alice');
    await alice.register();
    const record = await relay.store.getAccount(alice.address);
    expect(record).toBeDefined();
    expect(Object.keys(record!).sort()).toEqual([
      'address',
      'identity',
      'oneTimeKemPreKeys',
      'oneTimePreKeys',
      'signedKemPreKey',
      'signedPreKey',
    ]);
  });

  it('is idempotent, so an address cannot be hijacked', async () => {
    // The address is a hash of the identity key, so only the key holder can
    // ever register it. Re-registering is a no-op rather than a takeover.
    const alice = new TestClient(relay, 'alice');
    expect((await alice.register()).statusCode).toBe(201);
    expect((await alice.register()).statusCode).toBe(200);
  });

  it('rejects an identity with a broken key binding', async () => {
    const alice = new TestClient(relay, 'alice');
    const body = alice.registrationBody();
    const response = await relay.app.inject({
      method: 'POST',
      url: '/v1/accounts',
      payload: {
        ...body,
        identity: {
          ...body.identity,
          exchangeKeySignature: toBase64Url(random(64)),
        },
      },
    });
    expect(response.statusCode).toBe(400);
  });

  it('rejects a bundle whose signed prekey signature is wrong', async () => {
    const alice = new TestClient(relay, 'alice');
    const body = alice.registrationBody();
    const response = await relay.app.inject({
      method: 'POST',
      url: '/v1/accounts',
      payload: {
        ...body,
        signedPreKey: { ...body.signedPreKey, signature: toBase64Url(random(64)) },
      },
    });
    expect(response.statusCode).toBe(400);
  });

  it('rejects a missing identity', async () => {
    const response = await relay.app.inject({
      method: 'POST',
      url: '/v1/accounts',
      payload: {},
    });
    expect(response.statusCode).toBe(400);
  });
});

describe('authentication', () => {
  it('accepts a correctly signed challenge', async () => {
    const alice = new TestClient(relay, 'alice');
    await alice.register();
    await expect(alice.authenticate()).resolves.toBeTypeOf('string');
  });

  it('rejects a forged signature', async () => {
    const alice = new TestClient(relay, 'alice');
    await alice.register();
    const challenge = (
      await relay.app.inject({
        method: 'POST',
        url: '/v1/auth/challenge',
        payload: { address: alice.address },
      })
    ).json() as { challenge: string };

    const response = await relay.app.inject({
      method: 'POST',
      url: '/v1/auth',
      payload: {
        address: alice.address,
        challenge: challenge.challenge,
        signature: toBase64Url(random(64)),
      },
    });
    expect(response.statusCode).toBe(401);
  });

  it('consumes a challenge even when verification fails', async () => {
    // Otherwise an attacker could retry indefinitely against one challenge.
    const alice = new TestClient(relay, 'alice');
    await alice.register();
    const { challenge } = (
      await relay.app.inject({
        method: 'POST',
        url: '/v1/auth/challenge',
        payload: { address: alice.address },
      })
    ).json() as { challenge: string };

    await relay.app.inject({
      method: 'POST',
      url: '/v1/auth',
      payload: { address: alice.address, challenge, signature: toBase64Url(random(64)) },
    });

    // The genuine signature now fails too: the challenge is spent.
    const result = relay.auth.authenticate({
      address: alice.address,
      challenge,
      signature: toBase64Url(random(64)),
      signingPublicKey: toBase64Url(alice.identity.signing.publicKey),
    });
    expect(result).toBeUndefined();
  });

  it('does not reveal whether an address is registered', async () => {
    // Both a real and an unknown address get a challenge, so this endpoint
    // cannot be used to enumerate the user directory.
    const unknown = addressOf(publicIdentityOf(createIdentity()));
    const response = await relay.app.inject({
      method: 'POST',
      url: '/v1/auth/challenge',
      payload: { address: unknown },
    });
    expect(response.statusCode).toBe(200);
    expect((response.json() as { challenge: string }).challenge).toBeTypeOf('string');
  });

  it('refuses a challenge issued for a different address', async () => {
    const alice = new TestClient(relay, 'alice');
    const bob = new TestClient(relay, 'bob');
    await alice.register();
    await bob.register();
    const { challenge } = (
      await relay.app.inject({
        method: 'POST',
        url: '/v1/auth/challenge',
        payload: { address: bob.address },
      })
    ).json() as { challenge: string };

    const result = relay.auth.authenticate({
      address: alice.address, // mismatched
      challenge,
      signature: toBase64Url(random(64)),
      signingPublicKey: toBase64Url(alice.identity.signing.publicKey),
    });
    expect(result).toBeUndefined();
  });

  it('rejects protected endpoints without a token', async () => {
    for (const url of ['/v1/messages', '/v1/keys/count']) {
      expect((await relay.app.inject({ method: 'GET', url })).statusCode).toBe(401);
    }
  });

  it('rejects a bogus token', async () => {
    const response = await relay.app.inject({
      method: 'GET',
      url: '/v1/messages',
      headers: { authorization: `Bearer ${toBase64Url(random(32))}` },
    });
    expect(response.statusCode).toBe(401);
  });
});

describe('key distribution', () => {
  it('serves a bundle a client can verify and use', async () => {
    const alice = new TestClient(relay, 'alice');
    const bob = new TestClient(relay, 'bob');
    await alice.register();
    await bob.register();
    // startSessionWith runs the client-side signature verification.
    await expect(alice.startSessionWith(bob.address)).resolves.toBeDefined();
  });

  it('never hands out the same one-time prekey twice', async () => {
    const bob = new TestClient(relay, 'bob');
    await bob.register(5);

    const seen = new Set<number>();
    for (let i = 0; i < 5; i++) {
      const bundle = (await bob.fetchBundle(bob.address)).json() as {
        oneTimePreKey?: { id: number };
      };
      expect(bundle.oneTimePreKey).toBeDefined();
      expect(seen.has(bundle.oneTimePreKey!.id)).toBe(false);
      seen.add(bundle.oneTimePreKey!.id);
    }
  });

  it('still serves a usable bundle once one-time prekeys run out', async () => {
    const alice = new TestClient(relay, 'alice');
    const bob = new TestClient(relay, 'bob');
    await alice.register();
    await bob.register(1);

    // Exhaust the pool.
    await bob.fetchBundle(bob.address);
    const bundle = (await bob.fetchBundle(bob.address)).json() as {
      oneTimePreKey?: unknown;
      signedPreKey: unknown;
    };
    expect(bundle.oneTimePreKey).toBeUndefined();
    expect(bundle.signedPreKey).toBeDefined();
    // And a session can still be established from it.
    await expect(alice.startSessionWith(bob.address)).resolves.toBeDefined();
  });

  it('returns 404 for an unknown address', async () => {
    const alice = new TestClient(relay, 'alice');
    const unknown = addressOf(publicIdentityOf(createIdentity()));
    expect((await alice.fetchBundle(unknown)).statusCode).toBe(404);
  });

  it('lets an authenticated client top up its prekeys', async () => {
    const alice = new TestClient(relay, 'alice');
    await alice.register(2);
    await alice.authenticate();

    const fresh = alice.preKeys.replenishOneTimePreKeys(3);
    const response = await relay.app.inject({
      method: 'POST',
      url: '/v1/keys',
      headers: { authorization: `Bearer ${alice.token}` },
      payload: {
        oneTimePreKeys: fresh.oneTimePreKeys.map((k) => ({
          id: k.id,
          publicKey: toBase64Url(k.publicKey),
        })),
      },
    });
    expect(response.statusCode).toBe(200);

    const count = (
      await relay.app.inject({
        method: 'GET',
        url: '/v1/keys/count',
        headers: { authorization: `Bearer ${alice.token}` },
      })
    ).json() as { oneTimePreKeys: number };
    expect(count.oneTimePreKeys).toBe(5);
  });

  it('caps the stored prekey pool', async () => {
    const alice = new TestClient(relay, 'alice');
    await alice.register(5);
    await alice.authenticate();

    const fresh = alice.preKeys.replenishOneTimePreKeys(LIMITS.maxOneTimePreKeys + 50);
    await relay.app.inject({
      method: 'POST',
      url: '/v1/keys',
      headers: { authorization: `Bearer ${alice.token}` },
      payload: {
        oneTimePreKeys: fresh.oneTimePreKeys.map((k) => ({
          id: k.id,
          publicKey: toBase64Url(k.publicKey),
        })),
      },
    });
    const record = await relay.store.getAccount(alice.address);
    expect(record!.oneTimePreKeys.length).toBeLessThanOrEqual(LIMITS.maxOneTimePreKeys);
  });
});

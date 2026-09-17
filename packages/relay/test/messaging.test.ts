import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { LIMITS, toBase64Url } from '@veil/protocol';
import { random } from '@veil/crypto';
import { InMemoryRelayStore, RateLimiter, buildRelay, type Relay } from '../src/index.js';
import { TestClient } from './client.js';

let relay: Relay;
let store: InMemoryRelayStore;

beforeEach(async () => {
  store = new InMemoryRelayStore();
  relay = await buildRelay({ store, disableTimers: true });
});

afterEach(async () => {
  await relay.close();
});

/** Register two clients and establish a session from Alice to Bob. */
async function pair() {
  const alice = new TestClient(relay, 'alice');
  const bob = new TestClient(relay, 'bob');
  await alice.register();
  await bob.register();
  await alice.authenticate();
  await bob.authenticate();
  await alice.startSessionWith(bob.address);
  return { alice, bob };
}

describe('message delivery', () => {
  it('delivers a message end to end through the relay', async () => {
    const { alice, bob } = await pair();
    expect((await alice.send(bob.address, 'hello bob')).statusCode).toBe(200);

    const delivered = (await bob.fetchMessages()).json() as {
      messages: Array<{ id: string; envelope: Parameters<typeof bob.decryptText>[0] }>;
    };
    expect(delivered.messages).toHaveLength(1);
    expect(bob.decryptText(delivered.messages[0]!.envelope)).toBe('hello bob');
  });

  it('carries a full two-way conversation', async () => {
    const { alice, bob } = await pair();

    for (let round = 0; round < 5; round++) {
      await alice.send(bob.address, `from alice ${round}`);
      const inbox = (await bob.fetchMessages()).json() as {
        messages: Array<{ id: string; envelope: never }>;
      };
      const latest = inbox.messages[inbox.messages.length - 1]!;
      expect(bob.decryptText(latest.envelope)).toBe(`from alice ${round}`);
      await bob.acknowledge(inbox.messages.map((m) => m.id));

      await bob.send(alice.address, `from bob ${round}`);
      const aliceInbox = (await alice.fetchMessages()).json() as {
        messages: Array<{ id: string; envelope: never }>;
      };
      const reply = aliceInbox.messages[aliceInbox.messages.length - 1]!;
      expect(alice.decryptText(reply.envelope)).toBe(`from bob ${round}`);
      await alice.acknowledge(aliceInbox.messages.map((m) => m.id));
    }
  });

  it('deletes messages on acknowledgement', async () => {
    // "Delivered" must mean gone, not archived.
    const { alice, bob } = await pair();
    await alice.send(bob.address, 'ephemeral');
    const inbox = (await bob.fetchMessages()).json() as { messages: Array<{ id: string }> };
    expect(await store.countQueued(bob.address)).toBe(1);

    await bob.acknowledge(inbox.messages.map((m) => m.id));
    expect(await store.countQueued(bob.address)).toBe(0);
    expect(((await bob.fetchMessages()).json() as { messages: [] }).messages).toHaveLength(0);
  });

  it('will not let one account delete another account\'s messages', async () => {
    const { alice, bob } = await pair();
    await alice.send(bob.address, 'for bob only');
    const inbox = (await bob.fetchMessages()).json() as { messages: Array<{ id: string }> };

    // Alice tries to delete Bob's queued message by id.
    const response = await alice.acknowledge(inbox.messages.map((m) => m.id));
    expect((response.json() as { removed: number }).removed).toBe(0);
    expect(await store.countQueued(bob.address)).toBe(1);
  });

  it('queues messages while the recipient is offline', async () => {
    const { alice, bob } = await pair();
    for (let i = 0; i < 10; i++) await alice.send(bob.address, `queued ${i}`);
    const inbox = (await bob.fetchMessages()).json() as {
      messages: Array<{ envelope: never }>;
    };
    expect(inbox.messages).toHaveLength(10);
    inbox.messages.forEach((message, i) => {
      expect(bob.decryptText(message.envelope)).toBe(`queued ${i}`);
    });
  });
});

describe('what the relay can see', () => {
  it('stores no plaintext', async () => {
    const { alice, bob } = await pair();
    const secret = 'the meeting is at midnight';
    await alice.send(bob.address, secret);

    const stored = JSON.stringify(await store.queued(bob.address));
    expect(stored.includes(secret)).toBe(false);
    expect(stored.includes('midnight')).toBe(false);
  });

  it('cannot tell who sent a message', async () => {
    // The whole point of sealed sender: the stored record must not contain
    // Alice's address or identity key anywhere.
    const { alice, bob } = await pair();
    await alice.send(bob.address, 'anonymous to the operator');

    const stored = JSON.stringify(await store.queued(bob.address));
    expect(stored.includes(alice.address)).toBe(false);
    expect(stored.includes(toBase64Url(alice.identity.signing.publicKey))).toBe(false);
    expect(stored.includes(toBase64Url(alice.identity.exchange.publicKey))).toBe(false);
  });

  it('stores only routing fields per message', async () => {
    const { alice, bob } = await pair();
    await alice.send(bob.address, 'x');
    const [message] = await store.queued(bob.address);
    expect(Object.keys(message!).sort()).toEqual(['envelope', 'id', 'receivedAt']);
    expect(Object.keys(message!.envelope).sort()).toEqual([
      'ciphertext',
      'ephemeralPublicKey',
      'recipient',
    ]);
  });

  it('cannot link two messages from the same sender', async () => {
    const { alice, bob } = await pair();
    await alice.send(bob.address, 'one');
    await alice.send(bob.address, 'two');

    const queued = await store.queued(bob.address);
    // Every observable field differs between the two envelopes, so the relay
    // has nothing to group them by.
    expect(queued[0]!.envelope.ephemeralPublicKey).not.toBe(
      queued[1]!.envelope.ephemeralPublicKey,
    );
    expect(queued[0]!.envelope.ciphertext).not.toBe(queued[1]!.envelope.ciphertext);
  });

  it('blurs delivery timestamps to the hour', async () => {
    const { alice, bob } = await pair();
    await alice.send(bob.address, 'timing matters');
    const inbox = (await bob.fetchMessages()).json() as {
      messages: Array<{ receivedAtHour: number }>;
    };
    expect(inbox.messages[0]!.receivedAtHour % 3_600_000).toBe(0);
  });

  it('writes nothing to the log while handling traffic', async () => {
    // Fastify's default logger records the IP, path, and timing of every
    // request - precisely the delivery metadata this design withholds. Assert
    // the observable behaviour rather than a config flag, so enabling a
    // logger later fails this test.
    const { alice, bob } = await pair();

    const writes: string[] = [];
    const captured = [process.stdout, process.stderr].map((stream) => {
      const original = stream.write.bind(stream);
      stream.write = ((chunk: unknown, ...rest: unknown[]) => {
        writes.push(String(chunk));
        return (original as (...args: unknown[]) => boolean)(chunk, ...rest);
      }) as typeof stream.write;
      return { stream, original };
    });

    try {
      await alice.send(bob.address, 'should not be logged');
      await bob.fetchMessages();
    } finally {
      for (const { stream, original } of captured) stream.write = original;
    }

    expect(writes.join('')).toBe('');
  });
});

describe('abuse resistance', () => {
  it('accepts messages without authenticating the sender', async () => {
    // Necessary consequence of sealed sender: there is no sender identity to
    // authenticate. Asserted so the property is not "fixed" by accident.
    const { alice, bob } = await pair();
    const envelopeResponse = await alice.send(bob.address, 'unauthenticated send');
    expect(envelopeResponse.statusCode).toBe(200);
  });

  it('rate limits message submission per source', async () => {
    const limited = await buildRelay({ sendRateLimit: 3, disableTimers: true });
    try {
      const alice = new TestClient(limited, 'alice');
      const bob = new TestClient(limited, 'bob');
      await alice.register();
      await bob.register();
      await alice.startSessionWith(bob.address);

      const codes: number[] = [];
      for (let i = 0; i < 5; i++) {
        codes.push((await alice.send(bob.address, `spam ${i}`)).statusCode);
      }
      expect(codes.filter((c) => c === 200)).toHaveLength(3);
      expect(codes.filter((c) => c === 429)).toHaveLength(2);
    } finally {
      await limited.close();
    }
  });

  it('rejects an oversized envelope', async () => {
    const { bob } = await pair();
    const response = await relay.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        envelope: {
          recipient: bob.address,
          ephemeralPublicKey: toBase64Url(random(32)),
          ciphertext: 'A'.repeat(LIMITS.maxEnvelopeBytes + 1),
        },
      },
    });
    expect([413, 400]).toContain(response.statusCode);
  });

  it('rejects a malformed envelope', async () => {
    const response = await relay.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: { envelope: { recipient: 'someone' } },
    });
    expect(response.statusCode).toBe(400);
  });

  it('does not reveal whether a recipient exists', async () => {
    // Sending to an unknown address returns the same 200 as a real one, so the
    // endpoint cannot be used to probe the directory.
    const response = await relay.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: {
        envelope: {
          recipient: 'nonexistentaddress',
          ephemeralPublicKey: toBase64Url(random(32)),
          ciphertext: toBase64Url(random(64)),
        },
      },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ accepted: true });
  });

  it('bounds a recipient queue', async () => {
    // One recipient must not be usable to exhaust the server's storage.
    const queue = new InMemoryRelayStore();
    for (let i = 0; i < LIMITS.maxQueueLength + 25; i++) {
      await queue.enqueue({
        id: `m${i}`,
        envelope: { recipient: 'target', ephemeralPublicKey: 'x', ciphertext: 'y' },
        receivedAt: Date.now(),
      });
    }
    expect(await queue.countQueued('target')).toBe(LIMITS.maxQueueLength);
  });

  it('expires undelivered messages', async () => {
    const queue = new InMemoryRelayStore();
    const now = Date.now();
    await queue.enqueue({
      id: 'old',
      envelope: { recipient: 'target', ephemeralPublicKey: 'x', ciphertext: 'y' },
      receivedAt: now - LIMITS.messageTtlMs - 1000,
    });
    await queue.enqueue({
      id: 'fresh',
      envelope: { recipient: 'target', ephemeralPublicKey: 'x', ciphertext: 'y' },
      receivedAt: now,
    });
    expect(await queue.expire(now)).toBe(1);
    expect(await queue.countQueued('target')).toBe(1);
  });
});

describe('rate limiter', () => {
  it('allows up to the limit then refuses', () => {
    let clock = 0;
    const limiter = new RateLimiter(3, 1000, () => clock);
    expect([limiter.allow('a'), limiter.allow('a'), limiter.allow('a')]).toEqual([
      true,
      true,
      true,
    ]);
    expect(limiter.allow('a')).toBe(false);
  });

  it('resets after the window', () => {
    let clock = 0;
    const limiter = new RateLimiter(1, 1000, () => clock);
    expect(limiter.allow('a')).toBe(true);
    expect(limiter.allow('a')).toBe(false);
    clock = 1001;
    expect(limiter.allow('a')).toBe(true);
  });

  it('tracks sources independently', () => {
    const limiter = new RateLimiter(1, 1000, () => 0);
    expect(limiter.allow('a')).toBe(true);
    expect(limiter.allow('b')).toBe(true);
    expect(limiter.allow('a')).toBe(false);
  });
});

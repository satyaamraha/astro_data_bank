import { describe, expect, it } from 'vitest';
import { IdentityChangedError, formatSafetyNumber } from '@veil/crypto';
import type { Message, Payload } from '../src/core/types.js';
import { createUser, withRelay } from './harness.js';

describe('messaging end to end', () => {
  it('delivers a message between two users', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      await alice.messenger.sendText(bob.address, 'hello bob');
      const result = await bob.messenger.sync();
      expect(result).toEqual({ processed: 1, failed: 0 });

      const history = await bob.messenger.history(alice.address);
      expect(history.map((m) => m.body)).toEqual(['hello bob']);
      expect(history[0]!.direction).toBe('incoming');
    });
  });

  it('carries a two-way conversation', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      await alice.messenger.sendText(bob.address, 'first');
      await bob.messenger.sync();
      await bob.messenger.sendText(alice.address, 'second');
      await alice.messenger.sync();
      await alice.messenger.sendText(bob.address, 'third');
      await bob.messenger.sync();

      expect((await bob.messenger.history(alice.address)).map((m) => m.body)).toEqual([
        'first',
        'second',
        'third',
      ]);
    });
  });

  it('delivers a burst sent while the peer is offline', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      for (let i = 0; i < 12; i++) {
        await alice.messenger.sendText(bob.address, `offline ${i}`);
      }
      const result = await bob.messenger.sync();
      expect(result.failed).toBe(0);
      expect(result.processed).toBe(12);

      const history = await bob.messenger.history(alice.address);
      expect(history.map((m) => m.body)).toEqual(
        Array.from({ length: 12 }, (_, i) => `offline ${i}`),
      );
    });
  });

  it('records a conversation with preview and unread count', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      await alice.messenger.sendText(bob.address, 'unread message');
      await bob.messenger.sync();

      const conversations = await bob.messenger.listConversations();
      expect(conversations).toHaveLength(1);
      expect(conversations[0]!.address).toBe(alice.address);
      expect(conversations[0]!.lastMessagePreview).toBe('unread message');
      expect(conversations[0]!.unreadCount).toBe(1);

      await bob.messenger.markRead(alice.address);
      expect((await bob.messenger.listConversations())[0]!.unreadCount).toBe(0);
    });
  });

  it('marks a failed send as failed rather than losing it', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      // No such account, so session setup fails.
      await expect(
        alice.messenger.sendText('nonexistentaddress', 'into the void'),
      ).rejects.toThrow();
      // The message is still on record, visibly not sent.
      const history = await alice.messenger.history('nonexistentaddress');
      expect(history).toHaveLength(1);
      expect(history[0]!.status).toBe('failed');
    });
  });

  it('reuses one identity across restarts', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const firstAddress = alice.address;

      // A "restart" reuses the same secret store, as the keystore would.
      const { Messenger } = await import('../src/core/messenger.js');
      const { RelayClient } = await import('../src/core/relayClient.js');
      const { InjectTransport } = await import('./harness.js');

      const restarted = new Messenger({
        relay: new RelayClient(new InjectTransport(relay)),
        secrets: alice.secrets,
        database: alice.database,
        vault: alice.vault,
      });
      const { address, created } = await restarted.initialise();
      expect(address).toBe(firstAddress);
      expect(created).toBe(false);
    });
  });
});

describe('local storage privacy', () => {
  it('stores no plaintext in the database', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      const secret = 'the password is hunter2';
      await alice.messenger.sendText(bob.address, secret);
      await bob.messenger.sync();

      // A seized device yields this file. It must reveal nothing.
      for (const user of [alice, bob]) {
        const raw = await user.database.raw();
        expect(raw.includes(secret)).toBe(false);
        expect(raw.includes('hunter2')).toBe(false);
      }
    });
  });

  it('keeps the identity key out of the message database', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const raw = await alice.database.raw();
      const backup = JSON.parse(alice.messenger.exportIdentityBackup()) as {
        signing: string;
      };
      // The identity secret belongs in the platform keystore only.
      expect(raw.includes(backup.signing)).toBe(false);
    });
  });

  it('deletes a conversation irreversibly', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');
      await alice.messenger.sendText(bob.address, 'delete me');
      await bob.messenger.sync();

      await bob.messenger.deleteConversation(alice.address);
      expect(await bob.messenger.history(alice.address)).toHaveLength(0);
      expect(await bob.messenger.listConversations()).toHaveLength(0);
    });
  });
});

describe('disappearing messages', () => {
  it('removes a message once it expires', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      await alice.messenger.sendText(bob.address, 'burn after reading', {
        expiresInSeconds: 60,
      });
      await bob.messenger.sync();
      expect(await bob.messenger.history(alice.address)).toHaveLength(1);

      // Re-open the same store with a clock past the expiry.
      const { Messenger } = await import('../src/core/messenger.js');
      const { RelayClient } = await import('../src/core/relayClient.js');
      const { InjectTransport } = await import('./harness.js');
      // Offset from the real clock, because the stored messages were written
      // with it. Two minutes past a sixty-second timer.
      const later = new Messenger({
        relay: new RelayClient(new InjectTransport(relay)),
        secrets: bob.secrets,
        database: bob.database,
        vault: bob.vault,
        now: () => Date.now() + 120_000,
      });
      await later.initialise();

      expect(await later.history(alice.address)).toHaveLength(0);
      // And it is deleted, not merely filtered out of the view.
      expect(await later.purgeExpired()).toBe(0);
    });
  });
});

describe('identity verification', () => {
  it('produces a matching safety number on both sides', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      await alice.messenger.sendText(bob.address, 'hi');
      await bob.messenger.sync();

      const fromAlice = await alice.messenger.safetyNumberWith(bob.address);
      const fromBob = await bob.messenger.safetyNumberWith(alice.address);
      expect(fromAlice).toBeDefined();
      expect(fromAlice).toBe(fromBob);
      expect(formatSafetyNumber(fromAlice!).split(' ')).toHaveLength(12);
    });
  });

  it('starts contacts unverified and lets the user verify them', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      await alice.messenger.sendText(bob.address, 'hi');
      const contact = await alice.messenger.getContact(bob.address);
      // Nothing is trusted until a human checks it out-of-band.
      expect(contact!.verification).toBe('unverified');

      await alice.messenger.markVerified(bob.address);
      expect((await alice.messenger.getContact(bob.address))!.verification).toBe('verified');
    });
  });

  it('refuses to send to a verified contact whose key changed', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      await alice.messenger.sendText(bob.address, 'first');
      await alice.messenger.markVerified(bob.address);

      // Simulate the relay serving a different identity key for Bob's address:
      // the active-MITM case. Rewrite the stored record directly.
      const record = await relay.store.getAccount(bob.address);
      const impostor = await createUser(relay, 'impostor');
      const impostorRecord = await relay.store.getAccount(impostor.address);
      record!.identity.signingPublicKey = impostorRecord!.identity.signingPublicKey;
      record!.identity.exchangePublicKey = impostorRecord!.identity.exchangePublicKey;
      record!.identity.exchangeKeySignature = impostorRecord!.identity.exchangeKeySignature;

      // Drop the cached session so the next send refetches the bundle.
      await alice.messenger.deleteConversation(bob.address);

      await expect(alice.messenger.sendText(bob.address, 'second')).rejects.toThrow();
      const contact = await alice.messenger.getContact(bob.address);
      expect(contact!.verification).toBe('changed');
    });
  });

  it('resets verification when a key change is accepted', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');
      await alice.messenger.sendText(bob.address, 'hi');
      await alice.messenger.markVerified(bob.address);

      await alice.messenger.acceptIdentityChange(bob.address);
      // A new key must never inherit the old key's verified status.
      expect((await alice.messenger.getContact(bob.address))!.verification).toBe(
        'unverified',
      );
    });
  });
});

describe('metadata minimisation', () => {
  it('does not send receipts by default', async () => {
    await withRelay(async (relay) => {
      const received: Payload[] = [];
      const alice = await createUser(relay, 'alice', {
        events: { onCallPayload: (_, payload) => received.push(payload) },
      });
      const bob = await createUser(relay, 'bob');

      const updates: Message[] = [];
      await alice.messenger.sendText(bob.address, 'no receipt please');
      await bob.messenger.sync(); // would send a receipt if enabled
      await alice.messenger.sync();

      // Alice's message stays "sent", never upgraded to "delivered", because
      // Bob sent no receipt. Read receipts are behavioural metadata that also
      // confirm presence, so they are opt-in.
      const history = await alice.messenger.history(bob.address);
      expect(history[0]!.status).toBe('sent');
      void updates;
      void received;
    });
  });

  it('sends receipts when the user opts in', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice', { sendReceipts: true });
      const bob = await createUser(relay, 'bob', { sendReceipts: true });

      await alice.messenger.sendText(bob.address, 'receipt please');
      await bob.messenger.sync();
      await alice.messenger.sync();

      const history = await alice.messenger.history(bob.address);
      expect(history[0]!.status).toBe('delivered');
    });
  });

  it('does not send typing indicators by default', async () => {
    await withRelay(async (relay) => {
      let typingSeen = false;
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob', {
        events: { onTyping: () => (typingSeen = true) },
      });

      await alice.messenger.sendText(bob.address, 'hi');
      await alice.messenger.sendTyping(bob.address, true);
      await bob.messenger.sync();
      expect(typingSeen).toBe(false);
    });
  });
});

describe('prekey maintenance', () => {
  it('tops up one-time prekeys when the relay runs low', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const record = await relay.store.getAccount(alice.address);
      // Drain the pool, as many new conversations would.
      record!.oneTimePreKeys.length = 0;
      record!.oneTimeKemPreKeys.length = 0;

      expect(await alice.messenger.replenishPreKeysIfNeeded()).toBe(true);
      const after = await relay.store.getAccount(alice.address);
      expect(after!.oneTimePreKeys.length).toBeGreaterThan(20);
    });
  });

  it('does not upload when the pool is healthy', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      expect(await alice.messenger.replenishPreKeysIfNeeded()).toBe(false);
    });
  });
});

describe('identity errors surface to the app', () => {
  it('exposes IdentityChangedError for the UI to warn on', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');
      await alice.messenger.sendText(bob.address, 'hi');
      await alice.messenger.markVerified(bob.address);

      const record = await relay.store.getAccount(bob.address);
      const impostor = await createUser(relay, 'impostor');
      const impostorRecord = await relay.store.getAccount(impostor.address);
      record!.identity.signingPublicKey = impostorRecord!.identity.signingPublicKey;
      record!.identity.exchangePublicKey = impostorRecord!.identity.exchangePublicKey;
      record!.identity.exchangeKeySignature = impostorRecord!.identity.exchangeKeySignature;
      await alice.messenger.deleteConversation(bob.address);

      let caught: unknown;
      try {
        await alice.messenger.sendText(bob.address, 'again');
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(IdentityChangedError);
    });
  });
});

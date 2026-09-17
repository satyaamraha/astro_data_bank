import { describe, expect, it } from 'vitest';
import { MalformedInputError } from '@veil/crypto';
import { chunkCode, groupSafetyNumber, looksLikeCode, relativeTime } from '../src/core/display.js';
import { createUser, withRelay } from './harness.js';

describe('starting a conversation from a verification code', () => {
  it('starts already verified, because the code carries the full identity', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      const address = await alice.messenger.addContactFromCode(
        bob.messenger.verificationCode(),
      );
      expect(address).toBe(bob.address);

      const contact = await alice.messenger.getContact(bob.address);
      // Obtaining the whole key out-of-band is stronger evidence than
      // comparing a digit prefix aloud, so this is verified, not unverified.
      expect(contact!.verification).toBe('verified');
    });
  });

  it('lets messages flow after adding by code', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      await alice.messenger.addContactFromCode(bob.messenger.verificationCode());
      await alice.messenger.sendText(bob.address, 'added you by code');
      await bob.messenger.sync();

      expect((await bob.messenger.history(alice.address)).map((m) => m.body)).toEqual([
        'added you by code',
      ]);
    });
  });

  it('shows a safety number immediately, before any message is sent', async () => {
    // The code supplies the peer identity, so verification does not have to
    // wait for a round trip.
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      await alice.messenger.addContactFromCode(bob.messenger.verificationCode());
      const number = await alice.messenger.safetyNumberWith(bob.address);
      expect(number).toMatch(/^\d{60}$/);
    });
  });

  it('rejects a tampered code', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      const code = bob.messenger.verificationCode();
      // Flip a character in the middle of the encoded identity.
      const middle = Math.floor(code.length / 2);
      const tampered =
        code.slice(0, middle) + (code[middle] === 'A' ? 'B' : 'A') + code.slice(middle + 1);

      await expect(alice.messenger.addContactFromCode(tampered)).rejects.toThrow();
    });
  });

  it('cannot be used to claim someone else\'s address', async () => {
    // The address is a hash of the identity key and the code's binding is
    // signed, so a forged code cannot impersonate a third party.
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');
      const mallory = await createUser(relay, 'mallory');

      const address = await alice.messenger.addContactFromCode(
        mallory.messenger.verificationCode(),
      );
      expect(address).toBe(mallory.address);
      expect(address).not.toBe(bob.address);
    });
  });

  it('refuses your own code', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      await expect(
        alice.messenger.addContactFromCode(alice.messenger.verificationCode()),
      ).rejects.toThrow(/your own code/);
    });
  });

  it('rejects a code that is not a Veil code at all', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      // Not a Veil code at all: rejected on the magic-tag check, before any
      // signature work.
      await expect(
        alice.messenger.addContactFromCode('bm90LWEtdmVpbC1jb2Rl'),
      ).rejects.toThrow(MalformedInputError);
    });
  });
});

describe('starting a conversation from an address', () => {
  it('starts unverified, because the key came from the server', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');

      await alice.messenger.startConversation(bob.address);
      const contact = await alice.messenger.getContact(bob.address);
      expect(contact!.verification).toBe('unverified');
      // And it appears in the conversation list straight away.
      expect((await alice.messenger.listConversations()).map((c) => c.address)).toContain(
        bob.address,
      );
    });
  });

  it('fails loudly for an unknown address', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      await expect(alice.messenger.startConversation('nosuchaddress')).rejects.toThrow();
    });
  });
});

describe('disappearing message timer', () => {
  it('persists across reads', async () => {
    await withRelay(async (relay) => {
      const alice = await createUser(relay, 'alice');
      const bob = await createUser(relay, 'bob');
      await alice.messenger.startConversation(bob.address);

      await alice.messenger.setDisappearTimer(bob.address, 3600);
      const conversations = await alice.messenger.listConversations();
      expect(
        conversations.find((c) => c.address === bob.address)!.disappearAfterSeconds,
      ).toBe(3600);
    });
  });
});

describe('display helpers', () => {
  it('groups a safety number into twelve groups of five', () => {
    const groups = groupSafetyNumber('1'.repeat(60));
    expect(groups).toHaveLength(12);
    expect(groups.every((group) => group.length === 5)).toBe(true);
  });

  it('chunks a verification code into readable lines', () => {
    const lines = chunkCode('a'.repeat(70), 32);
    expect(lines).toEqual(['a'.repeat(32), 'a'.repeat(32), 'a'.repeat(6)]);
  });

  it('formats relative times', () => {
    const now = 10_000_000;
    expect(relativeTime(now, now)).toBe('now');
    expect(relativeTime(now - 120_000, now)).toBe('2m');
    expect(relativeTime(now - 7_200_000, now)).toBe('2h');
    expect(relativeTime(now - 172_800_000, now)).toBe('2d');
  });

  it('distinguishes a code from an address', () => {
    // Addresses are short base32; codes are long base64url. Getting this wrong
    // would mislabel an unverified conversation as verified.
    expect(looksLikeCode('a'.repeat(200))).toBe(true);
    expect(looksLikeCode('abcdefghijkmnpqr')).toBe(false);
  });
});

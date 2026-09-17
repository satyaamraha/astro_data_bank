import { describe, expect, it } from 'vitest';
import {
  DEFAULT_UNLOCK_POLICY,
  EMPTY_ATTEMPT_STATE,
  canAttempt,
  formatLockout,
  lockoutRemainingMs,
  parseAttemptState,
  recordFailure,
  recordSuccess,
  serialiseAttemptState,
  shouldWipe,
} from '../src/core/unlockPolicy.js';
import { decideInbound, decideOutbound, explainRefusal } from '../src/core/pairing.js';
import { createPairedUsers, createUser, withRelay } from './harness.js';

/**
 * Two-person mode.
 *
 * This is the configuration the shipped app uses, and it is the one that makes
 * the strongest claim: exactly one peer, established in person, everything
 * else discarded. These tests are the evidence for that claim.
 */

describe('a paired pair can talk', () => {
  it('exchanges messages in both directions', async () => {
    await withRelay(async (relay) => {
      const { alice, bob } = await createPairedUsers(relay);

      await alice.messenger.sendText(bob.address, 'hello');
      await bob.messenger.sync();
      await bob.messenger.sendText(alice.address, 'hi back');
      await alice.messenger.sync();

      expect((await bob.messenger.history(alice.address)).map((m) => m.body)).toEqual([
        'hello',
        'hi back',
      ]);
    });
  });

  it('is verified from the start, with no safety number to compare later', async () => {
    // Pairing uses a verification code carrying the peer's signed identity, so
    // the conversation never passes through an unverified state - which is the
    // window a first-contact attack needs.
    await withRelay(async (relay) => {
      const { alice, bob } = await createPairedUsers(relay);
      const contact = await alice.messenger.getContact(bob.address);
      expect(contact!.verification).toBe('verified');
    });
  });

  it('records who it is paired with', async () => {
    await withRelay(async (relay) => {
      const { alice, bob } = await createPairedUsers(relay);
      const peer = alice.messenger.pairedPeer();
      expect(peer!.peerAddress).toBe(bob.address);
      expect(peer!.displayName).toBe('Bob');
    });
  });

  it('still shows a matching safety number, for reassurance', async () => {
    await withRelay(async (relay) => {
      const { alice, bob } = await createPairedUsers(relay);
      const fromAlice = await alice.messenger.safetyNumberWith(bob.address);
      const fromBob = await bob.messenger.safetyNumberWith(alice.address);
      expect(fromAlice).toBeDefined();
      expect(fromAlice).toBe(fromBob);
    });
  });
});

describe('nobody else can get in', () => {
  it('discards a message from a stranger before it reaches the ratchet', async () => {
    await withRelay(async (relay) => {
      const { bob } = await createPairedUsers(relay);
      // An outsider who knows Bob's address - it is not a secret - and tries to
      // message him. In open mode this would create a conversation.
      const eve = await createUser(relay, 'eve', { mode: 'open' });
      await eve.messenger.startConversation(bob.address);
      await eve.messenger.sendText(bob.address, 'let me in');

      const result = await bob.messenger.sync();
      // Fetched and acknowledged, but not accepted.
      expect(result.processed).toBe(1);
      expect(result.failed).toBe(1);

      // No conversation, no contact, no history.
      expect(await bob.messenger.history(eve.address)).toHaveLength(0);
      expect(await bob.messenger.getContact(eve.address)).toBeUndefined();
      expect((await bob.messenger.listConversations()).map((c) => c.address)).not.toContain(
        eve.address,
      );
    });
  });

  it('reports a blocked stranger so the app can log it', async () => {
    await withRelay(async (relay) => {
      const blocked: Array<{ reason: string; detail: string }> = [];
      const bob = await createUser(relay, 'bob', {
        mode: 'paired',
        events: { onBlocked: (reason, detail) => blocked.push({ reason, detail }) },
      });
      const alice = await createUser(relay, 'alice', { mode: 'paired' });
      await bob.messenger.pairWithCode(alice.messenger.verificationCode(), 'Alice');

      const eve = await createUser(relay, 'eve', { mode: 'open' });
      await eve.messenger.startConversation(bob.address);
      await eve.messenger.sendText(bob.address, 'hello?');
      await bob.messenger.sync();

      expect(blocked).toHaveLength(1);
      expect(blocked[0]!.reason).toBe('stranger');
    });
  });

  it('refuses to send to anyone but the paired peer', async () => {
    await withRelay(async (relay) => {
      const { alice } = await createPairedUsers(relay);
      const eve = await createUser(relay, 'eve', { mode: 'open' });
      await expect(alice.messenger.sendText(eve.address, 'hi')).rejects.toThrow(
        /not paired with/i,
      );
    });
  });

  it('accepts nothing at all before pairing', async () => {
    // An unpaired device has no legitimate correspondent, so anything arriving
    // is unsolicited by definition.
    await withRelay(async (relay) => {
      const fresh = await createUser(relay, 'fresh', { mode: 'paired' });
      const eve = await createUser(relay, 'eve', { mode: 'open' });
      await eve.messenger.startConversation(fresh.address);
      await eve.messenger.sendText(fresh.address, 'first!');

      const result = await fresh.messenger.sync();
      expect(result.failed).toBe(1);
      expect(await fresh.messenger.listConversations()).toHaveLength(0);
    });
  });

  it('will not pair twice without an explicit unpair', async () => {
    await withRelay(async (relay) => {
      const { alice } = await createPairedUsers(relay);
      const eve = await createUser(relay, 'eve', { mode: 'open' });
      await expect(
        alice.messenger.pairWithCode(eve.messenger.verificationCode(), 'Eve'),
      ).rejects.toThrow(/already paired/i);
    });
  });
});

describe('unpairing', () => {
  it('deletes the conversation, because a new pairing could not read it', async () => {
    await withRelay(async (relay) => {
      const { alice, bob } = await createPairedUsers(relay);
      await alice.messenger.sendText(bob.address, 'history');
      await bob.messenger.sync();
      expect(await bob.messenger.history(alice.address)).toHaveLength(1);

      await bob.messenger.unpair();
      expect(bob.messenger.pairedPeer()).toBeUndefined();
      expect(await bob.messenger.history(alice.address)).toHaveLength(0);
      expect(await bob.messenger.getContact(alice.address)).toBeUndefined();
    });
  });

  it('allows pairing with someone new afterwards', async () => {
    await withRelay(async (relay) => {
      const { bob } = await createPairedUsers(relay);
      await bob.messenger.unpair();
      const carol = await createUser(relay, 'carol', { mode: 'paired' });
      await expect(
        bob.messenger.pairWithCode(carol.messenger.verificationCode(), 'Carol'),
      ).resolves.toBeDefined();
    });
  });
});

describe('pairing decision rules', () => {
  const pairing = {
    peerAddress: 'peer-address',
    peerIdentityKey: 'peer-key',
    pairedAt: 0,
    displayName: 'Peer',
  };

  it('allows the paired peer', () => {
    expect(decideInbound(pairing, 'peer-address', 'peer-key')).toEqual({ allow: true });
    expect(decideOutbound(pairing, 'peer-address')).toEqual({ allow: true });
  });

  it('refuses everything when unpaired', () => {
    expect(decideInbound(undefined, 'anyone', 'any-key')).toEqual({
      allow: false,
      reason: 'not-paired',
    });
    expect(decideOutbound(undefined, 'anyone')).toEqual({
      allow: false,
      reason: 'not-paired',
    });
  });

  it('refuses a different address', () => {
    expect(decideInbound(pairing, 'someone-else', 'peer-key')).toEqual({
      allow: false,
      reason: 'stranger',
    });
  });

  it('refuses the right address with the wrong key', () => {
    expect(decideInbound(pairing, 'peer-address', 'different-key')).toEqual({
      allow: false,
      reason: 'key-changed',
    });
  });

  it('explains a key change in terms of both causes', () => {
    // A warning that only mentions the innocent cause trains people to
    // dismiss it; one that only mentions attack cries wolf on every reinstall.
    const message = explainRefusal('key-changed');
    expect(message).toMatch(/reinstalled/i);
    expect(message).toMatch(/intercept/i);
    expect(message).toMatch(/in person/i);
  });
});

describe('passphrase throttling', () => {
  const policy = DEFAULT_UNLOCK_POLICY;

  it('allows ordinary typos without delay', () => {
    let state = EMPTY_ATTEMPT_STATE;
    for (let i = 0; i < policy.freeAttempts; i++) {
      state = recordFailure(state, 1000);
      expect(canAttempt(state, 1000, policy)).toBe(true);
    }
  });

  it('locks out after the free attempts are used', () => {
    let state = EMPTY_ATTEMPT_STATE;
    for (let i = 0; i <= policy.freeAttempts; i++) state = recordFailure(state, 1000);
    expect(canAttempt(state, 1000, policy)).toBe(false);
    expect(lockoutRemainingMs(state, 1000, policy)).toBe(policy.baseLockoutMs);
  });

  it('escalates the lockout with each further failure', () => {
    let state = EMPTY_ATTEMPT_STATE;
    for (let i = 0; i <= policy.freeAttempts; i++) state = recordFailure(state, 0);
    const first = lockoutRemainingMs(state, 0, policy);
    state = recordFailure(state, 0);
    const second = lockoutRemainingMs(state, 0, policy);
    expect(second).toBeGreaterThan(first);
  });

  it('caps the lockout so the owner is never locked out for ever', () => {
    let state = EMPTY_ATTEMPT_STATE;
    for (let i = 0; i < 100; i++) state = recordFailure(state, 0);
    expect(lockoutRemainingMs(state, 0, policy)).toBe(policy.maxLockoutMs);
  });

  it('does not overflow on an absurd failure count', () => {
    const state = { failures: 1e9, lastFailureAt: 0 };
    expect(lockoutRemainingMs(state, 0, policy)).toBe(policy.maxLockoutMs);
  });

  it('expires the lockout once the wait has elapsed', () => {
    let state = EMPTY_ATTEMPT_STATE;
    for (let i = 0; i <= policy.freeAttempts; i++) state = recordFailure(state, 1000);
    expect(canAttempt(state, 1000 + policy.baseLockoutMs, policy)).toBe(true);
  });

  it('does not let a backwards clock shorten a lockout', () => {
    let state = EMPTY_ATTEMPT_STATE;
    for (let i = 0; i <= policy.freeAttempts; i++) state = recordFailure(state, 10_000);
    // Clock rolled back, as an attacker changing the device time would do.
    expect(canAttempt(state, 5000, policy)).toBe(false);
  });

  it('clears the counter on success', () => {
    let state = EMPTY_ATTEMPT_STATE;
    for (let i = 0; i < 10; i++) state = recordFailure(state, 0);
    expect(canAttempt(recordSuccess(), 0, policy)).toBe(true);
  });

  it('never wipes unless a threshold is configured', () => {
    let state = EMPTY_ATTEMPT_STATE;
    for (let i = 0; i < 1000; i++) state = recordFailure(state, 0);
    // Default is off: a child mashing the keyboard must not destroy the only
    // copy of a history that has no backup.
    expect(shouldWipe(state, policy)).toBe(false);
    expect(shouldWipe(state, { ...policy, wipeAfterFailures: 10 })).toBe(true);
  });

  it('round-trips persisted state', () => {
    const state = { failures: 4, lastFailureAt: 12_345 };
    expect(parseAttemptState(serialiseAttemptState(state), 0)).toEqual(state);
  });

  it('treats a first run as no failures', () => {
    expect(parseAttemptState(undefined, 0)).toEqual(EMPTY_ATTEMPT_STATE);
  });

  it('fails closed on tampered state', () => {
    // If corrupting the counter reset it, an attacker could disable the
    // throttle by damaging one keystore entry.
    for (const tampered of ['not json', '{}', '{"failures":-5,"lastFailureAt":0}', 'null']) {
      const parsed = parseAttemptState(tampered, 9999);
      expect(canAttempt(parsed, 9999)).toBe(false);
    }
  });

  it('formats the wait for a human', () => {
    expect(formatLockout(1000)).toBe('1 second');
    expect(formatLockout(15_000)).toBe('15 seconds');
    expect(formatLockout(120_000)).toBe('2 minutes');
  });
});

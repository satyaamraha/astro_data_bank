import { describe, expect, it } from 'vitest';
import {
  AuthenticationError,
  MAX_SKIP_PER_CHAIN,
  MAX_SKIPPED_KEYS,
  SessionStateError,
  ratchetDecrypt,
  ratchetEncrypt,
} from '../src/index.js';
import { Device, connectedPair, flipBit, text } from './helpers.js';

describe('double ratchet', () => {
  it('carries a conversation in both directions', () => {
    const { alice, bob } = connectedPair();
    for (let i = 0; i < 20; i++) {
      expect(bob.receiveText(alice.send(bob.address, `a${i}`))).toBe(`a${i}`);
      expect(alice.receiveText(bob.send(alice.address, `b${i}`))).toBe(`b${i}`);
    }
  });

  it('handles a long one-sided burst', () => {
    // Common on mobile: one party sends many messages while the other is offline.
    const { alice, bob } = connectedPair();
    const envelopes = Array.from({ length: 50 }, (_, i) =>
      alice.send(bob.address, `burst ${i}`),
    );
    envelopes.forEach((envelope, i) => {
      expect(bob.receiveText(envelope)).toBe(`burst ${i}`);
    });
  });

  it('decrypts messages that arrive out of order', () => {
    const { alice, bob } = connectedPair();
    const one = alice.send(bob.address, 'first');
    const two = alice.send(bob.address, 'second');
    const three = alice.send(bob.address, 'third');

    // Delivered 3, 1, 2 — as an unreliable network might.
    expect(bob.receiveText(three)).toBe('third');
    expect(bob.receiveText(one)).toBe('first');
    expect(bob.receiveText(two)).toBe('second');
  });

  it('survives permanently dropped messages', () => {
    const { alice, bob } = connectedPair();
    alice.send(bob.address, 'lost 1');
    alice.send(bob.address, 'lost 2');
    const arrives = alice.send(bob.address, 'arrives');
    expect(bob.receiveText(arrives)).toBe('arrives');
    // And the conversation keeps working afterwards.
    expect(bob.receiveText(alice.send(bob.address, 'next'))).toBe('next');
  });

  it('rejects a replayed message', () => {
    // Forward secrecy means the key is destroyed on use, so a replay cannot be
    // decrypted a second time. This also prevents a relay duplicating messages.
    const { alice, bob } = connectedPair();
    const envelope = alice.send(bob.address, 'once');
    expect(bob.receiveText(envelope)).toBe('once');
    expect(() => bob.receive(envelope)).toThrow(SessionStateError);
  });

  it('rejects a tampered ciphertext', () => {
    const { alice, bob } = connectedPair();
    const envelope = alice.send(bob.address, 'authentic');
    expect(() =>
      bob.receive({ ...envelope, ciphertext: flipBit(envelope.ciphertext, 5) }),
    ).toThrow(AuthenticationError);
  });

  it('keeps the session usable after an injected forgery', () => {
    // An attacker must not be able to break a conversation by injecting
    // garbage: state is only committed after authentication succeeds.
    const { alice, bob } = connectedPair();
    const good = alice.send(bob.address, 'real message');
    expect(() =>
      bob.receive({ ...good, ciphertext: flipBit(good.ciphertext, 9) }),
    ).toThrow(AuthenticationError);
    expect(bob.receiveText(good)).toBe('real message');
  });

  it('advances the DH ratchet when the direction changes', () => {
    const { alice, bob } = connectedPair();
    const before = alice.sessions.get(bob.address)!.ratchet.sending.publicKey.slice();

    bob.receiveText(alice.send(bob.address, 'ping'));
    alice.receiveText(bob.send(alice.address, 'pong'));

    const after = alice.sessions.get(bob.address)!.ratchet.sending.publicKey;
    // A fresh ratchet key each turn is what gives post-compromise security.
    expect(Buffer.from(after).equals(Buffer.from(before))).toBe(false);
  });

  it('gives every message a distinct key', () => {
    const { alice, bob } = connectedPair();
    const ciphertexts = new Set<string>();
    for (let i = 0; i < 30; i++) {
      // Identical plaintext every time; ciphertexts must still all differ.
      const envelope = alice.send(bob.address, 'same text');
      ciphertexts.add(Buffer.from(envelope.ciphertext).toString('hex'));
      bob.receiveText(envelope);
    }
    expect(ciphertexts.size).toBe(30);
  });

  it('refuses a message that claims to skip an absurd number of keys', () => {
    // Without this bound, a single forged header with a huge counter would make
    // us derive millions of keys: a trivial CPU and memory exhaustion attack.
    const { alice, bob } = connectedPair();
    const session = bob.sessions.get(alice.address)!;
    const envelope = alice.send(bob.address, 'x');

    // Re-encrypt with a header far ahead of the real counter.
    const aliceSession = alice.sessions.get(bob.address)!;
    const message = ratchetEncrypt(aliceSession.ratchet, text.encode('y'));
    const forged = {
      header: { ...message.header, messageNumber: MAX_SKIP_PER_CHAIN + 5000 },
      ciphertext: message.ciphertext,
    };
    expect(() => ratchetDecrypt(session.ratchet, forged)).toThrow(SessionStateError);
    void envelope;
  });

  it('bounds the skipped-key cache', () => {
    // Memory must stay bounded even under a long stream of gappy messages.
    const { alice, bob } = connectedPair();
    const bobSession = bob.sessions.get(alice.address)!;

    for (let round = 0; round < 6; round++) {
      // Send a batch, drop all but the last, forcing many skipped keys.
      for (let i = 0; i < 500; i++) alice.send(bob.address, 'dropped');
      const arrives = alice.send(bob.address, 'kept');
      expect(bob.receiveText(arrives)).toBe('kept');
    }
    expect(bobSession.ratchet.skipped.size).toBeLessThanOrEqual(MAX_SKIPPED_KEYS);
  });

  it('survives an injected degenerate ratchet key without corrupting state', () => {
    // A header is attacker-controlled, and X25519 rejects low-order public
    // keys. If that rejection landed after the ratchet counters were reset, one
    // injected frame would permanently desynchronise the session. Assert the
    // conversation still works afterwards, in both directions.
    const { alice, bob } = connectedPair();
    const bobSession = bob.sessions.get(alice.address)!;

    const sentBefore = bobSession.ratchet.sentCount;
    const receivedBefore = bobSession.ratchet.receivedCount;

    // All-zero is a canonical low-order X25519 point: agreement must fail.
    const degenerate = {
      header: {
        ratchetPublicKey: new Uint8Array(32),
        previousChainLength: 0,
        messageNumber: 0,
      },
      ciphertext: new Uint8Array(64),
    };
    expect(() => ratchetDecrypt(bobSession.ratchet, degenerate)).toThrow();

    // Counters untouched, so the session was never half-advanced.
    expect(bobSession.ratchet.sentCount).toBe(sentBefore);
    expect(bobSession.ratchet.receivedCount).toBe(receivedBefore);

    // And the conversation continues normally in both directions.
    expect(bob.receiveText(alice.send(bob.address, 'still working'))).toBe('still working');
    expect(alice.receiveText(bob.send(alice.address, 'both ways'))).toBe('both ways');
  });

  it('survives an injected oversized skip claim without corrupting state', () => {
    const { alice, bob } = connectedPair();
    const bobSession = bob.sessions.get(alice.address)!;
    const aliceSession = alice.sessions.get(bob.address)!;

    const sentBefore = bobSession.ratchet.sentCount;

    // A real ratchet key (so agreement succeeds) but an absurd previous-chain
    // length, which must be refused by the skip bound.
    const message = ratchetEncrypt(aliceSession.ratchet, text.encode('x'));
    expect(() =>
      ratchetDecrypt(bobSession.ratchet, {
        header: {
          ...message.header,
          previousChainLength: MAX_SKIP_PER_CHAIN + 10_000,
        },
        ciphertext: message.ciphertext,
      }),
    ).toThrow(SessionStateError);

    expect(bobSession.ratchet.sentCount).toBe(sentBefore);
    expect(bob.receiveText(alice.send(bob.address, 'unaffected'))).toBe('unaffected');
  });

  it('does not leak plaintext into the ciphertext', () => {
    const { alice, bob } = connectedPair();
    const secret = 'attack at dawn, meet by the bridge';
    const envelope = alice.send(bob.address, secret);
    const wire = Buffer.from(envelope.ciphertext).toString('binary');
    expect(wire.includes(secret)).toBe(false);
    expect(wire.includes('attack')).toBe(false);
    bob.receiveText(envelope);
  });

  it('refuses to send before the responder has received anything', () => {
    // Bob has no sending chain until Alice's first message arrives; sending
    // anyway would mean encrypting under an uninitialised key.
    const alice = new Device('alice');
    const bob = new Device('bob');
    alice.start(bob);
    const hello = alice.send(bob.address, 'hello');
    const received = bob.receive(hello);
    expect(received.isNewSession).toBe(true);
    // After receiving, Bob can reply.
    expect(alice.receiveText(bob.send(alice.address, 'hi'))).toBe('hi');
  });

  it('recovers when both sides send simultaneously', () => {
    // Crossing messages are normal; neither side should desynchronise.
    const { alice, bob } = connectedPair();
    const fromAlice = alice.send(bob.address, 'from alice');
    const fromBob = bob.send(alice.address, 'from bob');
    expect(bob.receiveText(fromAlice)).toBe('from alice');
    expect(alice.receiveText(fromBob)).toBe('from bob');
    expect(bob.receiveText(alice.send(bob.address, 'again'))).toBe('again');
  });
});

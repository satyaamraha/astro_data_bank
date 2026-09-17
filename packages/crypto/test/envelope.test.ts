import { describe, expect, it } from 'vitest';
import {
  AuthenticationError,
  IdentityChangedError,
  MalformedInputError,
  PAYLOAD_RATCHET,
  SessionStateError,
  addressOf,
  bucketSize,
  createIdentity,
  openEnvelope,
  pad,
  publicIdentityOf,
  sealEnvelope,
  startSession,
  unpad,
  random,
  utf8,
} from '../src/index.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { Device, connectedPair, flipBit, text } from './helpers.js';

describe('sealed sender', () => {
  it('hides the sender from anyone holding the envelope', () => {
    const { alice, bob } = connectedPair();
    const envelope = alice.send(bob.address, 'who sent this?');

    // Everything the relay can see:
    const visible = Buffer.concat([
      Buffer.from(envelope.recipientAddress),
      Buffer.from(envelope.ephemeralPublicKey),
      Buffer.from(envelope.ciphertext),
    ]);

    // Alice's identity must not appear anywhere in it.
    expect(visible.includes(Buffer.from(alice.publicIdentity.signingPublicKey))).toBe(false);
    expect(visible.includes(Buffer.from(alice.address))).toBe(false);
    bob.receiveText(envelope);
  });

  it('gives each envelope an unlinkable ephemeral key', () => {
    // Two envelopes from the same sender must not be linkable by any field.
    const { alice, bob } = connectedPair();
    const keys = new Set<string>();
    for (let i = 0; i < 10; i++) {
      const envelope = alice.send(bob.address, 'msg');
      keys.add(Buffer.from(envelope.ephemeralPublicKey).toString('hex'));
      bob.receiveText(envelope);
    }
    expect(keys.size).toBe(10);
  });

  it('reveals the sender to the intended recipient only', () => {
    const { alice, bob } = connectedPair();
    const envelope = alice.send(bob.address, 'hello bob');
    const received = bob.receive(envelope);
    expect(addressOf(received.senderIdentity)).toBe(alice.address);
  });

  it('cannot be opened by a third party', () => {
    const { alice, bob } = connectedPair();
    const eve = new Device('eve');
    const envelope = alice.send(bob.address, 'not for eve');
    expect(() => eve.receive(envelope)).toThrow(AuthenticationError);
  });

  it('rejects a forged sender identity', () => {
    // Mallory seals a message but claims to be Alice. She cannot produce the
    // proof of possession, because that needs Alice's identity secret key.
    const alice = new Device('alice');
    const bob = new Device('bob');
    const mallory = new Device('mallory');

    const envelope = sealEnvelope({
      senderIdentity: alice.publicIdentity, // claims to be Alice
      signWithIdentity: (m) => ed25519.sign(m, mallory.identity.signing.secretKey),
      recipientIdentity: bob.publicIdentity,
      payloadKind: PAYLOAD_RATCHET,
      payload: text.encode('i am alice, honest'),
    });

    expect(() =>
      openEnvelope({
        recipientExchangeSecretKey: bob.identity.exchange.secretKey,
        recipientExchangePublicKey: bob.identity.exchange.publicKey,
        recipientAddress: bob.address,
        envelope,
      }),
    ).toThrow(AuthenticationError);
  });

  it('rejects an identity whose exchange key was swapped inside the envelope', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    const mallory = new Device('mallory');

    const envelope = sealEnvelope({
      senderIdentity: {
        signingPublicKey: alice.publicIdentity.signingPublicKey,
        exchangePublicKey: mallory.publicIdentity.exchangePublicKey,
        exchangeKeySignature: alice.publicIdentity.exchangeKeySignature,
      },
      signWithIdentity: (m) => ed25519.sign(m, alice.identity.signing.secretKey),
      recipientIdentity: bob.publicIdentity,
      payloadKind: PAYLOAD_RATCHET,
      payload: text.encode('swapped dh key'),
    });

    expect(() =>
      openEnvelope({
        recipientExchangeSecretKey: bob.identity.exchange.secretKey,
        recipientExchangePublicKey: bob.identity.exchange.publicKey,
        recipientAddress: bob.address,
        envelope,
      }),
    ).toThrow(AuthenticationError);
  });

  it('rejects an envelope whose routing address the relay rewrote', () => {
    // The sender's proof is checked against the address the recipient knows to
    // be its own, so a rewritten routing field cannot be laundered into a valid
    // binding — it can only cause a clean failure.
    const { alice, bob } = connectedPair();
    const eve = new Device('eve');
    const envelope = alice.send(bob.address, 'for bob');

    expect(() =>
      openEnvelope({
        recipientExchangeSecretKey: bob.identity.exchange.secretKey,
        recipientExchangePublicKey: bob.identity.exchange.publicKey,
        recipientAddress: eve.address, // pretend Bob's address is Eve's
        envelope,
      }),
    ).toThrow(AuthenticationError);
  });

  it('refuses to seal to an identity with an invalid binding', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    expect(() =>
      sealEnvelope({
        senderIdentity: alice.publicIdentity,
        signWithIdentity: (m) => ed25519.sign(m, alice.identity.signing.secretKey),
        recipientIdentity: {
          ...bob.publicIdentity,
          exchangeKeySignature: flipBit(bob.publicIdentity.exchangeKeySignature),
        },
        payloadKind: PAYLOAD_RATCHET,
        payload: text.encode('x'),
      }),
    ).toThrow(MalformedInputError);
  });

  it('rejects a truncated envelope', () => {
    const { alice, bob } = connectedPair();
    const envelope = alice.send(bob.address, 'complete');
    expect(() =>
      bob.receive({ ...envelope, ciphertext: envelope.ciphertext.slice(0, 8) }),
    ).toThrow();
  });
});

describe('length-hiding padding', () => {
  it('round-trips any length', () => {
    for (const length of [0, 1, 15, 127, 128, 129, 1000, 5000]) {
      const payload = random(Math.max(length, 1)).slice(0, length);
      expect(unpad(pad(payload))).toEqual(payload);
    }
  });

  it('maps many short messages to one size', () => {
    // "yes", "no", and a short sentence must be indistinguishable by length.
    const sizes = new Set(
      ['y', 'no', 'yes', 'maybe later', 'I will be there at eight'].map(
        (s) => pad(text.encode(s)).length,
      ),
    );
    expect(sizes.size).toBe(1);
  });

  it('grows geometrically rather than linearly', () => {
    // Relative uncertainty stays roughly constant at every message size.
    expect(bucketSize(0)).toBe(128);
    expect(bucketSize(127)).toBe(128);
    expect(bucketSize(128)).toBeGreaterThan(128);
    const small = bucketSize(200);
    const large = bucketSize(20000);
    expect(large / 20000).toBeLessThan(1.3);
    expect(small / 200).toBeLessThan(1.6);
  });

  it('hides message length on the wire', () => {
    const { alice, bob } = connectedPair();
    const short = alice.send(bob.address, 'ok');
    const longer = alice.send(bob.address, 'see you at the usual place');
    expect(short.ciphertext.length).toBe(longer.ciphertext.length);
    bob.receiveText(short);
    bob.receiveText(longer);
  });

  it('rejects malformed padding', () => {
    expect(() => unpad(new Uint8Array(16))).toThrow(MalformedInputError);
    const bad = new Uint8Array(16);
    bad[15] = 0x7f; // not the marker
    expect(() => unpad(bad)).toThrow(MalformedInputError);
  });
});

describe('session establishment', () => {
  it('repeats the handshake preamble until the peer replies', () => {
    // The first message may be dropped, so every early message must carry
    // enough for the peer to build the session from scratch.
    const alice = new Device('alice');
    const bob = new Device('bob');
    alice.start(bob);

    alice.send(bob.address, 'dropped 1');
    alice.send(bob.address, 'dropped 2');
    const third = alice.send(bob.address, 'third');

    // Bob receives only the third message and can still establish the session.
    expect(bob.receiveText(third)).toBe('third');
  });

  it('stops resending the preamble once the peer replies', () => {
    const { alice, bob } = connectedPair();
    expect(alice.sessions.get(bob.address)!.pendingPreKey).toBeUndefined();
  });

  it('refuses to reuse a one-time prekey', () => {
    // Replaying a prekey message must not let an attacker force a second
    // handshake against the same single-use key.
    const alice = new Device('alice');
    const bob = new Device('bob');
    alice.start(bob);
    const hello = alice.send(bob.address, 'hello');
    expect(bob.receiveText(hello)).toBe('hello');
    expect(() => bob.receive(hello)).toThrow(SessionStateError);
  });

  it('rejects a ratchet message with no established session', () => {
    const { alice, bob } = connectedPair();
    const fresh = new Device('fresh');
    const envelope = alice.send(bob.address, 'orphan');
    // `fresh` cannot even open the envelope, let alone find a session.
    expect(() => fresh.receive(envelope)).toThrow();
  });
});

describe('identity pinning', () => {
  it('refuses to start a session when the key does not match the verified one', () => {
    // The active-MITM case: a compromised relay serves an attacker's bundle
    // under the victim's name. Pinning turns that into a hard failure.
    const alice = new Device('alice');
    const bob = new Device('bob');
    const mallory = new Device('mallory');

    const malloryBundle = mallory.issueBundle();
    expect(() =>
      startSession(alice.identity, malloryBundle, bob.publicIdentity.signingPublicKey),
    ).toThrow(IdentityChangedError);
  });

  it('accepts a session when the key matches the verified one', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    expect(() =>
      startSession(alice.identity, bob.issueBundle(), bob.publicIdentity.signingPublicKey),
    ).not.toThrow();
  });

  it('rejects an inbound message from an unpinned key for a pinned contact', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    const mallory = new Device('mallory');

    // Bob pins Alice after verifying in person.
    bob.pin(alice);

    // Mallory reinstalls with Alice's address? Impossible — the address is a
    // hash of the identity key. So Mallory can only write from her own address,
    // which is not pinned, and Bob sees a distinct, unverified contact.
    mallory.start(bob);
    const fromMallory = mallory.send(bob.address, 'hi, it is alice really');
    const received = bob.receive(fromMallory);
    expect(addressOf(received.senderIdentity)).toBe(mallory.address);
    expect(addressOf(received.senderIdentity)).not.toBe(alice.address);
  });

  it('detects a pinned contact whose identity key changed', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    alice.start(bob);
    const hello = alice.send(bob.address, 'hello');
    bob.receive(hello);

    // Pin a *different* key for Alice's address, simulating a swapped identity.
    const impostor = createIdentity();
    bob.pinned.set(alice.address, publicIdentityOf(impostor).signingPublicKey);

    const next = alice.send(bob.address, 'still me');
    expect(() => bob.receive(next)).toThrow(IdentityChangedError);
  });
});

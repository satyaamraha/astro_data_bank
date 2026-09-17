/**
 * Test harness: a pair of simulated devices and a simulated relay.
 *
 * The relay is deliberately modelled as *hostile but functional* — it delivers
 * messages correctly in the happy path, and several tests reach into it to
 * tamper, reorder, drop, and replay, so we are testing the protocol's claims
 * rather than only its plumbing.
 */

import {
  InMemoryPreKeyStore,
  addressOf,
  createIdentity,
  decryptEnvelope,
  encryptMessage,
  publicIdentityOf,
  startSession,
  type DecryptedMessage,
  type PreKeyBundle,
  type PrivateIdentity,
  type PublicIdentity,
  type SealedEnvelope,
  type Session,
} from '../src/index.js';

export class Device {
  readonly identity: PrivateIdentity;
  readonly preKeys: InMemoryPreKeyStore;
  readonly sessions = new Map<string, Session>();
  readonly pinned = new Map<string, Uint8Array>();

  constructor(readonly name: string) {
    this.identity = createIdentity();
    this.preKeys = new InMemoryPreKeyStore(this.identity);
  }

  get publicIdentity(): PublicIdentity {
    return publicIdentityOf(this.identity);
  }

  get address(): string {
    return addressOf(this.publicIdentity);
  }

  /** What this device publishes to the relay for others to fetch. */
  issueBundle(): PreKeyBundle {
    return this.preKeys.issueBundle(this.publicIdentity);
  }

  /** Begin a conversation with a peer from their fetched bundle. */
  start(peer: Device, bundle: PreKeyBundle = peer.issueBundle()): Session {
    const session = startSession(this.identity, bundle);
    this.sessions.set(addressOf(bundle.identity), session);
    return session;
  }

  send(peerAddress: string, text: string): SealedEnvelope {
    const session = this.sessions.get(peerAddress);
    if (!session) throw new Error(`${this.name} has no session with ${peerAddress}`);
    return encryptMessage(this.identity, session, new TextEncoder().encode(text));
  }

  sendBytes(peerAddress: string, bytes: Uint8Array): SealedEnvelope {
    const session = this.sessions.get(peerAddress);
    if (!session) throw new Error(`${this.name} has no session with ${peerAddress}`);
    return encryptMessage(this.identity, session, bytes);
  }

  receive(envelope: SealedEnvelope): DecryptedMessage {
    const result = decryptEnvelope({
      self: this.identity,
      envelope,
      lookupSession: (address) => this.sessions.get(address),
      preKeys: this.preKeys,
      pinnedIdentityKey: (address) => this.pinned.get(address),
    });
    this.sessions.set(addressOf(result.senderIdentity), result.session);
    return result;
  }

  receiveText(envelope: SealedEnvelope): string {
    return new TextDecoder().decode(this.receive(envelope).plaintext);
  }

  /** Pin a peer's identity key, as the UI does after in-person verification. */
  pin(peer: Device): void {
    this.pinned.set(peer.address, peer.publicIdentity.signingPublicKey);
  }
}

/** Create two devices that have already exchanged a first message. */
export function connectedPair(): { alice: Device; bob: Device } {
  const alice = new Device('alice');
  const bob = new Device('bob');
  alice.start(bob);
  // Alice's first message carries the handshake; Bob's reply completes it.
  const hello = alice.send(bob.address, 'hello');
  bob.receive(hello);
  const reply = bob.send(alice.address, 'hi');
  alice.receive(reply);
  return { alice, bob };
}

export const text = {
  encode: (s: string) => new TextEncoder().encode(s),
  decode: (b: Uint8Array) => new TextDecoder().decode(b),
};

/** Flip one bit in a copy of `bytes`, for tamper-detection tests. */
export function flipBit(bytes: Uint8Array, index = 0): Uint8Array {
  if (bytes.length === 0) throw new Error('cannot flip a bit in an empty buffer');
  const copy = bytes.slice();
  const position = index % copy.length;
  copy[position] = (copy[position] ?? 0) ^ 0x01;
  return copy;
}

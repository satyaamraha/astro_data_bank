import { describe, expect, it, vi } from 'vitest';
import { createIdentity, publicIdentityOf } from '@veil/crypto';
import { CallManager, type MediaEngine } from '../src/core/callManager.js';
import type { CallInfo, Payload } from '../src/core/types.js';

/**
 * A fake WebRTC engine.
 *
 * Only the platform media plumbing is faked. All the call logic under test —
 * key derivation, SAS generation, the refusal to run without frame
 * encryption, and key wiping — is the real implementation.
 */
class FakeEngine implements MediaEngine {
  installedKeys?: { sendKey: Uint8Array; receiveKey: Uint8Array };
  closed = false;
  muted = false;
  private candidateHandler?: (candidate: string) => void;
  private connectedHandler?: () => void;
  private disconnectedHandler?: () => void;

  constructor(
    readonly supportsFrameEncryption = true,
    private readonly fingerprint = 'AA:BB:CC',
  ) {}

  async createOffer() {
    return { sdp: 'v=0 offer', dtlsFingerprint: this.fingerprint };
  }

  async createAnswer(_remoteSdp: string) {
    return { sdp: 'v=0 answer', dtlsFingerprint: this.fingerprint };
  }

  async acceptAnswer(_remoteSdp: string): Promise<void> {}
  async addRemoteCandidate(_candidate: string): Promise<void> {}

  onLocalCandidate(handler: (candidate: string) => void): void {
    this.candidateHandler = handler;
  }
  onConnected(handler: () => void): void {
    this.connectedHandler = handler;
  }
  onDisconnected(handler: () => void): void {
    this.disconnectedHandler = handler;
  }

  async installFrameKeys(keys: { sendKey: Uint8Array; receiveKey: Uint8Array }) {
    this.installedKeys = keys;
  }

  setMuted(muted: boolean): void {
    this.muted = muted;
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  emitCandidate(candidate: string): void {
    this.candidateHandler?.(candidate);
  }
  emitConnected(): void {
    this.connectedHandler?.();
  }
  emitDisconnected(): void {
    this.disconnectedHandler?.();
  }
}

/** Two call managers wired directly to each other's signalling. */
function pair(options: { supportsFrameEncryption?: boolean } = {}) {
  const supports = options.supportsFrameEncryption ?? true;

  const aliceIdentity = publicIdentityOf(createIdentity());
  const bobIdentity = publicIdentityOf(createIdentity());
  const aliceAddress = 'alice-address';
  const bobAddress = 'bob-address';

  const engines: { alice?: FakeEngine; bob?: FakeEngine } = {};
  const states: { alice: CallInfo[]; bob: CallInfo[] } = { alice: [], bob: [] };

  // Deferred so each manager can signal the other.
  let alice!: CallManager;
  let bob!: CallManager;

  alice = new CallManager({
    selfIdentity: aliceIdentity,
    resolvePeerIdentity: (address) => (address === bobAddress ? bobIdentity : undefined),
    createMediaEngine: () => {
      engines.alice = new FakeEngine(supports, 'ALICE:FINGERPRINT');
      return engines.alice;
    },
    sendSignal: async (_to, payload) => {
      await bob.handleSignal(aliceAddress, payload);
    },
    events: { onStateChange: (call) => states.alice.push({ ...call }) },
  });

  bob = new CallManager({
    selfIdentity: bobIdentity,
    resolvePeerIdentity: (address) => (address === aliceAddress ? aliceIdentity : undefined),
    createMediaEngine: () => {
      engines.bob = new FakeEngine(supports, 'BOB:FINGERPRINT');
      return engines.bob;
    },
    sendSignal: async (_to, payload) => {
      await alice.handleSignal(bobAddress, payload);
    },
    events: { onStateChange: (call) => states.bob.push({ ...call }) },
  });

  return { alice, bob, engines, states, aliceAddress, bobAddress };
}

describe('placing and answering a call', () => {
  it('completes setup and agrees on the same SAS', async () => {
    const { alice, bob, bobAddress } = pair();

    await alice.placeCall(bobAddress);
    expect(bob.activeCall?.state).toBe('ringing-incoming');

    await bob.answerCall();

    // Both ends must show identical words, or the users cannot compare them.
    expect(alice.activeCall?.sas).toBeDefined();
    expect(alice.activeCall?.sas).toBe(bob.activeCall?.sas);
    expect(alice.activeCall?.sas?.split(' ')).toHaveLength(4);
    expect(alice.activeCall?.sasDigits).toMatch(/^\d{6}$/);
  });

  it('installs mirrored directional media keys', async () => {
    const { alice, bob, engines, bobAddress } = pair();
    await alice.placeCall(bobAddress);
    await bob.answerCall();

    const aliceKeys = engines.alice!.installedKeys!;
    const bobKeys = engines.bob!.installedKeys!;
    expect(aliceKeys).toBeDefined();
    expect(bobKeys).toBeDefined();
    // Alice's send key is Bob's receive key, so each direction has its own
    // keystream.
    expect(Buffer.from(aliceKeys.sendKey).equals(Buffer.from(bobKeys.receiveKey))).toBe(true);
    expect(Buffer.from(aliceKeys.receiveKey).equals(Buffer.from(bobKeys.sendKey))).toBe(true);
    expect(Buffer.from(aliceKeys.sendKey).equals(Buffer.from(aliceKeys.receiveKey))).toBe(
      false,
    );
  });

  it('installs frame keys before reporting the call connected', async () => {
    // Otherwise audio would briefly flow protected only by DTLS-SRTP, which a
    // relaying TURN server terminates.
    const { alice, bob, engines, bobAddress } = pair();
    await alice.placeCall(bobAddress);
    await bob.answerCall();
    expect(engines.alice!.installedKeys).toBeDefined();
    expect(alice.activeCall?.state).not.toBe('connected');

    engines.alice!.emitConnected();
    expect(alice.activeCall?.state).toBe('connected');
  });

  it('requires the user to confirm the SAS', async () => {
    const { alice, bob, bobAddress } = pair();
    await alice.placeCall(bobAddress);
    await bob.answerCall();

    expect(alice.activeCall?.sasConfirmed).toBeUndefined();
    alice.confirmSas();
    expect(alice.activeCall?.sasConfirmed).toBe(true);
  });

  it('relays ICE candidates over the encrypted channel', async () => {
    const { alice, bob, engines, bobAddress } = pair();
    await alice.placeCall(bobAddress);
    await bob.answerCall();

    const addRemote = vi.spyOn(engines.bob!, 'addRemoteCandidate');
    engines.alice!.emitCandidate('candidate:1 udp 1.2.3.4');
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(addRemote).toHaveBeenCalledWith('candidate:1 udp 1.2.3.4');
  });
});

describe('MITM detection', () => {
  it('produces a different SAS when the media path fingerprint differs', async () => {
    // An attacker terminating DTLS presents its own certificate, so the words
    // the two users read aloud stop matching and the substitution is visible.
    const honest = pair();
    await honest.alice.placeCall(honest.bobAddress);
    await honest.bob.answerCall();
    const honestSas = honest.alice.activeCall!.sas;

    const aliceIdentity = publicIdentityOf(createIdentity());
    const bobIdentity = publicIdentityOf(createIdentity());
    let alice!: CallManager;
    let bob!: CallManager;

    alice = new CallManager({
      selfIdentity: aliceIdentity,
      resolvePeerIdentity: () => bobIdentity,
      createMediaEngine: () => new FakeEngine(true, 'ALICE:FINGERPRINT'),
      sendSignal: async (_to, payload) => {
        // The attacker rewrites the callee's DTLS fingerprint in flight.
        const tampered: Payload =
          payload.kind === 'call-answer'
            ? { ...payload, dtlsFingerprint: 'ATTACKER:FINGERPRINT' }
            : payload;
        await bob.handleSignal('alice-address', tampered);
      },
      events: {},
    });
    bob = new CallManager({
      selfIdentity: bobIdentity,
      resolvePeerIdentity: () => aliceIdentity,
      createMediaEngine: () => new FakeEngine(true, 'BOB:FINGERPRINT'),
      sendSignal: async (_to, payload) => {
        const tampered: Payload =
          payload.kind === 'call-answer'
            ? { ...payload, dtlsFingerprint: 'ATTACKER:FINGERPRINT' }
            : payload;
        await alice.handleSignal('bob-address', tampered);
      },
      events: {},
    });

    await alice.placeCall('bob-address');
    await bob.answerCall();
    // Alice derived against the attacker's fingerprint, Bob against his own.
    expect(alice.activeCall!.sas).not.toBe(bob.activeCall!.sas);
    expect(honestSas).toBeDefined();
  });
});

describe('refusing an unprotected call', () => {
  it('will not place a call when frame encryption is unavailable', async () => {
    // Without SFrame the media is readable by whatever relays it. Falling back
    // silently would break the app's core promise, so we refuse.
    const { alice, bobAddress } = pair({ supportsFrameEncryption: false });
    await expect(alice.placeCall(bobAddress)).rejects.toThrow(/cannot encrypt call media/);
  });

  it('will not answer a call when frame encryption is unavailable', async () => {
    const aliceIdentity = publicIdentityOf(createIdentity());
    const bobIdentity = publicIdentityOf(createIdentity());
    const sent: Payload[] = [];

    const bob = new CallManager({
      selfIdentity: bobIdentity,
      resolvePeerIdentity: () => aliceIdentity,
      createMediaEngine: () => new FakeEngine(false, 'BOB:FINGERPRINT'),
      sendSignal: async (_to, payload) => {
        sent.push(payload);
      },
      events: {},
    });

    await bob.handleSignal('alice-address', {
      kind: 'call-offer',
      callId: 'call-1',
      mediaSecret: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      sdp: 'v=0 offer',
      dtlsFingerprint: 'ALICE:FINGERPRINT',
    });
    await expect(bob.answerCall()).rejects.toThrow(/cannot encrypt call media/);
    // The caller is told why, rather than being left ringing.
    expect(sent.some((p) => p.kind === 'call-hangup')).toBe(true);
  });

  it('can be allowed explicitly when the operator accepts the risk', async () => {
    const aliceIdentity = publicIdentityOf(createIdentity());
    const bobIdentity = publicIdentityOf(createIdentity());
    const manager = new CallManager({
      selfIdentity: aliceIdentity,
      resolvePeerIdentity: () => bobIdentity,
      createMediaEngine: () => new FakeEngine(false),
      sendSignal: async () => {},
      requireFrameEncryption: false,
      events: {},
    });
    await expect(manager.placeCall('bob-address')).resolves.toBeDefined();
  });
});

describe('call teardown', () => {
  it('wipes media keys when the call ends', async () => {
    const { alice, bob, engines, bobAddress } = pair();
    await alice.placeCall(bobAddress);
    await bob.answerCall();

    const installed = engines.alice!.installedKeys!;
    await alice.endCall('hung up');

    // The engine's key buffers are the same objects we handed it, so a memory
    // capture after the call finds zeros rather than audio keys.
    expect(installed.sendKey.every((b) => b === 0)).toBe(true);
    expect(installed.receiveKey.every((b) => b === 0)).toBe(true);
    expect(engines.alice!.closed).toBe(true);
    expect(alice.activeCall?.state).toBe('ended');
  });

  it('tells the peer when we hang up', async () => {
    const { alice, bob, bobAddress } = pair();
    await alice.placeCall(bobAddress);
    await bob.answerCall();
    await alice.endCall('hung up');
    expect(bob.activeCall?.state).toBe('ended');
  });

  it('ends the call when the transport drops', async () => {
    const { alice, bob, engines, bobAddress } = pair();
    await alice.placeCall(bobAddress);
    await bob.answerCall();
    engines.alice!.emitDisconnected();
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(alice.activeCall?.state).toBe('ended');
  });

  it('declines a second call instead of disturbing the live one', async () => {
    const { alice, bob, bobAddress } = pair();
    await alice.placeCall(bobAddress);
    await bob.answerCall();
    const liveCallId = bob.activeCall!.callId;

    await bob.handleSignal('charlie-address', {
      kind: 'call-offer',
      callId: 'intruding-call',
      mediaSecret: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      sdp: 'v=0 offer',
      dtlsFingerprint: 'CHARLIE:FINGERPRINT',
    });
    expect(bob.activeCall!.callId).toBe(liveCallId);
    expect(bob.activeCall!.state).not.toBe('ringing-incoming');
  });

  it('ignores signalling for an unknown call', async () => {
    const { bob } = pair();
    await expect(
      bob.handleSignal('someone', { kind: 'call-hangup', callId: 'nope', reason: 'x' }),
    ).resolves.toBe(true);
    expect(bob.activeCall).toBeUndefined();
  });

  it('refuses to derive keys for a peer with no known identity', async () => {
    const manager = new CallManager({
      selfIdentity: publicIdentityOf(createIdentity()),
      resolvePeerIdentity: () => undefined, // unknown peer
      createMediaEngine: () => new FakeEngine(true),
      sendSignal: async () => {},
      events: {},
    });
    await manager.handleSignal('stranger', {
      kind: 'call-offer',
      callId: 'call-1',
      mediaSecret: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      sdp: 'v=0 offer',
      dtlsFingerprint: 'X',
    });
    await expect(manager.answerCall()).rejects.toThrow(/no verified identity/);
  });
});

describe('mute', () => {
  it('passes mute through to the media engine', async () => {
    const { alice, bob, engines, bobAddress } = pair();
    await alice.placeCall(bobAddress);
    await bob.answerCall();
    alice.setMuted(true);
    expect(engines.alice!.muted).toBe(true);
  });
});

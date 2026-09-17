import { describe, expect, it } from 'vitest';
import {
  MalformedInputError,
  AuthenticationError,
  REPLAY_WINDOW,
  ReplayError,
  SAS_WORDS,
  createCallSecrets,
  createReceiver,
  createSender,
  decryptFrame,
  deriveCallKeys,
  encryptFrame,
  random,
  sasNumeric,
  sasWords,
} from '../src/index.js';
import { Device, flipBit } from './helpers.js';

/** Set up a call between two devices, as the signalling layer would. */
function setUpCall(overrides: { calleeDtlsFingerprint?: Uint8Array } = {}) {
  const alice = new Device('alice');
  const bob = new Device('bob');

  // Caller generates the media secret and sends it over the ratchet (E2EE).
  const secrets = createCallSecrets();
  const callId = random(16);
  const callerDtlsFingerprint = random(32);
  const calleeDtlsFingerprint = overrides.calleeDtlsFingerprint ?? random(32);

  const common = {
    callerIdentity: alice.publicIdentity,
    calleeIdentity: bob.publicIdentity,
    callId,
    callerDtlsFingerprint,
    calleeDtlsFingerprint,
  };

  const callerKeys = deriveCallKeys({ secrets, role: 'caller', ...common });
  const calleeKeys = deriveCallKeys({ secrets, role: 'callee', ...common });
  return { alice, bob, secrets, common, callerKeys, calleeKeys };
}

describe('call key agreement', () => {
  it('gives both parties matching directional keys', () => {
    const { callerKeys, calleeKeys } = setUpCall();
    // Caller's send key is the callee's receive key, and vice versa.
    expect(callerKeys.sendKey).toEqual(calleeKeys.receiveKey);
    expect(callerKeys.receiveKey).toEqual(calleeKeys.sendKey);
  });

  it('never uses the same key in both directions', () => {
    // Sharing a key across directions would reuse a keystream: catastrophic.
    const { callerKeys } = setUpCall();
    expect(callerKeys.sendKey).not.toEqual(callerKeys.receiveKey);
  });

  it('shows both parties the same short authentication string', () => {
    const { callerKeys, calleeKeys } = setUpCall();
    expect(callerKeys.sas).toBe(calleeKeys.sas);
    expect(callerKeys.sasDigits).toBe(calleeKeys.sasDigits);
    expect(callerKeys.sas.split(' ')).toHaveLength(4);
    expect(callerKeys.sasDigits).toMatch(/^\d{6}$/);
  });

  it('changes the SAS if the media is relayed through a different DTLS session', () => {
    // This is the detection mechanism for an active MITM on the media path: an
    // attacker terminating DTLS presents a different certificate fingerprint,
    // so the words the two users read aloud no longer match.
    const base = setUpCall();
    const substituted = deriveCallKeys({
      secrets: base.secrets,
      role: 'callee',
      ...base.common,
      calleeDtlsFingerprint: random(32), // attacker's certificate
    });
    expect(substituted.sas).not.toBe(base.callerKeys.sas);
  });

  it('changes the SAS for every call', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 10; i++) seen.add(setUpCall().callerKeys.sas);
    expect(seen.size).toBe(10);
  });

  it('uses a 256-word list so bytes map to words without bias', () => {
    expect(SAS_WORDS).toHaveLength(256);
    expect(new Set(SAS_WORDS).size).toBe(256);
  });

  it('maps SAS bytes deterministically', () => {
    const bytes = Uint8Array.of(0, 1, 254, 255, 9, 9, 9, 9);
    expect(sasWords(bytes)).toBe(
      `${SAS_WORDS[0]} ${SAS_WORDS[1]} ${SAS_WORDS[254]} ${SAS_WORDS[255]}`,
    );
    expect(sasNumeric(bytes)).toMatch(/^\d{6}$/);
  });

  it('rejects too little SAS entropy', () => {
    expect(() => sasWords(Uint8Array.of(1, 2))).toThrow(MalformedInputError);
    expect(() => sasNumeric(Uint8Array.of(1))).toThrow(MalformedInputError);
  });
});

describe('SFrame media encryption', () => {
  const frame = (n: number) => random(160).map((_, i) => (n + i) % 256);

  it('round-trips voice frames', () => {
    const { callerKeys, calleeKeys } = setUpCall();
    const sender = createSender(callerKeys.sendKey);
    const receiver = createReceiver(calleeKeys.receiveKey);

    for (let i = 0; i < 100; i++) {
      const payload = frame(i);
      const encrypted = encryptFrame(sender, payload);
      expect(decryptFrame(receiver, encrypted)).toEqual(payload);
    }
  });

  it('keeps media unreadable to a relay that sees every frame', () => {
    const { callerKeys } = setUpCall();
    const sender = createSender(callerKeys.sendKey);
    const payload = new Uint8Array(160).fill(0x41); // highly predictable
    const encrypted = encryptFrame(sender, payload);
    expect(Buffer.from(encrypted.payload).includes(Buffer.from(payload))).toBe(false);
  });

  it('tolerates lost frames', () => {
    // UDP loss is normal; each frame decrypts independently.
    const { callerKeys, calleeKeys } = setUpCall();
    const sender = createSender(callerKeys.sendKey);
    const receiver = createReceiver(calleeKeys.receiveKey);

    const frames = Array.from({ length: 50 }, (_, i) => encryptFrame(sender, frame(i)));
    // Deliver only every third frame.
    for (let i = 0; i < frames.length; i += 3) {
      expect(decryptFrame(receiver, frames[i]!)).toEqual(frame(i));
    }
  });

  it('tolerates reordered frames', () => {
    const { callerKeys, calleeKeys } = setUpCall();
    const sender = createSender(callerKeys.sendKey);
    const receiver = createReceiver(calleeKeys.receiveKey);

    const frames = Array.from({ length: 10 }, (_, i) => encryptFrame(sender, frame(i)));
    for (const i of [7, 3, 9, 1, 0, 8, 2, 6, 4, 5]) {
      expect(decryptFrame(receiver, frames[i]!)).toEqual(frame(i));
    }
  });

  it('rejects a replayed frame', () => {
    // Stops a relay re-injecting captured audio into a live call.
    const { callerKeys, calleeKeys } = setUpCall();
    const sender = createSender(callerKeys.sendKey);
    const receiver = createReceiver(calleeKeys.receiveKey);
    const encrypted = encryptFrame(sender, frame(1));
    expect(decryptFrame(receiver, encrypted)).toEqual(frame(1));
    expect(() => decryptFrame(receiver, encrypted)).toThrow(ReplayError);
  });

  it('rejects a frame older than the replay window', () => {
    const { callerKeys, calleeKeys } = setUpCall();
    const sender = createSender(callerKeys.sendKey);
    const receiver = createReceiver(calleeKeys.receiveKey);

    const old = encryptFrame(sender, frame(0));
    // Advance well past the window.
    for (let i = 0; i < REPLAY_WINDOW + 10; i++) encryptFrame(sender, frame(i));
    const recent = encryptFrame(sender, frame(999));
    expect(decryptFrame(receiver, recent)).toEqual(frame(999));
    expect(() => decryptFrame(receiver, old)).toThrow(ReplayError);
  });

  it('keeps the replay set bounded during a long call', () => {
    const { callerKeys, calleeKeys } = setUpCall();
    const sender = createSender(callerKeys.sendKey);
    const receiver = createReceiver(calleeKeys.receiveKey);
    for (let i = 0; i < REPLAY_WINDOW * 3; i++) {
      decryptFrame(receiver, encryptFrame(sender, frame(i % 7)));
    }
    // A 30-minute call must not accumulate 90,000 entries.
    expect(receiver.seen.size).toBeLessThanOrEqual(REPLAY_WINDOW + 1);
  });

  it('rejects a tampered frame', () => {
    const { callerKeys, calleeKeys } = setUpCall();
    const sender = createSender(callerKeys.sendKey);
    const receiver = createReceiver(calleeKeys.receiveKey);
    const encrypted = encryptFrame(sender, frame(1));
    expect(() =>
      decryptFrame(receiver, { ...encrypted, payload: flipBit(encrypted.payload, 3) }),
    ).toThrow(AuthenticationError);
  });

  it('rejects a frame whose counter was altered', () => {
    // The counter is authenticated, so renumbering a frame breaks the tag.
    const { callerKeys, calleeKeys } = setUpCall();
    const sender = createSender(callerKeys.sendKey);
    const receiver = createReceiver(calleeKeys.receiveKey);
    const encrypted = encryptFrame(sender, frame(1));
    expect(() => decryptFrame(receiver, { ...encrypted, counter: 500n })).toThrow(
      AuthenticationError,
    );
  });

  it('binds the RTP header to the frame', () => {
    // A relay may read routing headers but must not rewrite them undetected.
    const { callerKeys, calleeKeys } = setUpCall();
    const sender = createSender(callerKeys.sendKey);
    const receiver = createReceiver(calleeKeys.receiveKey);
    const header = random(12);
    const encrypted = encryptFrame(sender, frame(1), header);
    expect(decryptFrame(receiver, encrypted, header)).toEqual(frame(1));

    const sender2 = createSender(callerKeys.sendKey);
    const receiver2 = createReceiver(calleeKeys.receiveKey);
    const encrypted2 = encryptFrame(sender2, frame(1), header);
    expect(() => decryptFrame(receiver2, encrypted2, flipBit(header))).toThrow(
      AuthenticationError,
    );
  });

  it('cannot be decrypted with the wrong direction key', () => {
    const { callerKeys } = setUpCall();
    const sender = createSender(callerKeys.sendKey);
    const wrongReceiver = createReceiver(callerKeys.receiveKey);
    const encrypted = encryptFrame(sender, frame(1));
    expect(() => decryptFrame(wrongReceiver, encrypted)).toThrow(AuthenticationError);
  });

  it('gives every frame a distinct ciphertext', () => {
    const { callerKeys } = setUpCall();
    const sender = createSender(callerKeys.sendKey);
    const silence = new Uint8Array(160); // identical input every time
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      seen.add(Buffer.from(encryptFrame(sender, silence).payload).toString('hex'));
    }
    expect(seen.size).toBe(200);
  });

  it('rejects a wrong-size call key', () => {
    expect(() => createSender(random(16))).toThrow(MalformedInputError);
    expect(() => createReceiver(random(64))).toThrow(MalformedInputError);
  });

  it('increments the counter monotonically', () => {
    const { callerKeys } = setUpCall();
    const sender = createSender(callerKeys.sendKey);
    const counters = Array.from({ length: 5 }, () => encryptFrame(sender, frame(0)).counter);
    expect(counters).toEqual([0n, 1n, 2n, 3n, 4n]);
  });
});

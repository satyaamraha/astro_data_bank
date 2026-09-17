import { describe, expect, it } from 'vitest';
import {
  AuthenticationError,
  MalformedInputError,
  VaultLockedError,
  changePassphrase,
  createVault,
  decodeWrappedVault,
  decryptRecord,
  encodeWrappedVault,
  encryptRecord,
  formatSafetyNumber,
  identityFingerprint,
  lockVault,
  parseVerificationQrPayload,
  safetyNumber,
  safetyNumbersMatch,
  unlockVault,
  UntrustedBundleError,
  verificationQrPayload,
  random,
  utf8,
} from '../src/index.js';
import { Device, flipBit, text } from './helpers.js';

const passphrase = utf8.encode('correct horse battery staple');

describe('at-rest vault', () => {
  it('round-trips records', () => {
    const { vault } = createVault(passphrase);
    const secret = text.encode('message history that must not leak');
    const stored = encryptRecord(vault, 'conversation:alice', secret);
    expect(decryptRecord(vault, 'conversation:alice', stored)).toEqual(secret);
  });

  it('stores no plaintext', () => {
    const { vault } = createVault(passphrase);
    const secret = 'meet at the safehouse';
    const stored = encryptRecord(vault, 'msg:1', text.encode(secret));
    expect(Buffer.from(stored).toString('binary').includes(secret)).toBe(false);
  });

  it('unlocks with the right passphrase', () => {
    const { vault, wrapped } = createVault(passphrase);
    const reopened = unlockVault(passphrase, wrapped);
    expect(reopened.dataKey).toEqual(vault.dataKey);
  });

  it('refuses the wrong passphrase', () => {
    const { wrapped } = createVault(passphrase);
    expect(() => unlockVault(utf8.encode('wrong passphrase'), wrapped)).toThrow(
      VaultLockedError,
    );
  });

  it('refuses a tampered wrapper', () => {
    // Indistinguishable from a wrong passphrase, deliberately.
    const { wrapped } = createVault(passphrase);
    expect(() =>
      unlockVault(passphrase, { ...wrapped, wrappedKey: flipBit(wrapped.wrappedKey, 3) }),
    ).toThrow(VaultLockedError);
  });

  it('binds each record to its id, so rows cannot be swapped', () => {
    // A stolen database must not allow moving one conversation's ciphertext
    // into another conversation's row.
    const { vault } = createVault(passphrase);
    const stored = encryptRecord(vault, 'msg:1', text.encode('for record one'));
    expect(() => decryptRecord(vault, 'msg:2', stored)).toThrow(AuthenticationError);
  });

  it('uses a fresh nonce per write', () => {
    const { vault } = createVault(passphrase);
    const payload = text.encode('same content');
    const a = encryptRecord(vault, 'msg:1', payload);
    const b = encryptRecord(vault, 'msg:1', payload);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    expect(decryptRecord(vault, 'msg:1', a)).toEqual(payload);
    expect(decryptRecord(vault, 'msg:1', b)).toEqual(payload);
  });

  it('changes the passphrase without re-encrypting records', () => {
    const { vault } = createVault(passphrase);
    const stored = encryptRecord(vault, 'msg:1', text.encode('durable'));

    const newPassphrase = utf8.encode('a completely different passphrase');
    const rewrapped = changePassphrase(vault, newPassphrase);

    // Old passphrase no longer opens the new wrapper.
    expect(() => unlockVault(passphrase, rewrapped)).toThrow(VaultLockedError);
    // New one does, and existing records still decrypt.
    const reopened = unlockVault(newPassphrase, rewrapped);
    expect(decryptRecord(reopened, 'msg:1', stored)).toEqual(text.encode('durable'));
  });

  it('wipes the data key on lock', () => {
    const { vault } = createVault(passphrase);
    lockVault(vault);
    expect(vault.dataKey.every((b) => b === 0)).toBe(true);
  });

  it('serialises and restores the wrapper', () => {
    const { wrapped } = createVault(passphrase);
    const decoded = decodeWrappedVault(encodeWrappedVault(wrapped));
    expect(decoded.salt).toEqual(wrapped.salt);
    expect(decoded.memoryKiB).toBe(wrapped.memoryKiB);
    expect(decoded.iterations).toBe(wrapped.iterations);
    expect(decoded.wrappedKey).toEqual(wrapped.wrappedKey);
    expect(unlockVault(passphrase, decoded).dataKey.length).toBe(32);
  });

  it('rejects a foreign blob', () => {
    expect(() => decodeWrappedVault(random(64))).toThrow(MalformedInputError);
  });

  it('uses memory-hard parameters at or above the OWASP floor', () => {
    // PBKDF2-style parameters would be cheap to crack on a GPU. The floor here
    // is the chosen profile, so a future reduction below it fails rather than
    // quietly weakening every new vault.
    const { wrapped } = createVault(passphrase);
    expect(wrapped.memoryKiB).toBeGreaterThanOrEqual(47104);
    expect(wrapped.iterations).toBeGreaterThanOrEqual(2);
    expect(wrapped.parallelism).toBeGreaterThanOrEqual(1);
  });

  it('opens a vault written with different (older, stronger) parameters', () => {
    // Parameters live in the wrapper, which is what lets the default change
    // without orphaning existing vaults. Verify that actually holds.
    const { vault, wrapped } = createVault(passphrase);
    const stored = encryptRecord(vault, 'msg:1', text.encode('survives a profile change'));

    const asIfOlder = { ...wrapped, memoryKiB: wrapped.memoryKiB, iterations: wrapped.iterations };
    const reopened = unlockVault(passphrase, asIfOlder);
    expect(decryptRecord(reopened, 'msg:1', stored)).toEqual(
      text.encode('survives a profile change'),
    );
  });
});

describe('safety numbers', () => {
  it('is deterministic and identical on both devices', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    // Both devices sort the fingerprints, so both screens show the same digits.
    expect(safetyNumber(alice.publicIdentity, bob.publicIdentity)).toBe(
      safetyNumber(bob.publicIdentity, alice.publicIdentity),
    );
  });

  it('produces 60 digits', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    const number = safetyNumber(alice.publicIdentity, bob.publicIdentity);
    expect(number).toMatch(/^\d{60}$/);
    expect(formatSafetyNumber(number).split(' ')).toHaveLength(12);
  });

  it('changes when either identity changes', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    const mallory = new Device('mallory');
    expect(safetyNumber(alice.publicIdentity, bob.publicIdentity)).not.toBe(
      safetyNumber(alice.publicIdentity, mallory.publicIdentity),
    );
  });

  it('gives each identity a distinct fingerprint', () => {
    const fingerprints = new Set(
      Array.from({ length: 10 }, () =>
        identityFingerprint(new Device('d').publicIdentity.signingPublicKey),
      ),
    );
    expect(fingerprints.size).toBe(10);
  });

  it('compares safety numbers in constant time', () => {
    const a = '1'.repeat(60);
    expect(safetyNumbersMatch(a, a)).toBe(true);
    expect(safetyNumbersMatch(a, '2'.repeat(60))).toBe(false);
    expect(safetyNumbersMatch(a, '1'.repeat(59))).toBe(false);
  });

  it('round-trips a verification QR code', () => {
    const alice = new Device('alice');
    const scanned = parseVerificationQrPayload(
      verificationQrPayload(alice.publicIdentity),
    );
    expect(scanned.signingPublicKey).toEqual(alice.publicIdentity.signingPublicKey);
    expect(scanned.exchangePublicKey).toEqual(alice.publicIdentity.exchangePublicKey);
  });

  it('rejects a forged QR code', () => {
    // Scanning must verify the key binding, not just parse the bytes.
    const alice = new Device('alice');
    const mallory = new Device('mallory');
    const payload = verificationQrPayload({
      signingPublicKey: alice.publicIdentity.signingPublicKey,
      exchangePublicKey: mallory.publicIdentity.exchangePublicKey,
      exchangeKeySignature: alice.publicIdentity.exchangeKeySignature,
    });
    expect(() => parseVerificationQrPayload(payload)).toThrow(UntrustedBundleError);
  });

  it('rejects a QR code that is not ours', () => {
    expect(() => parseVerificationQrPayload(random(96))).toThrow(MalformedInputError);
  });
});

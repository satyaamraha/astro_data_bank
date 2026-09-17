import { describe, expect, it } from 'vitest';
import {
  addressMatches,
  addressOf,
  createIdentity,
  createSignedPreKey,
  publicIdentityOf,
  restoreIdentity,
  UntrustedBundleError,
  verifyIdentityBinding,
  verifyPreKeyBundle,
  MalformedInputError,
  random,
} from '../src/index.js';
import { Device, flipBit } from './helpers.js';

describe('identity', () => {
  it('binds the exchange key to the signing key', () => {
    const identity = createIdentity();
    expect(verifyIdentityBinding(publicIdentityOf(identity))).toBe(true);
  });

  it('rejects an identity whose exchange key was swapped', () => {
    const victim = publicIdentityOf(createIdentity());
    const attacker = publicIdentityOf(createIdentity());

    // The classic attack: keep the victim's signing key so the safety number
    // looks unchanged, but substitute a DH key the attacker controls.
    const forged = {
      signingPublicKey: victim.signingPublicKey,
      exchangePublicKey: attacker.exchangePublicKey,
      exchangeKeySignature: victim.exchangeKeySignature,
    };
    expect(verifyIdentityBinding(forged)).toBe(false);
  });

  it('rejects a corrupted binding signature', () => {
    const identity = publicIdentityOf(createIdentity());
    expect(
      verifyIdentityBinding({
        ...identity,
        exchangeKeySignature: flipBit(identity.exchangeKeySignature),
      }),
    ).toBe(false);
  });

  it('derives a stable, self-certifying address', () => {
    const identity = publicIdentityOf(createIdentity());
    expect(addressOf(identity)).toBe(addressOf(identity));
    expect(addressMatches(addressOf(identity), identity)).toBe(true);
    expect(addressMatches(addressOf(identity), publicIdentityOf(createIdentity()))).toBe(
      false,
    );
  });

  it('gives different identities different addresses', () => {
    const addresses = new Set(
      Array.from({ length: 25 }, () => addressOf(publicIdentityOf(createIdentity()))),
    );
    expect(addresses.size).toBe(25);
  });

  it('contains no phone number or other external identifier', () => {
    // The address is a hash of a public key and nothing else, so there is no
    // user-supplied identifier for an operator to disclose.
    const identity = publicIdentityOf(createIdentity());
    expect(addressOf(identity)).toMatch(/^[a-z2-9]+$/);
  });

  it('restores from stored secrets and recomputes public keys', () => {
    const original = createIdentity();
    const restored = restoreIdentity(
      original.signing.secretKey,
      original.exchange.secretKey,
      original.exchangeKeySignature,
    );
    expect(restored.signing.publicKey).toEqual(original.signing.publicKey);
    expect(restored.exchange.publicKey).toEqual(original.exchange.publicKey);
  });

  it('refuses to restore an identity with a mismatched binding', () => {
    const a = createIdentity();
    const b = createIdentity();
    // Storage tampered with: exchange key from a different identity.
    expect(() =>
      restoreIdentity(a.signing.secretKey, b.exchange.secretKey, a.exchangeKeySignature),
    ).toThrow(UntrustedBundleError);
  });
});

describe('prekey bundles', () => {
  it('accepts a well-formed bundle', () => {
    const device = new Device('d');
    expect(() => verifyPreKeyBundle(device.issueBundle())).not.toThrow();
  });

  it('rejects a bundle whose signed prekey was substituted', () => {
    const victim = new Device('victim');
    const attacker = new Device('attacker');
    const bundle = victim.issueBundle();

    const attackerPreKey = createSignedPreKey(attacker.identity, bundle.signedPreKey.id);
    expect(() =>
      verifyPreKeyBundle({
        ...bundle,
        // Attacker's prekey, but the victim's signature: must not verify.
        signedPreKey: {
          id: bundle.signedPreKey.id,
          publicKey: attackerPreKey.published.publicKey,
          signature: bundle.signedPreKey.signature,
        },
      }),
    ).toThrow(UntrustedBundleError);
  });

  it('rejects a bundle whose signed prekey id was altered', () => {
    // The id is inside the signed transcript, so renumbering invalidates it.
    // This stops a relay from making us derive keys against the wrong prekey.
    const device = new Device('d');
    const bundle = device.issueBundle();
    expect(() =>
      verifyPreKeyBundle({
        ...bundle,
        signedPreKey: { ...bundle.signedPreKey, id: bundle.signedPreKey.id + 1 },
      }),
    ).toThrow(UntrustedBundleError);
  });

  it('rejects a bundle whose ML-KEM prekey was substituted', () => {
    const victim = new Device('victim');
    const attacker = new Device('attacker');
    const bundle = victim.issueBundle();
    const attackerBundle = attacker.issueBundle();
    expect(() =>
      verifyPreKeyBundle({
        ...bundle,
        signedKemPreKey: {
          id: bundle.signedKemPreKey.id,
          publicKey: attackerBundle.signedKemPreKey.publicKey,
          signature: bundle.signedKemPreKey.signature,
        },
      }),
    ).toThrow(UntrustedBundleError);
  });

  it('rejects a bundle with a wrong-length one-time prekey', () => {
    const device = new Device('d');
    const bundle = device.issueBundle();
    expect(() =>
      verifyPreKeyBundle({
        ...bundle,
        oneTimePreKey: { id: 99, publicKey: random(16) },
      }),
    ).toThrow(MalformedInputError);
  });

  it('never issues the same one-time prekey twice', () => {
    const device = new Device('d');
    const ids = new Set<number>();
    for (let i = 0; i < 40; i++) {
      const bundle = device.issueBundle();
      const id = bundle.oneTimePreKey?.id;
      expect(id).toBeDefined();
      expect(ids.has(id!)).toBe(false);
      ids.add(id!);
    }
  });
});

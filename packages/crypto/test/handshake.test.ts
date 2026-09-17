import { describe, expect, it } from 'vitest';
import {
  MLKEM_CIPHERTEXT_LEN,
  SHARED_SECRET_LEN,
  UntrustedBundleError,
  associatedData,
  initiateHandshake,
  publicIdentityOf,
  respondToHandshake,
  MalformedInputError,
} from '../src/index.js';
import { Device, flipBit } from './helpers.js';

/** Run a full PQXDH exchange between two devices and return both root secrets. */
function exchange(alice: Device, bob: Device) {
  const bundle = bob.issueBundle();
  const initiator = initiateHandshake(alice.identity, bundle);

  const responder = respondToHandshake(bob.identity, {
    initiatorIdentity: alice.publicIdentity,
    ephemeralPublicKey: initiator.ephemeralPublicKey,
    kemCiphertext: initiator.kemCiphertext,
    keyIds: initiator.keyIds,
    signedPreKeySecret: bob.preKeys.signedPreKey(initiator.keyIds.signedPreKeyId)!.secretKey,
    signedKemPreKeySecret: bob.preKeys.signedKemPreKey(
      initiator.keyIds.signedKemPreKeyId,
    )!.secretKey,
    ...(initiator.keyIds.oneTimePreKeyId !== undefined
      ? {
          oneTimePreKeySecret: bob.preKeys.oneTimePreKey(initiator.keyIds.oneTimePreKeyId)!
            .secretKey,
        }
      : {}),
    ...(initiator.keyIds.oneTimeKemPreKeyId !== undefined
      ? {
          oneTimeKemPreKeySecret: bob.preKeys.oneTimeKemPreKey(
            initiator.keyIds.oneTimeKemPreKeyId,
          )!.secretKey,
        }
      : {}),
  });

  return { bundle, initiator, responder };
}

describe('PQXDH handshake', () => {
  it('lets both sides derive the same root secret', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    const { initiator, responder } = exchange(alice, bob);
    expect(initiator.rootSecret.length).toBe(SHARED_SECRET_LEN);
    expect(responder.rootSecret).toEqual(initiator.rootSecret);
  });

  it('produces a different secret for every handshake', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    const secrets = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const { initiator } = exchange(alice, bob);
      secrets.add(Buffer.from(initiator.rootSecret).toString('hex'));
    }
    expect(secrets.size).toBe(5);
  });

  it('includes a real ML-KEM ciphertext, so the handshake is hybrid', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    const { initiator } = exchange(alice, bob);
    // A classical-only handshake would have nothing to send here. Its presence
    // is what defends against harvest-now-decrypt-later.
    expect(initiator.kemCiphertext.length).toBe(MLKEM_CIPHERTEXT_LEN);
  });

  it('verifies the bundle before agreeing on any key', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    const bundle = bob.issueBundle();
    expect(() =>
      initiateHandshake(alice.identity, {
        ...bundle,
        signedPreKey: {
          ...bundle.signedPreKey,
          signature: flipBit(bundle.signedPreKey.signature),
        },
      }),
    ).toThrow(UntrustedBundleError);
  });

  it('fails to agree when the ML-KEM ciphertext is tampered with', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    const bundle = bob.issueBundle();
    const initiator = initiateHandshake(alice.identity, bundle);

    // ML-KEM is implicitly rejecting: decapsulation yields a *different*
    // pseudorandom secret rather than an error, so the divergence shows up here
    // and becomes an AEAD failure in the message layer.
    const responder = respondToHandshake(bob.identity, {
      initiatorIdentity: alice.publicIdentity,
      ephemeralPublicKey: initiator.ephemeralPublicKey,
      kemCiphertext: flipBit(initiator.kemCiphertext, 42),
      keyIds: initiator.keyIds,
      signedPreKeySecret: bob.preKeys.signedPreKey(initiator.keyIds.signedPreKeyId)!.secretKey,
      signedKemPreKeySecret: bob.preKeys.signedKemPreKey(
        initiator.keyIds.signedKemPreKeyId,
      )!.secretKey,
      ...(initiator.keyIds.oneTimePreKeyId !== undefined
        ? {
            oneTimePreKeySecret: bob.preKeys.oneTimePreKey(
              initiator.keyIds.oneTimePreKeyId,
            )!.secretKey,
          }
        : {}),
      ...(initiator.keyIds.oneTimeKemPreKeyId !== undefined
        ? {
            oneTimeKemPreKeySecret: bob.preKeys.oneTimeKemPreKey(
              initiator.keyIds.oneTimeKemPreKeyId,
            )!.secretKey,
          }
        : {}),
    });
    expect(responder.rootSecret).not.toEqual(initiator.rootSecret);
  });

  it('fails to agree when the ephemeral key is substituted', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    const mallory = new Device('mallory');
    const bundle = bob.issueBundle();
    const initiator = initiateHandshake(alice.identity, bundle);
    const other = initiateHandshake(mallory.identity, bob.issueBundle());

    const responder = respondToHandshake(bob.identity, {
      initiatorIdentity: alice.publicIdentity,
      ephemeralPublicKey: other.ephemeralPublicKey,
      kemCiphertext: initiator.kemCiphertext,
      keyIds: initiator.keyIds,
      signedPreKeySecret: bob.preKeys.signedPreKey(initiator.keyIds.signedPreKeyId)!.secretKey,
      signedKemPreKeySecret: bob.preKeys.signedKemPreKey(
        initiator.keyIds.signedKemPreKeyId,
      )!.secretKey,
      ...(initiator.keyIds.oneTimePreKeyId !== undefined
        ? {
            oneTimePreKeySecret: bob.preKeys.oneTimePreKey(
              initiator.keyIds.oneTimePreKeyId,
            )!.secretKey,
          }
        : {}),
      ...(initiator.keyIds.oneTimeKemPreKeyId !== undefined
        ? {
            oneTimeKemPreKeySecret: bob.preKeys.oneTimeKemPreKey(
              initiator.keyIds.oneTimeKemPreKeyId,
            )!.secretKey,
          }
        : {}),
    });
    expect(responder.rootSecret).not.toEqual(initiator.rootSecret);
  });

  it('fails to agree when the claimed initiator identity is wrong', () => {
    // Bob thinks the message came from Mallory. DH1 then uses the wrong
    // identity key, so the secrets diverge: this is what authenticates Alice.
    const alice = new Device('alice');
    const bob = new Device('bob');
    const mallory = new Device('mallory');
    const bundle = bob.issueBundle();
    const initiator = initiateHandshake(alice.identity, bundle);

    const responder = respondToHandshake(bob.identity, {
      initiatorIdentity: mallory.publicIdentity,
      ephemeralPublicKey: initiator.ephemeralPublicKey,
      kemCiphertext: initiator.kemCiphertext,
      keyIds: initiator.keyIds,
      signedPreKeySecret: bob.preKeys.signedPreKey(initiator.keyIds.signedPreKeyId)!.secretKey,
      signedKemPreKeySecret: bob.preKeys.signedKemPreKey(
        initiator.keyIds.signedKemPreKeyId,
      )!.secretKey,
      ...(initiator.keyIds.oneTimePreKeyId !== undefined
        ? {
            oneTimePreKeySecret: bob.preKeys.oneTimePreKey(
              initiator.keyIds.oneTimePreKeyId,
            )!.secretKey,
          }
        : {}),
      ...(initiator.keyIds.oneTimeKemPreKeyId !== undefined
        ? {
            oneTimeKemPreKeySecret: bob.preKeys.oneTimeKemPreKey(
              initiator.keyIds.oneTimeKemPreKeyId,
            )!.secretKey,
          }
        : {}),
    });
    expect(responder.rootSecret).not.toEqual(initiator.rootSecret);
  });

  it('refuses a key-id/secret mismatch instead of deriving a useless key', () => {
    const alice = new Device('alice');
    const bob = new Device('bob');
    const bundle = bob.issueBundle();
    const initiator = initiateHandshake(alice.identity, bundle);

    expect(() =>
      respondToHandshake(bob.identity, {
        initiatorIdentity: alice.publicIdentity,
        ephemeralPublicKey: initiator.ephemeralPublicKey,
        kemCiphertext: initiator.kemCiphertext,
        keyIds: initiator.keyIds, // names a one-time prekey...
        signedPreKeySecret: bob.preKeys.signedPreKey(initiator.keyIds.signedPreKeyId)!
          .secretKey,
        signedKemPreKeySecret: bob.preKeys.signedKemPreKey(
          initiator.keyIds.signedKemPreKeyId,
        )!.secretKey,
        // ...but supplies no secret for it.
      }),
    ).toThrow(MalformedInputError);
  });

  it('still works when the relay has run out of one-time prekeys', () => {
    // Degraded but functional: the signed "last resort" keys carry the
    // handshake, and both sides still agree.
    const alice = new Device('alice');
    const bob = new Device('bob');
    const bundle = bob.issueBundle();
    const withoutOneTime = {
      identity: bundle.identity,
      signedPreKey: bundle.signedPreKey,
      signedKemPreKey: bundle.signedKemPreKey,
    };
    const initiator = initiateHandshake(alice.identity, withoutOneTime);
    expect(initiator.keyIds.oneTimePreKeyId).toBeUndefined();
    expect(initiator.keyIds.oneTimeKemPreKeyId).toBeUndefined();

    const responder = respondToHandshake(bob.identity, {
      initiatorIdentity: alice.publicIdentity,
      ephemeralPublicKey: initiator.ephemeralPublicKey,
      kemCiphertext: initiator.kemCiphertext,
      keyIds: initiator.keyIds,
      signedPreKeySecret: bob.preKeys.signedPreKey(initiator.keyIds.signedPreKeyId)!.secretKey,
      signedKemPreKeySecret: bob.preKeys.signedKemPreKey(
        initiator.keyIds.signedKemPreKeyId,
      )!.secretKey,
    });
    expect(responder.rootSecret).toEqual(initiator.rootSecret);
  });

  it('binds associated data to both identities in a fixed order', () => {
    const alice = publicIdentityOf(new Device('alice').identity);
    const bob = publicIdentityOf(new Device('bob').identity);
    expect(associatedData(alice, bob)).toEqual(associatedData(alice, bob));
    // Direction matters: swapping the roles must change the AD, otherwise a
    // message could be reflected back at its sender.
    expect(associatedData(alice, bob)).not.toEqual(associatedData(bob, alice));
  });
});

/**
 * Input validation for published key material.
 *
 * The relay verifies signatures on everything a client publishes. It is not
 * trusted to do so — clients re-verify every bundle they fetch, because the
 * whole design assumes the relay may be hostile. The point of checking here is
 * integrity of the *directory*: without it, one client could upload nonsense
 * that makes another client's session setup fail, which is a cheap
 * denial-of-service against a third party.
 */

import {
  addressOf as cryptoAddressOf,
  verifyPreKeyBundle,
  type PublicIdentity,
} from '@veil/crypto';
import {
  decodeIdentity,
  decodeOneTimePreKey,
  decodeSignedPreKey,
  type WireOneTimePreKey,
  type WirePublicIdentity,
  type WireSignedPreKey,
} from '@veil/protocol';

export { random, toHex } from '@veil/crypto';

export interface PublishedKeys {
  readonly identity: WirePublicIdentity;
  readonly signedPreKey: WireSignedPreKey;
  readonly signedKemPreKey: WireSignedPreKey;
  readonly oneTimePreKeys?: WireOneTimePreKey[];
  readonly oneTimeKemPreKeys?: WireOneTimePreKey[];
}

export type ValidationResult =
  | { readonly ok: true; readonly address: string; readonly identity: PublicIdentity }
  | { readonly ok: false; readonly error: string };

/**
 * Verify an uploaded key set.
 *
 * Reuses the client's own bundle verifier, so the relay cannot accept a bundle
 * that a client would reject — one implementation of the rule, not two that
 * can drift apart.
 */
export function verifyPublishedPreKeys(published: PublishedKeys): ValidationResult {
  let identity: PublicIdentity;
  try {
    identity = decodeIdentity(published.identity);
  } catch {
    return { ok: false, error: 'malformed identity encoding' };
  }

  if (!published.signedPreKey || !published.signedKemPreKey) {
    return { ok: false, error: 'missing signed prekeys' };
  }

  try {
    verifyPreKeyBundle({
      identity,
      signedPreKey: decodeSignedPreKey(published.signedPreKey),
      signedKemPreKey: decodeSignedPreKey(published.signedKemPreKey),
    });
  } catch (error) {
    return { ok: false, error: `invalid key material: ${(error as Error).message}` };
  }

  // One-time prekeys carry no signature (they are covered by the handshake
  // transcript instead), so all we can check is that they are well formed.
  for (const list of [published.oneTimePreKeys ?? [], published.oneTimeKemPreKeys ?? []]) {
    for (const key of list) {
      if (!Number.isInteger(key?.id) || typeof key?.publicKey !== 'string') {
        return { ok: false, error: 'malformed one-time prekey' };
      }
      try {
        decodeOneTimePreKey(key);
      } catch {
        return { ok: false, error: 'malformed one-time prekey encoding' };
      }
    }
  }

  return { ok: true, address: cryptoAddressOf(identity), identity };
}

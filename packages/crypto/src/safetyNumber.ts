/**
 * Safety numbers: the human half of the protocol.
 *
 * All the cryptography above is worthless against an active attacker if the
 * user never checks that the key they hold belongs to the person they think.
 * That check cannot be done by the app — it requires an out-of-band channel
 * (meeting up, or a voice call already recognised) — so the only job here is to
 * render key material in a form two humans can compare without error.
 *
 * Design points that matter for that:
 *  - Digits, not hex. Non-technical users compare digits far more reliably,
 *    and digits read aloud over a phone call unambiguously.
 *  - Sorted concatenation, so both devices display the identical string and
 *    neither user has to work out "mine" versus "theirs".
 *  - An iterated hash, so generating a key whose safety number collides in the
 *    displayed prefix is expensive. Users compare prefixes in practice; this
 *    raises the cost of a partial-collision vanity attack.
 */

import { hash512, constantTimeEqual } from './primitives.js';
import { MalformedInputError, UntrustedBundleError } from './errors.js';
import { Reader, Writer, concat, utf8 } from './wire.js';
import { verifyIdentityBinding, type PublicIdentity } from './identity.js';

/**
 * Iteration count for the fingerprint hash.
 *
 * Matches Signal's choice. It costs a few milliseconds once per contact, which
 * is invisible to the user, while multiplying the work of anyone grinding keys
 * for a colliding display prefix by the same factor.
 */
export const FINGERPRINT_ITERATIONS = 5200;

/** Digits contributed by each party. Two parties -> a 60-digit safety number. */
const DIGITS_PER_PARTY = 30;

/** Digits per display group, for chunked rendering. */
const GROUP_SIZE = 5;

function iteratedFingerprint(signingPublicKey: Uint8Array): Uint8Array {
  if (signingPublicKey.length !== 32) {
    throw new MalformedInputError('identity signing key has wrong length');
  }
  // The key is folded back in on every round, so the chain cannot be
  // precomputed independently of the key.
  let digest = concat(utf8.encode('Veil/v1/Fingerprint'), signingPublicKey);
  for (let i = 0; i < FINGERPRINT_ITERATIONS; i++) {
    digest = hash512(digest, signingPublicKey);
  }
  return digest;
}

/**
 * Convert hash output into decimal digits.
 *
 * Each group of 5 digits comes from 40 bits reduced mod 100000. The modulus is
 * not a power of ten, so the reduction is very slightly biased; that is
 * irrelevant here because this is a comparison string, not key material.
 */
function encodeDigits(digest: Uint8Array, count: number): string {
  let out = '';
  let offset = 0;
  while (out.length < count) {
    if (offset + 5 > digest.length) {
      throw new MalformedInputError('digest exhausted while encoding safety number');
    }
    let value = 0n;
    for (let i = 0; i < 5; i++) value = (value << 8n) | BigInt(digest[offset + i]!);
    offset += 5;
    out += (value % 100000n).toString().padStart(GROUP_SIZE, '0');
  }
  return out.slice(0, count);
}

/** The 30 digits contributed by one identity. */
export function identityFingerprint(signingPublicKey: Uint8Array): string {
  return encodeDigits(iteratedFingerprint(signingPublicKey), DIGITS_PER_PARTY);
}

/**
 * The 60-digit safety number for a conversation.
 *
 * Both sides sort the two fingerprints, so both screens show the same number.
 */
export function safetyNumber(a: PublicIdentity, b: PublicIdentity): string {
  const fa = identityFingerprint(a.signingPublicKey);
  const fb = identityFingerprint(b.signingPublicKey);
  return fa < fb ? fa + fb : fb + fa;
}

/** Grouped for display: 12 groups of 5 digits. */
export function formatSafetyNumber(number: string): string {
  const groups: string[] = [];
  for (let i = 0; i < number.length; i += GROUP_SIZE) {
    groups.push(number.slice(i, i + GROUP_SIZE));
  }
  return groups.join(' ');
}

/** Compare two safety numbers in constant time. */
export function safetyNumbersMatch(a: string, b: string): boolean {
  return constantTimeEqual(utf8.encode(a), utf8.encode(b));
}

/**
 * Payload for the QR code shown during in-person verification.
 *
 * Contains the full identity (both keys plus the binding signature) so the
 * scanning device verifies the binding itself rather than trusting the
 * displayed digits. Scanning is strictly stronger than reading digits aloud —
 * it compares all 256 bits, not the prefix a human bothers to check.
 */
export function verificationQrPayload(identity: PublicIdentity): Uint8Array {
  return new Writer()
    .fixed(utf8.encode('Veil/v1/Verify'))
    .bytes(identity.signingPublicKey)
    .bytes(identity.exchangePublicKey)
    .bytes(identity.exchangeKeySignature)
    .finish();
}

/**
 * Parse a scanned QR payload back into an identity.
 *
 * Verifies the key-binding signature before returning, so a forged QR code is
 * rejected here rather than becoming a "verified" contact.
 */
export function parseVerificationQrPayload(bytes: Uint8Array): PublicIdentity {
  const expectedTag = utf8.encode('Veil/v1/Verify');
  const reader = new Reader(bytes);
  const tag = reader.fixed(expectedTag.length);
  if (!constantTimeEqual(tag, expectedTag)) {
    throw new MalformedInputError('not a Veil verification code');
  }
  const identity: PublicIdentity = {
    signingPublicKey: reader.bytes(),
    exchangePublicKey: reader.bytes(),
    exchangeKeySignature: reader.bytes(),
  };
  reader.end();
  if (!verifyIdentityBinding(identity)) {
    throw new UntrustedBundleError('scanned identity failed its key-binding check');
  }
  return identity;
}

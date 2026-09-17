/**
 * Authentication against a registered identity key.
 *
 * There is no password, so there is nothing to phish, nothing to reuse across
 * services, and nothing for the relay to store that could be stolen. A client
 * proves control of its identity key by signing a single-use challenge.
 *
 * Consequence worth being explicit about: losing the identity key means losing
 * the account, and the relay genuinely cannot help. That is the cost of the
 * operator holding no secret of yours, and it is why the app's backup flow
 * exports the key rather than offering "reset my account".
 */

import { random, verify } from '@veil/crypto';
import { LIMITS, challengeTranscript, fromBase64Url, toBase64Url } from '@veil/protocol';

interface Challenge {
  readonly address: string;
  readonly value: Uint8Array;
  readonly expiresAt: number;
}

interface Token {
  readonly address: string;
  readonly expiresAt: number;
}

export class AuthService {
  private readonly challenges = new Map<string, Challenge>();
  private readonly tokens = new Map<string, Token>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  /** Issue a single-use challenge for an address. */
  issueChallenge(address: string): { challenge: string; expiresAt: number } {
    const value = random(32);
    const expiresAt = this.now() + LIMITS.challengeTtlMs;
    const encoded = toBase64Url(value);
    this.challenges.set(encoded, { address, value, expiresAt });
    return { challenge: encoded, expiresAt };
  }

  /**
   * Verify a signed challenge and issue a bearer token.
   *
   * The challenge is consumed whether or not verification succeeds, so a
   * failed attempt cannot be retried against the same challenge and an
   * attacker gets no oracle to grind.
   */
  authenticate(params: {
    address: string;
    challenge: string;
    signature: string;
    signingPublicKey: string;
  }): { token: string; expiresAt: number } | undefined {
    const record = this.challenges.get(params.challenge);
    this.challenges.delete(params.challenge);

    if (!record) return undefined;
    if (record.expiresAt < this.now()) return undefined;
    // The challenge was issued for one address; it cannot be used for another.
    if (record.address !== params.address) return undefined;

    let signature: Uint8Array;
    let publicKey: Uint8Array;
    try {
      signature = fromBase64Url(params.signature);
      publicKey = fromBase64Url(params.signingPublicKey);
    } catch {
      return undefined;
    }

    const transcript = challengeTranscript(params.address, record.value);
    if (!verify(publicKey, transcript, signature)) return undefined;

    const token = toBase64Url(random(32));
    const expiresAt = this.now() + LIMITS.tokenTtlMs;
    this.tokens.set(token, { address: params.address, expiresAt });
    return { token, expiresAt };
  }

  /** Resolve a bearer token to an address, or undefined if invalid/expired. */
  resolve(token: string | undefined): string | undefined {
    if (!token) return undefined;
    const record = this.tokens.get(token);
    if (!record) return undefined;
    if (record.expiresAt < this.now()) {
      this.tokens.delete(token);
      return undefined;
    }
    return record.address;
  }

  revoke(token: string): void {
    this.tokens.delete(token);
  }

  /** Drop expired challenges and tokens. Called on the same timer as message expiry. */
  prune(): void {
    const now = this.now();
    for (const [key, challenge] of this.challenges) {
      if (challenge.expiresAt < now) this.challenges.delete(key);
    }
    for (const [key, token] of this.tokens) {
      if (token.expiresAt < now) this.tokens.delete(key);
    }
  }

  /** Test helper. */
  get activeTokenCount(): number {
    return this.tokens.size;
  }
}

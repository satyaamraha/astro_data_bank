/**
 * Passphrase attempt throttling.
 *
 * Argon2id makes each guess cost ~1-3 seconds on a phone, which stops a fast
 * offline attack on a copied database. It does *not* stop someone holding the
 * unlocked-but-locked device from sitting there trying passphrases: a few
 * thousand attempts at 2 seconds each is a weekend, and people pick guessable
 * passphrases.
 *
 * So attempts are throttled, with escalating lockouts. Two design points that
 * matter more than the numbers:
 *
 *  - **The counter lives in the platform keystore, not the database.** If it
 *    lived alongside the encrypted data, an attacker could copy the database,
 *    attempt, restore the copy, and reset the counter. Keeping it in the
 *    keystore means clearing app data destroys the vault too, which is a
 *    pointless trade for the attacker.
 *
 *  - **It fails closed.** An unreadable or absent counter is treated as
 *    "locked out for the base interval", never as "no failures yet". Otherwise
 *    deleting one keystore entry would disable the throttle entirely.
 *
 * Optional wipe-after-N is available but **off by default**. For a personal
 * two-person app, a child or a pocket mashing the keyboard should not be able
 * to destroy the only copy of a conversation history that has no backup.
 */

export interface UnlockAttemptState {
  /** Consecutive failures since the last success. */
  readonly failures: number;
  /** Local clock at the most recent failure. */
  readonly lastFailureAt: number;
}

export interface UnlockPolicy {
  /** Failures allowed with no delay. Covers ordinary typos. */
  readonly freeAttempts: number;
  /** Base lockout, doubling per failure past the free allowance. */
  readonly baseLockoutMs: number;
  /** Cap, so the app never locks a legitimate owner out permanently. */
  readonly maxLockoutMs: number;
  /**
   * Wipe the vault after this many consecutive failures.
   *
   * Undefined (the default) means never. Enabling it makes a forgotten
   * passphrase plus persistence indistinguishable from an attack, and there is
   * no backup to fall back on.
   */
  readonly wipeAfterFailures?: number;
}

export const DEFAULT_UNLOCK_POLICY: UnlockPolicy = {
  freeAttempts: 3,
  baseLockoutMs: 15_000,
  // Five minutes. Long enough that guessing is hopeless (a 6-word passphrase
  // would take longer than the universe has existed), short enough that the
  // owner is not locked out of their own messages for an afternoon.
  maxLockoutMs: 300_000,
};

export const EMPTY_ATTEMPT_STATE: UnlockAttemptState = { failures: 0, lastFailureAt: 0 };

/**
 * How long the caller must wait before the next attempt.
 *
 * Doubles per failure beyond the free allowance, capped. Returns 0 when an
 * attempt is allowed now.
 */
export function lockoutRemainingMs(
  state: UnlockAttemptState,
  currentTime: number,
  policy: UnlockPolicy = DEFAULT_UNLOCK_POLICY,
): number {
  if (state.failures <= policy.freeAttempts) return 0;

  const over = state.failures - policy.freeAttempts;
  // 2^(over-1) * base, capped. Exponent is bounded before shifting so a
  // corrupted large failure count cannot overflow into a small number.
  const exponent = Math.min(over - 1, 20);
  const lockout = Math.min(policy.baseLockoutMs * 2 ** exponent, policy.maxLockoutMs);

  const elapsed = currentTime - state.lastFailureAt;
  // A clock moved backwards must not shorten a lockout.
  if (elapsed < 0) return lockout;
  return Math.max(0, lockout - elapsed);
}

export function canAttempt(
  state: UnlockAttemptState,
  currentTime: number,
  policy: UnlockPolicy = DEFAULT_UNLOCK_POLICY,
): boolean {
  return lockoutRemainingMs(state, currentTime, policy) === 0;
}

export function recordFailure(
  state: UnlockAttemptState,
  currentTime: number,
): UnlockAttemptState {
  return { failures: state.failures + 1, lastFailureAt: currentTime };
}

export function recordSuccess(): UnlockAttemptState {
  return EMPTY_ATTEMPT_STATE;
}

/** Whether the configured wipe threshold has been reached. */
export function shouldWipe(
  state: UnlockAttemptState,
  policy: UnlockPolicy = DEFAULT_UNLOCK_POLICY,
): boolean {
  if (policy.wipeAfterFailures === undefined) return false;
  return state.failures >= policy.wipeAfterFailures;
}

/**
 * Parse persisted attempt state, failing closed.
 *
 * Anything unreadable, missing, or nonsensical becomes "just failed once past
 * the free allowance", which imposes the base lockout. Treating bad input as
 * "no failures" would let an attacker disable the throttle by corrupting one
 * keystore entry.
 */
export function parseAttemptState(
  raw: string | undefined,
  currentTime: number,
  policy: UnlockPolicy = DEFAULT_UNLOCK_POLICY,
): UnlockAttemptState {
  const failClosed: UnlockAttemptState = {
    failures: policy.freeAttempts + 1,
    lastFailureAt: currentTime,
  };
  if (raw === undefined) return EMPTY_ATTEMPT_STATE; // genuinely first run
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return failClosed;
    const { failures, lastFailureAt } = parsed as Partial<UnlockAttemptState>;
    if (
      typeof failures !== 'number' ||
      typeof lastFailureAt !== 'number' ||
      !Number.isFinite(failures) ||
      !Number.isFinite(lastFailureAt) ||
      failures < 0 ||
      lastFailureAt < 0
    ) {
      return failClosed;
    }
    return { failures: Math.floor(failures), lastFailureAt: Math.floor(lastFailureAt) };
  } catch {
    return failClosed;
  }
}

export function serialiseAttemptState(state: UnlockAttemptState): string {
  return JSON.stringify(state);
}

/** Human-readable wait, for the unlock screen. */
export function formatLockout(remainingMs: number): string {
  const seconds = Math.ceil(remainingMs / 1000);
  if (seconds < 60) return `${seconds} second${seconds === 1 ? '' : 's'}`;
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} minute${minutes === 1 ? '' : 's'}`;
}

/**
 * When to lock the vault.
 *
 * The rule lives here, apart from the React Native lifecycle plumbing, because
 * it is the security-relevant part and it should be testable without a device.
 *
 * Once the vault is unlocked its data key is in memory. While the app is in the
 * foreground that is unavoidable. While it is in the background it is not, so
 * the key is wiped and the passphrase is required again. This is the difference
 * between "someone who picks up an unlocked phone reads everything" and
 * "someone who picks up the phone needs the passphrase".
 */

/**
 * Grace period before a backgrounded app locks.
 *
 * Zero is stricter but locks on every permission dialog and every two-second
 * app switch, and a passphrase prompt that often trains people into short
 * passphrases - which costs more security than the strict timeout gains.
 * Thirty seconds survives an interruption and still locks a phone left on a
 * table before someone else picks it up.
 */
export const BACKGROUND_LOCK_GRACE_MS = 30_000;

/**
 * Whether a lock is due.
 *
 * Driven by elapsed time rather than by a timer having fired, because a
 * suspended process may never run its timer: the OS can freeze the app and
 * resume it hours later with the timer still pending. Checking the clock on
 * resume is what makes the lock actually happen in that case.
 */
export function shouldLock(
  backgroundedAt: number | undefined,
  currentTime: number,
  graceMs: number = BACKGROUND_LOCK_GRACE_MS,
): boolean {
  if (backgroundedAt === undefined) return false;
  if (currentTime < backgroundedAt) {
    // Clock moved backwards (NTP correction, user change). Treat an
    // untrustworthy elapsed time as "lock", never as "stay unlocked".
    return true;
  }
  return currentTime - backgroundedAt >= graceMs;
}

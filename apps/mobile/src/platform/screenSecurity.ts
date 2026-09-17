/**
 * Screen and lifecycle protection.
 *
 * Two leaks that encryption does nothing about:
 *
 *  1. **Screenshots and the recents thumbnail.** Android snapshots the visible
 *     screen when an app backgrounds, to draw the app-switcher card. That
 *     snapshot is written to disk outside this app's encrypted database, and on
 *     older or rooted devices it is readable. A messenger that encrypts
 *     everything and then leaves a plaintext screenshot of the conversation in
 *     the recents cache has not protected the conversation. FLAG_SECURE (which
 *     is what `preventScreenCaptureAsync` sets on Android) blocks both the
 *     screenshot and the thumbnail.
 *
 *  2. **The unlocked vault sitting in memory.** Once unlocked, the data key is
 *     in RAM. While the app is foregrounded that is unavoidable. While it is
 *     backgrounded it is avoidable, so we wipe it and require the passphrase
 *     again. This is the difference between "a thief who grabs an unlocked
 *     phone reads everything" and "a thief needs the passphrase".
 *
 * Neither defence survives a compromised OS. Both meaningfully raise the cost
 * of the ordinary cases: shoulder-surfing, a borrowed phone, a forensic tool
 * pulling cached thumbnails.
 */

import { AppState, type AppStateStatus, type NativeEventSubscription } from 'react-native';
import * as ScreenCapture from 'expo-screen-capture';
import { BACKGROUND_LOCK_GRACE_MS, shouldLock } from '../core/lockPolicy.js';

/**
 * Block screenshots and the app-switcher preview.
 *
 * Returns whether protection is actually in force. The caller should surface a
 * warning if it is not, rather than assume it worked: an app that silently
 * fails to set FLAG_SECURE looks identical to one that succeeded.
 */
export async function preventScreenCapture(): Promise<boolean> {
  try {
    if (!(await ScreenCapture.isAvailableAsync())) return false;
    await ScreenCapture.preventScreenCaptureAsync();
    // Separate API, and the one that covers the recents card specifically.
    await ScreenCapture.enableAppSwitcherProtectionAsync();
    return true;
  } catch {
    return false;
  }
}

export async function allowScreenCapture(): Promise<void> {
  try {
    await ScreenCapture.disableAppSwitcherProtectionAsync();
    await ScreenCapture.allowScreenCaptureAsync();
  } catch {
    // Best effort; failing to *relax* a restriction is not a security problem.
  }
}

export interface LifecycleLockOptions {
  /** Wipe the data key and return to the unlock screen. */
  readonly onLock: () => void;
  readonly graceMs?: number;
  readonly now?: () => number;
}

/**
 * Lock the vault after the app has been backgrounded for the grace period.
 *
 * Exported as a plain function over an injectable clock so the timing rule is
 * testable without a device.
 */
export function startLifecycleLock(options: LifecycleLockOptions): () => void {
  const graceMs = options.graceMs ?? BACKGROUND_LOCK_GRACE_MS;
  const now = options.now ?? (() => Date.now());

  let backgroundedAt: number | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const subscription: NativeEventSubscription = AppState.addEventListener(
    'change',
    (state: AppStateStatus) => {
      if (state === 'active') {
        if (timer !== undefined) {
          clearTimeout(timer);
          timer = undefined;
        }
        // Also check on resume: a suspended process may not have run the
        // timer at all, so elapsed time is the authority, not the timer.
        if (shouldLock(backgroundedAt, now(), graceMs)) {
          options.onLock();
        }
        backgroundedAt = undefined;
        return;
      }

      // 'background' or 'inactive'
      if (backgroundedAt === undefined) {
        backgroundedAt = now();
        timer = setTimeout(() => {
          timer = undefined;
          options.onLock();
        }, graceMs);
      }
    },
  );

  return () => {
    if (timer !== undefined) clearTimeout(timer);
    subscription.remove();
  };
}

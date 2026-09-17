/**
 * Pure formatting helpers for security-relevant text.
 *
 * These live in `core` rather than beside the screens for two reasons: they are
 * testable in Node without React Native, and getting them wrong has security
 * consequences. `looksLikeCode` in particular decides whether a new
 * conversation is labelled verified or unverified, so it is worth a test.
 */

/** Insert a break every five digits, matching how a safety number is read aloud. */
export function groupSafetyNumber(value: string): string[] {
  const groups: string[] = [];
  for (let i = 0; i < value.length; i += 5) groups.push(value.slice(i, i + 5));
  return groups;
}

/** Break a long verification code into fixed-width lines for display. */
export function chunkCode(code: string, width = 32): string[] {
  const lines: string[] = [];
  for (let i = 0; i < code.length; i += width) lines.push(code.slice(i, i + width));
  return lines;
}

/**
 * Whether input is a full verification code rather than a bare address.
 *
 * A code is long base64url and carries a signed identity; an address is short
 * base32 and carries nothing. Misclassifying an address as a code would label
 * an unverified conversation as verified, so the length bound is deliberately
 * well clear of any address (16 bytes of base32 is 26 characters).
 */
export function looksLikeCode(input: string): boolean {
  return input.length > 64 && /^[A-Za-z0-9_-]+$/.test(input);
}

/** Short relative time for conversation rows. */
export function relativeTime(timestamp: number, now: number): string {
  const seconds = Math.max(0, Math.floor((now - timestamp) / 1000));
  if (seconds < 60) return 'now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86_400)}d`;
}

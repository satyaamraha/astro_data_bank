/**
 * CSPRNG bootstrap.
 *
 * Hermes does not ship `crypto.getRandomValues`, and @noble/hashes needs it.
 * This import must run before any key generation, so it is the first import in
 * the app entry point.
 *
 * The check below is deliberately fatal. A silent fallback to Math.random
 * anywhere in a key path would produce predictable keys while the app looked
 * like it was working — the worst possible failure mode for this codebase.
 */

import 'react-native-get-random-values';

export function assertSecureRandomAvailable(): void {
  const cryptoObject = (
    globalThis as { crypto?: { getRandomValues?: (buffer: Uint8Array) => Uint8Array } }
  ).crypto;
  if (!cryptoObject || typeof cryptoObject.getRandomValues !== 'function') {
    throw new Error(
      'No cryptographically secure random source is available. Refusing to start: ' +
        'generating keys without one would produce predictable keys.',
    );
  }

  // Sanity check that it actually fills the buffer rather than no-opping.
  const probe = new Uint8Array(32);
  cryptoObject.getRandomValues(probe);
  if (probe.every((byte) => byte === 0)) {
    throw new Error('The platform random source returned all zeros. Refusing to start.');
  }
}

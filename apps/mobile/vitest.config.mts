import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

/**
 * Core logic is tested in Node against the TypeScript sources of the workspace
 * packages. The React Native layer is intentionally excluded: anything that
 * matters for security lives in src/core and is testable without a device.
 */
export default defineConfig({
  resolve: {
    alias: {
      '@veil/crypto': fileURLToPath(
        new URL('../../packages/crypto/src/index.ts', import.meta.url),
      ),
      '@veil/protocol': fileURLToPath(
        new URL('../../packages/protocol/src/index.ts', import.meta.url),
      ),
    },
  },
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 60_000,
  },
});

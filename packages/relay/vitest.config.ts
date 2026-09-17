import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

/**
 * Tests resolve the workspace packages to their TypeScript sources rather than
 * their built output. Without this, a stale `dist/` silently tests the wrong
 * code — which is exactly the sort of thing that hides a protocol regression.
 */
export default defineConfig({
  resolve: {
    alias: {
      '@veil/crypto': fileURLToPath(new URL('../crypto/src/index.ts', import.meta.url)),
      '@veil/protocol': fileURLToPath(new URL('../protocol/src/index.ts', import.meta.url)),
    },
  },
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 30_000,
  },
});

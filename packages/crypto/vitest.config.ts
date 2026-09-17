import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    // The PQ handshake and Argon2id are deliberately slow; give them room.
    testTimeout: 60_000,
  },
});

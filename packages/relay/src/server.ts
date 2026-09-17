/**
 * Relay entry point.
 *
 * Reads only PORT and HOST from the environment. Nothing here needs a secret,
 * because the relay holds no key material of its own beyond its TLS
 * certificate, which is terminated by the deployment platform.
 */

import { buildRelay } from './relay.js';

const port = Number.parseInt(process.env['PORT'] ?? '8443', 10);
const host = process.env['HOST'] ?? '0.0.0.0';

const relay = await buildRelay();

try {
  await relay.app.listen({ port, host });
  // One line on startup, and nothing per request.
  process.stdout.write(`veil-relay listening on ${host}:${port}\n`);
} catch (error) {
  process.stderr.write(`veil-relay failed to start: ${String(error)}\n`);
  process.exit(1);
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    void relay.close().then(() => process.exit(0));
  });
}

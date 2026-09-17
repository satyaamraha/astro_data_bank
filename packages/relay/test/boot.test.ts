import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { buildRelay, type Relay } from '../src/index.js';

/**
 * Boots the relay on a real port and drives it over real HTTP.
 *
 * The other suites use Fastify's `inject`, which skips the HTTP server itself.
 * This one exists so a regression in actual startup, listening, or JSON
 * handling cannot pass CI.
 */

let relay: Relay;
let baseUrl: string;

beforeEach(async () => {
  relay = await buildRelay({ disableTimers: true });
  await relay.app.listen({ port: 0, host: '127.0.0.1' });
  const address = relay.app.server.address();
  if (!address || typeof address === 'string') throw new Error('no port assigned');
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  await relay.close();
});

describe('relay over real HTTP', () => {
  it('answers a health check', async () => {
    const response = await fetch(`${baseUrl}/v1/health`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: 'ok' });
  });

  it('rejects a body over the size limit', async () => {
    // Enforced before parsing, so a hostile client cannot make the server
    // allocate an arbitrary amount of memory.
    const response = await fetch(`${baseUrl}/v1/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ padding: 'A'.repeat(400_000) }),
    });
    expect([413, 400]).toContain(response.status);
  });

  it('rejects malformed JSON without crashing', async () => {
    const response = await fetch(`${baseUrl}/v1/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{not json',
    });
    expect(response.status).toBe(400);
    // Still serving afterwards.
    expect((await fetch(`${baseUrl}/v1/health`)).status).toBe(200);
  });

  it('requires a bearer token on protected routes', async () => {
    const response = await fetch(`${baseUrl}/v1/messages`);
    expect(response.status).toBe(401);
  });

  it('returns 404 for an unknown route rather than leaking a stack trace', async () => {
    const response = await fetch(`${baseUrl}/v1/does-not-exist`);
    expect(response.status).toBe(404);
    expect(JSON.stringify(await response.json())).not.toContain('at ');
  });
});

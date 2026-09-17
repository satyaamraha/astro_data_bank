/**
 * App-core test harness.
 *
 * Wires the real Messenger to the real relay through an in-process transport,
 * so these tests exercise the actual client/server path: registration,
 * challenge-response login, bundle verification, sealed sending, and sync.
 * Nothing here is a mock of Veil's own logic — only the network hop is
 * short-circuited.
 */

import { createVault, utf8, type Vault } from '@veil/crypto';
import { buildRelay, type Relay } from '../../../packages/relay/src/index.js';
import { Messenger, type MessengerEvents } from '../src/core/messenger.js';
import { RelayClient, type HttpResponse, type Transport } from '../src/core/relayClient.js';
import {
  InMemoryDatabase,
  InMemorySecretStore,
} from '../src/core/storage.js';

/** Transport that calls Fastify's inject instead of opening a socket. */
export class InjectTransport implements Transport {
  constructor(private readonly relay: Relay) {}

  async request(options: {
    method: 'GET' | 'POST';
    path: string;
    body?: unknown;
    headers?: Record<string, string>;
  }): Promise<HttpResponse> {
    const response = await this.relay.app.inject({
      method: options.method,
      url: options.path,
      ...(options.body !== undefined ? { payload: options.body as object } : {}),
      ...(options.headers ? { headers: options.headers } : {}),
    });
    return {
      status: response.statusCode,
      json: async () => {
        try {
          return response.json();
        } catch {
          return {};
        }
      },
    };
  }
}

export interface TestUser {
  readonly name: string;
  readonly messenger: Messenger;
  readonly database: InMemoryDatabase;
  readonly secrets: InMemorySecretStore;
  readonly vault: Vault;
  address: string;
}

/**
 * Create a messenger against the relay.
 *
 * `mode` defaults to `'open'` here, not to the product default of `'paired'`,
 * so the general multi-contact behaviour stays covered. Paired mode - which is
 * what the shipped app uses - has its own suite in `pairing.test.ts`.
 */
export async function createUser(
  relay: Relay,
  name: string,
  options: {
    events?: MessengerEvents;
    sendReceipts?: boolean;
    sendTypingIndicators?: boolean;
    mode?: 'paired' | 'open';
  } = {},
): Promise<TestUser> {
  const database = new InMemoryDatabase();
  const secrets = new InMemorySecretStore();
  const { vault } = createVault(utf8.encode(`${name}-passphrase`));
  const client = new RelayClient(new InjectTransport(relay));

  const messenger = new Messenger({
    relay: client,
    secrets,
    database,
    vault,
    mode: options.mode ?? 'open',
    ...(options.events ? { events: options.events } : {}),
    ...(options.sendReceipts !== undefined ? { sendReceipts: options.sendReceipts } : {}),
    ...(options.sendTypingIndicators !== undefined
      ? { sendTypingIndicators: options.sendTypingIndicators }
      : {}),
  });

  const { address } = await messenger.initialise();
  return { name, messenger, database, secrets, vault, address };
}

/**
 * Two devices in the shipped configuration: paired mode, paired to each other
 * by exchanging verification codes, as two people would do in person.
 */
export async function createPairedUsers(
  relay: Relay,
  options: { events?: MessengerEvents; sendReceipts?: boolean } = {},
): Promise<{ alice: TestUser; bob: TestUser }> {
  const alice = await createUser(relay, 'alice', { ...options, mode: 'paired' });
  const bob = await createUser(relay, 'bob', { ...options, mode: 'paired' });
  await alice.messenger.pairWithCode(bob.messenger.verificationCode(), 'Bob');
  await bob.messenger.pairWithCode(alice.messenger.verificationCode(), 'Alice');
  return { alice, bob };
}

export async function withRelay<T>(fn: (relay: Relay) => Promise<T>): Promise<T> {
  const relay = await buildRelay({ disableTimers: true });
  try {
    return await fn(relay);
  } finally {
    await relay.close();
  }
}

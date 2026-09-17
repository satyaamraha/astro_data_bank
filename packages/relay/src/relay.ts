/**
 * The Veil relay.
 *
 * Its job is to be a dumb, blind post box. Stated as properties it must uphold:
 *
 *  1. It never sees plaintext. Every body it stores is a sealed envelope.
 *  2. It never learns who sent a message. Sender identity is inside the seal.
 *  3. It stores no personal identifier. An account is a public key.
 *  4. It logs no request metadata. See `buildRelay`'s logger configuration.
 *  5. It deletes on delivery. Acknowledged messages are gone, not archived.
 *
 * What it unavoidably does learn, and which no amount of care removes:
 *  - the recipient address of each message (it has to route);
 *  - the IP address of whoever connects (the network layer requires it);
 *  - timing and volume.
 * A user who needs those hidden too must reach the relay over Tor or a VPN.
 * The relay is written so that this is the *whole* residual exposure rather
 * than one item on a longer list.
 */

import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import websocket from '@fastify/websocket';
import {
  LIMITS,
  type AcknowledgeRequest,
  type AuthenticateRequest,
  type AuthenticateResponse,
  type ChallengeRequest,
  type ChallengeResponse,
  type ClientSocketMessage,
  type DeliveredMessage,
  type FetchMessagesResponse,
  type PreKeyBundleResponse,
  type RegisterRequest,
  type RegisterResponse,
  type SendMessageRequest,
  type ServerSocketMessage,
  type UploadPreKeysRequest,
  type WireEnvelope,
} from '@veil/protocol';
import { random, toHex, verifyPublishedPreKeys } from './validate.js';
import { AuthService } from './auth.js';
import { InMemoryRelayStore, type RelayStore } from './store.js';
import { RateLimiter } from './rateLimit.js';

export interface RelayOptions {
  readonly store?: RelayStore;
  /** Requests per minute per IP for unauthenticated message submission. */
  readonly sendRateLimit?: number;
  /** Set true only in tests; disables the background expiry timer. */
  readonly disableTimers?: boolean;
}

interface SocketState {
  address?: string;
}

export interface Relay {
  readonly app: FastifyInstance;
  readonly store: RelayStore;
  readonly auth: AuthService;
  close(): Promise<void>;
}

/** Round a timestamp down to the hour, to blunt timing metadata. */
function toHour(timestamp: number): number {
  return Math.floor(timestamp / 3_600_000) * 3_600_000;
}

function deliveryOf(message: { id: string; envelope: WireEnvelope; receivedAt: number }): DeliveredMessage {
  return {
    id: message.id,
    envelope: message.envelope,
    receivedAtHour: toHour(message.receivedAt),
  };
}

export async function buildRelay(options: RelayOptions = {}): Promise<Relay> {
  const store = options.store ?? new InMemoryRelayStore();
  const auth = new AuthService();
  const sendLimiter = new RateLimiter(options.sendRateLimit ?? 120, 60_000);

  const app = Fastify({
    // Logging is off by default and must stay that way. Fastify's default
    // logger records the IP, path, and timing of every request, which would
    // reconstruct exactly the delivery metadata this design is meant to
    // withhold. Operators who need health signals should export aggregate
    // counters, not per-request logs.
    logger: false,
    bodyLimit: LIMITS.maxBodyBytes,
    // Do not trust X-Forwarded-For: it is client-controlled, and trusting it
    // would let an attacker forge a different IP per request to slip the rate
    // limiter. Deployments behind a proxy must set this explicitly.
    trustProxy: false,
  });

  await app.register(websocket, {
    options: { maxPayload: LIMITS.maxBodyBytes },
  });

  /** Sockets currently connected, so we can push instead of making clients poll. */
  const sockets = new Map<string, Set<{ send(data: string): void }>>();

  function pushToAddress(address: string, message: ServerSocketMessage): void {
    const connections = sockets.get(address);
    if (!connections) return;
    const payload = JSON.stringify(message);
    for (const connection of connections) {
      try {
        connection.send(payload);
      } catch {
        // A dead socket is not an error worth surfacing; the message stays
        // queued and is delivered on the client's next fetch.
      }
    }
  }

  function requireAuth(request: FastifyRequest): string | undefined {
    const header = request.headers.authorization;
    if (typeof header !== 'string' || !header.startsWith('Bearer ')) return undefined;
    return auth.resolve(header.slice('Bearer '.length));
  }

  // -------------------------------------------------------------------------
  // Registration
  // -------------------------------------------------------------------------

  app.post('/v1/accounts', async (request, reply) => {
    const body = request.body as RegisterRequest | undefined;
    if (!body?.identity) return reply.code(400).send({ error: 'missing identity' });

    // Validate every published signature before storing. The client verifies
    // again on fetch (it must never trust us), but rejecting garbage here stops
    // one client from poisoning another's bundle fetch.
    const validation = verifyPublishedPreKeys(body);
    if (!validation.ok) return reply.code(400).send({ error: validation.error });

    const address = validation.address;

    const existing = await store.getAccount(address);
    if (existing) {
      // The address is a hash of the identity key, so "already registered"
      // means the same key. Re-registering is therefore idempotent and cannot
      // be used to hijack someone else's address.
      return reply.code(200).send({ address } satisfies RegisterResponse);
    }

    await store.createAccount({
      address,
      identity: body.identity,
      signedPreKey: body.signedPreKey,
      signedKemPreKey: body.signedKemPreKey,
      oneTimePreKeys: (body.oneTimePreKeys ?? []).slice(0, LIMITS.maxOneTimePreKeys),
      oneTimeKemPreKeys: (body.oneTimeKemPreKeys ?? []).slice(0, LIMITS.maxOneTimePreKeys),
    });

    return reply.code(201).send({ address } satisfies RegisterResponse);
  });

  // -------------------------------------------------------------------------
  // Authentication
  // -------------------------------------------------------------------------

  app.post('/v1/auth/challenge', async (request, reply) => {
    const body = request.body as ChallengeRequest | undefined;
    if (!body?.address) return reply.code(400).send({ error: 'missing address' });
    // Issue a challenge even for unknown addresses, so this endpoint cannot be
    // used to enumerate which addresses are registered.
    const issued = auth.issueChallenge(body.address);
    return reply.send(issued satisfies ChallengeResponse);
  });

  app.post('/v1/auth', async (request, reply) => {
    const body = request.body as AuthenticateRequest | undefined;
    if (!body?.address || !body.challenge || !body.signature) {
      return reply.code(400).send({ error: 'missing fields' });
    }
    const account = await store.getAccount(body.address);
    if (!account) return reply.code(401).send({ error: 'authentication failed' });

    const result = auth.authenticate({
      address: body.address,
      challenge: body.challenge,
      signature: body.signature,
      signingPublicKey: account.identity.signingPublicKey,
    });
    // One opaque failure for every cause: unknown address, expired challenge,
    // bad signature. Distinguishing them would leak account existence.
    if (!result) return reply.code(401).send({ error: 'authentication failed' });
    return reply.send(result satisfies AuthenticateResponse);
  });

  // -------------------------------------------------------------------------
  // Key distribution
  // -------------------------------------------------------------------------

  app.get<{ Params: { address: string } }>('/v1/keys/:address', async (request, reply) => {
    const account = await store.getAccount(request.params.address);
    if (!account) return reply.code(404).send({ error: 'not found' });

    const oneTime = await store.takeOneTimePreKeys(account.address);
    const bundle: PreKeyBundleResponse = {
      identity: account.identity,
      signedPreKey: account.signedPreKey,
      signedKemPreKey: account.signedKemPreKey,
      ...(oneTime.oneTimePreKey ? { oneTimePreKey: oneTime.oneTimePreKey } : {}),
      ...(oneTime.oneTimeKemPreKey ? { oneTimeKemPreKey: oneTime.oneTimeKemPreKey } : {}),
    };
    return reply.send(bundle);
  });

  app.post('/v1/keys', async (request, reply) => {
    const address = requireAuth(request);
    if (!address) return reply.code(401).send({ error: 'unauthorized' });

    const account = await store.getAccount(address);
    if (!account) return reply.code(404).send({ error: 'not found' });

    const body = (request.body ?? {}) as UploadPreKeysRequest;
    const validation = verifyPublishedPreKeys({
      identity: account.identity,
      signedPreKey: body.signedPreKey ?? account.signedPreKey,
      signedKemPreKey: body.signedKemPreKey ?? account.signedKemPreKey,
      oneTimePreKeys: body.oneTimePreKeys ?? [],
      oneTimeKemPreKeys: body.oneTimeKemPreKeys ?? [],
    });
    if (!validation.ok) return reply.code(400).send({ error: validation.error });

    await store.updatePreKeys(address, {
      ...(body.signedPreKey ? { signedPreKey: body.signedPreKey } : {}),
      ...(body.signedKemPreKey ? { signedKemPreKey: body.signedKemPreKey } : {}),
      ...(body.oneTimePreKeys ? { oneTimePreKeys: body.oneTimePreKeys } : {}),
      ...(body.oneTimeKemPreKeys ? { oneTimeKemPreKeys: body.oneTimeKemPreKeys } : {}),
    });
    return reply.send({ accepted: true });
  });

  /** How many one-time prekeys remain, so the client knows when to top up. */
  app.get('/v1/keys/count', async (request, reply) => {
    const address = requireAuth(request);
    if (!address) return reply.code(401).send({ error: 'unauthorized' });
    const account = await store.getAccount(address);
    if (!account) return reply.code(404).send({ error: 'not found' });
    return reply.send({
      oneTimePreKeys: account.oneTimePreKeys.length,
      oneTimeKemPreKeys: account.oneTimeKemPreKeys.length,
    });
  });

  // -------------------------------------------------------------------------
  // Messaging
  // -------------------------------------------------------------------------

  /**
   * Submit a message.
   *
   * Deliberately unauthenticated. Sealed sender means the relay cannot know who
   * is sending, so there is no identity to authenticate — requiring a login
   * here would reintroduce exactly the sender metadata the design removes.
   *
   * The cost is that spam must be handled without knowing the sender, so we
   * rely on per-IP rate limiting, strict size caps, and bounded queues. A
   * production deployment should add privacy-preserving delivery tokens
   * (blind-signed by the recipient) to push back on spam without deanonymising
   * senders; that is noted as future work rather than pretended here.
   */
  app.post('/v1/messages', async (request, reply) => {
    const clientKey = request.ip;
    if (!sendLimiter.allow(clientKey)) {
      return reply.code(429).send({ error: 'rate limited' });
    }

    const body = request.body as SendMessageRequest | undefined;
    const envelope = body?.envelope;
    if (!envelope?.recipient || !envelope.ciphertext || !envelope.ephemeralPublicKey) {
      return reply.code(400).send({ error: 'malformed envelope' });
    }
    if (envelope.ciphertext.length > LIMITS.maxEnvelopeBytes) {
      return reply.code(413).send({ error: 'envelope too large' });
    }

    // Accept only for known recipients, but do not say whether the recipient
    // exists: a distinguishable response would let anyone probe the directory.
    const account = await store.getAccount(envelope.recipient);
    if (!account) return reply.send({ accepted: true });

    const message = {
      id: toHex(random(16)),
      envelope,
      receivedAt: Date.now(),
    };
    await store.enqueue(message);
    pushToAddress(envelope.recipient, { type: 'deliver', message: deliveryOf(message) });

    return reply.send({ accepted: true });
  });

  app.get('/v1/messages', async (request, reply) => {
    const address = requireAuth(request);
    if (!address) return reply.code(401).send({ error: 'unauthorized' });
    const messages = await store.queued(address);
    return reply.send({
      messages: messages.map(deliveryOf),
    } satisfies FetchMessagesResponse);
  });

  app.post('/v1/messages/acknowledge', async (request, reply) => {
    const address = requireAuth(request);
    if (!address) return reply.code(401).send({ error: 'unauthorized' });
    const body = request.body as AcknowledgeRequest | undefined;
    if (!Array.isArray(body?.ids)) return reply.code(400).send({ error: 'missing ids' });
    // Scoped to the caller's own queue, so one account cannot delete another's
    // messages by guessing ids.
    const removed = await store.acknowledge(address, body.ids);
    return reply.send({ removed });
  });

  // -------------------------------------------------------------------------
  // Realtime socket
  // -------------------------------------------------------------------------

  app.get('/v1/socket', { websocket: true }, (connection) => {
    const state: SocketState = {};

    const send = (message: ServerSocketMessage) => {
      try {
        connection.send(JSON.stringify(message));
      } catch {
        /* socket already gone */
      }
    };

    connection.on('message', (raw: Buffer) => {
      void (async () => {
        let parsed: ClientSocketMessage;
        try {
          parsed = JSON.parse(raw.toString('utf8')) as ClientSocketMessage;
        } catch {
          send({ type: 'error', code: 'malformed', message: 'invalid JSON' });
          return;
        }

        if (parsed.type === 'authenticate') {
          const address = auth.resolve(parsed.token);
          if (!address) {
            send({ type: 'error', code: 'unauthorized', message: 'invalid token' });
            return;
          }
          state.address = address;
          const set = sockets.get(address) ?? new Set();
          set.add(connection);
          sockets.set(address, set);
          send({ type: 'authenticated', address });

          // Drain anything queued while the client was offline.
          for (const message of await store.queued(address)) {
            send({ type: 'deliver', message: deliveryOf(message) });
          }
          return;
        }

        if (parsed.type === 'ping') {
          send({ type: 'pong' });
          return;
        }

        if (parsed.type === 'send') {
          // Same reasoning as the HTTP endpoint: no sender authentication, so
          // the socket accepts sends whether or not it has authenticated.
          const envelope = parsed.envelope;
          if (!envelope?.recipient || !envelope.ciphertext) {
            send({ type: 'error', code: 'malformed', message: 'invalid envelope' });
            return;
          }
          if (envelope.ciphertext.length > LIMITS.maxEnvelopeBytes) {
            send({ type: 'error', code: 'too_large', message: 'envelope too large' });
            return;
          }
          const account = await store.getAccount(envelope.recipient);
          if (account) {
            const message = { id: toHex(random(16)), envelope, receivedAt: Date.now() };
            await store.enqueue(message);
            pushToAddress(envelope.recipient, {
              type: 'deliver',
              message: deliveryOf(message),
            });
          }
          send({ type: 'accepted' });
          return;
        }

        if (parsed.type === 'acknowledge') {
          if (!state.address) {
            send({ type: 'error', code: 'unauthorized', message: 'not authenticated' });
            return;
          }
          await store.acknowledge(state.address, parsed.ids ?? []);
          return;
        }

        send({ type: 'error', code: 'unknown', message: 'unrecognised message type' });
      })();
    });

    connection.on('close', () => {
      if (!state.address) return;
      const set = sockets.get(state.address);
      set?.delete(connection);
      if (set && set.size === 0) sockets.delete(state.address);
    });
  });

  // -------------------------------------------------------------------------
  // Health and housekeeping
  // -------------------------------------------------------------------------

  app.get('/v1/health', async () => ({ status: 'ok' }));

  const timer = options.disableTimers
    ? undefined
    : setInterval(
        () => {
          void store.expire(Date.now());
          auth.prune();
        },
        60 * 60 * 1000,
      );
  // Do not hold the event loop open for a housekeeping timer.
  timer?.unref?.();

  return {
    app,
    store,
    auth,
    async close() {
      if (timer) clearInterval(timer);
      await app.close();
    },
  };
}

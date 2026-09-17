import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { encodeEnvelope } from '@veil/protocol';
import { encryptMessage } from '@veil/crypto';
import type { ServerSocketMessage } from '@veil/protocol';
import { buildRelay, type Relay } from '../src/index.js';
import { TestClient } from './client.js';

/**
 * These tests bind a real port and use a real WebSocket client, because the
 * push-delivery path is where the relay decides what to send to whom — the
 * place an authorisation mistake would leak another account's traffic.
 */

let relay: Relay;
let baseUrl: string;

beforeEach(async () => {
  relay = await buildRelay({ disableTimers: true });
  await relay.app.listen({ port: 0, host: '127.0.0.1' });
  const address = relay.app.server.address();
  if (!address || typeof address === 'string') throw new Error('no port assigned');
  baseUrl = `ws://127.0.0.1:${address.port}/v1/socket`;
});

afterEach(async () => {
  await relay.close();
});

function open(): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(baseUrl);
    socket.once('open', () => resolve(socket));
    socket.once('error', reject);
  });
}

/** Wait for the next server message of a given type. */
function waitFor(
  socket: WebSocket,
  type: ServerSocketMessage['type'],
  timeoutMs = 5000,
): Promise<ServerSocketMessage> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.off('message', onMessage);
      reject(new Error(`timed out waiting for "${type}"`));
    }, timeoutMs);

    function onMessage(raw: WebSocket.RawData) {
      const parsed = JSON.parse(raw.toString()) as ServerSocketMessage;
      if (parsed.type !== type) return;
      clearTimeout(timer);
      socket.off('message', onMessage);
      resolve(parsed);
    }
    socket.on('message', onMessage);
  });
}

describe('realtime socket', () => {
  it('authenticates with a bearer token', async () => {
    const alice = new TestClient(relay, 'alice');
    await alice.register();
    await alice.authenticate();

    const socket = await open();
    try {
      socket.send(JSON.stringify({ type: 'authenticate', token: alice.token }));
      const message = await waitFor(socket, 'authenticated');
      expect(message).toEqual({ type: 'authenticated', address: alice.address });
    } finally {
      socket.close();
    }
  });

  it('refuses a bad token', async () => {
    const socket = await open();
    try {
      socket.send(JSON.stringify({ type: 'authenticate', token: 'not-a-token' }));
      const message = await waitFor(socket, 'error');
      expect(message).toMatchObject({ type: 'error', code: 'unauthorized' });
    } finally {
      socket.close();
    }
  });

  it('pushes a message to a connected recipient', async () => {
    const alice = new TestClient(relay, 'alice');
    const bob = new TestClient(relay, 'bob');
    await alice.register();
    await bob.register();
    await bob.authenticate();
    await alice.startSessionWith(bob.address);

    const socket = await open();
    try {
      socket.send(JSON.stringify({ type: 'authenticate', token: bob.token }));
      await waitFor(socket, 'authenticated');

      const delivered = waitFor(socket, 'deliver');
      await alice.send(bob.address, 'pushed in realtime');
      const message = await delivered;

      expect(message.type).toBe('deliver');
      if (message.type !== 'deliver') throw new Error('unexpected message');
      expect(bob.decryptText(message.message.envelope)).toBe('pushed in realtime');
    } finally {
      socket.close();
    }
  });

  it('drains the offline queue on connect', async () => {
    const alice = new TestClient(relay, 'alice');
    const bob = new TestClient(relay, 'bob');
    await alice.register();
    await bob.register();
    await bob.authenticate();
    await alice.startSessionWith(bob.address);

    // Sent while Bob has no socket open.
    await alice.send(bob.address, 'while you were out');

    const socket = await open();
    try {
      const delivered = waitFor(socket, 'deliver');
      socket.send(JSON.stringify({ type: 'authenticate', token: bob.token }));
      const message = await delivered;
      if (message.type !== 'deliver') throw new Error('unexpected message');
      expect(bob.decryptText(message.message.envelope)).toBe('while you were out');
    } finally {
      socket.close();
    }
  });

  it('never pushes a message to the wrong account', async () => {
    const alice = new TestClient(relay, 'alice');
    const bob = new TestClient(relay, 'bob');
    const eve = new TestClient(relay, 'eve');
    await alice.register();
    await bob.register();
    await eve.register();
    await eve.authenticate();
    await alice.startSessionWith(bob.address);

    const socket = await open();
    try {
      socket.send(JSON.stringify({ type: 'authenticate', token: eve.token }));
      await waitFor(socket, 'authenticated');

      const received: ServerSocketMessage[] = [];
      socket.on('message', (raw) => {
        received.push(JSON.parse(raw.toString()) as ServerSocketMessage);
      });

      // Traffic for Bob must not reach Eve's socket.
      await alice.send(bob.address, 'for bob alone');
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(received.filter((m) => m.type === 'deliver')).toHaveLength(0);
    } finally {
      socket.close();
    }
  });

  it('accepts a send over the socket', async () => {
    const alice = new TestClient(relay, 'alice');
    const bob = new TestClient(relay, 'bob');
    await alice.register();
    await bob.register();
    await bob.authenticate();
    const session = await alice.startSessionWith(bob.address);

    const socket = await open();
    try {
      const envelope = encryptMessage(
        alice.identity,
        session,
        new TextEncoder().encode('over the socket'),
      );
      socket.send(
        JSON.stringify({ type: 'send', envelope: encodeEnvelope(envelope) }),
      );
      await waitFor(socket, 'accepted');

      const inbox = (await bob.fetchMessages()).json() as {
        messages: Array<{ envelope: never }>;
      };
      expect(bob.decryptText(inbox.messages[0]!.envelope)).toBe('over the socket');
    } finally {
      socket.close();
    }
  });

  it('refuses to acknowledge without authentication', async () => {
    const socket = await open();
    try {
      socket.send(JSON.stringify({ type: 'acknowledge', ids: ['whatever'] }));
      const message = await waitFor(socket, 'error');
      expect(message).toMatchObject({ code: 'unauthorized' });
    } finally {
      socket.close();
    }
  });

  it('answers a ping', async () => {
    const socket = await open();
    try {
      socket.send(JSON.stringify({ type: 'ping' }));
      expect(await waitFor(socket, 'pong')).toEqual({ type: 'pong' });
    } finally {
      socket.close();
    }
  });

  it('rejects malformed JSON without dropping the connection', async () => {
    const socket = await open();
    try {
      socket.send('this is not json');
      const message = await waitFor(socket, 'error');
      expect(message).toMatchObject({ code: 'malformed' });
      // Connection survives, so one bad frame is not a denial of service.
      socket.send(JSON.stringify({ type: 'ping' }));
      expect(await waitFor(socket, 'pong')).toEqual({ type: 'pong' });
    } finally {
      socket.close();
    }
  });
});

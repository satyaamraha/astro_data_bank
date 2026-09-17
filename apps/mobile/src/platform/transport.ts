/**
 * Network transports.
 *
 * Both are thin. The interesting privacy decision is what is *absent*: no
 * custom headers, no user agent, no device identifier, no analytics. Every
 * request carries only what the relay needs to route it, because anything else
 * would be a correlatable fingerprint even though the bodies are encrypted.
 */

import type { ServerSocketMessage } from '@veil/protocol';
import type { HttpResponse, SocketTransport, Transport } from '../core/relayClient.js';

export class FetchTransport implements Transport {
  constructor(private readonly baseUrl: string) {}

  async request(options: {
    method: 'GET' | 'POST';
    path: string;
    body?: unknown;
    headers?: Record<string, string>;
  }): Promise<HttpResponse> {
    const response = await fetch(`${this.baseUrl}${options.path}`, {
      method: options.method,
      headers: {
        ...(options.body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...options.headers,
      },
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
    });
    return {
      status: response.status,
      json: async () => {
        try {
          return (await response.json()) as unknown;
        } catch {
          return {};
        }
      },
    };
  }
}

/**
 * WebSocket channel with reconnection.
 *
 * Reconnect matters for more than convenience: while the socket is down,
 * messages queue on the relay, and a queue that is never drained is a queue
 * the relay keeps holding. Prompt delivery means prompt deletion.
 */
export class WebSocketTransport implements SocketTransport {
  private socket?: WebSocket;
  private closedByUs = false;
  private retryDelayMs = 1000;

  constructor(
    private readonly url: string,
    private readonly getToken: () => string | undefined,
  ) {}

  async connect(handlers: {
    onMessage: (message: ServerSocketMessage) => void;
    onClose: () => void;
  }): Promise<void> {
    this.closedByUs = false;

    const open = () => {
      const socket = new WebSocket(this.url);
      this.socket = socket;

      socket.onopen = () => {
        this.retryDelayMs = 1000;
        const token = this.getToken();
        if (token) socket.send(JSON.stringify({ type: 'authenticate', token }));
      };

      socket.onmessage = (event: { data?: unknown }) => {
        try {
          handlers.onMessage(JSON.parse(String(event.data)) as ServerSocketMessage);
        } catch {
          // A malformed frame from the relay is ignored rather than fatal.
        }
      };

      socket.onclose = () => {
        handlers.onClose();
        if (this.closedByUs) return;
        // Exponential backoff, capped, so a relay outage does not become a
        // battery drain.
        setTimeout(open, this.retryDelayMs);
        this.retryDelayMs = Math.min(this.retryDelayMs * 2, 60_000);
      };

      socket.onerror = () => {
        // Handled via onclose.
      };
    };

    open();
  }

  send(message: unknown): void {
    if (this.socket?.readyState === 1) {
      this.socket.send(JSON.stringify(message));
    }
  }

  close(): void {
    this.closedByUs = true;
    this.socket?.close();
  }
}

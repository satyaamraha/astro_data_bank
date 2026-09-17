/**
 * Client for the Veil relay.
 *
 * Written against a `Transport` interface rather than calling `fetch` directly,
 * so the messenger can be tested without a network and so a deployment can
 * route traffic through Tor or a pluggable proxy by swapping the transport.
 *
 * The client treats every relay response as untrusted. Prekey bundles are
 * verified by @veil/crypto before use, and nothing the relay says about an
 * identity is believed on its own.
 */

import {
  LIMITS,
  challengeTranscript,
  decodeBundle,
  encodeEnvelope,
  encodeIdentity,
  encodeOneTimePreKey,
  encodeSignedPreKey,
  fromBase64Url,
  toBase64Url,
  type AuthenticateResponse,
  type ChallengeResponse,
  type DeliveredMessage,
  type FetchMessagesResponse,
  type PreKeyBundleResponse,
  type ServerSocketMessage,
} from '@veil/protocol';
import {
  sign,
  type PreKeyBundle,
  type PrivateIdentity,
  type PublicIdentity,
  type SealedEnvelope,
} from '@veil/crypto';
import type { PublishedPreKeys } from '@veil/crypto';

export interface HttpResponse {
  readonly status: number;
  json(): Promise<unknown>;
}

export interface Transport {
  request(options: {
    method: 'GET' | 'POST';
    path: string;
    body?: unknown;
    headers?: Record<string, string>;
  }): Promise<HttpResponse>;
}

/** Realtime channel. Implemented by a WebSocket on device, in-memory in tests. */
export interface SocketTransport {
  connect(handlers: {
    onMessage: (message: ServerSocketMessage) => void;
    onClose: () => void;
  }): Promise<void>;
  send(message: unknown): void;
  close(): void;
}

export class RelayError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = 'RelayError';
  }
}

export class RelayClient {
  private token?: string;
  private tokenExpiresAt = 0;

  constructor(
    private readonly transport: Transport,
    private readonly now: () => number = () => Date.now(),
  ) {}

  private async expectJson(response: HttpResponse, context: string): Promise<unknown> {
    if (response.status < 200 || response.status >= 300) {
      throw new RelayError(`${context} failed with status ${response.status}`, response.status);
    }
    return response.json();
  }

  async register(identity: PublicIdentity, keys: PublishedPreKeys): Promise<string> {
    const response = await this.transport.request({
      method: 'POST',
      path: '/v1/accounts',
      body: {
        identity: encodeIdentity(identity),
        signedPreKey: encodeSignedPreKey(keys.signedPreKey),
        signedKemPreKey: encodeSignedPreKey(keys.signedKemPreKey),
        oneTimePreKeys: keys.oneTimePreKeys.map(encodeOneTimePreKey),
        oneTimeKemPreKeys: keys.oneTimeKemPreKeys.map(encodeOneTimePreKey),
      },
    });
    const body = (await this.expectJson(response, 'registration')) as { address: string };
    return body.address;
  }

  /**
   * Authenticate, reusing a live token.
   *
   * The signature is produced here from the identity key, so on a device with a
   * hardware keystore this is the one place that needs a keystore-backed
   * signing call.
   */
  async authenticate(identity: PrivateIdentity, address: string): Promise<string> {
    if (this.token && this.tokenExpiresAt > this.now() + 60_000) return this.token;

    const challengeResponse = await this.transport.request({
      method: 'POST',
      path: '/v1/auth/challenge',
      body: { address },
    });
    const challenge = (await this.expectJson(
      challengeResponse,
      'challenge',
    )) as ChallengeResponse;

    const signature = sign(
      identity.signing.secretKey,
      challengeTranscript(address, fromBase64Url(challenge.challenge)),
    );

    const authResponse = await this.transport.request({
      method: 'POST',
      path: '/v1/auth',
      body: {
        address,
        challenge: challenge.challenge,
        signature: toBase64Url(signature),
      },
    });
    const auth = (await this.expectJson(authResponse, 'authentication')) as AuthenticateResponse;
    this.token = auth.token;
    this.tokenExpiresAt = auth.expiresAt;
    return auth.token;
  }

  private authHeaders(): Record<string, string> {
    if (!this.token) throw new RelayError('not authenticated', 401);
    return { authorization: `Bearer ${this.token}` };
  }

  /**
   * Fetch and verify a peer's prekey bundle.
   *
   * `decodeBundle` hands the raw response to @veil/crypto, whose verifier
   * rejects any bundle whose signatures do not chain to the claimed identity
   * key. A hostile relay can therefore deny service but cannot substitute keys.
   */
  async fetchBundle(address: string): Promise<PreKeyBundle> {
    const response = await this.transport.request({
      method: 'GET',
      path: `/v1/keys/${encodeURIComponent(address)}`,
    });
    const body = (await this.expectJson(response, 'bundle fetch')) as PreKeyBundleResponse;
    return decodeBundle(body);
  }

  async send(envelope: SealedEnvelope): Promise<void> {
    const wire = encodeEnvelope(envelope);
    if (wire.ciphertext.length > LIMITS.maxEnvelopeBytes) {
      throw new RelayError('message too large to send', 413);
    }
    const response = await this.transport.request({
      method: 'POST',
      path: '/v1/messages',
      body: { envelope: wire },
    });
    await this.expectJson(response, 'send');
  }

  async fetchMessages(): Promise<DeliveredMessage[]> {
    const response = await this.transport.request({
      method: 'GET',
      path: '/v1/messages',
      headers: this.authHeaders(),
    });
    const body = (await this.expectJson(response, 'fetch')) as FetchMessagesResponse;
    return body.messages;
  }

  async acknowledge(ids: string[]): Promise<void> {
    if (ids.length === 0) return;
    const response = await this.transport.request({
      method: 'POST',
      path: '/v1/messages/acknowledge',
      headers: this.authHeaders(),
      body: { ids },
    });
    await this.expectJson(response, 'acknowledge');
  }

  async preKeyCount(): Promise<{ oneTimePreKeys: number; oneTimeKemPreKeys: number }> {
    const response = await this.transport.request({
      method: 'GET',
      path: '/v1/keys/count',
      headers: this.authHeaders(),
    });
    return (await this.expectJson(response, 'prekey count')) as {
      oneTimePreKeys: number;
      oneTimeKemPreKeys: number;
    };
  }

  async uploadPreKeys(keys: {
    oneTimePreKeys: PublishedPreKeys['oneTimePreKeys'];
    oneTimeKemPreKeys: PublishedPreKeys['oneTimeKemPreKeys'];
  }): Promise<void> {
    const response = await this.transport.request({
      method: 'POST',
      path: '/v1/keys',
      headers: this.authHeaders(),
      body: {
        oneTimePreKeys: keys.oneTimePreKeys.map(encodeOneTimePreKey),
        oneTimeKemPreKeys: keys.oneTimeKemPreKeys.map(encodeOneTimePreKey),
      },
    });
    await this.expectJson(response, 'prekey upload');
  }

  get currentToken(): string | undefined {
    return this.token;
  }
}

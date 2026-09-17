/**
 * A minimal test client that speaks the real protocol against the relay.
 *
 * Uses Fastify's `inject`, so tests exercise routing, parsing, and limits
 * without binding a port.
 */

import {
  createIdentity,
  publicIdentityOf,
  addressOf,
  sign,
  InMemoryPreKeyStore,
  startSession,
  encryptMessage,
  decryptEnvelope,
  type PrivateIdentity,
  type Session,
} from '@veil/crypto';
import {
  challengeTranscript,
  decodeBundle,
  encodeEnvelope,
  encodeIdentity,
  encodeOneTimePreKey,
  encodeSignedPreKey,
  fromBase64Url,
  toBase64Url,
  type PreKeyBundleResponse,
  type RegisterRequest,
} from '@veil/protocol';
import type { Relay } from '../src/index.js';

export class TestClient {
  readonly identity: PrivateIdentity;
  readonly preKeys: InMemoryPreKeyStore;
  readonly sessions = new Map<string, Session>();
  token?: string;

  constructor(
    private readonly relay: Relay,
    readonly name: string,
  ) {
    this.identity = createIdentity();
    this.preKeys = new InMemoryPreKeyStore(this.identity);
  }

  get address(): string {
    return addressOf(publicIdentityOf(this.identity));
  }

  registrationBody(oneTimeCount = 5): RegisterRequest {
    const published = this.preKeys.published();
    return {
      identity: encodeIdentity(publicIdentityOf(this.identity)),
      signedPreKey: encodeSignedPreKey(published.signedPreKey),
      signedKemPreKey: encodeSignedPreKey(published.signedKemPreKey),
      oneTimePreKeys: published.oneTimePreKeys.slice(0, oneTimeCount).map(encodeOneTimePreKey),
      oneTimeKemPreKeys: published.oneTimeKemPreKeys
        .slice(0, oneTimeCount)
        .map(encodeOneTimePreKey),
    };
  }

  async register(oneTimeCount = 5) {
    return this.relay.app.inject({
      method: 'POST',
      url: '/v1/accounts',
      payload: this.registrationBody(oneTimeCount),
    });
  }

  /** Full challenge-response login. */
  async authenticate(): Promise<string> {
    const challengeResponse = await this.relay.app.inject({
      method: 'POST',
      url: '/v1/auth/challenge',
      payload: { address: this.address },
    });
    const { challenge } = challengeResponse.json() as { challenge: string };

    const signature = sign(
      this.identity.signing.secretKey,
      challengeTranscript(this.address, fromBase64Url(challenge)),
    );

    const authResponse = await this.relay.app.inject({
      method: 'POST',
      url: '/v1/auth',
      payload: {
        address: this.address,
        challenge,
        signature: toBase64Url(signature),
      },
    });
    if (authResponse.statusCode !== 200) {
      throw new Error(`authentication failed: ${authResponse.statusCode} ${authResponse.body}`);
    }
    this.token = (authResponse.json() as { token: string }).token;
    return this.token;
  }

  private authHeaders(): Record<string, string> {
    if (!this.token) throw new Error(`${this.name} is not authenticated`);
    return { authorization: `Bearer ${this.token}` };
  }

  async fetchBundle(address: string) {
    return this.relay.app.inject({ method: 'GET', url: `/v1/keys/${address}` });
  }

  /** Start a session with a peer by fetching and verifying their bundle. */
  async startSessionWith(peerAddress: string): Promise<Session> {
    const response = await this.fetchBundle(peerAddress);
    if (response.statusCode !== 200) {
      throw new Error(`bundle fetch failed: ${response.statusCode}`);
    }
    // decodeBundle -> startSession runs the client's own signature checks, so
    // this path is exactly what a real client does with untrusted server data.
    const bundle = decodeBundle(response.json() as PreKeyBundleResponse);
    const session = startSession(this.identity, bundle);
    this.sessions.set(peerAddress, session);
    return session;
  }

  async send(peerAddress: string, body: string) {
    const session = this.sessions.get(peerAddress);
    if (!session) throw new Error(`no session with ${peerAddress}`);
    const envelope = encryptMessage(
      this.identity,
      session,
      new TextEncoder().encode(body),
    );
    return this.relay.app.inject({
      method: 'POST',
      url: '/v1/messages',
      payload: { envelope: encodeEnvelope(envelope) },
    });
  }

  async fetchMessages() {
    const response = await this.relay.app.inject({
      method: 'GET',
      url: '/v1/messages',
      headers: this.authHeaders(),
    });
    return response;
  }

  async acknowledge(ids: string[]) {
    return this.relay.app.inject({
      method: 'POST',
      url: '/v1/messages/acknowledge',
      headers: this.authHeaders(),
      payload: { ids },
    });
  }

  /** Decrypt a delivered envelope, mirroring the real client flow. */
  decrypt(wireEnvelope: { recipient: string; ephemeralPublicKey: string; ciphertext: string }) {
    const result = decryptEnvelope({
      self: this.identity,
      envelope: {
        recipientAddress: wireEnvelope.recipient,
        ephemeralPublicKey: fromBase64Url(wireEnvelope.ephemeralPublicKey),
        ciphertext: fromBase64Url(wireEnvelope.ciphertext),
      },
      lookupSession: (address) => this.sessions.get(address),
      preKeys: this.preKeys,
    });
    this.sessions.set(addressOf(result.senderIdentity), result.session);
    return result;
  }

  decryptText(wireEnvelope: {
    recipient: string;
    ephemeralPublicKey: string;
    ciphertext: string;
  }): string {
    return new TextDecoder().decode(this.decrypt(wireEnvelope).plaintext);
  }
}

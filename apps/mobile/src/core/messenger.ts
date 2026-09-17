/**
 * The messenger: identity, sessions, sending, receiving.
 *
 * This is the layer the UI talks to. It owns the rules that must hold no matter
 * what the screens do:
 *
 *  - A conversation cannot be started without verifying the peer's bundle.
 *  - A pinned contact whose key changed raises a visible warning and blocks
 *    silent re-keying, because silent re-keying is how an active MITM would
 *    look from the inside.
 *  - Sessions and messages are persisted only through the vault.
 *  - Receipts and typing indicators are opt-in, because both leak behaviour to
 *    the peer and (through timing) to anyone watching the network.
 */

import {
  IdentityChangedError,
  InMemoryPreKeyStore,
  addressOf,
  createIdentity,
  decryptEnvelope,
  encryptMessage,
  publicIdentityOf,
  random,
  restoreIdentity,
  safetyNumber,
  startSession,
  toHex,
  type PrivateIdentity,
  type PublicIdentity,
  type SealedEnvelope,
  type Session,
  type Vault,
} from '@veil/crypto';
import { toBase64Url, fromBase64Url, type DeliveredMessage } from '@veil/protocol';
import { decodeEnvelope } from '@veil/protocol';
import { RelayClient } from './relayClient.js';
import { EncryptedCollection, type Database, type SecretStore } from './storage.js';
import {
  decodePayload,
  encodePayload,
  type Contact,
  type Conversation,
  type Message,
  type Payload,
} from './types.js';

const SECRET_IDENTITY_SIGNING = 'veil.identity.signing';
const SECRET_IDENTITY_EXCHANGE = 'veil.identity.exchange';
const SECRET_IDENTITY_BINDING = 'veil.identity.binding';

/** Below this many one-time prekeys on the relay, upload more. */
const PREKEY_LOW_WATER = 20;

export interface MessengerEvents {
  onMessage?: (message: Message) => void;
  onConversationChanged?: (conversation: Conversation) => void;
  onContactChanged?: (contact: Contact) => void;
  /** A pinned contact's key changed. The UI must warn prominently. */
  onIdentityChanged?: (address: string) => void;
  onCallPayload?: (peerAddress: string, payload: Payload) => void;
  onTyping?: (peerAddress: string, typing: boolean) => void;
}

export interface MessengerOptions {
  readonly relay: RelayClient;
  readonly secrets: SecretStore;
  readonly database: Database;
  readonly vault: Vault;
  readonly events?: MessengerEvents;
  /** Send delivery/read receipts. Off by default: it is behavioural metadata. */
  readonly sendReceipts?: boolean;
  /** Send typing indicators. Off by default, for the same reason. */
  readonly sendTypingIndicators?: boolean;
  readonly now?: () => number;
}

interface StoredSession {
  readonly peerIdentity: {
    signingPublicKey: string;
    exchangePublicKey: string;
    exchangeKeySignature: string;
  };
}

export class Messenger {
  private identity!: PrivateIdentity;
  private preKeys!: InMemoryPreKeyStore;
  private address!: string;

  private readonly sessions = new Map<string, Session>();
  private readonly contacts: EncryptedCollection<Contact>;
  private readonly conversations: EncryptedCollection<Conversation>;
  private readonly messages: EncryptedCollection<Message>;
  private readonly sessionMeta: EncryptedCollection<StoredSession>;

  private readonly now: () => number;

  constructor(private readonly options: MessengerOptions) {
    this.now = options.now ?? (() => Date.now());
    this.contacts = new EncryptedCollection(options.database, options.vault, 'contacts');
    this.conversations = new EncryptedCollection(
      options.database,
      options.vault,
      'conversations',
    );
    this.messages = new EncryptedCollection(options.database, options.vault, 'messages');
    this.sessionMeta = new EncryptedCollection(options.database, options.vault, 'sessions');
  }

  // -------------------------------------------------------------------------
  // Identity lifecycle
  // -------------------------------------------------------------------------

  /**
   * Load an existing identity, or create and register one.
   *
   * The identity key is the account. There is no server-side recovery, because
   * the relay holds no secret of the user's — so the app must make key backup
   * an explicit, understood step rather than pretending an account can be
   * "reset".
   */
  async initialise(): Promise<{ address: string; created: boolean }> {
    const storedSigning = await this.options.secrets.get(SECRET_IDENTITY_SIGNING);
    const storedExchange = await this.options.secrets.get(SECRET_IDENTITY_EXCHANGE);
    const storedBinding = await this.options.secrets.get(SECRET_IDENTITY_BINDING);

    let created = false;
    if (storedSigning && storedExchange && storedBinding) {
      this.identity = restoreIdentity(
        fromBase64Url(storedSigning),
        fromBase64Url(storedExchange),
        fromBase64Url(storedBinding),
      );
    } else {
      this.identity = createIdentity();
      await this.options.secrets.set(
        SECRET_IDENTITY_SIGNING,
        toBase64Url(this.identity.signing.secretKey),
      );
      await this.options.secrets.set(
        SECRET_IDENTITY_EXCHANGE,
        toBase64Url(this.identity.exchange.secretKey),
      );
      await this.options.secrets.set(
        SECRET_IDENTITY_BINDING,
        toBase64Url(this.identity.exchangeKeySignature),
      );
      created = true;
    }

    this.preKeys = new InMemoryPreKeyStore(this.identity);
    this.address = addressOf(publicIdentityOf(this.identity));

    await this.options.relay.register(publicIdentityOf(this.identity), this.preKeys.published());
    await this.options.relay.authenticate(this.identity, this.address);
    await this.restoreSessions();

    return { address: this.address, created };
  }

  get myAddress(): string {
    return this.address;
  }

  get myIdentity(): PublicIdentity {
    return publicIdentityOf(this.identity);
  }

  /**
   * Export the identity key for backup.
   *
   * Deliberately explicit and deliberately not automatic: this string *is* the
   * account, so an automatic cloud backup of it would quietly undo the
   * device-bound key storage. The UI must present it as such.
   */
  exportIdentityBackup(): string {
    return JSON.stringify({
      version: 1,
      signing: toBase64Url(this.identity.signing.secretKey),
      exchange: toBase64Url(this.identity.exchange.secretKey),
      binding: toBase64Url(this.identity.exchangeKeySignature),
    });
  }

  // -------------------------------------------------------------------------
  // Sessions
  // -------------------------------------------------------------------------

  private async restoreSessions(): Promise<void> {
    // Session *metadata* is restored (who we have talked to), but ratchet state
    // is intentionally not resumed across restarts in this build: a partially
    // written ratchet is worse than a fresh handshake, because reusing a chain
    // key after a rollback would repeat a nonce. Re-handshaking costs one round
    // trip and is always safe.
    for (const { id } of await this.sessionMeta.all()) {
      void id;
    }
  }

  private async ensureSession(peerAddress: string): Promise<Session> {
    const existing = this.sessions.get(peerAddress);
    if (existing) return existing;

    const bundle = await this.options.relay.fetchBundle(peerAddress);

    // Pin check: if we have a contact for this address, the bundle's identity
    // key must match what we already know, or we refuse and warn.
    const contact = await this.contacts.get(peerAddress);
    const presented = toBase64Url(bundle.identity.signingPublicKey);
    if (contact && contact.identityKey !== presented) {
      contact.verification = 'changed';
      contact.identityChangedAt = this.now();
      await this.contacts.put(peerAddress, contact);
      this.options.events?.onContactChanged?.(contact);
      this.options.events?.onIdentityChanged?.(peerAddress);
      throw new IdentityChangedError(
        'the safety number for this contact has changed; verify before sending',
        contact.identityKey,
        presented,
      );
    }

    // startSession re-verifies every signature in the bundle.
    const session = startSession(this.identity, bundle);
    this.sessions.set(peerAddress, session);

    if (!contact) {
      const created: Contact = {
        address: peerAddress,
        displayName: peerAddress.slice(0, 8),
        identityKey: presented,
        verification: 'unverified',
      };
      await this.contacts.put(peerAddress, created);
      this.options.events?.onContactChanged?.(created);
    }

    await this.sessionMeta.put(peerAddress, {
      peerIdentity: {
        signingPublicKey: toBase64Url(bundle.identity.signingPublicKey),
        exchangePublicKey: toBase64Url(bundle.identity.exchangePublicKey),
        exchangeKeySignature: toBase64Url(bundle.identity.exchangeKeySignature),
      },
    });

    return session;
  }

  /**
   * Persist a peer's identity and create a contact if we have none.
   *
   * Called for inbound messages, where no `ensureSession` ran. Without this, a
   * conversation someone else started would have no stored identity and the
   * user could never compare a safety number for it.
   */
  private async rememberPeer(
    peerAddress: string,
    identity: PublicIdentity,
  ): Promise<void> {
    const presented = toBase64Url(identity.signingPublicKey);

    const existing = await this.sessionMeta.get(peerAddress);
    if (!existing) {
      await this.sessionMeta.put(peerAddress, {
        peerIdentity: {
          signingPublicKey: presented,
          exchangePublicKey: toBase64Url(identity.exchangePublicKey),
          exchangeKeySignature: toBase64Url(identity.exchangeKeySignature),
        },
      });
    }

    const contact = await this.contacts.get(peerAddress);
    if (!contact) {
      const created: Contact = {
        address: peerAddress,
        displayName: peerAddress.slice(0, 8),
        identityKey: presented,
        verification: 'unverified',
      };
      await this.contacts.put(peerAddress, created);
      this.options.events?.onContactChanged?.(created);
      return;
    }

    // A verified contact presenting a different key is the active-MITM case.
    // decryptEnvelope already rejects it when the key is pinned; this covers
    // the unpinned-but-known case by flagging it for the UI.
    if (contact.identityKey !== presented && contact.verification !== 'changed') {
      contact.verification = 'changed';
      contact.identityChangedAt = this.now();
      await this.contacts.put(peerAddress, contact);
      this.options.events?.onContactChanged?.(contact);
      this.options.events?.onIdentityChanged?.(peerAddress);
    }
  }

  // -------------------------------------------------------------------------
  // Sending
  // -------------------------------------------------------------------------

  private async sendPayload(peerAddress: string, payload: Payload): Promise<void> {
    const session = await this.ensureSession(peerAddress);
    const envelope: SealedEnvelope = encryptMessage(
      this.identity,
      session,
      encodePayload(payload),
    );
    await this.options.relay.send(envelope);
  }

  /** Send a text message. Returns the local record immediately. */
  async sendText(
    peerAddress: string,
    body: string,
    options: { expiresInSeconds?: number } = {},
  ): Promise<Message> {
    const message: Message = {
      id: toHex(random(12)),
      conversationAddress: peerAddress,
      direction: 'outgoing',
      body,
      timestamp: this.now(),
      status: 'pending',
      ...(options.expiresInSeconds
        ? { expiresAt: this.now() + options.expiresInSeconds * 1000 }
        : {}),
    };
    await this.messages.put(message.id, message);
    this.options.events?.onMessage?.(message);

    try {
      await this.sendPayload(peerAddress, {
        kind: 'text',
        messageId: message.id,
        body,
        ...(options.expiresInSeconds ? { expiresInSeconds: options.expiresInSeconds } : {}),
      });
      message.status = 'sent';
    } catch (error) {
      // A failed send stays visible as failed rather than disappearing, so the
      // user is never told something was delivered when it was not.
      message.status = 'failed';
      await this.messages.put(message.id, message);
      this.options.events?.onMessage?.(message);
      throw error;
    }

    await this.messages.put(message.id, message);
    await this.touchConversation(peerAddress, body, 0);
    this.options.events?.onMessage?.(message);
    return message;
  }

  /** Relay call signalling over the encrypted channel. */
  async sendCallPayload(peerAddress: string, payload: Payload): Promise<void> {
    await this.sendPayload(peerAddress, payload);
  }

  async sendTyping(peerAddress: string, typing: boolean): Promise<void> {
    if (!this.options.sendTypingIndicators) return;
    await this.sendPayload(peerAddress, { kind: 'typing', typing });
  }

  async sendReceipt(
    peerAddress: string,
    messageIds: string[],
    receipt: 'delivered' | 'read',
  ): Promise<void> {
    if (!this.options.sendReceipts || messageIds.length === 0) return;
    await this.sendPayload(peerAddress, { kind: 'receipt', messageIds, receipt });
  }

  // -------------------------------------------------------------------------
  // Receiving
  // -------------------------------------------------------------------------

  /**
   * Process one delivered envelope.
   *
   * Returns the id to acknowledge. A message that fails to decrypt is still
   * acknowledged, because leaving it queued would make the relay redeliver it
   * forever — but it is reported so the app can surface a decryption failure
   * rather than silently dropping traffic.
   */
  async handleDelivered(delivered: DeliveredMessage): Promise<{ id: string; ok: boolean }> {
    try {
      const envelope = decodeEnvelope(delivered.envelope);
      const result = decryptEnvelope({
        self: this.identity,
        envelope,
        lookupSession: (address) => this.sessions.get(address),
        preKeys: this.preKeys,
        pinnedIdentityKey: (address) => this.pinnedKeyCache.get(address),
      });

      const peerAddress = addressOf(result.senderIdentity);
      this.sessions.set(peerAddress, result.session);
      // Record the sender before handling the payload: whoever writes to us
      // first must still be verifiable, which needs their identity on file.
      await this.rememberPeer(peerAddress, result.senderIdentity);
      await this.onPayload(peerAddress, decodePayload(result.plaintext));
      return { id: delivered.id, ok: true };
    } catch (error) {
      if (error instanceof IdentityChangedError) {
        this.options.events?.onIdentityChanged?.(error.presentedFingerprint);
      }
      return { id: delivered.id, ok: false };
    }
  }

  /** Pinned keys, kept in memory for the synchronous callback the core needs. */
  private readonly pinnedKeyCache = new Map<string, Uint8Array>();

  private async onPayload(peerAddress: string, payload: Payload): Promise<void> {
    switch (payload.kind) {
      case 'text': {
        const message: Message = {
          // Keyed by the sender's id so our receipt names an id they know.
          id: payload.messageId,
          conversationAddress: peerAddress,
          direction: 'incoming',
          body: payload.body,
          timestamp: this.now(),
          status: 'delivered',
          ...(payload.expiresInSeconds
            ? { expiresAt: this.now() + payload.expiresInSeconds * 1000 }
            : {}),
        };
        await this.messages.put(message.id, message);
        await this.touchConversation(peerAddress, payload.body, 1);
        this.options.events?.onMessage?.(message);
        await this.sendReceipt(peerAddress, [message.id], 'delivered');
        return;
      }
      case 'receipt': {
        for (const id of payload.messageIds) {
          const message = await this.messages.get(id);
          if (!message || message.direction !== 'outgoing') continue;
          message.status = payload.receipt;
          await this.messages.put(id, message);
          this.options.events?.onMessage?.(message);
        }
        return;
      }
      case 'typing': {
        this.options.events?.onTyping?.(peerAddress, payload.typing);
        return;
      }
      case 'call-offer':
      case 'call-answer':
      case 'call-ice':
      case 'call-hangup': {
        // Call signalling is handled by the call manager, which the app wires
        // to this event. It rides the encrypted channel so the relay sees no
        // SDP and therefore no IP addresses or call metadata.
        this.options.events?.onCallPayload?.(peerAddress, payload);
        return;
      }
      default: {
        // Unknown kinds are ignored rather than fatal, so a newer peer version
        // adding a payload type does not break this client.
        return;
      }
    }
  }

  /** Fetch and process everything queued, then acknowledge. */
  async sync(): Promise<{ processed: number; failed: number }> {
    const queued = await this.options.relay.fetchMessages();
    const acknowledgeable: string[] = [];
    let failed = 0;

    for (const delivered of queued) {
      const result = await this.handleDelivered(delivered);
      acknowledgeable.push(result.id);
      if (!result.ok) failed += 1;
    }

    await this.options.relay.acknowledge(acknowledgeable);
    await this.replenishPreKeysIfNeeded();
    return { processed: queued.length, failed };
  }

  /**
   * Top up one-time prekeys.
   *
   * If the relay runs out, new conversations lose one forward-secrecy term, so
   * this runs on every sync rather than on a timer.
   */
  async replenishPreKeysIfNeeded(): Promise<boolean> {
    let count: { oneTimePreKeys: number; oneTimeKemPreKeys: number };
    try {
      count = await this.options.relay.preKeyCount();
    } catch {
      return false;
    }
    if (
      count.oneTimePreKeys >= PREKEY_LOW_WATER &&
      count.oneTimeKemPreKeys >= PREKEY_LOW_WATER
    ) {
      return false;
    }
    const fresh = this.preKeys.replenishOneTimePreKeys(100);
    await this.options.relay.uploadPreKeys(fresh);
    return true;
  }

  // -------------------------------------------------------------------------
  // Contacts and verification
  // -------------------------------------------------------------------------

  async listContacts(): Promise<Contact[]> {
    return (await this.contacts.all()).map((row) => row.value);
  }

  async getContact(address: string): Promise<Contact | undefined> {
    return this.contacts.get(address);
  }

  /**
   * The peer's public identity, as recorded for this conversation.
   *
   * The call layer needs this to derive media keys bound to both identities.
   * Returning our own identity instead would make both ends derive different
   * keys and every call would fail its SAS comparison.
   */
  async peerIdentity(address: string): Promise<PublicIdentity | undefined> {
    const stored = await this.sessionMeta.get(address);
    if (!stored) return undefined;
    return {
      signingPublicKey: fromBase64Url(stored.peerIdentity.signingPublicKey),
      exchangePublicKey: fromBase64Url(stored.peerIdentity.exchangePublicKey),
      exchangeKeySignature: fromBase64Url(stored.peerIdentity.exchangeKeySignature),
    };
  }

  /** The 60-digit number both users compare out-of-band. */
  async safetyNumberWith(address: string): Promise<string | undefined> {
    const stored = await this.sessionMeta.get(address);
    if (!stored) return undefined;
    return safetyNumber(publicIdentityOf(this.identity), {
      signingPublicKey: fromBase64Url(stored.peerIdentity.signingPublicKey),
      exchangePublicKey: fromBase64Url(stored.peerIdentity.exchangePublicKey),
      exchangeKeySignature: fromBase64Url(stored.peerIdentity.exchangeKeySignature),
    });
  }

  /**
   * Record that the user verified a contact out-of-band.
   *
   * Only call this after the user confirms the safety numbers matched. From
   * then on the key is pinned, and a change is a hard error rather than a
   * silent re-key.
   */
  async markVerified(address: string): Promise<void> {
    const contact = await this.contacts.get(address);
    if (!contact) throw new Error(`no contact for ${address}`);
    contact.verification = 'verified';
    delete contact.identityChangedAt;
    await this.contacts.put(address, contact);
    this.pinnedKeyCache.set(address, fromBase64Url(contact.identityKey));
    this.options.events?.onContactChanged?.(contact);
  }

  /** Accept a changed identity key, e.g. after the peer reinstalled. */
  async acceptIdentityChange(address: string): Promise<void> {
    const contact = await this.contacts.get(address);
    if (!contact) return;
    // Drop the stale session and the pin, so the next send re-handshakes
    // against the new key — and the contact returns to "unverified", because
    // the new key has not been checked by a human.
    this.sessions.delete(address);
    this.pinnedKeyCache.delete(address);
    await this.sessionMeta.delete(address);
    const bundle = await this.options.relay.fetchBundle(address);
    contact.identityKey = toBase64Url(bundle.identity.signingPublicKey);
    contact.verification = 'unverified';
    await this.contacts.put(address, contact);
    this.options.events?.onContactChanged?.(contact);
  }

  async renameContact(address: string, displayName: string): Promise<void> {
    const contact = await this.contacts.get(address);
    if (!contact) return;
    contact.displayName = displayName;
    await this.contacts.put(address, contact);
    this.options.events?.onContactChanged?.(contact);
  }

  /** Restore pins into memory after unlock. */
  async loadPins(): Promise<void> {
    for (const { value } of await this.contacts.all()) {
      if (value.verification === 'verified') {
        this.pinnedKeyCache.set(value.address, fromBase64Url(value.identityKey));
      }
    }
  }

  // -------------------------------------------------------------------------
  // Conversations and history
  // -------------------------------------------------------------------------

  private async touchConversation(
    address: string,
    preview: string,
    unreadDelta: number,
  ): Promise<void> {
    const existing = await this.conversations.get(address);
    const conversation: Conversation = existing ?? {
      address,
      lastMessageAt: 0,
      lastMessagePreview: '',
      unreadCount: 0,
      disappearAfterSeconds: 0,
    };
    conversation.lastMessageAt = this.now();
    conversation.lastMessagePreview = preview.slice(0, 120);
    conversation.unreadCount = Math.max(0, conversation.unreadCount + unreadDelta);
    await this.conversations.put(address, conversation);
    this.options.events?.onConversationChanged?.(conversation);
  }

  async listConversations(): Promise<Conversation[]> {
    const rows = await this.conversations.all();
    return rows.map((row) => row.value).sort((a, b) => b.lastMessageAt - a.lastMessageAt);
  }

  /** Message history for a conversation, oldest first, expired entries removed. */
  async history(address: string): Promise<Message[]> {
    const rows = await this.messages.all();
    const now = this.now();
    const live: Message[] = [];
    for (const { id, value } of rows) {
      if (value.conversationAddress !== address) continue;
      if (value.expiresAt !== undefined && value.expiresAt <= now) {
        // Disappearing messages are deleted on read, not merely hidden.
        await this.messages.delete(id);
        continue;
      }
      live.push(value);
    }
    return live.sort((a, b) => a.timestamp - b.timestamp);
  }

  async markRead(address: string): Promise<void> {
    const conversation = await this.conversations.get(address);
    if (!conversation) return;
    conversation.unreadCount = 0;
    await this.conversations.put(address, conversation);
    this.options.events?.onConversationChanged?.(conversation);
  }

  /** Delete a conversation's history and its session. Irreversible. */
  async deleteConversation(address: string): Promise<void> {
    for (const { id, value } of await this.messages.all()) {
      if (value.conversationAddress === address) await this.messages.delete(id);
    }
    await this.conversations.delete(address);
    await this.sessionMeta.delete(address);
    this.sessions.delete(address);
  }

  /** Sweep expired disappearing messages. Called on a timer by the app. */
  async purgeExpired(): Promise<number> {
    const now = this.now();
    let removed = 0;
    for (const { id, value } of await this.messages.all()) {
      if (value.expiresAt !== undefined && value.expiresAt <= now) {
        await this.messages.delete(id);
        removed += 1;
      }
    }
    return removed;
  }
}

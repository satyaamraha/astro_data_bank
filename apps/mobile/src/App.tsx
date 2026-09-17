/**
 * App shell: navigation and wiring.
 *
 * Deliberately a single stateful component with an explicit screen union rather
 * than a navigation library. The app has six screens and one security-relevant
 * invariant — the vault must be unlocked before any screen that can read
 * messages renders — and expressing that as a plain discriminated union makes
 * it checkable by the compiler instead of by convention.
 */

// Must come first: installs the CSPRNG before any key is generated.
import './platform/random.js';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ActivityIndicator, StyleSheet, Text, View } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import {
  createVault,
  decodeWrappedVault,
  encodeWrappedVault,
  lockVault,
  unlockVault,
  utf8,
  type PublicIdentity,
  type Vault,
} from '@veil/crypto';
import { assertSecureRandomAvailable } from './platform/random.js';
import { KeystoreSecretStore } from './platform/secureStore.js';
import { SqliteDatabase } from './platform/database.js';
import { FetchTransport, WebSocketTransport } from './platform/transport.js';
import { WebRtcMediaEngine, type IceConfiguration } from './platform/webrtc.js';
import { Messenger } from './core/messenger.js';
import { RelayClient } from './core/relayClient.js';
import { CallManager } from './core/callManager.js';
import type { CallInfo, Contact, Conversation, Message, Payload } from './core/types.js';
import { OnboardingScreen } from './screens/OnboardingScreen.js';
import { ConversationsScreen, type ConversationRow } from './screens/ConversationsScreen.js';
import { ChatScreen } from './screens/ChatScreen.js';
import { VerifyScreen } from './screens/VerifyScreen.js';
import { CallScreen } from './screens/CallScreen.js';
import { theme } from './ui/theme.js';

const VAULT_KEY = 'veil.vault.wrapper';

/**
 * Deployment configuration.
 *
 * The relay URL and ICE servers are the two places where a user's traffic meets
 * infrastructure someone operates. They are configuration, not constants, so a
 * user or organisation can point the app at their own.
 */
export interface AppConfig {
  readonly relayHttpUrl: string;
  readonly relaySocketUrl: string;
  readonly ice: IceConfiguration;
}

type Route =
  | { readonly name: 'loading' }
  | { readonly name: 'onboarding'; readonly mode: 'create' | 'unlock' }
  | { readonly name: 'conversations' }
  | { readonly name: 'chat'; readonly address: string }
  | { readonly name: 'verify'; readonly address: string }
  | { readonly name: 'call' };

export function App({ config }: { config: AppConfig }) {
  const [route, setRoute] = useState<Route>({ name: 'loading' });
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [contacts, setContacts] = useState<Map<string, Contact>>(new Map());
  const [messages, setMessages] = useState<Message[]>([]);
  const [call, setCall] = useState<CallInfo | undefined>();
  const [muted, setMuted] = useState(false);
  const [myAddress, setMyAddress] = useState('');

  const messengerRef = useRef<Messenger | undefined>(undefined);
  const callManagerRef = useRef<CallManager | undefined>(undefined);
  const vaultRef = useRef<Vault | undefined>(undefined);
  const socketRef = useRef<WebSocketTransport | undefined>(undefined);
  /** Fills the call layer's identity cache for a peer before signalling runs. */
  const warmPeerIdentityRef = useRef<(peerAddress: string) => Promise<void>>(
    async () => {},
  );
  const warmPeerIdentity = useCallback(
    (peerAddress: string) => warmPeerIdentityRef.current(peerAddress),
    [],
  );

  const refreshLists = useCallback(async () => {
    const messenger = messengerRef.current;
    if (!messenger) return;
    setConversations(await messenger.listConversations());
    const list = await messenger.listContacts();
    setContacts(new Map(list.map((contact) => [contact.address, contact])));
  }, []);

  // -------------------------------------------------------------------------
  // Start-up: decide between onboarding and unlock
  // -------------------------------------------------------------------------

  useEffect(() => {
    void (async () => {
      try {
        assertSecureRandomAvailable();
        const secrets = new KeystoreSecretStore();
        // A stored wrapper means this device already has an identity, so ask
        // for the existing passphrase rather than offering to create a new one
        // (which would orphan the old history).
        const existing = await secrets.get(VAULT_KEY);
        setRoute({ name: 'onboarding', mode: existing ? 'unlock' : 'create' });
      } catch (caught) {
        setError((caught as Error).message);
      }
    })();
  }, []);

  /**
   * Create or unlock the vault, then bring the messenger online.
   *
   * Argon2id runs here, which is why this is the one place with a spinner: on a
   * phone it takes a few hundred milliseconds by design, and that cost is what
   * makes a stolen database expensive to attack.
   */
  const start = useCallback(
    async (passphrase: string) => {
      setBusy(true);
      setError(undefined);
      try {
        const secrets = new KeystoreSecretStore();
        const database = await SqliteDatabase.open();

        const storedWrapper = await secrets.get(VAULT_KEY);
        let vault: Vault;
        if (storedWrapper) {
          vault = unlockVault(
            utf8.encode(passphrase),
            decodeWrappedVault(Buffer.from(storedWrapper, 'base64')),
          );
        } else {
          const created = createVault(utf8.encode(passphrase));
          vault = created.vault;
          await secrets.set(
            VAULT_KEY,
            Buffer.from(encodeWrappedVault(created.wrapped)).toString('base64'),
          );
        }
        vaultRef.current = vault;

        const relayClient = new RelayClient(new FetchTransport(config.relayHttpUrl));
        const messenger = new Messenger({
          relay: relayClient,
          secrets,
          database,
          vault,
          events: {
            onMessage: () => void refreshLists(),
            onConversationChanged: () => void refreshLists(),
            onContactChanged: () => void refreshLists(),
            onIdentityChanged: () => void refreshLists(),
            onCallPayload: (peerAddress, payload) => {
              void (async () => {
                await warmPeerIdentity(peerAddress);
                await callManagerRef.current?.handleSignal(peerAddress, payload);
              })();
            },
          },
        });
        messengerRef.current = messenger;

        const { address } = await messenger.initialise();
        await messenger.loadPins();
        setMyAddress(address);

        // Call key derivation needs the peer's real identity, so identities are
        // cached synchronously here: deriveCallKeys cannot await.
        const peerIdentities = new Map<string, PublicIdentity>();
        warmPeerIdentityRef.current = async (peerAddress: string) => {
          const identity = await messenger.peerIdentity(peerAddress);
          if (identity) peerIdentities.set(peerAddress, identity);
        };

        callManagerRef.current = new CallManager({
          selfIdentity: messenger.myIdentity,
          resolvePeerIdentity: (peerAddress) => peerIdentities.get(peerAddress),
          createMediaEngine: () => new WebRtcMediaEngine(config.ice),
          sendSignal: (peerAddress, payload: Payload) =>
            messenger.sendCallPayload(peerAddress, payload),
          events: {
            onStateChange: (info) => {
              setCall(info);
              if (info.state !== 'ended') setRoute({ name: 'call' });
            },
            onSasAvailable: setCall,
            onError: (caught) => setError(caught.message),
          },
        });

        // Realtime delivery, so messages do not sit in the relay's queue.
        const socket = new WebSocketTransport(
          config.relaySocketUrl,
          () => relayClient.currentToken,
        );
        socketRef.current = socket;
        await socket.connect({
          onMessage: (serverMessage) => {
            if (serverMessage.type === 'deliver') {
              void messenger.handleDelivered(serverMessage.message).then((result) => {
                socket.send({ type: 'acknowledge', ids: [result.id] });
                void refreshLists();
              });
            }
          },
          onClose: () => {},
        });

        await messenger.sync();
        await refreshLists();
        setRoute({ name: 'conversations' });
      } catch (caught) {
        setError((caught as Error).message);
      } finally {
        setBusy(false);
      }
    },
    [config, refreshLists],
  );

  // Sweep expired disappearing messages while the app is open.
  useEffect(() => {
    const timer = setInterval(() => {
      void messengerRef.current?.purgeExpired().then((removed) => {
        if (removed > 0) void refreshLists();
      });
    }, 30_000);
    return () => clearInterval(timer);
  }, [refreshLists]);

  // Wipe the data key from memory when the app shuts down.
  useEffect(
    () => () => {
      socketRef.current?.close();
      if (vaultRef.current) lockVault(vaultRef.current);
    },
    [],
  );

  const openChat = useCallback(async (address: string) => {
    const messenger = messengerRef.current;
    if (!messenger) return;
    setMessages(await messenger.history(address));
    await messenger.markRead(address);
    setRoute({ name: 'chat', address });
  }, []);

  const rows: ConversationRow[] = useMemo(
    () =>
      conversations.map((conversation) => {
        const contact = contacts.get(conversation.address);
        return contact ? { conversation, contact } : { conversation };
      }),
    [conversations, contacts],
  );

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  if (route.name === 'loading') {
    return (
      <View style={styles.centered}>
        <StatusBar style="light" />
        <ActivityIndicator color={theme.colors.accent} />
      </View>
    );
  }

  if (route.name === 'onboarding') {
    return (
      <>
        <StatusBar style="light" />
        <OnboardingScreen
          mode={route.mode}
          onSubmit={(passphrase: string) => void start(passphrase)}
          busy={busy}
          {...(error !== undefined ? { error } : {})}
        />
      </>
    );
  }

  if (route.name === 'call' && call) {
    const peer = contacts.get(call.peerAddress);
    return (
      <>
        <StatusBar style="light" />
        <CallScreen
          call={call}
          peerName={peer?.displayName ?? call.peerAddress.slice(0, 10)}
          muted={muted}
          onAnswer={() => void callManagerRef.current?.answerCall()}
          onHangUp={() => {
            void callManagerRef.current?.endCall('hung up');
            setRoute({ name: 'conversations' });
          }}
          onToggleMute={() => {
            const next = !muted;
            setMuted(next);
            callManagerRef.current?.setMuted(next);
          }}
          onConfirmSas={() => callManagerRef.current?.confirmSas()}
        />
      </>
    );
  }

  if (route.name === 'chat') {
    const contact = contacts.get(route.address);
    if (!contact) {
      setRoute({ name: 'conversations' });
      return null;
    }
    const conversation = conversations.find((c) => c.address === route.address);
    return (
      <>
        <StatusBar style="light" />
        <ChatScreen
          contact={contact}
          messages={messages}
          disappearAfterSeconds={conversation?.disappearAfterSeconds ?? 0}
          onSend={(body) => {
            void (async () => {
              const messenger = messengerRef.current;
              if (!messenger) return;
              try {
                await messenger.sendText(route.address, body, {
                  ...(conversation && conversation.disappearAfterSeconds > 0
                    ? { expiresInSeconds: conversation.disappearAfterSeconds }
                    : {}),
                });
              } catch (caught) {
                setError((caught as Error).message);
              }
              setMessages(await messenger.history(route.address));
              await refreshLists();
            })();
          }}
          onBack={() => setRoute({ name: 'conversations' })}
          onVerify={() => setRoute({ name: 'verify', address: route.address })}
          onCall={() => {
            void (async () => {
              await warmPeerIdentity(route.address);
              await callManagerRef.current?.placeCall(route.address);
            })();
          }}
          onChangeDisappear={(seconds) => {
            void (async () => {
              if (!conversation) return;
              conversation.disappearAfterSeconds = seconds;
              await refreshLists();
            })();
          }}
        />
      </>
    );
  }

  if (route.name === 'verify') {
    const contact = contacts.get(route.address);
    if (!contact) {
      setRoute({ name: 'conversations' });
      return null;
    }
    return (
      <>
        <StatusBar style="light" />
        <VerifyContainer
          contact={contact}
          loadSafetyNumber={(address) =>
            messengerRef.current?.safetyNumberWith(address) ?? Promise.resolve(undefined)
          }
          onBack={() => setRoute({ name: 'chat', address: route.address })}
          onMarkVerified={() => {
            void messengerRef.current?.markVerified(route.address).then(refreshLists);
          }}
          onAcceptChange={() => {
            void messengerRef.current?.acceptIdentityChange(route.address).then(refreshLists);
          }}
        />
      </>
    );
  }

  return (
    <>
      <StatusBar style="light" />
      <ConversationsScreen
        rows={rows}
        myAddress={myAddress}
        onOpen={(address) => void openChat(address)}
        onNewConversation={() => setRoute({ name: 'conversations' })}
        onShowMyCode={() => setRoute({ name: 'conversations' })}
      />
      {error !== undefined ? (
        <View style={styles.errorBar}>
          <Text style={styles.errorText}>{error}</Text>
        </View>
      ) : null}
    </>
  );
}

/** Loads the safety number asynchronously, then renders the verify screen. */
function VerifyContainer({
  contact,
  loadSafetyNumber,
  onBack,
  onMarkVerified,
  onAcceptChange,
}: {
  contact: Contact;
  loadSafetyNumber: (address: string) => Promise<string | undefined>;
  onBack: () => void;
  onMarkVerified: () => void;
  onAcceptChange: () => void;
}) {
  const [safetyNumber, setSafetyNumber] = useState<string | undefined>();

  useEffect(() => {
    let cancelled = false;
    setSafetyNumber(undefined);
    void loadSafetyNumber(contact.address).then((value) => {
      if (!cancelled) setSafetyNumber(value);
    });
    return () => {
      cancelled = true;
    };
  }, [contact.address, loadSafetyNumber]);

  return (
    <VerifyScreen
      contact={contact}
      {...(safetyNumber !== undefined ? { safetyNumber } : {})}
      onBack={onBack}
      onMarkVerified={onMarkVerified}
      onScanCode={onBack}
      onAcceptChange={onAcceptChange}
    />
  );
}

const styles = StyleSheet.create({
  centered: {
    alignItems: 'center',
    backgroundColor: theme.colors.background,
    flex: 1,
    justifyContent: 'center',
  },
  errorBar: {
    backgroundColor: theme.colors.danger,
    padding: theme.spacing(1.5),
  },
  errorText: {
    color: theme.colors.text,
    fontSize: theme.font.small,
  },
});

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
import { ActivityIndicator, Share, StyleSheet, Text, View } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import {
  createVault,
  decodeWrappedVault,
  destroySession,
  encodeWrappedVault,
  lockVault,
  unlockVault,
  utf8,
  type PublicIdentity,
  type Vault,
} from '@veil/crypto';
import { assertSecureRandomAvailable } from './platform/random.js';
import {
  KeystoreSecretStore,
  readEitherMode,
  type KeystoreMode,
} from './platform/secureStore.js';
import { SqliteDatabase } from './platform/database.js';
import { FetchTransport, WebSocketTransport } from './platform/transport.js';
import { preventScreenCapture, startLifecycleLock } from './platform/screenSecurity.js';
import { WebRtcMediaEngine, type IceConfiguration } from './platform/webrtc.js';
import { Messenger } from './core/messenger.js';
import {
  canAttempt,
  formatLockout,
  lockoutRemainingMs,
  parseAttemptState,
  recordFailure,
  recordSuccess,
  serialiseAttemptState,
} from './core/unlockPolicy.js';
import { RelayClient } from './core/relayClient.js';
import { CallManager } from './core/callManager.js';
import type { CallInfo, Contact, Conversation, Message, Payload } from './core/types.js';
import { OnboardingScreen } from './screens/OnboardingScreen.js';
import { PairScreen } from './screens/PairScreen.js';
import { ConversationsScreen, type ConversationRow } from './screens/ConversationsScreen.js';
import { ChatScreen } from './screens/ChatScreen.js';
import { VerifyScreen } from './screens/VerifyScreen.js';
import { CallScreen } from './screens/CallScreen.js';
import { MyCodeScreen } from './screens/MyCodeScreen.js';
import { NewConversationScreen } from './screens/NewConversationScreen.js';
import { theme } from './ui/theme.js';

const VAULT_KEY = 'veil.vault.wrapper';
/**
 * Failed-unlock counter.
 *
 * Deliberately in the keystore rather than the encrypted database: if it lived
 * beside the data, an attacker could copy the database, burn attempts, restore
 * the copy and reset the throttle. In the keystore, clearing app data destroys
 * the vault too, which is no help to them.
 */
const ATTEMPTS_KEY = 'veil.unlock.attempts';

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
  | { readonly name: 'pair' }
  | { readonly name: 'my-code' }
  | { readonly name: 'new-conversation' }
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
  /** False when the platform refused to block screenshots; the UI must say so. */
  const [screenProtected, setScreenProtected] = useState(true);
  /** Which protection the keystore is actually giving us, not what we hoped for. */
  const [keystoreMode, setKeystoreMode] = useState<KeystoreMode>('authenticated');

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
        // Read through both keystore modes: an install predating
        // authentication-bound storage has entries the stronger options cannot
        // open, and treating that as "no identity" would offer to create a new
        // one and orphan the user's history.
        const existing = await readEitherMode(VAULT_KEY);
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
        const secrets = await KeystoreSecretStore.open();
        setKeystoreMode(secrets.mode);
        const database = await SqliteDatabase.open();

        const storedWrapper = await secrets.get(VAULT_KEY);

        // Argon2id makes each guess cost seconds, which defeats a fast offline
        // attack. It does not stop someone with the phone grinding attempts by
        // hand, so throttle those too.
        let attempts = parseAttemptState(await secrets.get(ATTEMPTS_KEY), Date.now());
        if (storedWrapper && !canAttempt(attempts, Date.now())) {
          const wait = formatLockout(lockoutRemainingMs(attempts, Date.now()));
          setError(`Too many incorrect attempts. Try again in ${wait}.`);
          return;
        }

        let vault: Vault;
        if (storedWrapper) {
          try {
            vault = unlockVault(
              utf8.encode(passphrase),
              decodeWrappedVault(Buffer.from(storedWrapper, 'base64')),
            );
          } catch (wrongPassphrase) {
            attempts = recordFailure(attempts, Date.now());
            await secrets.set(ATTEMPTS_KEY, serialiseAttemptState(attempts));
            const remaining = lockoutRemainingMs(attempts, Date.now());
            setError(
              remaining > 0
                ? `Incorrect passphrase. Try again in ${formatLockout(remaining)}.`
                : 'Incorrect passphrase.',
            );
            void wrongPassphrase;
            return;
          }
          await secrets.set(ATTEMPTS_KEY, serialiseAttemptState(recordSuccess()));
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
          // Explicit, though it is also the default: this app talks to exactly
          // one paired peer and discards everything else.
          mode: 'paired',
          events: {
            onMessage: () => void refreshLists(),
            onConversationChanged: () => void refreshLists(),
            onContactChanged: () => void refreshLists(),
            onIdentityChanged: () => void refreshLists(),
            onBlocked: (reason, detail) => {
              // A stranger being turned away is routine and stays quiet. A key
              // change on the paired peer is either a reinstall or an
              // interception attempt, and must be seen.
              if (reason === 'key-changed') setError(detail);
            },
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
        // A device with no pairing has nobody to talk to yet, so pairing is
        // the only sensible destination.
        setRoute(
          messenger.pairedPeer() === undefined
            ? { name: 'pair' }
            : { name: 'conversations' },
        );
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

  // Surface reduced protection rather than assuming the strong path worked.
  const platformWarnings = [
    screenProtected
      ? undefined
      : 'This device would not block screenshots, so other apps may be able to ' +
        'capture your conversations.',
    keystoreMode === 'authenticated'
      ? undefined
      : 'No device passcode is set, so your identity key is not protected by ' +
        'screen lock. Set a passcode in Android settings.',
  ].filter((warning): warning is string => warning !== undefined);
  const screenWarning = platformWarnings.length > 0 ? platformWarnings.join(' ') : undefined;

  /**
   * Wipe the in-memory data key and drop back to the unlock screen.
   *
   * Called on background timeout and on teardown. Sessions are dropped too:
   * their ratchet state is not persisted, so keeping them after a lock would
   * leave key material in memory for no benefit.
   */
  const lock = useCallback(() => {
    socketRef.current?.close();
    socketRef.current = undefined;
    const messenger = messengerRef.current;
    if (messenger) {
      for (const session of messenger.liveSessions()) destroySession(session);
    }
    messengerRef.current = undefined;
    callManagerRef.current = undefined;
    if (vaultRef.current) {
      lockVault(vaultRef.current);
      vaultRef.current = undefined;
    }
    setConversations([]);
    setContacts(new Map());
    setMessages([]);
    setCall(undefined);
    setError(undefined);
    setRoute({ name: 'onboarding', mode: 'unlock' });
  }, []);

  // Block screenshots and the recents thumbnail as soon as the app starts,
  // before any message can be on screen.
  useEffect(() => {
    void preventScreenCapture().then(setScreenProtected);
  }, []);

  // Lock the vault once the app has been backgrounded past the grace period.
  useEffect(() => startLifecycleLock({ onLock: lock }), [lock]);

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
            void messengerRef.current
              ?.setDisappearTimer(route.address, seconds)
              .then(refreshLists);
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

  if (route.name === 'pair') {
    return (
      <>
        <StatusBar style="light" />
        <PairScreen
          myCode={messengerRef.current?.verificationCode() ?? ''}
          busy={busy}
          {...(error !== undefined ? { error } : {})}
          onShareCode={() => {
            const code = messengerRef.current?.verificationCode();
            if (code !== undefined) void Share.share({ message: code });
          }}
          onPair={(theirCode, displayName) => {
            void (async () => {
              const messenger = messengerRef.current;
              if (!messenger) return;
              setBusy(true);
              setError(undefined);
              try {
                const peer = await messenger.pairWithCode(theirCode, displayName);
                await warmPeerIdentity(peer.peerAddress);
                await refreshLists();
                setRoute({ name: 'conversations' });
              } catch (caught) {
                setError((caught as Error).message);
              } finally {
                setBusy(false);
              }
            })();
          }}
        />
      </>
    );
  }

  if (route.name === 'my-code') {
    return (
      <>
        <StatusBar style="light" />
        <MyCodeScreen
          address={myAddress}
          code={messengerRef.current?.verificationCode() ?? ''}
          onBack={() => setRoute({ name: 'conversations' })}
          onShare={() => {
            const code = messengerRef.current?.verificationCode();
            if (code !== undefined) void Share.share({ message: code });
          }}
        />
      </>
    );
  }

  if (route.name === 'new-conversation') {
    return (
      <>
        <StatusBar style="light" />
        <NewConversationScreen
          busy={busy}
          {...(error !== undefined ? { error } : {})}
          onBack={() => setRoute({ name: 'conversations' })}
          onStart={(input, kind) => {
            void (async () => {
              const messenger = messengerRef.current;
              if (!messenger) return;
              setBusy(true);
              setError(undefined);
              try {
                const address =
                  kind === 'code'
                    ? await messenger.addContactFromCode(input)
                    : (await messenger.startConversation(input), input);
                await refreshLists();
                await openChat(address);
              } catch (caught) {
                setError((caught as Error).message);
              } finally {
                setBusy(false);
              }
            })();
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
        onNewConversation={() => {
          // In paired mode there is exactly one correspondent, so this opens
          // the pairing screen rather than a contact picker.
          setError(undefined);
          setRoute(
            messengerRef.current?.pairedPeer() === undefined
              ? { name: 'pair' }
              : { name: 'my-code' },
          );
        }}
        onShowMyCode={() => setRoute({ name: 'my-code' })}
      />
      {screenWarning !== undefined ? (
        <View style={styles.warningBar}>
          <Text style={styles.errorText}>{screenWarning}</Text>
        </View>
      ) : null}
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
  warningBar: {
    backgroundColor: theme.colors.unverified,
    padding: theme.spacing(1.5),
  },
  errorText: {
    color: theme.colors.text,
    fontSize: theme.font.small,
  },
});

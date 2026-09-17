/**
 * @veil/crypto — the Veil cryptographic core.
 *
 * Platform-independent and dependency-light on purpose: it runs unchanged in
 * Node (for tests and the relay's own key handling) and in React Native via
 * Hermes, with no native modules to audit separately.
 *
 * The security properties this package is responsible for:
 *
 *  | Property                        | Mechanism                              |
 *  |---------------------------------|----------------------------------------|
 *  | Confidentiality / integrity     | XChaCha20-Poly1305 under ratchet keys  |
 *  | Mutual authentication           | Ed25519 identity keys, bound into AD   |
 *  | Forward secrecy                 | Symmetric ratchet, keys wiped on use   |
 *  | Post-compromise security        | DH ratchet on every direction change   |
 *  | Post-quantum confidentiality    | ML-KEM-1024 mixed into the handshake   |
 *  | Sender anonymity from operator  | Sealed sender envelopes                |
 *  | Length privacy                  | Bucketed padding                       |
 *  | Replay resistance               | Consumed message keys, SFrame window   |
 *  | Media confidentiality vs relay  | SFrame inside DTLS-SRTP                |
 *  | MITM detectability by humans    | Safety numbers, call SAS               |
 *  | At-rest confidentiality         | Argon2id-wrapped vault                 |
 *
 * What it does NOT provide, stated plainly so callers do not assume it:
 *  - Recipient anonymity. The relay must learn a recipient address to route.
 *  - Traffic-analysis resistance. Timing and volume still leak.
 *  - Protection of a running, unlocked app on a compromised OS.
 */

export {
  VeilCryptoError,
  MalformedInputError,
  AuthenticationError,
  UntrustedBundleError,
  IdentityChangedError,
  SessionStateError,
  ReplayError,
  VaultLockedError,
} from './errors.js';

export {
  AEAD_KEY_LEN,
  AEAD_NONCE_LEN,
  AEAD_TAG_LEN,
  MLKEM_CIPHERTEXT_LEN,
  MLKEM_PUBLIC_LEN,
  SHARED_SECRET_LEN,
  X25519_PUBLIC_LEN,
  constantTimeEqual,
  random,
  sign,
  signingPublicKey,
  verify,
  wipe,
  type KeyPair,
} from './primitives.js';

export { Reader, Writer, concat, fromHex, toBase32, toHex, utf8 } from './wire.js';

export {
  addressMatches,
  addressOf,
  createIdentity,
  createOneTimeKemPreKeys,
  createOneTimePreKeys,
  createSignedKemPreKey,
  createSignedPreKey,
  publicIdentityOf,
  restoreIdentity,
  verifyIdentityBinding,
  verifyPreKeyBundle,
  type OneTimeKemPreKey,
  type OneTimePreKey,
  type PreKeyBundle,
  type PreKeyStoreState,
  type PrivateIdentity,
  type PublicIdentity,
  type SignedKemPreKey,
  type SignedPreKey,
} from './identity.js';

export {
  associatedData,
  initiateHandshake,
  respondToHandshake,
  type HandshakeKeyIds,
  type InitiatorHandshake,
  type ResponderHandshakeInput,
} from './pqxdh.js';

export {
  MAX_SKIPPED_KEYS,
  MAX_SKIP_PER_CHAIN,
  destroyRatchet,
  initialiseInitiator,
  initialiseResponder,
  ratchetDecrypt,
  ratchetEncrypt,
  type RatchetHeader,
  type RatchetMessage,
  type RatchetState,
} from './doubleRatchet.js';

export {
  PAYLOAD_PREKEY,
  PAYLOAD_RATCHET,
  openEnvelope,
  sealEnvelope,
  type OpenedEnvelope,
  type SealedEnvelope,
} from './envelope.js';

export { bucketSize, pad, unpad } from './padding.js';

export {
  decryptEnvelope,
  destroySession,
  encryptMessage,
  startSession,
  type DecryptedMessage,
  type PreKeyResolver,
  type PreKeyPreamble,
  type Session,
} from './session.js';

export {
  InMemoryPreKeyStore,
  ONE_TIME_PREKEY_LOW_WATER,
  ONE_TIME_PREKEY_TARGET,
  SIGNED_PREKEY_GENERATIONS,
  type PublishedPreKeys,
} from './preKeyStore.js';

export {
  FINGERPRINT_ITERATIONS,
  formatSafetyNumber,
  identityFingerprint,
  parseVerificationQrPayload,
  safetyNumber,
  safetyNumbersMatch,
  verificationQrPayload,
} from './safetyNumber.js';

export {
  SAS_WORDS,
  createCallSecrets,
  deriveCallKeys,
  sasNumeric,
  sasWords,
  type CallKeyMaterial,
  type CallRole,
  type CallSecrets,
} from './callKeys.js';

export {
  MAX_FRAME_COUNTER,
  REPLAY_WINDOW,
  createReceiver,
  createSender,
  decryptFrame,
  destroyReceiver,
  destroySender,
  encryptFrame,
  type EncryptedFrame,
  type SframeReceiver,
  type SframeSender,
} from './sframe.js';

export {
  ARGON2_PROFILE,
  changePassphrase,
  createVault,
  decodeWrappedVault,
  decryptRecord,
  encodeWrappedVault,
  encryptRecord,
  lockVault,
  unlockVault,
  type Vault,
  type WrappedVault,
} from './vault.js';

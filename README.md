# Veil

A private mobile messenger: end-to-end encrypted text and voice, with a server
that is built so it cannot read what it carries, cannot tell who sent a message,
and holds no personal identifier for anyone.

> **Status: not audited.** This is a careful implementation of well-specified
> constructions with 283 tests covering its security claims. That is not the
> same as an independent audit. Do not deploy it for people whose safety depends
> on it until it has had one. See [docs/SECURITY.md](docs/SECURITY.md).

---

## What makes it private

Most "encrypted messenger" claims cover message bodies and stop there. The
harder problems are metadata, voice, and the device itself. Veil addresses all
four.

**Messages** use a Double Ratchet, so every message has its own key. Stealing
today's keys does not decrypt yesterday's traffic (forward secrecy), and an
attacker who steals your session state loses it again the moment your contact
replies (post-compromise security).

**The handshake is post-quantum hybrid.** The session secret depends on X25519
*and* ML-KEM-1024 together, so an adversary who records your traffic now and
breaks elliptic-curve cryptography later still cannot read it. Both must fall,
which is strictly stronger than trusting either alone.

**The server never learns who you talk to.** Sender identity is encrypted to the
recipient inside the envelope, with a fresh ephemeral key per message. The relay
sees a destination address and ciphertext — it cannot attribute a message to a
sender, or link two messages to one sender. Because metadata is often the more
sensitive half: "who contacted a journalist, and when" is frequently the fact
worth protecting.

**There is no phone number.** An account is a keypair, and your address is a
hash of your identity key. There is no identifier for an operator to leak, sell,
or be compelled to disclose — and no directory that can point your name at
someone else's key.

**Voice calls are encrypted end to end, not just to the relay.** WebRTC's
DTLS-SRTP terminates at whatever handles the media, which on most mobile
networks is a TURN server — so DTLS alone means the operator can listen. Veil
encrypts every audio frame *before* it enters the RTP stack, with keys that
never leave the two devices. Where a platform cannot do this, the app refuses
the call rather than downgrading silently.

**You can detect an attacker.** Encryption authenticates a key, not a person.
Veil shows a 60-digit safety number for each conversation and four spoken words
during each call; if they match, nobody is in the middle. Verification state is
visible on every conversation row, not buried in a menu.

**Paired mode is the default: one peer, established in person.** The hardest
problem in an encrypted messenger is knowing the key belongs to the person you
think, and a general messenger cannot solve it — it has to let you message
strangers. Two people can: you pair once face to face with a code carrying each
other's signed identity, nothing the relay says is trusted, and afterwards
traffic from any other account is discarded *before decryption*. A key change is
a hard stop rather than a dismissable warning, because unlike a general
messenger there is no innocent "they reinstalled and I'm not with them" case
worth tolerating. See [docs/TWO_PERSON_SETUP.md](docs/TWO_PERSON_SETUP.md).

**Adding a contact by code starts the conversation already verified.** A
verification code carries the full identity plus a signature proving the keys
belong together, so pasting one is stronger than reading digits aloud — it
compares all 256 bits instead of whatever prefix a human checks. Adding by
address only asks the server where to look, so those conversations start
unverified and the UI says so explicitly rather than treating both paths as
"add contact".

**A seized phone gives up nothing.** History is encrypted under an
Argon2id-derived key; the identity key lives in the platform keystore, bound to
device unlock and kept out of cloud backups.

**What this does not do.** End-to-end encryption means the operator and the
network cannot read your messages. It does not mean nobody ever can: plaintext
exists on both phones, so anything controlling either device reads everything,
and a recipient can always screenshot or forward. Metadata leaks too — the relay
sees recipient addresses and IPs. [docs/ASSESSMENT.md §4](docs/ASSESSMENT.md)
sets out the full boundary; it is worth reading before relying on any messenger,
including this one.

**Also, deliberately absent:** no analytics, no crash reporting, no advertising
identifiers, no read receipts or typing indicators unless you turn them on (both
leak behaviour), and no contacts, location, or camera permissions.

---

## Layout

```
packages/crypto      The cryptographic core. Platform-independent, 108 tests.
packages/protocol    Wire types shared by client and relay.
packages/relay       The store-and-forward server. 54 tests.
apps/mobile          React Native (Expo) app. 121 tests (core logic, pairing, Android build config).
  src/core           Messenger, relay client, call manager - testable in Node.
  src/platform       Keystore, SQLite, WebRTC, transports.
  src/screens        UI.
deploy/              Docker Compose relay: TLS, TURN, no logs anywhere.
docs/TWO_PERSON_SETUP.md  Runbook for the two-person configuration.
docs/SECURITY.md     Threat model, and an explicit list of what is not protected.
docs/ASSESSMENT.md   Security audit, including the defects it found and fixed.
docs/COMPARISON.md   How this differs from WhatsApp and Instagram, fairly.
docs/PROTOCOL.md     Full protocol specification.
```

Two structural rules keep the security-relevant code reviewable:

- `packages/crypto/src/primitives.ts` is the **only** file that imports a
  cryptographic library, so every algorithm choice is visible in one screen and
  a change is a single-file diff.
- Everything security-relevant in the app lives in `src/core` and is tested in
  Node, without a device. The React Native layer holds no protocol decisions.

---

## Running it

Requires Node 20 or newer.

```bash
npm install
npm run build          # build the workspace packages
npm run typecheck      # strict typecheck, all packages
npm test               # 283 tests
```

### The relay

```bash
npm run build --workspace @veil/relay
PORT=8443 node packages/relay/dist/server.js
```

Terminate TLS in front of it. The relay deliberately keeps no request logs, so
if you need health signals, export aggregate counters rather than turning on a
logger — per-request logs would reconstruct the delivery metadata the design
exists to withhold.

### The Android app

Requires the Android SDK (API 36) and JDK 17+. The native project in
`apps/mobile/android` is committed for auditability, and is regenerated from
the config plugins by `expo prebuild`.

```bash
cd apps/mobile

# Debug build on a connected device or emulator
EXPO_PUBLIC_VEIL_RELAY_HTTP=https://relay.example \
EXPO_PUBLIC_VEIL_RELAY_WS=wss://relay.example/v1/socket \
EXPO_PUBLIC_VEIL_STUN=stun:stun.example:3478 \
npx expo run:android
```

Voice calls need this development build, not Expo Go: `react-native-webrtc` is
a native module, and so is the frame-transform hook that makes call media
end-to-end encrypted.

**Release build.** Signing keys come from the environment, never the repo. The
build fails rather than falling back to a debug key:

```bash
export VEIL_KEYSTORE_PATH=/secure/path/veil-release.jks
export VEIL_KEYSTORE_PASSWORD=...
export VEIL_KEY_ALIAS=veil
export VEIL_KEY_PASSWORD=...
cd apps/mobile/android && ./gradlew assembleRelease
```

**Regenerating the native project.** All Android hardening lives in
`apps/mobile/plugins/`, so it is reapplied on every prebuild rather than being
hand-edits that vanish:

```bash
cd apps/mobile && npx expo prebuild --platform android --clean
npm test    # asserts the regenerated manifest and Gradle config are still hardened
```

Set `EXPO_PUBLIC_VEIL_RELAY_ONLY=true` to force media through TURN, which hides
each participant's IP from the other. Safe for confidentiality — the TURN server
still cannot hear the call — at the cost of latency.

### What the Android build does about platform leaks

Encryption does nothing about these, so the platform config handles them:

| Leak | Handling |
|---|---|
| Recents-screen thumbnail and screenshots | `FLAG_SECURE` app-wide; a failure to set it is shown to the user, not assumed away |
| Cloud backup copying the database | Android Backup **and** device-to-device transfer excluded for every storage domain |
| Unlocked vault in memory | Wiped 30s after backgrounding, driven by elapsed time so a frozen process still locks |
| Identity key extraction | Android Keystore, with reads bound to device credential where the device supports it |
| Interception via an installed root CA | User-installed CAs not trusted; cleartext refused |
| Forged app updates | Release signing from the environment; OTA JavaScript updates disabled |
| Transitive permission creep | Permission list is closed and asserted by tests |

`apps/mobile/test/androidConfig.test.ts` asserts all of it, because platform
hardening regresses invisibly: a dependency adds a permission, `prebuild`
regenerates the manifest, and nobody notices until an audit.

---

## Testing approach

The tests assert the security properties, not just the happy path. Among the
283:

- key substitution, prekey downgrade, and forged-bundle rejection
- forged sender identities and rewritten routing fields
- message replay, tampering, and injected garbage that must not
  desynchronise a live session
- resource-exhaustion bounds on skipped keys and queues
- that the relay's stored records contain no plaintext, no sender address,
  and no sender key
- that two messages from one sender are unlinkable
- that the relay writes nothing to its log while handling traffic
- that a tampered DTLS fingerprint changes the spoken call SAS — the
  MITM-detection path
- that media keys are zeroed after a call, and the local database holds no
  plaintext

Three real protocol bugs were found this way and fixed: a message burst sent to
an offline peer failed after the first message; delivery receipts named an id
the sender had never seen; and a user who was messaged first could not display
a safety number — exactly the case where verification matters most.

---

## Honest limitations

In short, from [docs/SECURITY.md](docs/SECURITY.md):

- The relay must learn **recipient** addresses to route. Sender anonymity is
  protected; recipient anonymity is not.
- **Traffic analysis still works.** Padding hides length within a bucket; it
  does not hide timing or volume, and there is no cover traffic.
- **An unverified conversation is vulnerable to an active attacker.** If nobody
  ever compares safety numbers, key substitution succeeds.
- Calls reveal **IP addresses** to the STUN/TURN infrastructure.
- A **short passphrase** is still weak, whatever the KDF.
- **Memory wiping is best-effort** in a garbage-collected runtime.
- **Spam resistance is weak** by construction, since the relay cannot know who
  is sending.
- **No independent audit yet.**

---

## License

Not yet selected. Add one before distributing.

# Veil

A private mobile messenger: end-to-end encrypted text and voice, with a server
that is built so it cannot read what it carries, cannot tell who sent a message,
and holds no personal identifier for anyone.

> **Status: not audited.** This is a careful implementation of well-specified
> constructions with 195 tests covering its security claims. That is not the
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

**A seized phone gives up nothing.** History is encrypted under an
Argon2id-derived key; the identity key lives in the platform keystore, bound to
device unlock and kept out of cloud backups.

**Also, deliberately absent:** no analytics, no crash reporting, no advertising
identifiers, no read receipts or typing indicators unless you turn them on (both
leak behaviour), and no contacts, location, or camera permissions.

---

## Layout

```
packages/crypto      The cryptographic core. Platform-independent, 105 tests.
packages/protocol    Wire types shared by client and relay.
packages/relay       The store-and-forward server. 54 tests.
apps/mobile          React Native (Expo) app. 36 core tests.
  src/core           Messenger, relay client, call manager - testable in Node.
  src/platform       Keystore, SQLite, WebRTC, transports.
  src/screens        UI.
docs/SECURITY.md     Threat model, and an explicit list of what is not protected.
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
npm test               # 195 tests
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

### The app

```bash
cd apps/mobile
EXPO_PUBLIC_VEIL_RELAY_HTTP=https://relay.example \
EXPO_PUBLIC_VEIL_RELAY_WS=wss://relay.example/v1/socket \
EXPO_PUBLIC_VEIL_STUN=stun:stun.example:3478 \
npx expo run:ios        # or run:android
```

Voice calls need a development build rather than Expo Go, because
`react-native-webrtc` is a native module.

Set `EXPO_PUBLIC_VEIL_RELAY_ONLY=true` to force media through TURN, which hides
each participant's IP from the other. Safe for confidentiality — the TURN server
still cannot hear the call — at the cost of latency.

---

## Testing approach

The tests assert the security properties, not just the happy path. Among the
195:

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

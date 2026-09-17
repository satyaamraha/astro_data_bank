# Veil threat model

This document states what Veil protects, what it does not, and why. It is
written to be falsifiable: each claim names the mechanism that delivers it, and
the limitations section is deliberately specific rather than hedged.

If you are evaluating Veil for a situation where being wrong has serious
consequences, read the limitations first.

---

## 1. Who we are defending against

| Adversary | Capability assumed | Outcome |
|---|---|---|
| **Network observer** | Reads and modifies all traffic between device and relay | Learns nothing about content; sees recipient addresses, timing, volume |
| **Malicious relay operator** | Full control of the server, its database, and its logs | Cannot read messages or calls; cannot learn who sent a message; can deny service |
| **Compelled relay operator** | Served a lawful order for everything they hold | Can produce only recipient addresses, ciphertext, and connection IPs. There is no phone number, email, contact graph, or plaintext to hand over |
| **Active MITM** | Can substitute keys, including via a compromised relay | Detectable by the user via safety numbers and the spoken call SAS. Undetectable only if the user never verifies |
| **Device thief** | Has the locked phone | Cannot read history without the passphrase; identity key is bound to device unlock and non-exportable |
| **Future quantum adversary** | Recorded traffic today, breaks ECDH later | Cannot decrypt: the handshake secret also depends on ML-KEM-1024 |
| **Forensic examiner** | Images the device storage | Recovers only ciphertext from the database and the keystore-held wrapper |

Explicitly **out of scope**: a compromised operating system, a malicious build
of the app, and a hardware implant. If the platform is hostile, no application
running on it can protect anything — we do not pretend otherwise.

---

## 2. What is protected, and by what

| Property | Mechanism | Where |
|---|---|---|
| Message confidentiality and integrity | XChaCha20-Poly1305 under Double Ratchet keys | `packages/crypto/src/doubleRatchet.ts` |
| Mutual authentication | Ed25519 identity keys bound into AEAD associated data | `packages/crypto/src/pqxdh.ts` |
| Forward secrecy | Symmetric ratchet; message keys wiped on use | `doubleRatchet.ts` |
| Post-compromise security | DH ratchet on every change of direction | `doubleRatchet.ts` |
| Post-quantum confidentiality | ML-KEM-1024 mixed into the handshake KDF | `pqxdh.ts` |
| Sender anonymity from the operator | Sealed-sender envelopes with per-message ephemeral keys | `envelope.ts` |
| Message-length privacy | Geometric padding buckets | `padding.ts` |
| Replay resistance | Consumed message keys; SFrame sliding window | `doubleRatchet.ts`, `sframe.ts` |
| Voice confidentiality from the relay | SFrame per-frame AEAD inside DTLS-SRTP | `sframe.ts`, `callKeys.ts` |
| MITM detectability | 60-digit safety numbers; 4-word call SAS | `safetyNumber.ts`, `callKeys.ts` |
| At-rest confidentiality | Argon2id-wrapped vault, per-record key binding | `vault.ts` |
| No account identifiers | Address is a hash of the identity key | `identity.ts` |

### Why hybrid post-quantum

A network observer can record traffic today and decrypt it years later if
elliptic-curve Diffie-Hellman falls to a quantum computer. This is not
speculative for data with a long sensitivity lifetime — journalistic sources,
legal matters, medical information.

Veil's handshake derives its root secret from X25519 **and** ML-KEM-1024
together. Breaking it requires breaking both. Using ML-KEM alone would be worse
than the hybrid: it is a much younger assumption than Curve25519, and lattice
schemes have had parameter breaks before. Requiring both to fail is strictly
stronger than trusting either.

### Why sealed sender matters as much as content encryption

Metadata is often more sensitive than content. "Who contacted a journalist, and
when" is frequently the fact worth protecting; the message body may be
guessable from context. A conventional end-to-end encrypted messenger still
hands its operator a complete social graph.

Veil encrypts the sender's identity to the recipient's key using a fresh
ephemeral key per message. The relay sees a recipient address, an unlinkable
ephemeral public key, and ciphertext. It cannot attribute a message to a sender
or link two messages to one sender. This is asserted directly by tests in
`packages/relay/test/messaging.test.ts`.

### Why calls need SFrame and not just DTLS-SRTP

WebRTC provides DTLS-SRTP, and it is easy to call that "end-to-end encrypted".
It is not, in general: DTLS terminates at whatever handles the media. For a
direct peer-to-peer call that is the other participant, but as soon as the call
is relayed through a TURN server — which happens routinely behind symmetric NAT,
i.e. on most mobile networks — DTLS terminates at the relay, which then sees
plaintext audio.

So Veil encrypts each media frame *before* it enters the RTP stack, with keys
derived from the messaging session and never sent to any server. Where the
platform cannot install a frame transform, `CallManager` **refuses the call**
rather than silently downgrading. A fallback the user cannot see would be worse
than a failure they can.

---

## 3. Limitations

These are real. None of them are fixed by configuration.

### 3.1 The relay learns recipient addresses

To deliver a message, the relay must know where it goes. Sender identity is
hidden; recipient identity is not. An operator can therefore see that *someone*
messaged a given address, and how often.

A user who needs this hidden as well must reach the relay over Tor or a VPN, and
even then the address itself is visible to the relay. Hiding the recipient too
requires private information retrieval or a mixnet, which are not implemented
here.

### 3.2 Traffic analysis still works

Padding hides message length within a bucket; it does not hide that a message
was sent, when, or how many. A passive observer watching two users' connections
can correlate timing. Veil sends no cover traffic. Defeating traffic analysis
requires constant-rate padding or mixing, with costs in latency and battery that
this design does not pay.

### 3.3 Unverified conversations are vulnerable to an active attacker

Encryption authenticates a *key*, not a person. If a compromised relay serves an
attacker's key under your contact's address on first contact, and neither user
ever compares safety numbers, the attacker reads the conversation. All the
cryptography above is defeated by this and cannot detect it on its own.

This is why verification is surfaced on every conversation row and in a
persistent banner, and why the app never displays an unverified conversation as
simply "secure". Once verified, the key is pinned and a change is a hard error —
no silent re-keying.

### 3.4 Voice calls reveal IP addresses to the ICE infrastructure

STUN and TURN servers see the IP addresses of both participants. SFrame means
they cannot hear the call, but they learn who is calling whom and from where. A
direct peer-to-peer call also reveals each participant's IP to the other.
Setting `relayOnly` forces media through TURN, hiding the peers' IPs from each
other at the cost of exposing them both to the TURN operator, plus latency.

### 3.5 A short passphrase is still weak

Argon2id at 46 MiB and 2 passes makes each guess expensive, but a
six-character passphrase is guessable regardless of the KDF. The app enforces a
ten-character minimum, which is a floor rather than a recommendation. Binding
the data key to hardware-backed key material, so that extraction requires the
device and not just the file, is the correct additional defence and is noted
below as outstanding.

The parameters were chosen against measurement, not guessed. On a 2.8 GHz x86
core under V8 this implementation takes ~780 ms at 46 MiB / t=2 and ~1620 ms at
64 MiB / t=3; Hermes on a mid-range phone is a small multiple slower again. An
earlier revision of this document claimed 64 MiB / t=3 cost "roughly 100-300 ms
on a mid-range phone", which was wrong by an order of magnitude. Several
seconds of blocked UI at unlock risks an Android ANR, and an unlock that feels
broken gets "fixed" by cutting the parameters to something far weaker or by
users choosing short passphrases - both worse than the memory the stronger
profile buys. 46 MiB / t=2 is one of the two profiles OWASP documents for
Argon2id. Parameters are stored in each vault's wrapper, so the default can be
raised as phones get faster without orphaning existing vaults.

### 3.6 Memory hygiene is best-effort

`wipe()` overwrites key buffers, and every retired ratchet key goes through it.
But JavaScript gives no guarantee that a value has not already been copied by
the garbage collector, and a compacted heap cannot be scrubbed. This shortens
the window in which a key sits in memory; it does not eliminate it. An attacker
with live memory access to an unlocked app wins.

### 3.7 Spam resistance is weak by construction

Because sealed sender means the relay cannot know who is sending, it cannot rate
limit by sender. It falls back to per-IP limits, size caps, and bounded queues.
A determined spammer with many IP addresses can still flood a known address. The
correct fix is blind-signed delivery tokens issued by the recipient, which
provide abuse resistance without deanonymising senders; not implemented.

### 3.8 Ratchet state is not resumed across restarts

Deliberate. A partially written ratchet is worse than no ratchet, because
reusing a chain key after a rollback would repeat a nonce and break
confidentiality outright. Veil re-handshakes instead, which costs one round trip
and is always safe. The cost is that a message sent to an offline peer whose
signed prekey has since rotated past the retained generations may be
undecryptable.

### 3.9 This code has not been independently audited

It is a careful implementation of well-specified constructions with 283 tests
covering the security claims, including negative tests for key substitution,
forged senders, replays, tampering, and resource exhaustion. That is not the
same as an audit. Do not deploy it for people whose safety depends on it without
one.

### 3.10 Known dependency advisories

The crypto core and the relay have **zero** known vulnerabilities
(`npm audit --workspace @veil/crypto`, `--workspace @veil/relay`).

The mobile app pulls ten moderate advisories, all from one transitive
dependency: `expo → @expo/config-plugins → xcode → uuid@7`. `xcode` is
build-time-only tooling that edits Xcode project files during `expo prebuild`.
It is never bundled into the app, never runs on a device, and never touches key
material. An npm `overrides` pin was attempted and is not honoured by the
installed npm for this nested path, so it is recorded here rather than papered
over with config that does not work.

---

## 4. Cryptographic choices

| Purpose | Primitive | Reason |
|---|---|---|
| Key agreement | X25519 | Small, fast, no invalid-curve pitfalls; noble rejects low-order points |
| Signatures | Ed25519 | Deterministic; no ECDSA nonce-reuse foot-gun |
| Post-quantum KEM | ML-KEM-1024 | FIPS 203; highest parameter set |
| AEAD | XChaCha20-Poly1305 | 24-byte nonces make random nonces safe; no AES timing concerns without AES-NI |
| Hash / KDF | SHA-512 / HKDF-SHA-512 | Wide margin; fast on 64-bit mobile cores |
| Passphrase KDF | Argon2id (46 MiB, t=2, p=1) | Memory-hard; PBKDF2 parallelises almost for free |

All primitives come from the audited `@noble/*` libraries. `primitives.ts` is
the only file that imports them, so the algorithm choices are reviewable in one
screen and a change is a single-file diff.

### Domain separation

Every HKDF call passes a versioned label from `kdf.ts`. This is what guarantees
that the same input secret used in two contexts cannot produce the same key.
Labels are never edited in place; reusing one for a new purpose is a protocol
break.

### Signature context tags

Each signature covers a tagged, length-delimited transcript. Without tags, a
signature over one kind of key could be replayed as a signature over another —
a real attack against naive "sign the raw public key" schemes. Veil signs
identity bindings, signed prekeys, KEM prekeys, sender proofs, and auth
challenges under distinct contexts.

---

## 5. Outstanding work

Ordered by how much they would improve the security posture:

1. **Independent cryptographic audit.** The prerequisite for real use.
2. **Hardware-bound data key.** Bind the vault's data key to a
   Keychain/StrongBox-held key so offline attack requires the device, not the
   file. Removes most of the force of limitation 3.5.
3. **Blind-signed delivery tokens.** Real spam resistance without
   deanonymising senders (3.7).
4. **Reproducible builds and binary transparency.** Otherwise "the app is
   open source" says nothing about the binary users install.
5. **Persistent, crash-safe ratchet state.** Needs an atomic write-ahead
   discipline that cannot roll back a chain key (3.8).
6. **QR code scanning.** Verification codes can be shared and pasted as text
   today, and the payload format plus its signature check are implemented and
   tested (`verificationQrPayload` / `parseVerificationQrPayload`). What is
   missing is the camera flow to render and scan them, which is the easiest
   verification path for non-technical users to get right.
7. **Multi-device support.** Currently one device per identity.
8. **Sealed-sender delivery tokens for recipient privacy**, or a mixnet
   transport, to address 3.1 and 3.2.

---

## 6. Reporting a vulnerability

Open an issue describing the impact and reproduction. For anything that breaks
confidentiality or authentication, please include the concrete failure case —
inputs, expected behaviour, observed behaviour — so it can be turned into a
regression test alongside the fix.

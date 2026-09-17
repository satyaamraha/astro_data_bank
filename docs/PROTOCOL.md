# Veil protocol specification

Version `v1`. This describes the wire protocol and key schedule precisely
enough to reimplement or to review. Notation: `||` is concatenation,
`DH(a, B)` is X25519, `KDF(ikm, salt, label, n)` is HKDF-SHA-512.

---

## 1. Identities

An identity is two long-term keys plus a binding signature:

```
IK_sig  : Ed25519 keypair      -- the root of trust
IK_dh   : X25519 keypair       -- long-term agreement key
sig_bind = Sign(IK_sig_priv, T_bind)
```

where the binding transcript is

```
T_bind = "Veil/v1/KeyBinding" || 0x01 || len(IK_sig_pub) || IK_sig_pub
                              || u32(0) || len(IK_dh_pub) || IK_dh_pub
```

The binding is what stops a relay substituting its own agreement key while
keeping the victim's signing key — which would leave the displayed safety number
unchanged. Verifiers **must** check it before any key agreement.

### Address

```
address = base32( SHA-256("Veil/v1/Address" || IK_sig_pub)[0..16] )
```

Self-certifying: anyone holding an address can verify a claimed identity hashes
to it, so a directory cannot point a name at the wrong key. There is no phone
number or username anywhere in the protocol.

---

## 2. Published key material

A client publishes:

| Key | Type | Lifetime | Signed |
|---|---|---|---|
| `IK_sig`, `IK_dh` | Ed25519, X25519 | long-term | binding sig |
| `SPK` | X25519 | ~weekly | yes, context `0x02` |
| `PQSPK` | ML-KEM-1024 | ~weekly | yes, context `0x03` |
| `OPK_i` | X25519 | single use | no |
| `PQOPK_i` | ML-KEM-1024 | single use | no |

Signed-prekey transcripts use the same shape as `T_bind` with the listed
context byte and the key's `u32` id. The id is inside the transcript, so
renumbering a prekey invalidates its signature.

One-time prekeys are unsigned; they are instead bound by the handshake
transcript (§3.2), so a substituted one-time key produces a different root
secret and fails decryption rather than passing unnoticed.

Rotated-out signed prekeys are retained for 3 generations, so a message sent
against a bundle fetched just before rotation is still decryptable.

---

## 3. PQXDH handshake

### 3.1 Secret derivation

Alice (initiator) fetches Bob's bundle, verifies every signature, generates an
ephemeral `EK`, and computes:

```
DH1 = DH(IK_dh_A, SPK_B)          -- authenticates Alice
DH2 = DH(EK_A,    IK_dh_B)        -- authenticates Bob
DH3 = DH(EK_A,    SPK_B)          -- forward secrecy (medium-term)
DH4 = DH(EK_A,    OPK_B)          -- forward secrecy (single use), if present
(CT, SS) = ML-KEM-1024.Encaps(PQOPK_B or PQSPK_B)
```

Each term does a distinct job, so omitting any one costs a property. `DH4` is
the only optional term, and its absence is recorded in the transcript rather
than ignored.

```
IKM  = 0xFF*32 || DH1 || DH2 || DH3 || [DH4] || SS
root = KDF(IKM, T_handshake, "Veil/v1/PQXDH", 32)
```

The `0xFF * 32` prefix follows the X3DH/PQXDH convention: it makes the KDF
input unambiguously not a raw curve point, blocking cross-protocol confusion
with implementations that hash bare DH outputs.

Bob reconstructs the same value using his stored private keys and
`ML-KEM.Decaps(CT)`.

> ML-KEM is *implicitly rejecting*: a corrupted ciphertext yields a
> pseudorandom secret rather than an error. That is safe here because the
> resulting secret must still produce a valid AEAD tag one layer up, so
> tampering surfaces as an authentication failure.

### 3.2 Transcript

```
T_handshake = "Veil/v1/PQXDH/Transcript"
           || IK_sig_A || IK_dh_A || IK_sig_B || IK_dh_B
           || EK_A || CT
           || u32(spk_id) || u32(pqspk_id)
           || u8(has_opk)   || u32(opk_id)
           || u8(has_pqopk) || u32(pqopk_id)
```

Binding the key identifiers *and* the presence flags means the two sides derive
different keys if they disagree about which keys were used. A relay attempting
a prekey downgrade therefore causes an immediate decryption failure instead of
a silent weakening.

### 3.3 Associated data

```
AD = "Veil/v1/AD" || IK_sig_init || IK_dh_init || IK_sig_resp || IK_dh_resp
```

Bound into every AEAD operation for the session's lifetime. Initiator first, so
the ordering is fixed and a message cannot be reflected back at its sender.

---

## 4. Double Ratchet

### 4.1 Key schedule

```
Root chain:     (RK', CK) = split( KDF(dh_out, RK, "Veil/v1/RootChain", 64) )
Symmetric:      MK  = HMAC-SHA-512(CK, 0x01)[0..32]
                CK' = HMAC-SHA-512(CK, 0x02)[0..32]
Message keys:   (key, nonce) = split( KDF(MK, "", "Veil/v1/MessageKey", 56) )
                              -- 32-byte key, 24-byte nonce
```

The root key is the HKDF *salt* and the DH output the IKM, so both are needed
to continue the chain. The two distinct HMAC seeds keep `MK` and `CK'`
independent: learning a message key reveals nothing about the rest of the chain.

### 4.2 Header

```
header = ratchet_pub (32) || u32(prev_chain_len) || u32(msg_number)
```

Travels authenticated-but-readable inside the sealed envelope, so the transport
never sees it. AEAD associated data is `AD || header`, which is what prevents
reordering or renumbering.

### 4.3 Initialisation

- **Initiator**: generates a ratchet keypair and immediately takes one root-chain
  step against `SPK_B`, so it can send without waiting for a reply.
- **Responder**: its ratchet keypair *is* the signed prekey pair. It has no
  sending chain until the first message arrives.

### 4.4 Out-of-order handling

Skipped message keys are cached, bounded on three axes:

- `MAX_SKIP_PER_CHAIN = 1000` — refuses a header claiming an absurd counter,
  which would otherwise let one forged header force millions of HMACs.
- `MAX_SKIPPED_KEYS = 2000` — total retained keys, evicted oldest-first.
- Keys are consumed on successful decryption only, so a forged ciphertext
  cannot burn a real key and make a legitimate message permanently
  undecryptable.

Ratchet state is committed **after** the AEAD verifies, so injected garbage
cannot desynchronise a live session.

### 4.5 Repeated prekey preamble

The initiator repeats its handshake preamble on every message until it receives
a reply, because its first message may be dropped. The responder recognises a
repeated preamble by the initiator's ephemeral key and routes it to the session
that handshake already built — attempting a fresh handshake would fail, since
the one-time prekey is spent. Replay protection is unaffected: the ratchet has
already consumed that message key.

---

## 5. Sealed sender

```
E            = fresh X25519 keypair
shared       = DH(E_priv, IK_dh_recipient)
(key, nonce) = split( KDF(shared, E_pub || IK_dh_recipient,
                          "Veil/v1/SealedSender", 56) )

proof = Sign(IK_sig_sender,
             "Veil/v1/SenderProof" || E_pub || recipient_address
                                   || u8(kind) || payload)

inner = IK_sig_sender || IK_dh_sender || sig_bind || proof || u8(kind) || payload
envelope = { recipient_address, E_pub, AEAD(key, nonce, inner, "") }
```

Both public keys go into the KDF salt, binding the derived key to this exact
(ephemeral, recipient) pair so an ephemeral key cannot be lifted onto another
recipient's envelope.

`proof` is what stops anyone placing someone else's public identity in the
sealed layer and impersonating them. On open, the recipient:

1. decrypts,
2. verifies the sender's identity binding,
3. verifies `proof` against **its own locally computed address**, not the
   address in the envelope — that field is server-supplied, so a relay that
   rewrites it gets a clean verification failure rather than an accepted
   message.

Only then is the sender identity returned to the caller.

### Padding

Plaintext is padded before encryption to a bucket: `0x80` then zeros, to the
smallest size in `128 * 1.25^n`. Buckets grow geometrically so the *relative*
length uncertainty stays roughly constant at every message size; fixed-size
steps either waste bandwidth on short messages or barely hide long ones.

---

## 6. Voice calls

### 6.1 Setup

Call signalling travels as ordinary ratchet-encrypted payloads, so it inherits
the messaging layer's mutual authentication and the relay sees no SDP — and
therefore no IP addresses or call state.

```
caller -> callee : call-offer  { callId, mediaSecret, sdp, dtlsFingerprint }
callee -> caller : call-answer { callId, sdp, dtlsFingerprint }
both             : call-ice    { callId, candidate }
either           : call-hangup { callId, reason }
```

### 6.2 Media keys

```
T_call = "Veil/v1/Call" || callId || IK_sig_caller || IK_sig_callee
                        || fp_caller || fp_callee

K_caller = KDF(mediaSecret, T_call, "Veil/v1/SFrameSender/caller", 32)
K_callee = KDF(mediaSecret, T_call, "Veil/v1/SFrameSender/callee", 32)
sas_bytes = KDF(mediaSecret, T_call, "Veil/v1/CallSAS", 8)
```

Send and receive keys are separate and role-derived: sharing one key across
both directions would reuse a keystream, which is catastrophic with a stream
cipher.

Including both DTLS certificate fingerprints ties the SFrame layer to the actual
transport session. An attacker who terminated the media path presents a
different fingerprint, so the derived SAS differs and the users detect it.

### 6.3 SAS

`sas_bytes[0..4]` maps to four words from a 256-entry list (`callKeys.ts`), one
word per byte with no bias. A six-digit numeric form is also provided. Both
users must see the same words; the app reports the call as unverified until the
user confirms they matched.

### 6.4 SFrame

Media uses a counter, not a ratchet, because UDP frames are lost and reordered
and a ratchet would break on the first drop.

```
per frame:  info = "Veil/v1/SFrameFrame" || u64(counter)
            (key, nonce) = split( KDF(K_direction, "", info, 56) )
            payload = AEAD(key, nonce, frame, u64(counter) || rtp_header)
```

The counter is transmitted in the clear (the receiver needs it to derive the
key) but is authenticated as associated data, so it cannot be altered. A relay
therefore learns only a frame index.

Nonce uniqueness is enforced from both ends:

- the sender refuses to encrypt past `2^48 - 1` rather than wrapping;
- the receiver rejects replayed counters and counters more than 1024 behind the
  highest seen, and commits to the replay window only after authentication.

---

## 7. Relay API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/v1/accounts` | none | Register. Idempotent per identity key |
| POST | `/v1/auth/challenge` | none | Get a single-use challenge |
| POST | `/v1/auth` | signature | Exchange a signed challenge for a token |
| GET | `/v1/keys/:address` | none | Fetch a prekey bundle (consumes one-time keys) |
| POST | `/v1/keys` | bearer | Upload prekeys |
| GET | `/v1/keys/count` | bearer | Remaining one-time prekeys |
| POST | `/v1/messages` | **none** | Submit a sealed envelope |
| GET | `/v1/messages` | bearer | Fetch queued messages |
| POST | `/v1/messages/acknowledge` | bearer | Delete delivered messages |
| GET | `/v1/socket` | bearer (in-band) | Realtime push |

Message submission is unauthenticated **by design**: sealed sender means there
is no sender identity to authenticate, and requiring a login would reintroduce
exactly the sender metadata the design removes.

Authentication signs:

```
"Veil/v1/Auth:" || address || ":" || challenge
```

Domain-separated and address-bound, so an auth signature cannot be replayed as
a key binding or a sender proof — the same identity key serves all three.

### Server behaviour that is part of the security model

- Request logging is **off**. Fastify's default logger records the IP, path,
  and timing of every request, which would reconstruct the delivery metadata
  the design withholds. A test asserts nothing is written while traffic is
  handled.
- `trustProxy` is off, so a client cannot forge `X-Forwarded-For` to evade rate
  limiting.
- Delivery timestamps are rounded down to the hour.
- `/v1/auth/challenge` answers for unknown addresses, and `/v1/messages`
  returns the same `200` for unknown recipients, so neither can enumerate the
  directory.
- Authentication failures are indistinguishable regardless of cause.
- Challenges are consumed even on failure, so there is no retry oracle.
- Acknowledgement is scoped to the caller's own queue.

---

## 8. At-rest storage

```
KEK = KDF( Argon2id(passphrase, salt, m=64MiB, t=3, p=1, 32),
           salt, "Veil/v1/VaultKEK", 32 )
DEK = random(32)                        -- wrapped under KEK
record_key = KDF(DEK, record_id, "Veil/v1/VaultRecord", 32)
stored = nonce(24) || AEAD(record_key, nonce, plaintext, record_id)
```

The DEK indirection means a passphrase change re-wraps one small blob instead
of re-encrypting the database, and Argon2id runs once per unlock rather than
per record.

Record keys are bound to `collection/id`, so a stolen database cannot have its
rows swapped or moved between collections — a relocated ciphertext fails to
decrypt.

Argon2id parameters are stored in the wrapper, so they can be raised later
without making existing vaults unreadable.

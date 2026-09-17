# How Veil differs from WhatsApp and Instagram

A fair comparison, including the places where the mainstream apps are better.

**Caveat on accuracy:** the behaviour of commercial products changes, and the
details below reflect publicly documented behaviour as of early 2026. Treat the
*structural* differences as the durable part and verify current specifics
against each vendor's own documentation before relying on them.

---

## 1. The short version

WhatsApp's message encryption is genuinely good — it uses the Signal protocol,
the same academic construction Veil's ratchet is based on. If your only concern
is "can someone reading the network see my messages", WhatsApp already answers
that well, and Veil's advantage over it is narrow.

The differences are almost entirely about **everything other than message
content**: who you are to the operator, what the operator can infer about your
relationships, what happens to your backups, and what the app itself collects.
That is where a messenger leaks, and it is what Veil is designed around.

Instagram is a different case. Its DMs were not built as an encrypted messenger
and its privacy posture is substantially weaker than WhatsApp's.

---

## 2. Side by side

| | **Veil** | **WhatsApp** | **Instagram DMs** |
|---|---|---|---|
| Message E2EE | Always | Always | Rolled out, but historically opt-in and not uniform across all chat types |
| Voice call E2EE | Always, with SFrame inside DTLS-SRTP | Yes (Signal protocol + SRTP) | Audio/video calls encrypted; less independently documented |
| Protocol published | Yes, `docs/PROTOCOL.md` | Yes, whitepaper | Partially |
| Client source available | Yes | No | No |
| Post-quantum handshake | Yes, ML-KEM-1024 hybrid | No (as documented) | No |
| Identifier required | None — a keypair | Phone number | Account tied to a real-name-policy social profile |
| Operator learns who messages whom | **No** (sealed sender) | **Yes** — it routes by phone number and both ends are known | **Yes** |
| Contact discovery | None; you exchange a code | Uploads your address book | Social graph is the product |
| Metadata retained | Recipient address, connection IP | Extensive: contacts, device, usage, "business interactions", IP | Extensive, plus feed/engagement data |
| Data shared with parent company | No parent company | Shares with Meta | Is Meta |
| Cloud backup of messages | **Disabled entirely** | Optional E2EE backups; default was long unencrypted at the cloud provider | Server-side, operator-accessible |
| Analytics / crash reporting / ad IDs | **None** | Present | Extensive |
| Screenshot & recents blocking | Yes, app-wide (FLAG_SECURE) | Not app-wide | No |
| Locks itself when backgrounded | Yes, 30s | No | No |
| Over-the-air code updates | **Disabled** | App store only | App store only |
| Independent security audit | **No** | Protocol yes; client no | Client no |
| Anti-spam / abuse tooling | Weak by construction | Strong | Strong |
| Reliability, scale, support | None | Excellent | Excellent |

---

## 3. The differences that actually matter

### 3.1 No phone number

This is the single biggest structural difference.

WhatsApp *is* your phone number. That means:
- the operator necessarily knows who you are, and so does anyone they are
  compelled to tell;
- your number is your handle, so contacting someone reveals your number to
  them;
- an attacker who takes over your number by SIM swap attacks your account.

In Veil an account is a keypair, and your address is a hash of your public key.
There is no phone number, email, or username anywhere in the protocol or the
server schema. That has three consequences: there is no personal identifier for
the operator to leak or be compelled to hand over, there is nothing to SIM-swap,
and the directory cannot point your name at someone else's key because the
address *is* derived from the key.

The cost is real: no automatic contact discovery. You exchange a code with
people out-of-band. WhatsApp's "everyone in your address book is already here"
is a genuinely better user experience, and it is exactly the feature that
requires uploading your address book.

### 3.2 The operator cannot see your social graph

WhatsApp encrypts message *content* end to end. It still routes every message
from a known sender to a known recipient, so the operator can observe that you
messaged a particular person at a particular time. For many people that
metadata is the sensitive part — who contacted a journalist, a clinic, a lawyer,
a union organiser. Content encryption does not protect it.

Veil encrypts the sender's identity to the recipient, with a fresh ephemeral key
per message. The relay sees a destination address, an unlinkable ephemeral
public key, and ciphertext. It cannot attribute a message to a sender, or link
two messages to the same sender. This is asserted directly by tests in
`packages/relay/test/messaging.test.ts`.

**Be clear about what remains:** the relay still learns the *recipient* address
(it has to route) and your IP address (the network requires it), and timing and
volume still leak. Veil removes the operator's ability to build a sender-side
social graph. It is not anonymity.

### 3.3 Backups

Historically the biggest practical hole in WhatsApp's encryption was not the
protocol — it was that chat backups went to iCloud or Google Drive in a form the
cloud provider could read. WhatsApp now offers end-to-end encrypted backups, but
it is a setting, and defaults decide what most people actually get.

Veil disables Android Backup and device-to-device transfer outright, in the
manifest and in explicit rule files, with tests asserting every storage domain
is excluded. The encrypted database cannot leave the device through the platform
backup path at all.

The cost is blunt and worth stating: **lose your device or forget your
passphrase and your history is gone.** There is no recovery, because we hold
nothing to recover it with. WhatsApp's recoverable backup is a real feature that
many users want more than they want this property.

### 3.4 Post-quantum

Veil's handshake derives its root secret from X25519 **and** ML-KEM-1024
together, so recorded traffic stays confidential even if elliptic-curve
cryptography later falls to a quantum computer. WhatsApp's published protocol
does not do this. Signal does, via PQXDH — Veil's handshake is the same idea.

This matters for anything with a long sensitivity lifetime: source protection,
legal matters, medical information. For a conversation about dinner it is
irrelevant.

### 3.5 Instagram specifically

Instagram is not a comparable product and should not be treated as one for
private communication. Its DMs sit inside a social network whose business is
the graph and the engagement data. Even where message encryption applies, the
surrounding product collects who you follow, what you look at, how long, and
from where. There is no configuration that makes Instagram a private messenger.

If the question is "should I use Instagram DMs for something sensitive", the
answer is no, independently of anything about Veil.

---

## 4. Where WhatsApp is better than Veil

This is not a close call on several axes, and pretending otherwise would be
dishonest.

1. **It has been audited and attacked for a decade.** Veil has not been
   independently audited at all. A careful implementation with 254 tests is not
   equivalent to adversarial review by people paid to break it. This is the
   single strongest argument for using WhatsApp or Signal instead.
2. **Reliability.** Push notifications, multi-device, message history sync,
   group chats, media, delivery at billion-user scale. Veil has none of that.
3. **Abuse resistance.** Because Veil's relay cannot know who is sending, it
   cannot rate limit by sender, so its spam defences are weak by construction.
   WhatsApp's are strong.
4. **Recovery.** A forgotten passphrase is unrecoverable in Veil, by design.
5. **Multi-device.** Veil is one device per identity.
6. **Reproducible builds.** Veil's source is available, but "open source" says
   nothing about the binary a user installs unless builds are reproducible and
   verifiable. That is outstanding work.

**Signal, not WhatsApp, is the honest comparison** for Veil's design goals.
Signal already does sealed sender, PQXDH, no cloud backup by default, and has
been audited. Veil's genuine differences from Signal are narrower: no phone
number at all (Signal requires one, though usernames now hide it from contacts),
SFrame media encryption independent of the transport, and a relay schema with no
account identifier in it. Whether those are worth giving up Signal's audit
history and maturity is a real trade-off, and for most people the answer is no.

---

## 5. Choosing

- **Most people, most of the time:** use Signal. Audited, mature, well
  maintained, and strong on exactly these properties.
- **If you need content confidentiality and already use it:** WhatsApp's message
  encryption is sound. Turn on encrypted backups. Accept that Meta sees your
  social graph.
- **Never for anything sensitive:** Instagram DMs.
- **Veil:** use it to understand how these properties are built, to audit the
  design, or to run your own infrastructure where no third party holds any
  identifier for your users. Do not put people at risk on it before it has been
  independently audited.

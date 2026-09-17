# Setting up Veil for two people

A practical runbook for the configuration you asked about: two phones, one
paired peer each, nobody else able to read the messages or hear the calls, and
the data on each phone protected by a passphrase.

Read [§4 of the assessment](ASSESSMENT.md) first if you have not. The summary:
this protects you from the network, the server, and anyone who picks up your
phone. It cannot protect you from malware on either phone, or from the other
person choosing to share what you sent them.

---

## 1. Why two people is the strong case

The hardest problem in an encrypted messenger is not the encryption — it is
knowing that the key you hold belongs to the person you think. A general
messenger cannot solve this: it has to let you message someone you have never
met, so it hands you a key from the server and hopes you verify it later. If a
compromised server substitutes its own key at that moment, it reads everything,
and no protocol can detect it.

With two people you can close that hole completely, because you can meet once.
Veil's **paired mode** (the default, and what the app ships with) does:

- You pair once, in person, by exchanging codes that carry each other's full
  signed identity. Nothing the server says is trusted.
- After that, the peer's key is pinned permanently. Messages from any other
  account are discarded *before decryption* — a stranger cannot open a
  conversation with you at all.
- If your partner's key ever changes, the app **stops** instead of asking you
  to decide. You pair again, in person.

That last point is where this differs from WhatsApp or Signal. They must
tolerate a contact reinstalling, so they show a warning and let you continue —
and a warning that appears for innocent reasons gets dismissed. Here, a key
change means either your partner reinstalled (you are together, so re-pair) or
someone is attacking you. Refusing to continue costs almost nothing.

---

## 2. What you need

- **Two Android phones**, Android 8 or newer.
- **A small server** with a domain name. The cheapest VPS tier is ample: two
  people generate almost no load. You need a domain pointing at it.
- About an hour.

You could skip the server by using someone else's, but then they see your
connection metadata. Since the server cannot read messages, calls, or even tell
who sent what, running your own mainly removes that last metadata exposure —
and on the cheapest tier it costs very little.

---

## 3. Stand up the relay

```bash
git clone <this repo> && cd astro_data_bank/deploy
cp .env.example .env
```

Edit `.env`:

```
VEIL_DOMAIN=veil.yourdomain.com
TURN_USER=veil
TURN_PASSWORD=<a long random string>
```

Point `veil.yourdomain.com` at the server's IP, then:

```bash
docker compose up -d
```

Caddy gets a TLS certificate automatically. Check it:

```bash
curl https://veil.yourdomain.com/v1/health
# {"status":"ok"}
```

Open these ports on the server firewall: **443/tcp** (relay), **3478/udp** and
**3478/tcp** (STUN/TURN), **49160-49200/udp** (TURN media), and **80/tcp** for
certificate issuance only.

### What the server keeps

Almost nothing, deliberately:

- Queued messages, as ciphertext, deleted the moment they are delivered.
- Your two public keys and prekeys.
- No message database, no logs — not Caddy access logs, not relay request
  logs, not TURN logs. All three are switched off, because per-request logs
  would reconstruct exactly the delivery metadata the design exists not to
  keep.
- Nothing written to disk by the relay container at all: it runs `read_only`.
  A restart drops undelivered ciphertext, which the phones re-send.

---

## 4. Build and install the app

You need the Android SDK on a development machine.

```bash
cd apps/mobile
npm install

export EXPO_PUBLIC_VEIL_RELAY_HTTP=https://veil.yourdomain.com
export EXPO_PUBLIC_VEIL_RELAY_WS=wss://veil.yourdomain.com/v1/socket
export EXPO_PUBLIC_VEIL_STUN=turn:veil.yourdomain.com:3478

npx expo run:android --variant release
```

For a distributable APK, generate a signing key **once** and keep it safe — it
is what lets you ship updates to your own phones, and losing it means
reinstalling from scratch:

```bash
keytool -genkeypair -v -keystore veil-release.jks \
  -keyalg RSA -keysize 4096 -validity 10000 -alias veil

export VEIL_KEYSTORE_PATH=$PWD/veil-release.jks
export VEIL_KEYSTORE_PASSWORD=...
export VEIL_KEY_ALIAS=veil
export VEIL_KEY_PASSWORD=...
cd android && ./gradlew assembleRelease
# apps/mobile/android/app/build/outputs/apk/release/app-release.apk
```

Do not commit that keystore. The build refuses to fall back to a debug key, so
if the variables are missing you get an error rather than an insecurely signed
build.

> **Before trusting it:** install the release APK and check it end to end —
> register, pair, send messages both ways, place a call. R8 minification is
> enabled for release builds, and that configuration has not been verified on
> a device (finding M-7 in the assessment).

---

## 5. Pair the two phones — do this together

1. Open the app on both phones.
2. Each person sets a passphrase. **Use different passphrases**; they protect
   each phone separately and neither is sent anywhere.
3. Both phones land on the pairing screen.
4. Swap codes *directly* — show the screen, or share to a local channel like
   AirDrop-equivalent or a cable. **Not** over SMS, email, or another chat app.
5. Paste each other's code, name each other, tap Pair.

**Why in person matters:** the code is what establishes trust. Everything else
in the app is arithmetic that holds regardless of what you do. This is the one
step where security depends on you. If the code arrives over a channel someone
could tamper with, they can substitute their own and read everything
afterwards. Face to face, once, removes the entire attack.

After pairing, each phone talks only to the other. You will never need to
verify anything again unless a key changes.

---

## 6. Choosing passphrases

The passphrase is what stands between someone holding your phone and your
message history. There is **no reset** — we hold nothing to reset it with.

- Use **four or more unrelated words**: `copper-anchor-velvet-thunder`. Length
  beats symbols comfortably.
- Do not reuse a passphrase from anywhere else.
- Write it down and keep it somewhere physically safe. Forgetting it destroys
  the history, and that is not a bug we can fix for you.

What protects it, concretely:

- **Argon2id at 46 MiB per guess.** An attacker needs 46 MiB of memory and
  roughly a second or more per attempt, which makes GPU cracking uneconomic.
- **The key that unwraps your data lives in the Android Keystore**, not in the
  database. So copying the database file off the phone is useless on its own —
  an attacker needs the phone as well as the passphrase. On devices with secure
  hardware, that key cannot be extracted even from a rooted phone.
- **Attempt throttling.** Three free tries, then escalating lockouts up to five
  minutes. The counter lives in the keystore, not the database, so wiping app
  data cannot reset it — it destroys the vault too.
- **Where the device supports it**, reading the identity key also needs your
  screen unlock, so a running-but-locked phone will not hand it over.

---

## 7. Day-to-day behaviour worth knowing

| What you will see | Why |
|---|---|
| Passphrase prompt after ~30s in the background | The unlocked key is wiped from memory when you switch away |
| Screenshots refuse to work | `FLAG_SECURE` is on app-wide, which also keeps conversations out of the recents thumbnail |
| Four words shown during every call | Read them aloud. If they match, nobody is relaying the call. They are the only way to detect an active attacker on the media path |
| No message backup anywhere | Android Backup and device transfer are both disabled. A lost phone means a lost history |
| Unlock takes a second or two | Argon2id, deliberately. That cost is what makes guessing expensive |
| A call refuses to start on some devices | The app will not place a call it cannot encrypt end to end. It refuses rather than falling back to something the server could hear |

### Turning on read receipts

Off by default, because "delivered" and "read" tell your partner when you are
awake and holding your phone. For two people who already share that, it is a
reasonable thing to enable — it is a per-device setting, not a security
downgrade.

### If a key change warning appears

Stop. Do not send anything. Two possibilities:

1. Your partner reinstalled or changed phones. Ask them — over a channel where
   you recognise them, like a voice call.
2. Someone is trying to intercept you.

If it is (1), unpair on both phones and pair again in person. **Unpairing
deletes the conversation history**, because new keys cannot decrypt old
messages, so it would be unreadable ciphertext either way.

---

## 8. What this still does not protect against

Stated plainly, because your requirement was "no one else can tap into our call
or message" and it is worth knowing exactly where that holds.

**It does hold against:** the server operator, anyone watching the network,
anyone who steals a phone, anyone who copies the database off a phone, a
stranger trying to message you, and a future quantum adversary decrypting
traffic recorded today.

**It does not hold against:**

1. **Malware on either phone.** Plaintext exists on both devices — it must, or
   you could not read the messages. Anything with control of a phone reads
   everything, and this is where commercial spyware operates precisely because
   the transport layer is solved. Keep both phones updated; install little.
2. **Either of you.** The other person can photograph the screen or repeat what
   you said. No protocol constrains a legitimate recipient.
3. **Being made to unlock.** In many places a court can compel it, and so can
   someone standing next to you.
4. **Traffic analysis.** The server sees that your two addresses exchange
   messages, when, and roughly how much. It cannot see who sent which message
   or what any of them say. If even the pattern matters, route the phones
   through a VPN or Tor.
5. **Bugs.** The code has not been independently audited. Five real defects
   were found by its own author reviewing it; assuming that was all of them
   would be optimistic.

For two people who want their conversations private from the network, the
server, and anyone who picks up a phone, this configuration does the job. If
being wrong would be dangerous rather than embarrassing, use Signal — audited,
mature, and strong on the same properties — until this has had a real audit.

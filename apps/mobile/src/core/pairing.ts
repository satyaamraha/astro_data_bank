/**
 * Two-person pairing lock.
 *
 * Veil's weakest realistic link is not the cryptography — it is the moment of
 * first contact. If a compromised relay hands you an attacker's key under your
 * contact's address before you have ever verified them, every other defence in
 * the system is bypassed, and nothing in the protocol can detect it.
 *
 * For a two-person app that risk is almost entirely removable, because there
 * is exactly one legitimate peer and you can establish them once, in person.
 * After pairing:
 *
 *   - the peer's identity key is pinned permanently;
 *   - traffic from any other identity is discarded before it reaches the
 *     ratchet, so a stranger cannot even open a conversation;
 *   - a change in the peer's key is a hard stop, not a prompt. Re-pairing is
 *     deliberate, in person, and starts from scratch.
 *
 * That last point is the difference between this and general-purpose
 * messengers. They must tolerate a contact reinstalling, so they show a
 * warning and let you continue — and a warning that appears for innocent
 * reasons gets dismissed. Here, a key change means either your partner
 * reinstalled (in which case you are together and can re-pair) or someone is
 * attacking you. Refusing to proceed costs almost nothing and removes the
 * decision from the moment of greatest pressure.
 */

import { MalformedInputError } from '@veil/crypto';

export interface PairingState {
  /** The one peer this device will talk to. */
  readonly peerAddress: string;
  /** Base64url Ed25519 identity key, pinned at pairing time. */
  readonly peerIdentityKey: string;
  /** Local clock, for display only. */
  readonly pairedAt: number;
  /** What the user calls them. Local label, never transmitted. */
  displayName: string;
}

export type PairingDecision =
  /** Expected peer; proceed. */
  | { readonly allow: true }
  /**
   * Refuse. `reason` distinguishes a stranger (drop silently — it is either
   * spam or a probe, and an error reply would confirm the address exists) from
   * a key change on the paired peer (surface loudly — it is either a reinstall
   * or an attack, and the user must decide in person).
   */
  | { readonly allow: false; readonly reason: 'not-paired' | 'stranger' | 'key-changed' };

/**
 * Whether to accept traffic from a sender.
 *
 * Pure, so the rule that decides what reaches the ratchet is testable on its
 * own rather than only through the messenger.
 */
export function decideInbound(
  pairing: PairingState | undefined,
  senderAddress: string,
  senderIdentityKey: string,
): PairingDecision {
  // Not yet paired: accept nothing. An unpaired device has no legitimate
  // correspondent, so anything arriving is unsolicited.
  if (!pairing) return { allow: false, reason: 'not-paired' };

  if (senderAddress !== pairing.peerAddress) {
    return { allow: false, reason: 'stranger' };
  }

  // Same address but a different key is impossible without a key change,
  // because the address is a hash of the identity key — so reaching here means
  // the address matched while the key did not, which only a bug or a crafted
  // envelope produces. Treat it as hostile.
  if (senderIdentityKey !== pairing.peerIdentityKey) {
    return { allow: false, reason: 'key-changed' };
  }

  return { allow: true };
}

/** Whether we may open a conversation with an address. */
export function decideOutbound(
  pairing: PairingState | undefined,
  peerAddress: string,
): PairingDecision {
  if (!pairing) return { allow: false, reason: 'not-paired' };
  if (peerAddress !== pairing.peerAddress) return { allow: false, reason: 'stranger' };
  return { allow: true };
}

/**
 * Human-readable explanation for a refusal.
 *
 * Kept next to the decision so the wording cannot drift from the rule, and so
 * the "key changed" case always gets the full explanation rather than a
 * generic error.
 */
export function explainRefusal(reason: 'not-paired' | 'stranger' | 'key-changed'): string {
  switch (reason) {
    case 'not-paired':
      return 'This device is not paired yet. Pair with your contact in person first.';
    case 'stranger':
      return 'Blocked a message from someone you are not paired with.';
    case 'key-changed':
      return (
        'Your contact’s security key has changed. Either they reinstalled the ' +
        'app, or someone is trying to intercept your conversation. Do not send ' +
        'anything until you are together in person and can pair again.'
      );
    default:
      return 'Blocked.';
  }
}

export function createPairing(params: {
  peerAddress: string;
  peerIdentityKey: string;
  displayName: string;
  now: number;
}): PairingState {
  if (!params.peerAddress || !params.peerIdentityKey) {
    throw new MalformedInputError('pairing needs both an address and an identity key');
  }
  return {
    peerAddress: params.peerAddress,
    peerIdentityKey: params.peerIdentityKey,
    pairedAt: params.now,
    displayName: params.displayName || params.peerAddress.slice(0, 8),
  };
}

/**
 * Domain-separation labels.
 *
 * Every HKDF call in Veil passes one of these as `info`. This is not
 * decoration: it is what guarantees that the same input secret used in two
 * different contexts (say, a root-chain step and a media key) cannot produce
 * the same output key. Reusing a label for a new purpose is a protocol break,
 * so labels carry the protocol version and are never edited in place.
 */

const encoder = new TextEncoder();

function label(name: string): Uint8Array {
  return encoder.encode(`Veil/v1/${name}`);
}

export const LABELS = {
  /** Root secret derived by the PQXDH handshake. */
  handshake: label('PQXDH'),
  /** Root-chain step: (root key, chain key) <- DH output. */
  rootChain: label('RootChain'),
  /** Message key -> (AEAD key, AEAD nonce). */
  messageKey: label('MessageKey'),
  /** Sealed-sender outer envelope key. */
  sealedSender: label('SealedSender'),
  /** Per-call media secret derived from the message session. */
  callSecret: label('CallSecret'),
  /** SFrame sender key for one participant in one call epoch. */
  sframeSender: label('SFrameSender'),
  /** SFrame per-frame (key, nonce) pair. */
  sframeFrame: label('SFrameFrame'),
  /** Short authentication string shown to both parties during a call. */
  callSas: label('CallSAS'),
  /** Argon2id output -> vault key-encryption key. */
  vaultKek: label('VaultKEK'),
  /** Data-encryption key -> per-record key. */
  vaultRecord: label('VaultRecord'),
} as const;

/**
 * Chain-key ratchet constants (HMAC inputs, not HKDF labels).
 * Distinct single bytes keep the message key and the next chain key independent.
 */
export const CHAIN_MESSAGE_KEY_SEED = Uint8Array.of(0x01);
export const CHAIN_NEXT_KEY_SEED = Uint8Array.of(0x02);

/** Prepended to the PQXDH secret concatenation; mirrors the X3DH/PQXDH spec's `F`. */
export const HANDSHAKE_PREFIX = new Uint8Array(32).fill(0xff);

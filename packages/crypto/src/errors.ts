/**
 * Error taxonomy for the Veil crypto core.
 *
 * Every failure is explicit. We never fall back to a weaker mode, never return
 * a "best effort" plaintext, and never surface a partial decryption: a failed
 * authentication tag is an error, not a warning.
 */

/** Base class so callers can `catch (e) { if (e instanceof VeilCryptoError) ... }`. */
export class VeilCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** A key, ciphertext, or wire field had the wrong length or shape. */
export class MalformedInputError extends VeilCryptoError {}

/** An AEAD tag or signature did not verify. Treat as hostile input. */
export class AuthenticationError extends VeilCryptoError {}

/** A prekey bundle failed signature validation, so the identity binding is unproven. */
export class UntrustedBundleError extends VeilCryptoError {}

/** The peer's identity key changed; the user must re-verify before proceeding. */
export class IdentityChangedError extends VeilCryptoError {
  constructor(
    message: string,
    readonly knownFingerprint: string,
    readonly presentedFingerprint: string,
  ) {
    super(message);
  }
}

/** Ratchet state cannot decrypt this message (too far ahead, or replayed). */
export class SessionStateError extends VeilCryptoError {}

/** A message key was already used. Replays are rejected, not silently accepted. */
export class ReplayError extends SessionStateError {}

/** Vault passphrase was wrong, or the vault blob was tampered with. */
export class VaultLockedError extends VeilCryptoError {}

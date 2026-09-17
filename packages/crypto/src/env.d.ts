/**
 * Ambient declarations for the two platform globals this package relies on.
 *
 * Both Node >=20 and React Native (Hermes) provide these. We declare them
 * narrowly instead of pulling in the whole `DOM` lib, so that nothing else
 * browser-shaped accidentally typechecks inside the crypto core.
 */

declare class TextEncoder {
  encode(input?: string): Uint8Array;
}

declare class TextDecoder {
  constructor(label?: string, options?: { fatal?: boolean });
  decode(input?: Uint8Array): string;
}

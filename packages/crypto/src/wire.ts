/**
 * Minimal binary codec.
 *
 * Why hand-rolled instead of protobuf/JSON:
 *  - Deterministic. Two encodings of the same struct are byte-identical, which
 *    matters because we feed encoded headers into AEAD associated data. A
 *    canonicalisation ambiguity there would be an authentication bypass.
 *  - No parser surface. A message from the network is untrusted input; this
 *    reader bounds-checks every read and cannot allocate on attacker demand.
 */

import { MalformedInputError } from './errors.js';

export class Writer {
  private chunks: Uint8Array[] = [];
  private length = 0;

  private push(chunk: Uint8Array): this {
    this.chunks.push(chunk);
    this.length += chunk.length;
    return this;
  }

  u8(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) {
      throw new MalformedInputError(`u8 out of range: ${value}`);
    }
    return this.push(Uint8Array.of(value));
  }

  u32(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
      throw new MalformedInputError(`u32 out of range: ${value}`);
    }
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, value, false); // big-endian
    return this.push(buf);
  }

  u64(value: bigint): this {
    if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
      throw new MalformedInputError(`u64 out of range: ${value}`);
    }
    const buf = new Uint8Array(8);
    new DataView(buf.buffer).setBigUint64(0, value, false);
    return this.push(buf);
  }

  /** Raw bytes, no length prefix. Only for fixed-size fields. */
  fixed(bytes: Uint8Array): this {
    return this.push(bytes);
  }

  /** Length-prefixed bytes, for anything variable-length. */
  bytes(value: Uint8Array): this {
    this.u32(value.length);
    return this.push(value);
  }

  finish(): Uint8Array {
    const out = new Uint8Array(this.length);
    let offset = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }
}

export class Reader {
  private offset = 0;

  constructor(private readonly buffer: Uint8Array) {}

  private take(length: number): Uint8Array {
    if (length < 0 || this.offset + length > this.buffer.length) {
      throw new MalformedInputError(
        `truncated message: wanted ${length} bytes at offset ${this.offset} of ${this.buffer.length}`,
      );
    }
    // Copy rather than subarray: callers may wipe() the result, and we must not
    // scribble over a buffer the caller still owns.
    const out = this.buffer.slice(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }

  u8(): number {
    return this.take(1)[0]!;
  }

  u32(): number {
    const b = this.take(4);
    return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(0, false);
  }

  u64(): bigint {
    const b = this.take(8);
    return new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(0, false);
  }

  fixed(length: number): Uint8Array {
    return this.take(length);
  }

  bytes(): Uint8Array {
    return this.take(this.u32());
  }

  /** Reject trailing garbage: a well-formed message is consumed exactly. */
  end(): void {
    if (this.offset !== this.buffer.length) {
      throw new MalformedInputError(
        `trailing bytes: ${this.buffer.length - this.offset} unread`,
      );
    }
  }
}

const BASE32 = 'abcdefghijkmnpqrstuvwxyz23456789'; // Crockford-ish: no l/o/0/1

/** Lowercase base32 for human-facing addresses. Deterministic, no padding. */
export function toBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new MalformedInputError('hex string has odd length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new MalformedInputError('invalid hex digit');
    out[i] = byte;
  }
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export const utf8 = {
  encode: (text: string): Uint8Array => new TextEncoder().encode(text),
  decode: (bytes: Uint8Array): string => new TextDecoder('utf-8', { fatal: true }).decode(bytes),
};

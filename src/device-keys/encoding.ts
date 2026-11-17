/**
 * Encoding and hashing helpers (plan section 2). No Node-only APIs: runs in Node 20+,
 * Safari and Chrome. WebCrypto is taken from `globalThis.crypto`.
 *
 * @experimental
 */
import { canonicalize } from '../canonicalize';
import { fail } from './errors';

const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64U_INDEX: Record<string, number> = {};
for (let i = 0; i < B64U.length; i++) B64U_INDEX[B64U[i]] = i;

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

/** @experimental */
export function utf8(s: string): Uint8Array {
  return utf8Encoder.encode(s);
}

/** Strict UTF-8 decode; throws MALFORMED on invalid bytes. @experimental */
export function utf8Decode(b: Uint8Array): string {
  try {
    return utf8Decoder.decode(b);
  } catch {
    return fail('MALFORMED', 'invalid UTF-8');
  }
}

/** base64url without padding (section 2, rule 5). @experimental */
export function b64uEncode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64U[(n >> 18) & 63] + B64U[(n >> 12) & 63] + B64U[(n >> 6) & 63] + B64U[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += B64U[(n >> 18) & 63] + B64U[(n >> 12) & 63];
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64U[(n >> 18) & 63] + B64U[(n >> 12) & 63] + B64U[(n >> 6) & 63];
  }
  return out;
}

/**
 * Strict base64url decode: alphabet only, no padding, and canonical (the unused trailing
 * bits are zero, so exactly one string encodes each byte string). Throws MALFORMED.
 * @experimental
 */
export function b64uDecode(s: string): Uint8Array {
  if (typeof s !== 'string' || s.length % 4 === 1) return fail('MALFORMED', 'not base64url');
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < s.length; i++) {
    const v = B64U_INDEX[s[i]];
    if (v === undefined) return fail('MALFORMED', 'not base64url');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
      acc &= (1 << bits) - 1;
    }
  }
  if (acc !== 0) return fail('MALFORMED', 'non-canonical base64url');
  return out;
}

/** Decode base64url and require an exact byte length. @experimental */
export function b64uBytes(s: unknown, length: number, what: string): Uint8Array {
  if (typeof s !== 'string') return fail('MALFORMED', `${what} must be a string`);
  const b = b64uDecode(s);
  if (b.length !== length) return fail('MALFORMED', `${what} must be ${length} bytes`);
  return b;
}

/** @experimental */
export function hexEncode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

/** @experimental */
export function hexDecode(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) {
    return fail('MALFORMED', 'not lowercase hex');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** @experimental */
export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** @experimental */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/**
 * Minimal view of WebCrypto's SubtleCrypto. The package compiles without the DOM lib, so the
 * platform type is not available; calls are checked at run time by the platform.
 * @experimental
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Subtle = { [method: string]: (...args: any[]) => any };

/** @experimental */
export function subtle(): Subtle {
  const s = (globalThis as unknown as { crypto?: { subtle?: Subtle } }).crypto?.subtle;
  if (!s) throw new Error('WebCrypto (globalThis.crypto.subtle) is not available');
  return s;
}

/** Cryptographically secure random bytes. @experimental */
export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  (globalThis as unknown as { crypto: { getRandomValues(a: Uint8Array): Uint8Array } }).crypto.getRandomValues(out);
  return out;
}

/** SHA-256 digest (32 bytes). @experimental */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest('SHA-256', data));
}

/** `"sha256:" + lowercase hex` (section 2, rule 6). @experimental */
export async function sha256Hash(data: Uint8Array): Promise<string> {
  return 'sha256:' + hexEncode(await sha256(data));
}

/** Parse `"sha256:" + 64 lowercase hex` into the 32 digest bytes. Throws MALFORMED. @experimental */
export function hashBytes(h: unknown): Uint8Array {
  if (typeof h !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(h)) return fail('MALFORMED', 'not a sha256 hash string');
  return hexDecode(h.slice(7));
}

/** JCS text of a value; an unserialisable value (lone surrogate, undefined, ...) is MALFORMED. @experimental */
export function jcs(value: unknown): string {
  try {
    return canonicalize(value);
  } catch (e) {
    return fail('MALFORMED', (e as Error).message);
  }
}

/** True iff `o` has exactly the members `keys` (set comparison). @experimental */
export function sameMembers(o: object, keys: readonly string[]): boolean {
  const have = Object.keys(o);
  if (have.length !== keys.length) return false;
  const want = new Set(keys);
  if (want.size !== keys.length) return false;
  return have.every((k) => want.has(k));
}

const NOT_SIGNED = ['sig', 'sigs', 'checks'] as const;

/**
 * The signed bytes of an object (section 2, rule 3): `utf8(JCS(object))` taken without its
 * top-level `sig`, `sigs` and `checks` members. `typ` and `v` stay inside.
 * @experimental
 */
export function signedBytes(obj: object): Uint8Array {
  const copy: Record<string, unknown> = { ...(obj as Record<string, unknown>) };
  for (const k of NOT_SIGNED) delete copy[k];
  return utf8(jcs(copy));
}

/** `"sha256:" + hex(sha256(signedBytes(obj)))`: the entry hash / object hash. @experimental */
export async function objectHash(obj: object): Promise<string> {
  return sha256Hash(signedBytes(obj));
}

/** HMAC-SHA256. @experimental */
export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await subtle().importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle().sign('HMAC', k, data));
}

/** HKDF-SHA256 (RFC 5869) with UTF-8 salt and info strings. @experimental */
export async function hkdfSha256(ikm: Uint8Array, salt: string, info: string, length: number): Promise<Uint8Array> {
  const k = await subtle().importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await subtle().deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: utf8(salt), info: utf8(info) },
    k,
    length * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Ed25519 (strict), key ids and the recovery code with its root key (plan 2.1, 2.2, 2.3).
 *
 * @experimental
 */
import * as ed from '@noble/ed25519';
import { encodeDidKey } from '../did-key';
import { fail } from './errors';
import { b64uEncode, bytesEqual, concat, hkdfSha256, randomBytes, sha256, utf8 } from './encoding';

/** The Ed25519 group order. */
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

function leToBigInt(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
  return n;
}

/**
 * Strict Ed25519 verification (section 2, rule 4): refuses a non-canonical `S` (S >= L), a
 * non-canonical point encoding (R or A) and a small-order public key. Never throws; returns
 * false for anything it refuses.
 * @experimental
 */
export async function verifyEd25519(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  if (leToBigInt(signature.subarray(32)) >= L) return false;
  try {
    return await ed.verifyAsync(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

/** Sign with an Ed25519 private seed (32 bytes). Returns 64 bytes. @experimental */
export async function signEd25519(privateSeed: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  return ed.signAsync(message, privateSeed);
}

/** The Ed25519 public key (32 bytes) of a private seed. @experimental */
export async function ed25519PublicKey(privateSeed: Uint8Array): Promise<Uint8Array> {
  return ed.getPublicKeyAsync(privateSeed);
}

/** `key_id = base64url(sha256(sign_pub))`, 43 characters (section 2.3). @experimental */
export async function keyIdOf(signPub: Uint8Array): Promise<string> {
  return b64uEncode(await sha256(signPub));
}

// ---------------------------------------------------------------------------
// Recovery code (2.1)
// ---------------------------------------------------------------------------

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const RECOVERY_PREFIX = 'SV1-';
const CHECKSUM_LABEL = 'suveren-recovery-v1';

function base32Encode(bytes: Uint8Array): string {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += CROCKFORD[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += CROCKFORD[(acc << (5 - bits)) & 31];
  return out;
}

/** Decode Crockford base32 to `byteLength` bytes; the pad bits must be zero. */
function base32Decode(s: string, byteLength: number): Uint8Array | null {
  const out = new Uint8Array(byteLength);
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const ch of s) {
    const v = CROCKFORD.indexOf(ch);
    if (v < 0) return null;
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      if (o >= byteLength) return null;
      out[o++] = (acc >> bits) & 0xff;
      acc &= (1 << bits) - 1;
    }
  }
  // 145 bits were read for 144 bits of data: the one pad bit left in `acc` must be zero.
  if (o !== byteLength || acc !== 0) return null;
  return out;
}

async function recoveryChecksum(seed: Uint8Array): Promise<Uint8Array> {
  return (await sha256(concat(utf8(CHECKSUM_LABEL), seed))).subarray(0, 2);
}

/**
 * Encode a 16-byte seed as `SV1-XXXX-XXXX-...` (Crockford base32 of seed || checksum in
 * groups of 4; 29 characters, the last group has 1).
 * @experimental
 */
export async function encodeRecoveryCode(seed: Uint8Array): Promise<string> {
  if (seed.length !== 16) return fail('MALFORMED', 'recovery seed must be 16 bytes');
  const text = base32Encode(concat(seed, await recoveryChecksum(seed)));
  return RECOVERY_PREFIX + (text.match(/.{1,4}/g) as string[]).join('-');
}

/** A new random recovery code and its seed. @experimental */
export async function generateRecoveryCode(): Promise<{ seed: Uint8Array; code: string }> {
  const seed = randomBytes(16);
  return { seed, code: await encodeRecoveryCode(seed) };
}

/**
 * Parse and validate a recovery code. Accepts any letter case, and `-` and spaces anywhere
 * after the prefix. Crockford aliases (I, L read as 1; O read as 0) are accepted. Throws
 * `BAD_RECOVERY_CODE` (prefix, length, alphabet) or `BAD_CHECKSUM`.
 * @experimental
 */
export async function parseRecoveryCode(input: string): Promise<Uint8Array> {
  if (typeof input !== 'string') return fail('BAD_RECOVERY_CODE', 'not a string');
  const t = input.trim();
  if (t.slice(0, 4).toUpperCase() !== RECOVERY_PREFIX) return fail('BAD_RECOVERY_CODE', 'missing SV1- prefix');
  const body = t
    .slice(4)
    .toUpperCase()
    .replace(/[-\s]/g, '')
    .replace(/[IL]/g, '1')
    .replace(/O/g, '0');
  if (body.length !== 29) return fail('BAD_RECOVERY_CODE', 'wrong length');
  const raw = base32Decode(body, 18);
  if (!raw) return fail('BAD_RECOVERY_CODE', 'bad character or padding');
  const seed = raw.subarray(0, 16);
  if (!bytesEqual(raw.subarray(16), await recoveryChecksum(seed))) return fail('BAD_CHECKSUM');
  return new Uint8Array(seed);
}

/** True iff the text is a valid recovery code. Never throws. @experimental */
export async function isValidRecoveryCode(input: string): Promise<boolean> {
  try {
    await parseRecoveryCode(input);
    return true;
  } catch {
    return false;
  }
}

/** The root key pair and DID. @experimental */
export interface RootKey {
  /** The 32-byte Ed25519 private seed (HKDF output). */
  privateSeed: Uint8Array;
  publicKey: Uint8Array;
  /** `did:key:z6Mk...` of `publicKey` (hap-core `encodeDidKey`). */
  did: string;
}

/**
 * Root key from the 16-byte recovery seed: `HKDF-SHA256(ikm = seed, salt = "suveren-root-v1",
 * info = "ed25519", L = 32)` is the Ed25519 private seed.
 * @experimental
 */
export async function deriveRootKey(seed: Uint8Array): Promise<RootKey> {
  if (seed.length !== 16) return fail('MALFORMED', 'recovery seed must be 16 bytes');
  const privateSeed = await hkdfSha256(seed, 'suveren-root-v1', 'ed25519', 32);
  const publicKey = await ed25519PublicKey(privateSeed);
  return { privateSeed, publicKey, did: encodeDidKey(publicKey) };
}

/** Root key straight from the recovery code text. @experimental */
export async function rootKeyFromRecoveryCode(code: string): Promise<RootKey> {
  return deriveRootKey(await parseRecoveryCode(code));
}

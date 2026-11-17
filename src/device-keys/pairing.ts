/**
 * Pairing (plan 4.3): QR content, derived values, message MACs, comparison code, and the
 * identity code (4.4). Pure functions; the mailbox and the ceremony belong to the callers.
 *
 * @experimental
 */
import { fail } from './errors';
import {
  b64uBytes,
  b64uDecode,
  b64uEncode,
  bytesEqual,
  concat,
  hashBytes,
  hkdfSha256,
  hmacSha256,
  jcs,
  sameMembers,
  sha256,
  sha256Hash,
  signedBytes,
  utf8,
  utf8Decode,
} from './encoding';

/** @experimental */
export const PAIR_PREFIX = 'SUVEREN-PAIR-1:';

/** @experimental */
export interface PairingQr {
  v: 1;
  as_url: string;
  as_key: string;
  shown_by: 'admitter' | 'joiner';
  secret: string;
  root_did: string | null;
  head: { seq: number; hash: string } | null;
  key_id: string | null;
  expires_at: number;
}

/**
 * https only. `http` is allowed for `localhost` and `127.0.0.1` alone, because the dev and
 * test lanes run an Authority Server there.
 */
const AS_URL = /^(https:\/\/[^\s/?#]+|http:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?)(\/[^\s]*)?$/;

function isObj(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

/** Validate the QR object (exact members; nulls exactly when `shown_by` is `joiner`). @experimental */
export function validatePairingQr(o: unknown): PairingQr {
  if (!isObj(o)) return fail('MALFORMED', 'QR content must be an object');
  if (!sameMembers(o, ['v', 'as_url', 'as_key', 'shown_by', 'secret', 'root_did', 'head', 'key_id', 'expires_at'])) {
    return fail('MALFORMED', 'QR members');
  }
  if (o.v !== 1) return fail('MALFORMED', 'v');
  if (typeof o.as_url !== 'string' || !AS_URL.test(o.as_url)) return fail('MALFORMED', 'as_url must be an https:// address');
  if (typeof o.as_key !== 'string' || !/^[0-9a-f]{64}$/.test(o.as_key)) return fail('MALFORMED', 'as_key');
  b64uBytes(o.secret, 32, 'secret');
  if (typeof o.expires_at !== 'number' || !Number.isSafeInteger(o.expires_at)) return fail('MALFORMED', 'expires_at');
  if (o.shown_by === 'admitter') {
    if (typeof o.root_did !== 'string' || o.root_did.length === 0) return fail('MALFORMED', 'root_did');
    if (!isObj(o.head) || !sameMembers(o.head, ['hash', 'seq'])) return fail('MALFORMED', 'head');
    if (typeof o.head.seq !== 'number' || !Number.isSafeInteger(o.head.seq) || o.head.seq < 0) return fail('MALFORMED', 'head.seq');
    hashBytes(o.head.hash);
    b64uBytes(o.key_id, 32, 'key_id');
  } else if (o.shown_by === 'joiner') {
    if (o.root_did !== null || o.head !== null || o.key_id !== null) return fail('MALFORMED', 'joiner QR carries no chain facts');
  } else return fail('MALFORMED', 'shown_by');
  return o as unknown as PairingQr;
}

/** `SUVEREN-PAIR-1:` + base64url(utf8(JCS(qr))). @experimental */
export function encodePairingQr(qr: PairingQr): string {
  validatePairingQr(qr);
  return PAIR_PREFIX + b64uEncode(utf8(jcs(qr)));
}

/**
 * Decode the QR text. Refuses a wrong prefix, non-canonical base64url, JSON that is not its
 * own JCS form, wrong members, a missing `now`, and a QR past `expires_at` (`QR_EXPIRED`).
 * @experimental
 */
export function decodePairingQr(text: string, opts: { now: number }): PairingQr {
  if (!opts || typeof opts.now !== 'number' || !Number.isSafeInteger(opts.now)) return fail('MALFORMED', '`now` (epoch seconds) is required');
  if (typeof text !== 'string' || !text.startsWith(PAIR_PREFIX)) return fail('MALFORMED', 'not a pairing QR');
  const bytes = b64uDecode(text.slice(PAIR_PREFIX.length));
  const json = utf8Decode(bytes);
  let obj: unknown;
  try {
    obj = JSON.parse(json);
  } catch {
    return fail('MALFORMED', 'QR content is not JSON');
  }
  const qr = validatePairingQr(obj);
  if (jcs(qr) !== json) return fail('MALFORMED', 'QR content is not canonical JSON');
  if (opts.now > qr.expires_at) return fail('QR_EXPIRED');
  return qr;
}

/** QR lifetime: 10 minutes. @experimental */
export const PAIRING_TTL_SECONDS = 600;

/** Derived values: `pairing_id` (16 bytes, base64url) and `mac_key` (32 bytes). @experimental */
export async function derivePairing(secret: Uint8Array): Promise<{ pairingId: string; macKey: Uint8Array }> {
  if (secret.length !== 32) return fail('MALFORMED', 'secret must be 32 bytes');
  return {
    pairingId: b64uEncode(await hkdfSha256(secret, 'suveren-pair-v1', 'id', 16)),
    macKey: await hkdfSha256(secret, 'suveren-pair-v1', 'mac', 32),
  };
}

/** @experimental */
export type PairingKind = 'hello' | 'commit' | 'challenge' | 'open' | 'done';
/** @experimental */
export const PAIRING_KINDS: readonly PairingKind[] = ['hello', 'commit', 'challenge', 'open', 'done'];
/** @experimental */
export interface PairingMessage {
  kind: PairingKind;
  body: Record<string, unknown>;
  mac: string;
}

/** `mac = HMAC-SHA256(mac_key, utf8(kind) || 0x00 || utf8(JCS(body)))`, base64url. @experimental */
export async function pairingMac(macKey: Uint8Array, kind: string, body: unknown): Promise<string> {
  const data = concat(utf8(kind), Uint8Array.of(0), utf8(jcs(body)));
  return b64uEncode(await hmacSha256(macKey, data));
}

/** Build a MAC'd message. @experimental */
export async function buildPairingMessage(macKey: Uint8Array, kind: PairingKind, body: Record<string, unknown>): Promise<PairingMessage> {
  return { kind, body, mac: await pairingMac(macKey, kind, body) };
}

/**
 * Check the shape of a message, the shape of its body for its `kind`, and its MAC (constant
 * time). Throws MALFORMED or BAD_MAC.
 * @experimental
 */
export async function verifyPairingMessage(macKey: Uint8Array, msg: unknown): Promise<PairingMessage> {
  if (!isObj(msg) || !sameMembers(msg, ['body', 'kind', 'mac'])) return fail('MALFORMED', 'message members');
  if (!PAIRING_KINDS.includes(msg.kind as PairingKind)) return fail('MALFORMED', 'kind');
  if (!isObj(msg.body)) return fail('MALFORMED', 'body');
  const b = msg.body;
  const keys = (...k: string[]) => {
    if (!sameMembers(b, k)) fail('MALFORMED', `${msg.kind} body members`);
  };
  switch (msg.kind as PairingKind) {
    case 'hello':
      keys('root_did', 'head', 'key_id', 'as_key');
      if (typeof b.root_did !== 'string') return fail('MALFORMED', 'root_did');
      if (!isObj(b.head) || !sameMembers(b.head, ['hash', 'seq'])) return fail('MALFORMED', 'head');
      if (typeof b.head.seq !== 'number' || !Number.isSafeInteger(b.head.seq) || b.head.seq < 0) return fail('MALFORMED', 'head.seq');
      hashBytes(b.head.hash);
      b64uBytes(b.key_id, 32, 'key_id');
      if (typeof b.as_key !== 'string' || !/^[0-9a-f]{64}$/.test(b.as_key)) return fail('MALFORMED', 'as_key');
      break;
    case 'commit':
      keys('c');
      hashBytes(b.c);
      break;
    case 'challenge':
      keys('r_a');
      b64uBytes(b.r_a, 32, 'r_a');
      break;
    case 'open':
      keys('entry', 'sig', 'r_j');
      if (!isObj(b.entry)) return fail('MALFORMED', 'entry');
      b64uBytes(b.sig, 64, 'sig');
      b64uBytes(b.r_j, 32, 'r_j');
      break;
    case 'done':
      if ('refused' in b) {
        keys('refused');
        if (typeof b.refused !== 'string') return fail('MALFORMED', 'refused');
      } else {
        keys('entry_hash');
        hashBytes(b.entry_hash);
      }
      break;
  }
  const want = b64uDecode(await pairingMac(macKey, msg.kind as string, msg.body));
  const got = b64uBytes(msg.mac, 32, 'mac');
  if (!bytesEqual(want, got)) return fail('BAD_MAC');
  return msg as unknown as PairingMessage;
}

/**
 * The joiner's commitment (message 2): `c = sha256(signed bytes of the entry || joiner_sig ||
 * r_j)`, written `"sha256:" + hex`. `entry` is the `add` entry (any `sigs`/`checks` are ignored).
 * @experimental
 */
export async function pairingCommitment(entry: object, joinerSig: Uint8Array, rJ: Uint8Array): Promise<string> {
  return sha256Hash(concat(signedBytes(entry), joinerSig, rJ));
}

/**
 * Comparison code: 6 decimal digits, zero-padded: the first 4 bytes (big-endian, unsigned) of
 * `HMAC-SHA256(mac_key, "code" || 0x00 || signed bytes of the entry || r_j || r_a)` mod 1,000,000.
 * @experimental
 */
export async function comparisonCode(macKey: Uint8Array, entry: object, rJ: Uint8Array, rA: Uint8Array): Promise<string> {
  const mac = await hmacSha256(macKey, concat(utf8('code'), Uint8Array.of(0), signedBytes(entry), rJ, rA));
  const n = ((mac[0] << 24) >>> 0) + (mac[1] << 16) + (mac[2] << 8) + mac[3];
  return String(n % 1_000_000).padStart(6, '0');
}

/**
 * Identity code (4.4): 24 decimal digits in 6 groups of 4, from the first 80 bits of
 * `sha256("suveren-identity-code-v1" || root_did)` read as a big-endian integer, mod 10^24.
 * @experimental
 */
export async function identityCode(rootDid: string): Promise<string> {
  const digest = await sha256(concat(utf8('suveren-identity-code-v1'), utf8(rootDid)));
  let n = 0n;
  for (let i = 0; i < 10; i++) n = (n << 8n) | BigInt(digest[i]);
  const digits = (n % 10n ** 24n).toString().padStart(24, '0');
  return (digits.match(/.{4}/g) as string[]).join(' ');
}

/**
 * Checks (plan 3.1, DEC-47): a signature by a device's check key over the hash of one exact
 * object. Two types.
 *
 * Encodings fixed by this module (the plan left them open):
 *  - Every ECDSA signature on the wire is ASN.1 DER (what WebAuthn and the Secure Enclave
 *    produce). It is parsed strictly (minimal integers, no trailing bytes) and converted to
 *    the raw r || s that WebCrypto verifies. Raw r || s is NOT accepted on the wire.
 *  - `platform` `pub`: the uncompressed SEC1 point `0x04 || X || Y` (65 bytes, what WebCrypto
 *    `exportKey("raw")` and Apple's `x963Representation` give), base64url. Not SPKI.
 *  - `webauthn` `pub`: the COSE_Key (RFC 9052) CBOR bytes, base64url. Only EC2 / ES256 / P-256
 *    with exactly the five members kty, alg, crv, x, y is accepted.
 *  - The signed message of a `platform` check is the 32 raw SHA-256 digest bytes of the object
 *    hash (ECDSA hashes it once more with SHA-256, as is standard). The WebAuthn challenge is
 *    the same 32 bytes, base64url.
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
  sameMembers,
  sha256,
  subtle,
  utf8,
  utf8Decode,
} from './encoding';

/** @experimental */
export type CheckKey =
  | { type: 'webauthn'; rp_id: string; cred_id: string; pub: string }
  | { type: 'platform'; pub: string };

/** @experimental */
export type WebauthnProof = { authenticatorData: string; clientDataJSON: string; signature: string };
/** @experimental */
export type PlatformProof = { signature: string };
/** @experimental */
export type CheckProof = WebauthnProof | PlatformProof;

// ---------------------------------------------------------------------------
// DER <-> raw
// ---------------------------------------------------------------------------

function derInt(b: Uint8Array, pos: number): { value: Uint8Array; next: number } | null {
  if (b[pos] !== 0x02) return null;
  const len = b[pos + 1];
  if (len === undefined || len === 0 || len >= 0x80) return null;
  const start = pos + 2;
  if (start + len > b.length) return null;
  let v = b.subarray(start, start + len);
  if (v[0] & 0x80) return null; // negative
  if (v.length > 1 && v[0] === 0x00) {
    if (!(v[1] & 0x80)) return null; // non-minimal
    v = v.subarray(1);
  }
  if (v.length > 32) return null;
  return { value: v, next: start + len };
}

/** Strict DER ECDSA signature to 64 bytes r || s. Throws MALFORMED. @experimental */
export function ecdsaDerToRaw(der: Uint8Array): Uint8Array {
  if (der.length < 8 || der[0] !== 0x30 || der[1] >= 0x80 || der[1] !== der.length - 2) {
    return fail('MALFORMED', 'not a strict DER ECDSA signature');
  }
  const r = derInt(der, 2);
  const s = r && derInt(der, r.next);
  if (!r || !s || s.next !== der.length) return fail('MALFORMED', 'not a strict DER ECDSA signature');
  const out = new Uint8Array(64);
  out.set(r.value, 32 - r.value.length);
  out.set(s.value, 64 - s.value.length);
  return out;
}

/** 64 bytes r || s to minimal DER (used by authenticators and by test tooling). @experimental */
export function ecdsaRawToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) return fail('MALFORMED', 'raw ECDSA signature must be 64 bytes');
  const enc = (half: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < 31 && half[i] === 0) i++;
    let v = half.subarray(i);
    if (v[0] & 0x80) v = concat(Uint8Array.of(0), v);
    return concat(Uint8Array.of(0x02, v.length), v);
  };
  const body = concat(enc(raw.subarray(0, 32)), enc(raw.subarray(32)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

// ---------------------------------------------------------------------------
// COSE EC2 (minimal CBOR reader)
// ---------------------------------------------------------------------------

/** Read a CBOR head; supports only the shapes a COSE EC2 key uses. */
function cborHead(b: Uint8Array, pos: number): { major: number; arg: number; next: number } | null {
  if (pos >= b.length) return null;
  const major = b[pos] >> 5;
  const info = b[pos] & 31;
  if (info < 24) return { major, arg: info, next: pos + 1 };
  // one-byte argument: only for values 24 and up (shortest form, RFC 8949 4.2.1)
  if (info === 24) return pos + 1 < b.length && b[pos + 1] >= 24 ? { major, arg: b[pos + 1], next: pos + 2 } : null;
  return null;
}

/**
 * Decode a COSE_Key and return the uncompressed point `0x04 || x || y`. Accepts exactly a map
 * of kty 2 (EC2), alg -7 (ES256), crv 1 (P-256), x, y (32 bytes each). Throws MALFORMED.
 * @experimental
 */
export function coseEc2ToRawPoint(cose: Uint8Array): Uint8Array {
  const bad = (): never => fail('MALFORMED', 'not a COSE EC2 P-256 ES256 key');
  const h = cborHead(cose, 0);
  if (!h || h.major !== 5 || h.arg !== 5) return bad();
  let pos = h.next;
  const seen = new Map<number, number | Uint8Array>();
  let prevKeyByte = -1;
  for (let i = 0; i < 5; i++) {
    const k = cborHead(cose, pos);
    if (!k || (k.major !== 0 && k.major !== 1) || k.arg >= 24) return bad();
    // deterministic CBOR: map keys in ascending order of their encoding (1, 3, -1, -2, -3)
    if (cose[pos] <= prevKeyByte) return bad();
    prevKeyByte = cose[pos];
    const key = k.major === 0 ? k.arg : -1 - k.arg;
    if (seen.has(key)) return bad();
    pos = k.next;
    const v = cborHead(cose, pos);
    if (!v) return bad();
    if (v.major === 0 || v.major === 1) {
      seen.set(key, v.major === 0 ? v.arg : -1 - v.arg);
      pos = v.next;
    } else if (v.major === 2) {
      if (v.arg !== 32 || v.next + 32 > cose.length) return bad();
      seen.set(key, cose.subarray(v.next, v.next + 32));
      pos = v.next + 32;
    } else return bad();
  }
  if (pos !== cose.length) return bad();
  const x = seen.get(-2);
  const y = seen.get(-3);
  if (seen.get(1) !== 2 || seen.get(3) !== -7 || seen.get(-1) !== 1) return bad();
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) return bad();
  return concat(Uint8Array.of(0x04), x, y);
}

/** Encode P-256 x, y as a COSE_Key the way authenticators do (test tooling). @experimental */
export function encodeCoseEc2(x: Uint8Array, y: Uint8Array): Uint8Array {
  return concat(
    Uint8Array.of(0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20),
    x,
    Uint8Array.of(0x22, 0x58, 0x20),
    y,
  );
}

// ---------------------------------------------------------------------------
// Check keys and proofs
// ---------------------------------------------------------------------------

/**
 * Structural validation of a check key (MALFORMED on any defect). Does not test that the
 * point is on the curve; that is done when a proof is verified.
 * @experimental
 */
export function validateCheckKey(c: unknown): CheckKey {
  if (typeof c !== 'object' || c === null || Array.isArray(c)) return fail('MALFORMED', 'check key must be an object');
  const o = c as Record<string, unknown>;
  if (o.type === 'platform') {
    if (!sameMembers(o, ['pub', 'type'])) return fail('MALFORMED', 'platform check key members');
    const pub = b64uBytes(o.pub, 65, 'check.pub');
    if (pub[0] !== 0x04) return fail('MALFORMED', 'platform pub must be an uncompressed point');
    return { type: 'platform', pub: o.pub as string };
  }
  if (o.type === 'webauthn') {
    if (!sameMembers(o, ['cred_id', 'pub', 'rp_id', 'type'])) return fail('MALFORMED', 'webauthn check key members');
    if (typeof o.rp_id !== 'string' || o.rp_id.length === 0 || o.rp_id.length > 253) return fail('MALFORMED', 'rp_id');
    if (typeof o.cred_id !== 'string' || o.cred_id.length === 0) return fail('MALFORMED', 'cred_id');
    b64uDecode(o.cred_id);
    if (typeof o.pub !== 'string') return fail('MALFORMED', 'pub');
    coseEc2ToRawPoint(b64uDecode(o.pub));
    return { type: 'webauthn', rp_id: o.rp_id, cred_id: o.cred_id, pub: o.pub };
  }
  return fail('MALFORMED', 'unknown check type');
}

/** Structural validation of a proof against its key type. @experimental */
export function validateCheckProof(type: CheckKey['type'], p: unknown): CheckProof {
  if (typeof p !== 'object' || p === null || Array.isArray(p)) return fail('MALFORMED', 'check must be an object');
  const o = p as Record<string, unknown>;
  const bigString = Object.values(o).some((v) => typeof v !== 'string' || v.length > 4096);
  if (bigString) return fail('MALFORMED', 'check members must be strings of at most 4096 characters');
  if (type === 'platform') {
    if (!sameMembers(o, ['signature'])) return fail('MALFORMED', 'platform check members');
    b64uDecode(o.signature as string);
    return { signature: o.signature as string };
  }
  if (!sameMembers(o, ['authenticatorData', 'clientDataJSON', 'signature'])) return fail('MALFORMED', 'webauthn check members');
  for (const k of ['authenticatorData', 'clientDataJSON', 'signature']) b64uDecode(o[k] as string);
  return o as unknown as WebauthnProof;
}

async function verifyP256(rawPoint: Uint8Array, derSig: Uint8Array, data: Uint8Array): Promise<boolean> {
  const rs = ecdsaDerToRaw(derSig);
  const key = await subtle().importKey('raw', rawPoint, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'verify',
  ]);
  return subtle().verify({ name: 'ECDSA', hash: 'SHA-256' }, key, rs, data);
}

/**
 * Verify a check: `proof` is a signature by `check` over `hash` (an object hash string
 * `"sha256:..."`). Never throws; any defect gives false.
 *
 * `webauthn`: authenticatorData[0..32] = sha256(rp_id); flags UP (0x01) and UV (0x04) set;
 * clientDataJSON.type = "webauthn.get" and .challenge = base64url(32 digest bytes of `hash`);
 * ES256 signature over authenticatorData || sha256(clientDataJSON). The origin is not checked:
 * the relying-party id binds the credential.
 * `platform`: ECDSA P-256 / SHA-256 over the 32 digest bytes of `hash`.
 * @experimental
 */
export async function verifyCheck(check: CheckKey, hash: string, proof: unknown): Promise<boolean> {
  try {
    const key = validateCheckKey(check);
    const digest = hashBytes(hash);
    const p = validateCheckProof(key.type, proof);
    if (key.type === 'platform') {
      return await verifyP256(b64uDecode(key.pub), b64uDecode((p as PlatformProof).signature), digest);
    }
    const w = p as WebauthnProof;
    const authData = b64uDecode(w.authenticatorData);
    const cdj = b64uDecode(w.clientDataJSON);
    if (authData.length < 37) return false;
    if (!bytesEqual(authData.subarray(0, 32), await sha256(utf8(key.rp_id)))) return false;
    const flags = authData[32];
    if ((flags & 0x01) === 0 || (flags & 0x04) === 0) return false;
    const client = JSON.parse(utf8Decode(cdj)) as { type?: unknown; challenge?: unknown };
    if (client.type !== 'webauthn.get') return false;
    if (client.challenge !== b64uEncode(digest)) return false;
    const data = concat(authData, await sha256(cdj));
    return await verifyP256(coseEc2ToRawPoint(b64uDecode(key.pub)), b64uDecode(w.signature), data);
  } catch {
    return false;
  }
}

/**
 * did:key — encode/decode for KEY-BEARING DIDs (HAP v0.6).
 *
 * A real `did:key` is self-certifying: the public key IS the identifier, so
 * substituting the key produces a DIFFERENT DID and no key directory is ever
 * consulted. That property is what the Owner Mandate design stands on
 * (protocol.md → "Identity DIDs vs signing DIDs"): a signing DID MUST be
 * key-bearing, and verification uses the key carried in the identifier —
 * deliberately, there is no `public_key` field anywhere on the wire.
 *
 * Format (W3C did:key method, Ed25519):
 *   did:key:z<base58btc( 0xed 0x01 ‖ 32-byte-public-key )>
 * `z` is the multibase prefix for base58btc; `0xed 0x01` is the multicodec
 * varint for ed25519-pub. The result always starts `did:key:z6Mk`.
 *
 * Scope: Ed25519 only — the one signing curve this protocol version uses.
 * Anything else (including the reference implementation's legacy decorative
 * `did:key:<uuid-fragment>` identifiers) decodes as NOT key-bearing.
 */

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_MAP: Record<string, number> = {};
for (let i = 0; i < B58_ALPHABET.length; i++) B58_MAP[B58_ALPHABET[i]] = i;

/** multicodec ed25519-pub (0xed) as unsigned varint, followed by key bytes. */
const ED25519_MULTICODEC = Uint8Array.from([0xed, 0x01]);
const ED25519_KEY_BYTES = 32;

function base58btcEncode(bytes: Uint8Array): string {
  // Count leading zero bytes — they encode as leading '1's.
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] * 256;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let out = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += B58_ALPHABET[digits[i]];
  return out;
}

function base58btcDecode(s: string): Uint8Array {
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;

  const bytes: number[] = [];
  for (let i = zeros; i < s.length; i++) {
    const val = B58_MAP[s[i]];
    if (val === undefined) throw new Error(`invalid base58 character "${s[i]}"`);
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[zeros + i] = bytes[bytes.length - 1 - i];
  return out;
}

/** Encode a 32-byte Ed25519 public key as a key-bearing `did:key:z6Mk…`. */
export function encodeDidKey(publicKey: Uint8Array): string {
  if (publicKey.length !== ED25519_KEY_BYTES) {
    throw new Error(`INVALID_KEY: expected ${ED25519_KEY_BYTES} bytes, got ${publicKey.length}`);
  }
  const prefixed = new Uint8Array(ED25519_MULTICODEC.length + publicKey.length);
  prefixed.set(ED25519_MULTICODEC, 0);
  prefixed.set(publicKey, ED25519_MULTICODEC.length);
  return `did:key:z${base58btcEncode(prefixed)}`;
}

/**
 * Decode a key-bearing `did:key` to its Ed25519 public key bytes.
 *
 * @throws Error prefixed `NOT_KEY_BEARING:` for anything that is not a valid
 * base58btc-multibase Ed25519 did:key — including the legacy decorative
 * `did:key:<uuid-fragment>` identifiers, other multibase prefixes, and other
 * key types. The error name is the point: under the mandate design, a
 * non-key-bearing signing DID must fail STRUCTURALLY, never fall back.
 */
export function decodeDidKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) {
    throw new Error(`NOT_KEY_BEARING: ${JSON.stringify(did)} is not a base58btc did:key`);
  }
  let decoded: Uint8Array;
  try {
    decoded = base58btcDecode(did.slice('did:key:z'.length));
  } catch (err) {
    throw new Error(`NOT_KEY_BEARING: ${(err as Error).message}`);
  }
  if (
    decoded.length !== ED25519_MULTICODEC.length + ED25519_KEY_BYTES ||
    decoded[0] !== ED25519_MULTICODEC[0] ||
    decoded[1] !== ED25519_MULTICODEC[1]
  ) {
    throw new Error('NOT_KEY_BEARING: not an ed25519-pub multicodec payload');
  }
  return decoded.slice(ED25519_MULTICODEC.length);
}

/** True iff the DID decodes as a key-bearing Ed25519 did:key. Never throws. */
export function isKeyBearingDid(did: string): boolean {
  try {
    decodeDidKey(did);
    return true;
  } catch {
    return false;
  }
}

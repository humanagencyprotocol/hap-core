/**
 * base64url (RFC 4648 §5), strict — no padding, no standard-base64 characters.
 *
 * protocol.md → *Mandate Payload* rule 3: "Signatures MUST be encoded as
 * base64url without padding ... Implementations MUST NOT use standard base64
 * (which differs in `+`/`/` vs `-`/`_` and in padding) — third-party verifiers
 * reading the spec literally will reject standard-base64 signatures."
 *
 * Earlier hap-core verifiers were lenient: they translated `+`/`/` back from
 * `-`/`_` and re-added padding before decoding, so a standard-base64 signature
 * verified exactly as well as a base64url one — silently accepting the wire
 * format the spec forbids. v0.7 closes that: decoding a string that is not
 * strict base64url throws, never silently repairs it.
 */

const STRICT_B64URL = /^[A-Za-z0-9_-]*$/;
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const INDEX = new Map<string, number>([...ALPHABET].map((c, i) => [c, i]));

/** Encode bytes as base64url with no padding. Plain TypeScript: no Node `Buffer`, so it loads in a browser. */
export function toBase64Url(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63] + ALPHABET[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63];
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63];
  }
  return out;
}

/**
 * Decode a STRICT base64url string (no padding, no `+`/`/`/`=`).
 *
 * @throws Error (no protocol code — the caller knows which artifact it was
 * decoding and assigns the code) when the input carries a `+`, `/`, `=`, or
 * any other byte outside the base64url alphabet.
 */
export function fromBase64Url(s: string): Uint8Array {
  if (!STRICT_B64URL.test(s)) {
    throw new Error(
      `${JSON.stringify(s)} is not strict base64url — standard base64 ` +
        '("+"/"/"/padding) is retired (protocol.md → Mandate Payload, rule 3).',
    );
  }
  // Decoded as Node's Buffer did before 0.17.0 (kept byte for byte, test/base64url.test.ts): a length of
  // 1 mod 4 drops its last character, and the unused low bits of the last character are ignored.
  const full = s.length - (s.length % 4 === 1 ? 1 : 0);
  const out = new Uint8Array(Math.floor((full * 6) / 8));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < full; i++) {
    acc = (acc << 6) | (INDEX.get(s[i]) as number);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
    acc &= (1 << bits) - 1;
  }
  return out;
}

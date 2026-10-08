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

/** Encode bytes as base64url with no padding. */
export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
  const padding = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return new Uint8Array(Buffer.from(s + padding, 'base64'));
}

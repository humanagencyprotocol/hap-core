/**
 * JCS — JSON Canonicalization (RFC 8785) for signing.
 *
 * Both attestation and receipt signatures are computed over a canonical byte
 * serialization of the payload, so that two independent implementations (an AS,
 * a gateway, an external verifier — in any language) agree on exactly which
 * bytes were signed regardless of how they happened to construct the object.
 *
 * `JSON.stringify` is NOT sufficient: it preserves key *insertion* order, so the
 * same logical payload built with keys in a different order serializes to
 * different bytes and the signature fails to verify. Canonicalization removes
 * that dependency by sorting keys.
 *
 * This is RFC 8785-compatible and matches the v0.5 spec's normative signing
 * canonicalization (core.md "Signing Canonicalization"):
 *   1. UTF-8.
 *   2. Object keys sorted (RFC 8785 sorts by UTF-16 code units — exactly what
 *      JavaScript's default String comparison does, so `Object.keys().sort()` is
 *      correct here).
 *   3. No insignificant whitespace.
 *   4. Numbers in the shortest round-trippable form — the ECMAScript
 *      Number-to-String algorithm, which `JSON.stringify(number)` produces and
 *      RFC 8785 adopts verbatim.
 *   5. Strings escaped per RFC 8259; non-ASCII passed through as UTF-8 (this is
 *      `JSON.stringify`'s behaviour for strings).
 *   6. Array order preserved.
 *
 * Because it relies only on `JSON.stringify` for leaves plus `Object.keys`,
 * `Array`, and `String` sort — all of which are environment-independent in
 * JavaScript — Node and the browser produce byte-identical output. The
 * conformance test pins a (payload → canonical bytes) vector that any other
 * implementation can check against.
 */
export function canonicalize(value: unknown): string {
  if (value === undefined) {
    throw new Error('canonicalize: undefined is not serializable');
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new Error(`canonicalize: ${value} is not a valid JSON number`);
  }

  // Primitives: string, finite number, boolean, null — JSON.stringify is already
  // canonical (RFC 8259 string escaping, ECMAScript number formatting).
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    // Array order is preserved; undefined elements become null (matching
    // JSON.stringify), which keeps array length stable across serializers.
    const items = value.map((el) => (el === undefined ? 'null' : canonicalize(el)));
    return '[' + items.join(',') + ']';
  }

  // Plain object: sort keys, omit undefined-valued properties (as JSON.stringify
  // does), recurse on values.
  const obj = value as Record<string, unknown>;
  const parts: string[] = [];
  for (const key of Object.keys(obj).sort()) {
    const v = obj[key];
    if (v === undefined) continue;
    parts.push(JSON.stringify(key) + ':' + canonicalize(v));
  }
  return '{' + parts.join(',') + '}';
}

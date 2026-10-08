/**
 * JCS canonicalization (RFC 8785) — conformance.
 *
 * The point of canonicalization is that the bytes depend only on the *data*,
 * never on key insertion order or which implementation produced the object.
 * These tests pin that contract, including a published signing test vector
 * (payload → canonical bytes → signature) that any other implementation — in
 * any language, or a browser build of this library — can check itself against.
 */
import { describe, it, expect } from 'vitest';
import * as ed from '@noble/ed25519';
import { canonicalize } from '../src/canonicalize';

describe('canonicalize — RFC 8785 rules', () => {
  it('sorts object keys (the core difference from JSON.stringify)', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    // JSON.stringify would preserve insertion order — prove they differ.
    expect(JSON.stringify({ b: 1, a: 2 })).toBe('{"b":1,"a":2}');
  });

  it('is independent of key insertion order', () => {
    const a = { profile_id: 'charge@0.4', bounds_hash: 'sha256:x', commitment_mode: 'automatic' };
    const b = { commitment_mode: 'automatic', bounds_hash: 'sha256:x', profile_id: 'charge@0.4' };
    expect(canonicalize(a)).toBe(canonicalize(b));
  });

  it('sorts nested object keys but preserves array order', () => {
    expect(canonicalize({ list: [{ z: 1, a: 2 }, { b: 3 }] })).toBe('{"list":[{"a":2,"z":1},{"b":3}]}');
  });

  it('emits no insignificant whitespace', () => {
    expect(canonicalize({ a: 1, b: [1, 2] })).toBe('{"a":1,"b":[1,2]}');
  });

  it('omits undefined-valued properties (matching JSON.stringify)', () => {
    expect(canonicalize({ a: 1, b: undefined, c: 3 })).toBe('{"a":1,"c":3}');
  });

  it('serializes integers without a decimal point and passes non-ASCII through', () => {
    expect(canonicalize({ n: 100, s: 'café' })).toBe('{"n":100,"s":"café"}');
  });

  it('rejects non-finite numbers', () => {
    expect(() => canonicalize({ n: NaN })).toThrow();
    expect(() => canonicalize({ n: Infinity })).toThrow();
  });

  it('round-trips through Ed25519 sign/verify, order-independently', async () => {
    // Generic proof the mechanism works end to end — the SPEC's own
    // signing vectors (payload → canonical bytes → signature, under
    // published test keys) live at test/vectors/payload-signatures.test.ts,
    // reading content/0.7/vectors/payload-signatures.json rather than a
    // copy of its values kept here (vectors/README.md → *Provenance*:
    // "the reference core library is required to consume these files in
    // its tests rather than carry its own copies").
    const payload = { b: 1, a: 2, nested: { z: 'y', x: 'w' } };
    const priv = ed.utils.randomPrivateKey();
    const pub = await ed.getPublicKeyAsync(priv);
    const bytes = new TextEncoder().encode(canonicalize(payload));
    const sig = await ed.signAsync(bytes, priv);

    // A verifier that rebuilt the payload in a DIFFERENT key order still
    // verifies, because canonicalization makes the bytes identical.
    const reordered = { nested: { x: 'w', z: 'y' }, a: 2, b: 1 };
    const reBytes = new TextEncoder().encode(canonicalize(reordered));
    expect(await ed.verifyAsync(sig, reBytes, pub)).toBe(true);

    // Tampering with a value breaks verification.
    const tampered = { ...payload, a: 999 };
    const tBytes = new TextEncoder().encode(canonicalize(tampered));
    expect(await ed.verifyAsync(sig, tBytes, pub)).toBe(false);
  });
});

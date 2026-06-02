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
});

describe('canonicalize — signing test vector (cross-implementation conformance)', () => {
  // A representative v0.5 attestation payload. Keys are deliberately NOT in
  // sorted order here, to prove canonicalization reorders them.
  const PAYLOAD = {
    attestation_id: '11111111-1111-4111-8111-111111111111',
    version: '0.5',
    profile_id: 'charge@0.4',
    bounds_hash: 'sha256:aaaa',
    context_hash: 'sha256:bbbb',
    execution_context_hash: 'sha256:cccc',
    resolved_domains: [{ domain: 'owner', did: 'did:test:alice' }],
    gate_content_hashes: { intent: 'sha256:dddd' },
    commitment_mode: 'automatic',
    issued_at: 1700000000,
    expires_at: 1700003600,
  };

  // THE VECTOR — canonical bytes for the payload above. Other implementations
  // MUST reproduce this exact string. (Keys sorted; resolved_domains entry
  // reordered to {did, domain}.)
  const CANONICAL =
    '{"attestation_id":"11111111-1111-4111-8111-111111111111",' +
    '"bounds_hash":"sha256:aaaa",' +
    '"commitment_mode":"automatic",' +
    '"context_hash":"sha256:bbbb",' +
    '"execution_context_hash":"sha256:cccc",' +
    '"expires_at":1700003600,' +
    '"gate_content_hashes":{"intent":"sha256:dddd"},' +
    '"issued_at":1700000000,' +
    '"profile_id":"charge@0.4",' +
    '"resolved_domains":[{"did":"did:test:alice","domain":"owner"}],' +
    '"version":"0.5"}';

  it('produces the published canonical bytes', () => {
    expect(canonicalize(PAYLOAD)).toBe(CANONICAL);
  });

  it('round-trips through Ed25519 sign/verify, order-independently', async () => {
    const priv = ed.utils.randomPrivateKey();
    const pub = await ed.getPublicKeyAsync(priv);
    const bytes = new TextEncoder().encode(canonicalize(PAYLOAD));
    const sig = await ed.signAsync(bytes, priv);

    // A verifier that rebuilt the payload in a DIFFERENT key order still
    // verifies, because canonicalization makes the bytes identical.
    const reordered = {
      version: '0.5',
      expires_at: 1700003600,
      issued_at: 1700000000,
      commitment_mode: 'automatic',
      gate_content_hashes: { intent: 'sha256:dddd' },
      resolved_domains: [{ domain: 'owner', did: 'did:test:alice' }],
      execution_context_hash: 'sha256:cccc',
      context_hash: 'sha256:bbbb',
      bounds_hash: 'sha256:aaaa',
      profile_id: 'charge@0.4',
      attestation_id: '11111111-1111-4111-8111-111111111111',
    };
    const reBytes = new TextEncoder().encode(canonicalize(reordered));
    expect(await ed.verifyAsync(sig, reBytes, pub)).toBe(true);

    // Tampering with a value breaks verification.
    const tampered = { ...PAYLOAD, expires_at: 1700003601 };
    const tBytes = new TextEncoder().encode(canonicalize(tampered));
    expect(await ed.verifyAsync(sig, tBytes, pub)).toBe(false);
  });
});

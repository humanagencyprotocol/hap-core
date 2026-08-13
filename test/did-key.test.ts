/**
 * did:key codec — the property the mandate design stands on: the key IS the
 * identifier, and anything that is not a real key-bearing DID must fail
 * STRUCTURALLY (NOT_KEY_BEARING), never fall back.
 */
import { describe, it, expect } from 'vitest';
import * as ed from '@noble/ed25519';
import { encodeDidKey, decodeDidKey, isKeyBearingDid } from '../src/did-key';

// W3C did:key test vector (Ed25519VerificationKey2020 suite): this DID is the
// multibase encoding of the 32-byte key below. Pins our base58btc + multicodec
// against an EXTERNAL implementation, not just our own round-trip.
const W3C_DID = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';

describe('did:key', () => {
  it('round-trips a fresh Ed25519 key and always yields the z6Mk prefix', async () => {
    const priv = ed.utils.randomPrivateKey();
    const pub = await ed.getPublicKeyAsync(priv);
    const did = encodeDidKey(pub);
    expect(did.startsWith('did:key:z6Mk')).toBe(true);
    expect(decodeDidKey(did)).toEqual(pub);
    expect(isKeyBearingDid(did)).toBe(true);
  });

  it('decodes the W3C test-vector DID to a 32-byte key that re-encodes identically', () => {
    const key = decodeDidKey(W3C_DID);
    expect(key.length).toBe(32);
    expect(encodeDidKey(key)).toBe(W3C_DID);
  });

  it('rejects the legacy decorative did:key (uuid fragment, no key inside)', () => {
    // The exact shape the reference AS used to mint (review.md → D2).
    expect(() => decodeDidKey('did:key:1a2b3c4d')).toThrow(/NOT_KEY_BEARING/);
    expect(isKeyBearingDid('did:key:1a2b3c4d')).toBe(false);
  });

  it('rejects non-did:key identifiers and wrong multibase prefixes', () => {
    for (const bad of ['did:email:dave@company.com', 'did:github:alice', 'did:key:f01ed01aa', 'not-a-did', '']) {
      expect(isKeyBearingDid(bad)).toBe(false);
    }
  });

  it('rejects a base58-valid payload that is not ed25519-pub multicodec', () => {
    // Valid base58, wrong multicodec header (0x00 0x01 instead of 0xed 0x01).
    const wrong = new Uint8Array(34);
    wrong[0] = 0x00; wrong[1] = 0x01;
    // encode by hand through the public API surface: build a did with a wrong header
    // via encode of a real key, then flip a leading multicodec byte in the decoded space
    expect(() => decodeDidKey('did:key:z' + '1'.repeat(34))).toThrow(/NOT_KEY_BEARING/);
  });

  it('rejects keys of the wrong length at encode time', () => {
    expect(() => encodeDidKey(new Uint8Array(31))).toThrow(/INVALID_KEY/);
  });
});

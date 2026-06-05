/**
 * Content binding (HAP v0.5 Content Provenance) — conformance.
 *
 * Pins the (content → canonical bytes → sha256) contract so an independent
 * verifier in any language reproduces the exact hash the gateway signs into a
 * receipt. The hash is worthless if both sides don't agree on the bytes.
 */
import { describe, it, expect } from 'vitest';
import {
  canonicalizeText,
  contentCanonicalBytes,
  computeContentHash,
} from '../src/content-binding';

describe('canonicalizeText — text normalization rule', () => {
  it('normalizes CRLF and CR to LF', () => {
    expect(canonicalizeText('a\r\nb\rc')).toBe('a\nb\nc');
  });

  it('strips trailing per-line whitespace and trailing blank lines', () => {
    expect(canonicalizeText('a  \nb\t\n\n\n')).toBe('a\nb');
  });

  it('applies Unicode NFC (composed form wins)', () => {
    // "é" as e + combining acute (NFD) must normalize to the single code point.
    const nfd = 'é';
    const nfc = 'é';
    expect(canonicalizeText(nfd)).toBe(nfc);
    expect(canonicalizeText(nfd)).toBe(canonicalizeText(nfc));
  });

  it('is idempotent', () => {
    const once = canonicalizeText('  héllo \r\nwörld\n\n');
    expect(canonicalizeText(once)).toBe(once);
  });
});

describe('computeContentHash — pinned vectors', () => {
  it('jcs: sorts keys then hashes (order-independent)', () => {
    const a = computeContentHash({ version: '1', kind: 'jcs' }, { title: 'Q3 plan', type: 'note' });
    const b = computeContentHash({ version: '1', kind: 'jcs' }, { type: 'note', title: 'Q3 plan' });
    expect(a).toBe('sha256:82c28e63f951c1ac68080788fda46be42b2128f80c43dbc01d5c3b160a09717f');
    expect(a).toBe(b); // key order in the input must not change the hash
  });

  it('text: hashes the canonicalized string', () => {
    expect(computeContentHash({ version: '1', kind: 'text' }, 'Hello\r\nWorld  '))
      .toBe('sha256:35c6b9f66dceb6cf8f733d08689564e420e18eb40250d9435352617c027f36d6');
  });

  it('text: empty string hashes the sha256 of ""', () => {
    expect(computeContentHash({ version: '1', kind: 'text' }, ''))
      .toBe('sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});

describe('computeContentHash — kind/content mismatch fails closed', () => {
  it('jcs rejects a string', () => {
    expect(() => computeContentHash({ version: '1', kind: 'jcs' }, 'oops' as unknown as Record<string, unknown>))
      .toThrow(/jcs.*record payload/);
  });

  it('text rejects an object', () => {
    expect(() => computeContentHash({ version: '1', kind: 'text' }, { x: 1 } as unknown as string))
      .toThrow(/text.*string/);
  });

  it('contentCanonicalBytes exposes the exact bytes both sides hash', () => {
    expect(contentCanonicalBytes('jcs', { b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });
});

/**
 * The hand-written SHA-256 (src/sha256.ts) against Node's own: FIPS 180-4 vectors, every length
 * from 0 to 300 bytes (all padding boundaries), random inputs, and strings with non-ASCII text.
 */
import { createHash, randomBytes } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import { sha256, sha256Hex } from '../src/sha256';

const node = (b: Uint8Array | string) => createHash('sha256').update(b as never, typeof b === 'string' ? 'utf8' : undefined).digest('hex');

describe('sha256', () => {
  it('FIPS 180-4 vectors', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(sha256Hex('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))
      .toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
    expect(sha256Hex('a'.repeat(1_000_000))).toBe('cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
  });
  it('equals Node for every length 0..300', () => {
    for (let n = 0; n <= 300; n++) {
      const b = randomBytes(n);
      expect(sha256Hex(b)).toBe(node(b));
    }
  });
  it('equals Node for random inputs up to 100 kB', () => {
    for (let k = 0; k < 50; k++) {
      const b = randomBytes(Math.floor(Math.random() * 100_000));
      expect(sha256Hex(b)).toBe(node(b));
    }
  });
  it('hashes a string as its UTF-8 bytes, like Node', () => {
    for (const s of ['Grüße', '日本語', '😀 emoji', '\u0000nul', 'lone \ud800 surrogate', JSON.stringify({ a: 'ä', b: [1, 2] })]) {
      expect(sha256Hex(s)).toBe(node(s));
    }
  });
  it('returns 32 bytes', () => {
    expect(sha256('x')).toHaveLength(32);
  });
});

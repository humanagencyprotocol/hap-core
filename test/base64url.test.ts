/**
 * base64url without Node's Buffer (0.17.0) decodes and encodes exactly as the Buffer version did,
 * and still refuses standard base64.
 */
import { randomBytes } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import { toBase64Url, fromBase64Url } from '../src/base64url';

const oldEncode = (b: Uint8Array) => Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const oldDecode = (s: string) => {
  const padding = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return new Uint8Array(Buffer.from(s + padding, 'base64'));
};
const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

describe('base64url', () => {
  it('encodes like the Buffer version, every length 0..200', () => {
    for (let n = 0; n <= 200; n++) {
      const b = randomBytes(n);
      expect(toBase64Url(b)).toBe(oldEncode(b));
      expect(fromBase64Url(toBase64Url(b))).toEqual(new Uint8Array(b));
    }
  });
  it('decodes any strict string like the Buffer version (non-canonical tails included)', () => {
    for (let k = 0; k < 2000; k++) {
      const len = Math.floor(Math.random() * 40);
      let s = '';
      for (let i = 0; i < len; i++) s += ALPHA[Math.floor(Math.random() * 64)];
      expect(fromBase64Url(s)).toEqual(oldDecode(s));
    }
  });
  it('still refuses standard base64', () => {
    for (const s of ['ab+c', 'ab/c', 'abc=', 'a b']) expect(() => fromBase64Url(s)).toThrow(/not strict base64url/);
  });
});

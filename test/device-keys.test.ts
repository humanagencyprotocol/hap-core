/**
 * Device keys (experimental): runs the shared JSON vectors against the source, and checks
 * that the vectors cover every error name and the strict-signature cases.
 *
 * The same vectors run unchanged against the built bundle (`run-node.mjs`) and in browsers.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import * as ed from '@noble/ed25519';
import * as core from '../src/index';
import * as dk from '../src/device-keys/index';
// @ts-expect-error plain ESM without types
import { runVectors, VECTOR_FILES } from './vectors/device-keys/runner.mjs';

const DIR = join(__dirname, 'vectors', 'device-keys');
const files = VECTOR_FILES.map((f: string) => JSON.parse(readFileSync(join(DIR, f), 'utf8')));

const ERROR_NAMES = [
  'MALFORMED', 'WRONG_ROOT', 'BAD_SEQ', 'BAD_PREV', 'BAD_OP', 'BAD_KEY_ID', 'KEY_REUSED', 'NO_POSSESSION',
  'NOT_AUTHORISED', 'CHECK_REQUIRED', 'BAD_TARGET', 'NO_GRANTING_DEVICE', 'TOO_MANY_DEVICES', 'ROLLBACK', 'FORK',
];

describe('device-keys vectors (source)', async () => {
  const results = await runVectors(dk, files);
  it('has vectors', () => expect(results.length).toBeGreaterThan(100));
  for (const r of results as { suite: string; id: string; ok: boolean; detail: string }[]) {
    it(`${r.suite} / ${r.id}`, () => expect(r.detail).toBe(''));
  }
});

describe('device-keys vector coverage', () => {
  const chain = files.find((f: any) => f.suite === 'device-keys/chain');
  const expected = (f: any) => f.cases.map((c: any) => c.expect.error).filter(Boolean);
  it('every chain error name has a negative vector', () => {
    const have = new Set(expected(chain));
    for (const n of ERROR_NAMES) expect(have.has(n), `no vector for ${n}`).toBe(true);
  });
  it('has positive chain vectors for every op', () => {
    const ids = chain.cases.map((c: any) => c.id).join(' ');
    for (const part of ['genesis', 'add', 'set', 'remove', 'rotate-root', 'reset', 'ext']) expect(ids).toContain(part);
  });
  it('has the rotate-root case: old root signs after rotation is refused', () => {
    const c = chain.cases.find((x: any) => x.id === 'rotate-root-old-root-signs-after');
    expect(c.expect.error).toBe('NOT_AUTHORISED');
  });
  it('covers the strict Ed25519 cases of rule 2.4', () => {
    const strict = files.find((f: any) => f.suite === 'device-keys/ed25519-strict');
    const ids = strict.cases.map((c: any) => c.id);
    for (const id of ['non-canonical-S', 'non-canonical-point-key', 'small-order-key-identity', 'small-order-key-order-4', 'non-canonical-R']) {
      expect(ids).toContain(id);
    }
  });
  it('the strict vectors are meaningful: a ZIP-215 verifier accepts the small-order case', async () => {
    const strict = files.find((f: any) => f.suite === 'device-keys/ed25519-strict');
    const c = strict.cases.find((x: any) => x.id === 'small-order-key-identity').input;
    const h = (s: string) => dk.hexDecode(s);
    const zip215 = await ed.verifyAsync(h(c.signature_hex), h(c.message_hex), h(c.public_key_hex), { zip215: true });
    expect(zip215).toBe(true);
    expect(await dk.verifyEd25519(h(c.public_key_hex), h(c.message_hex), h(c.signature_hex))).toBe(false);
  });
  it('covers both check types, with the UV flag, rp id, type and challenge refusals', () => {
    const checks = files.find((f: any) => f.suite === 'device-keys/checks');
    const ids = checks.cases.map((c: any) => c.id).join(' ');
    for (const part of ['platform-valid', 'webauthn-valid', 'webauthn-no-uv', 'webauthn-wrong-rp-hash', 'webauthn-wrong-type', 'webauthn-wrong-challenge', 'platform-raw-signature-refused']) {
      expect(ids).toContain(part);
    }
  });
});

describe('device-keys direct API', () => {
  it('recovery code: random round trip, 29 characters in groups of 4', async () => {
    const { seed, code } = await dk.generateRecoveryCode();
    expect(code).toMatch(/^SV1-([0-9A-Z]{4}-){6}[0-9A-Z]{4}-[0-9A-Z]$/);
    expect(await dk.parseRecoveryCode(code)).toEqual(seed);
    expect(await dk.isValidRecoveryCode(code)).toBe(true);
    const root = await dk.rootKeyFromRecoveryCode(code);
    expect(root.did.startsWith('did:key:z6Mk')).toBe(true);
    expect(core.decodeDidKey(root.did)).toEqual(root.publicKey);
  });
  it('errors carry a code', async () => {
    await expect(dk.parseRecoveryCode('nope')).rejects.toMatchObject({ code: 'BAD_RECOVERY_CODE' });
    expect(new dk.DeviceKeysError('X').code).toBe('X');
  });
  it('is exported as a namespace and leaves the existing exports alone', () => {
    expect(typeof (core as any).deviceKeys.verifyChain).toBe('function');
    for (const n of ['canonicalize', 'encodeDidKey', 'verifyTicketSignature', 'toBase64Url']) expect(typeof (core as any)[n]).toBe('function');
    expect((core as any).verifyChain).toBeUndefined();
  });
  it('COSE encode/decode round trip', () => {
    const x = new Uint8Array(32).fill(1);
    const y = new Uint8Array(32).fill(2);
    expect(dk.coseEc2ToRawPoint(dk.encodeCoseEc2(x, y))).toEqual(Uint8Array.from([4, ...x, ...y]));
  });
  it('DER <-> raw round trip for random signatures', () => {
    for (let i = 0; i < 50; i++) {
      const raw = dk.randomBytes(64);
      if (i % 5 === 0) raw.fill(0, 0, 3);
      expect(dk.ecdsaDerToRaw(dk.ecdsaRawToDer(raw))).toEqual(raw);
    }
  });
});

describe('device-keys source stays portable', () => {
  it('no Node-only import, Buffer or process in src/device-keys', () => {
    const dir = join(__dirname, '..', 'src', 'device-keys');
    for (const f of readdirSync(dir)) {
      const text = readFileSync(join(dir, f), 'utf8');
      expect(text, f).not.toMatch(/from ['"]node:|require\(|\bBuffer\b|\bprocess\./);
    }
  });
});

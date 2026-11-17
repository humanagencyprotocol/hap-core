/**
 * Hardening after the independent review (M1, M2, L1, L2, L4 to L8). Each test failed
 * against the code before the fix.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as dk from '../src/device-keys/index';

const DIR = join(__dirname, 'vectors', 'device-keys');
const objects = JSON.parse(readFileSync(join(DIR, 'objects.json'), 'utf8'));
const chainFile = JSON.parse(readFileSync(join(DIR, 'chain.json'), 'utf8'));
const ROOT = objects.fixtures.root_did as string;
const MAIN = objects.fixtures.chains.main as any[];
const verified = (n: number) => dk.verifyChain({ expectedRootDid: ROOT, entries: MAIN.slice(0, n) });
const caseInput = (id: string) => objects.cases.find((c: any) => c.id === id).input;
const code = async (p: Promise<unknown>) => p.then(() => 'OK', (e) => e.code ?? `PLAIN:${e.message}`);

describe('M1 grant and decision expectations', () => {
  const g = caseInput('grant-by-computer-with-platform-check');
  const grantExpect = { ops: ['grant', 'change'], mandate_id: 'mand-1', mandate_version: 2 };
  it('a revoke without a check cannot be read as a grant', async () => {
    const r = caseInput('grant-revoke-without-check');
    const chain = await verified(r.chain.count);
    const ctx = { chain, mandateFields: r.mandate_fields };
    expect(await code(dk.verifyGrant(r.envelope, { ...ctx, expect: grantExpect } as any))).toBe('GRANT_MISMATCH');
    expect(await code(dk.verifyGrant(r.envelope, { ...ctx, expect: { ...grantExpect, ops: ['revoke'] } } as any))).toBe('OK');
  });
  it('a genuine grant for mandate m1 is refused for m2 and for another version', async () => {
    const chain = await verified(g.chain.count);
    const ctx = { chain, mandateFields: g.mandate_fields };
    expect(await code(dk.verifyGrant(g.envelope, { ...ctx, expect: grantExpect } as any))).toBe('OK');
    expect(await code(dk.verifyGrant(g.envelope, { ...ctx, expect: { ...grantExpect, mandate_id: 'm2' } } as any))).toBe('GRANT_MISMATCH');
    expect(await code(dk.verifyGrant(g.envelope, { ...ctx, expect: { ...grantExpect, mandate_version: 1 } } as any))).toBe('GRANT_MISMATCH');
  });
  it('expect is required by verifyGrant and verifyDecision', async () => {
    const chain = await verified(g.chain.count);
    expect(await code(dk.verifyGrant(g.envelope, { chain, mandateFields: g.mandate_fields } as any))).toBe('MALFORMED');
    const d = caseInput('decision-commit-by-phone');
    expect(await code(dk.verifyDecision(d.envelope, { chain: await verified(d.chain.count) } as any))).toBe('MALFORMED');
    expect(await code(dk.verifyDecision(d.envelope, { chain: await verified(d.chain.count), expect: { proposal_id: 'prop-1' } } as any))).toBe('MALFORMED');
  });
});

describe('M2 stored head is validated', () => {
  const entries = MAIN.slice(0, 3);
  it.each([[{}], [{ seq: 1 }], [{ hash: MAIN[1] && 'sha256:' + '0'.repeat(64) }], [{ seq: -1, hash: 'sha256:' + '0'.repeat(64) }], [{ seq: 1.5, hash: 'sha256:' + '0'.repeat(64) }], [{ seq: 1, hash: 'sha256:' + 'A'.repeat(64) }]])('refuses %j', async (head) => {
    expect(await code(dk.verifyChain({ expectedRootDid: ROOT, entries, storedHead: head as any }))).toBe('MALFORMED');
  });
});

describe('L1 reserved grant member names', () => {
  it.each(['sig', 'sigs', 'checks'])('refuses a mandate field named %s', async (name) => {
    expect(() => dk.buildGrant({ op: 'grant', owner_did: ROOT, key_id: 'x', chain_seq: 0, chain_head: 'h', mandate_id: 'm', mandate_version: 1, granted_at: 1, nonce: 'n' } as any, { [name]: 1 })).toThrowError(/MALFORMED/);
    const r = caseInput('grant-by-computer-with-platform-check');
    expect(await code(Promise.resolve().then(() => dk.validateGrant(r.envelope.grant, { ...r.mandate_fields, [name]: 1 })))).toBe('MALFORMED');
  });
});

describe('L2 no extra signatures or checks, bounded proofs', () => {
  const run = (mutate: (e: any) => void, n = 3) => {
    const entries = JSON.parse(JSON.stringify(MAIN.slice(0, n)));
    mutate(entries[n - 1]);
    return code(dk.verifyChain({ expectedRootDid: ROOT, entries }));
  };
  const G = chainFile.fixtures.devices.G as string;
  it('an unneeded signature is refused', async () => {
    expect(await run((e) => e.sigs.push({ by: G, sig: e.sigs[0].sig }), 5)).toBe('MALFORMED');
  });
  it('an unneeded check is refused', async () => {
    expect(await run((e) => e.checks.push({ by: G, check: MAIN[1].checks[0].check }), 5)).toBe('MALFORMED');
  });
  it('an oversized proof is refused', async () => {
    expect(await run((e) => (e.checks[0].check.signature = 'A'.repeat(100000)))).toBe('MALFORMED');
  });
  it('a proof with non-string members is refused', async () => {
    expect(await run((e) => (e.checks[0].check.extra = { a: 1 }))).toBe('MALFORMED');
  });
  it('the unchanged chain is still accepted', async () => {
    expect(await run(() => {})).toBe('OK');
  });
});

describe('L4 pairing QR and hello', () => {
  const base = { v: 1 as const, as_url: 'https://suveren.ai', as_key: 'ef'.repeat(32), shown_by: 'joiner' as const, secret: dk.b64uEncode(new Uint8Array(32).fill(1)), root_did: null, head: null, key_id: null, expires_at: 2000 };
  it('now is required', () => {
    const text = dk.encodePairingQr(base);
    expect(() => (dk.decodePairingQr as any)(text)).toThrowError(/MALFORMED/);
    expect(() => (dk.decodePairingQr as any)(text, {})).toThrowError(/MALFORMED/);
    expect(dk.decodePairingQr(text, { now: 1000 }).as_url).toBe('https://suveren.ai');
  });
  it('as_url must be https (or the local dev hosts)', () => {
    for (const bad of ['http://evil.example', 'javascript:alert(1)', 'ftp://x', 'https://', 'https://a b']) {
      expect(() => dk.encodePairingQr({ ...base, as_url: bad })).toThrowError(/MALFORMED/);
    }
    for (const good of ['https://suveren.ai/x', 'http://localhost:4100', 'http://127.0.0.1:4100']) {
      expect(dk.encodePairingQr({ ...base, as_url: good }).startsWith('SUVEREN-PAIR-1:')).toBe(true);
    }
  });
  it('hello.head.seq must be a non-negative integer', async () => {
    const key = new Uint8Array(32).fill(9);
    const body = (seq: unknown) => ({ root_did: ROOT, head: { seq, hash: MAIN[0] && 'sha256:' + '1'.repeat(64) }, key_id: dk.b64uEncode(new Uint8Array(32)), as_key: 'ab'.repeat(32) });
    for (const seq of [1.5, -1, '3']) {
      const m = await dk.buildPairingMessage(key, 'hello', body(seq));
      expect(await code(dk.verifyPairingMessage(key, m))).toBe('MALFORMED');
    }
    expect(await code(dk.verifyPairingMessage(key, await dk.buildPairingMessage(key, 'hello', body(3))))).toBe('OK');
  });
});

describe('L5 lone surrogates are DeviceKeysErrors', () => {
  it('pairing MAC body and QR content', async () => {
    const key = new Uint8Array(32).fill(1);
    expect(await code(dk.pairingMac(key, 'hello', { x: '\ud800' }))).toBe('MALFORMED');
    expect(await code(dk.buildPairingMessage(key, 'hello', { x: '\ud800' }))).toBe('MALFORMED');
    const qr = { v: 1 as const, as_url: 'https://a/\ud800', as_key: 'ef'.repeat(32), shown_by: 'joiner' as const, secret: dk.b64uEncode(new Uint8Array(32)), root_did: null, head: null, key_id: null, expires_at: 2 };
    expect(() => dk.encodePairingQr(qr)).toThrowError(/MALFORMED/);
    expect(await code(Promise.resolve().then(() => dk.signedBytes({ a: '\ud800' })))).toBe('MALFORMED');
  });
});

describe('L6 labels refuse format characters', () => {
  it.each(['a​b', 'a‏b', 'a‮b', 'a⁠b', 'a⁦b', '﻿a', 'a\u{E0041}b', 'a\u0007b', 'a b'])('refuses %j', (s) => {
    expect(dk.isValidLabel(s)).toBe(false);
  });
  it('accepts ordinary text', () => {
    expect(dk.isValidLabel("Alice's iPhone")).toBe(true);
    expect(dk.isValidLabel('Büro 2')).toBe(true);
  });
});

describe('L7 canonical comparison and strict COSE', () => {
  it('checkKeysEqual ignores member order', () => {
    expect(dk.checkKeysEqual({ type: 'platform', pub: 'x' } as any, { pub: 'x', type: 'platform' } as any)).toBe(true);
    expect(dk.checkKeysEqual(null, null)).toBe(true);
    expect(dk.checkKeysEqual({ type: 'platform', pub: 'x' } as any, null)).toBe(false);
  });
  const x = new Uint8Array(32).fill(1);
  const y = new Uint8Array(32).fill(2);
  const good = dk.encodeCoseEc2(x, y);
  it('accepts the canonical form', () => expect(dk.coseEc2ToRawPoint(good).length).toBe(65));
  it('refuses a non-minimal integer (0x18 0x02 for 2)', () => {
    const bad = Uint8Array.from([0xa5, 0x01, 0x18, 0x02, ...good.slice(3)]);
    expect(() => dk.coseEc2ToRawPoint(bad)).toThrowError(/MALFORMED/);
  });
  it('refuses a non-canonical map order (y before x)', () => {
    const bad = dk.concat(Uint8Array.of(0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x22, 0x58, 0x20), y, Uint8Array.of(0x21, 0x58, 0x20), x);
    expect(() => dk.coseEc2ToRawPoint(bad)).toThrowError(/MALFORMED/);
  });
});

describe('L8 member sets and device keys', () => {
  it('sameMembers compares sets, not joined strings', () => {
    expect(dk.sameMembers({ 'a,b': 1 }, ['a', 'b'])).toBe(false);
    expect(dk.sameMembers({ b: 1, a: 2 }, ['a', 'b'])).toBe(true);
    expect(dk.sameMembers({ a: 1 }, ['a', 'b'])).toBe(false);
  });
  it('read_pub equal to sign_pub is refused', () => {
    const d = JSON.parse(JSON.stringify(MAIN[0].device));
    d.read_pub = d.sign_pub;
    expect(() => dk.validateDevice(d)).toThrowError(/MALFORMED/);
  });
});

describe('subpath export', () => {
  it('package.json exports ./device-keys with types, import and require', () => {
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8'));
    expect(pkg.exports['./device-keys']).toEqual({
      types: './dist/device-keys/index.d.ts',
      import: './dist/device-keys/index.mjs',
      require: './dist/device-keys/index.js',
    });
    expect(pkg.exports['.'].import).toBe('./dist/index.mjs');
    expect(pkg.scripts.build).toContain('src/device-keys/index.ts');
  });
});

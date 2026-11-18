/**
 * New root DID objects (plan section 10, 20.1 item 4): cancel and override. The shared vectors
 * (identity.json) run in device-keys.test.ts; this file checks their coverage and a few
 * properties the vectors cannot show.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as dk from '../src/device-keys/index';

const file = JSON.parse(readFileSync(join(__dirname, 'vectors', 'device-keys', 'identity.json'), 'utf8'));
const cases = file.cases as any[];
const input = (id: string) => cases.find((c) => c.id === id).input;
const code = async (p: Promise<unknown>) => p.then(() => 'OK', (e) => e.code ?? `PLAIN:${e.message}`);
const chainOf = (spec: any) =>
  dk.verifyChain({ expectedRootDid: spec.expected_root_did ?? file.fixtures.root_did, entries: file.fixtures.chains[spec.ref].slice(0, spec.count) });

describe('identity cancel and override vectors', () => {
  it('every error code of both objects has a negative vector', () => {
    for (const prefix of ['cancel-', 'override-']) {
      const have = new Set(cases.filter((c) => c.id.startsWith(prefix)).map((c) => c.expect.error).filter(Boolean));
      for (const n of ['MALFORMED', 'BAD_AUD', 'REQUEST_MISMATCH', 'STALE', 'WRONG_ROOT', 'NOT_ACTIVE', 'BAD_SIGNATURE', 'FORK', 'CHAIN_AHEAD', 'CHECK_REQUIRED']) {
        expect(have.has(n), `${prefix} ${n}`).toBe(true);
      }
    }
  });
  it('signed bytes are JCS of the object without sig and check, typ inside', () => {
    const i = input('cancel-valid-with-check');
    const bytes = dk.utf8Decode(dk.signedBytes(i.envelope.cancel));
    expect(bytes.startsWith('{"aud":"')).toBe(true);
    expect(bytes).toContain('"typ":"suveren-identity-cancel","v":1');
    expect(bytes).not.toContain('sig');
    expect(bytes).not.toContain('check"');
  });
  it('a cancel is not an override and an override is not a cancel', async () => {
    const c = input('cancel-valid-with-check');
    expect(() => dk.validateIdentityOverride(c.envelope.cancel)).toThrow(/MALFORMED/);
    const o = input('override-valid');
    expect(() => dk.validateIdentityCancel(o.envelope.override)).toThrow(/MALFORMED/);
  });
  it('a missing chain, adminChain or aud is MALFORMED, never a TypeError', async () => {
    const i = input('cancel-valid-with-check');
    const chain = await chainOf(i.chain);
    const ctx = { chain, aud: i.aud, requestId: i.request_id, now: i.now };
    expect(await code(dk.verifyIdentityCancel(i.envelope, ctx))).toBe('OK');
    expect(await code(dk.verifyIdentityCancel(i.envelope, { ...ctx, chain: undefined } as any))).toBe('MALFORMED');
    expect(await code(dk.verifyIdentityCancel(i.envelope, { ...ctx, aud: undefined } as any))).toBe('MALFORMED');
    expect(await code(dk.verifyIdentityCancel(i.envelope, undefined as any))).toBe('MALFORMED');
    const o = input('override-valid');
    const octx = { adminChain: await chainOf(o.chain), aud: o.aud, requestId: o.request_id, memberUserId: o.member_user_id, now: o.now };
    expect(await code(dk.verifyIdentityOverride(o.envelope, octx))).toBe('OK');
    expect(await code(dk.verifyIdentityOverride(o.envelope, { ...octx, adminChain: undefined } as any))).toBe('MALFORMED');
    expect(await code(dk.verifyIdentityOverride(o.envelope, { ...octx, aud: undefined } as any))).toBe('MALFORMED');
  });
  it('a cancel for one Authority Server is refused by another (same request id)', async () => {
    const i = input('cancel-valid-with-check');
    const chain = await chainOf(i.chain);
    expect(await code(dk.verifyIdentityCancel(i.envelope, { chain, aud: 'cd'.repeat(32), requestId: i.request_id, now: i.now }))).toBe('BAD_AUD');
  });
  it('an override checked against the member chain by mistake is refused', async () => {
    const i = input('override-valid');
    const memberChain = await chainOf({ ref: 'member', count: 5 });
    expect(await code(dk.verifyIdentityOverride(i.envelope, { adminChain: memberChain, aud: i.aud, requestId: i.request_id, memberUserId: i.member_user_id, now: i.now }))).toBe('WRONG_ROOT');
  });
  it('an override check does not carry over to a cancel (check over another object)', async () => {
    const o = input('override-valid');
    const c = input('cancel-valid-with-check');
    // the same sort of device and check key, but a check made over the override is not valid over a cancel
    const chain = await chainOf(c.chain);
    const env = { cancel: c.envelope.cancel, sig: c.envelope.sig, check: o.envelope.check };
    expect(await code(dk.verifyIdentityCancel(env, { chain, aud: c.aud, requestId: c.request_id, now: c.now }))).toBe('CHECK_REQUIRED');
  });
});

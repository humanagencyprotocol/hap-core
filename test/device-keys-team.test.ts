/**
 * Team objects (DEC-73): suveren-team-members, suveren-team-anchor, suveren-team-leave and
 * verifyTeamTrust. The shared vectors (team.json) run in device-keys.test.ts; this file checks
 * their coverage and the properties the vectors cannot show.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as dk from '../src/device-keys/index';

const file = JSON.parse(readFileSync(join(__dirname, 'vectors', 'device-keys', 'team.json'), 'utf8'));
const cases = file.cases as any[];
const input = (id: string) => cases.find((c) => c.id === id).input;
const code = async (p: Promise<unknown>) => p.then(() => 'OK', (e) => e.code ?? `PLAIN:${e.message}`);
const chainOf = (spec: any) => dk.verifyChain({ expectedRootDid: spec.expected_root_did, entries: file.fixtures.chains[spec.ref].slice(0, spec.count) });

async function trustInput(id: string, patch: Record<string, unknown> = {}) {
  const i = input(id);
  const adminChains: Record<string, dk.ChainState> = {};
  for (const [did, spec] of Object.entries(i.admin_chains)) adminChains[did] = await chainOf(spec);
  return {
    team_id: i.team_id,
    anchor: i.anchor,
    anchorChain: await chainOf(i.anchor_chain),
    versions: i.versions,
    adminChains,
    pin: i.pin,
    ...patch,
  } as dk.TeamTrustInput;
}

describe('team vectors', () => {
  it('has vectors for all three objects and the trust walk', () => {
    for (const p of ['list-', 'anchor-', 'leave-', 'trust-']) expect(cases.filter((c) => c.id.startsWith(p)).length).toBeGreaterThan(10);
  });
  it('every error code has a negative vector', () => {
    const have = new Set(cases.map((c) => c.expect.error).filter(Boolean));
    for (const n of [
      'MALFORMED', 'WRONG_ROOT', 'BAD_VERSION', 'BAD_PREV', 'TEAM_MISMATCH', 'HANDOVER_REQUIRED', 'NOT_ACTIVE', 'BAD_SIGNATURE',
      'CHECK_REQUIRED', 'FORK', 'CHAIN_AHEAD', 'ROLLBACK', 'NO_TRUST', 'NOT_A_MEMBER', 'HISTORY_GAP', 'ADMIN_CANNOT_LEAVE',
    ]) {
      expect(have.has(n), `no vector for ${n}`).toBe(true);
    }
  });
  it('has the cases the design names', () => {
    const ids = cases.map((c) => c.id).join(' ');
    for (const part of [
      'members-unsorted', 'members-duplicate', 'no-check', 'admin-change-one-signature', 'signer-removed-no-pin', 'trust-fork',
      'trust-rollback', 'anchor-device-without-check-key', 'anchor-other-team', 'list-v4-handover-two-signatures', 'leave-valid',
    ]) {
      expect(ids, part).toContain(part);
    }
  });
});

describe('signed bytes and hash', () => {
  it('signed bytes are JCS of the object without sig, sigs and check; typ inside', () => {
    const e = input('list-v1-valid').envelope;
    const text = dk.utf8Decode(dk.signedBytes(e.list));
    expect(text.startsWith('{"admin_did":"')).toBe(true);
    expect(text).toContain('"typ":"suveren-team-members","v":1');
    expect(text).not.toContain('"sigs"');
    expect(text).not.toContain('"check"');
  });
  it('the list hash is the object hash and does not depend on the signatures', async () => {
    const e = input('list-v4-handover-two-signatures').envelope;
    const a = await dk.memberListHash(e.list);
    expect(a).toBe(await dk.objectHash(e.list));
    expect(a).toBe(await dk.memberListHash({ ...e.list }));
  });
  it('the three objects are not readable as one another', () => {
    const l = input('list-v1-valid').envelope.list;
    const a = input('anchor-v1-valid').envelope.anchor;
    const x = input('leave-valid').envelope.leave;
    expect(() => dk.validateAnchor(l)).toThrow(/MALFORMED/);
    expect(() => dk.validateMemberList(a)).toThrow(/MALFORMED/);
    expect(() => dk.validateLeave(a)).toThrow(/MALFORMED/);
    expect(() => dk.validateAnchor(x)).toThrow(/MALFORMED/);
  });
});

describe('shape limits', () => {
  const base = input('list-v1-valid').envelope.list;
  const mem = (n: number) => ({ did: `did:key:z${String(n).padStart(6, '0')}`, name: `Member ${n}`, code: '0000 0000 0000 0000 0000 0000' });
  it('500 members are fine, 501 are not', () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => mem(i));
    const mk = (n: number) => ({ ...base, version: 2, prev: base.chain_head, admin_did: mem(0).did, members: many(n) });
    expect(() => dk.validateMemberList(mk(500))).not.toThrow();
    expect(() => dk.validateMemberList(mk(501))).toThrow(/MALFORMED/);
  });
  it('a name counts characters, not UTF-16 units', () => {
    const l = (name: string) => ({ ...base, members: [{ ...base.members[0], name }] });
    expect(() => dk.validateMemberList(l('\u{1F600}'.repeat(64)))).not.toThrow();
    expect(() => dk.validateMemberList(l('\u{1F600}'.repeat(65)))).toThrow(/MALFORMED/);
  });
  it('a missing context is MALFORMED, never a TypeError', async () => {
    const i = input('list-v1-valid');
    expect(await code(dk.verifyMemberList(i.envelope, undefined as any))).toBe('MALFORMED');
    expect(await code(dk.verifyAnchor(input('anchor-v1-valid').envelope, {} as any))).toBe('MALFORMED');
    expect(await code(dk.verifyLeave(input('leave-valid').envelope, { chain: await chainOf(input('leave-valid').chain) } as any))).toBe('MALFORMED');
    expect(await code(dk.verifyTeamTrust(undefined as any))).toBe('MALFORMED');
  });
});

describe('verifyTeamTrust', () => {
  it('returns the pin to store', async () => {
    const t = await dk.verifyTeamTrust(await trustInput('trust-follows-handover'));
    expect(t.pin).toEqual({ version: 4, hash: t.hash });
    expect(t.admin_did).toBe(file.fixtures.roots.ben);
    expect(t.members.map((m) => m.name)).toContain('Max Muster');
  });
  it('storing the returned pin and asking again accepts the same state, refuses an older one', async () => {
    const first = await dk.verifyTeamTrust(await trustInput('trust-follows-handover'));
    expect((await dk.verifyTeamTrust(await trustInput('trust-follows-handover', { pin: first.pin }))).version).toBe(4);
    const older = await trustInput('trust-after-join', { pin: first.pin });
    expect(await code(dk.verifyTeamTrust(older))).toBe('ROLLBACK');
  });
  it('a tampered list never raises the result', async () => {
    const i = await trustInput('trust-follows-handover');
    // rename a member in version 3: its signature no longer fits, so the walk ends at version 2
    const tampered = structuredClone(i.versions) as any[];
    const v3 = tampered.find((e) => e.list.version === 3);
    v3.list.members[0].name = 'Somebody Else';
    const t = await dk.verifyTeamTrust({ ...i, versions: tampered });
    expect(t.version).toBe(2);
  });
  it('checkTeamPin: lower is ROLLBACK, same version with another hash is FORK, higher passes', () => {
    const h = (c: string) => 'sha256:' + c.repeat(64);
    const pin = { version: 5, hash: h('a') };
    expect(() => dk.checkTeamPin(4, h('a'), pin)).toThrow(/ROLLBACK/);
    expect(() => dk.checkTeamPin(5, h('b'), pin)).toThrow(/FORK/);
    expect(() => dk.checkTeamPin(5, h('a'), pin)).not.toThrow();
    expect(() => dk.checkTeamPin(6, h('b'), pin)).not.toThrow();
    expect(() => dk.checkTeamPin(1, h('b'), undefined)).not.toThrow();
  });
  it('a pin that is not a hash is MALFORMED', () => {
    expect(() => dk.checkTeamPin(6, 'sha256:' + 'a'.repeat(64), { version: 5, hash: 'nope' })).toThrow(/MALFORMED/);
  });
  it('the old admin cannot be swapped for a chain of another person', async () => {
    const i = await trustInput('trust-follows-handover');
    // the chain filed under Ada\'s DID is Xavier\'s: the hand-over and the first lists do not verify
    const bad = { ...i.adminChains, [file.fixtures.roots.ada]: await chainOf({ ref: 'xav', count: 1, expected_root_did: file.fixtures.roots.xav }) };
    const code1 = await code(dk.verifyTeamTrust({ ...i, adminChains: bad }));
    expect(['WRONG_ROOT', 'NO_TRUST']).toContain(code1);
  });
});

describe('admin hand-over', () => {
  it('needs both signatures: each one alone is refused', async () => {
    const i = input('list-v4-handover-two-signatures');
    const ctx = { chain: await chainOf(i.chain), prev: i.prev, oldAdminChain: await chainOf(i.old_admin_chain) };
    expect(await code(dk.verifyMemberList(i.envelope, ctx))).toBe('OK');
    const [newSig, oldSig] = i.envelope.sigs;
    expect(await code(dk.verifyMemberList({ list: i.envelope.list, sigs: [newSig] }, ctx))).toBe('MALFORMED');
    expect(await code(dk.verifyMemberList({ list: i.envelope.list, sigs: [oldSig] }, ctx))).toBe('MALFORMED');
  });
  it('the new admin cannot sign the old admin\'s part, nor the reverse', async () => {
    const i = input('list-v4-handover-two-signatures');
    const ctx = { chain: await chainOf(i.chain), prev: i.prev, oldAdminChain: await chainOf(i.old_admin_chain) };
    const [newSig, oldSig] = i.envelope.sigs;
    // swap the signatures between the two entries: each key_id now carries the other's signature
    const swapped = [{ ...newSig, sig: oldSig.sig }, { ...oldSig, sig: newSig.sig }];
    expect(await code(dk.verifyMemberList({ list: i.envelope.list, sigs: swapped }, ctx))).toBe('BAD_SIGNATURE');
  });
  it('a list that changes the admin but not by hand-over is accepted only where an anchor stands in', async () => {
    const i = input('list-admin-change-one-signature');
    const ctx = { chain: await chainOf(i.chain), prev: i.prev };
    expect(await code(dk.verifyMemberList(i.envelope, ctx))).toBe('HANDOVER_REQUIRED');
    expect(await code(dk.verifyMemberList(i.envelope, { ...ctx, anchored: true }))).toBe('OK');
  });
});

describe('leave', () => {
  it('is not a check-bearing object: a check is refused, a missing one is fine', async () => {
    const i = input('leave-valid');
    const ctx = { chain: await chainOf(i.chain), expect: { team_id: i.team_id } };
    expect(await code(dk.verifyLeave(i.envelope, ctx))).toBe('OK');
    expect(await code(dk.verifyLeave({ ...i.envelope, check: { signature: 'AAAA' } }, ctx))).toBe('MALFORMED');
  });
  it('verifyTeamTrust: a member sees a colleague\'s leave before the admin signed, and the leaver is out', async () => {
    const t = await dk.verifyTeamTrust(await (async () => {
      const i = input('trust-leave-applies');
      const base = await trustInput('trust-leave-applies');
      const leaves = [];
      for (const l of i.leaves) leaves.push({ env: l.env, chain: await chainOf(l.chain) });
      return { ...base, leaves };
    })());
    expect(t.left).toEqual([file.fixtures.roots.max]);
    expect(t.members.map((m) => m.did)).not.toContain(file.fixtures.roots.max);
  });
});

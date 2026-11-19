/**
 * Generates team.json: vectors for `suveren-team-members`, `suveren-team-anchor`,
 * `suveren-team-leave` and `verifyTeamTrust` (DEC-73, design 20.21.3). Like generate-identity.mjs it
 * builds its own chains and leaves every other vector file untouched.
 *
 * RUN ONCE, then commit the output (the P-256 check keys and signatures are random).
 *
 *   pnpm build && node test/vectors/device-keys/generate-team.mjs
 *
 * People are fictional: Ada (first admin), Ben (second admin), Max and Nora (members), Xavier
 * (a stranger who is admin of another team).
 */
import { writeFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { deviceKeys as dk } from '../../../dist/index.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const subtle = webcrypto.subtle;
const T0 = 1794200000;
const b64u = dk.b64uEncode;
const ecdsa = { name: 'ECDSA', hash: 'SHA-256' };
const filled = (n, len = 32) => new Uint8Array(len).fill(n);

async function p256() {
  const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  return { priv: kp.privateKey, raw: new Uint8Array(await subtle.exportKey('raw', kp.publicKey)) };
}
const platformKey = (k) => ({ type: 'platform', pub: b64u(k.raw) });
const maker = (k) => async (hash) => ({
  signature: b64u(dk.ecdsaRawToDer(new Uint8Array(await subtle.sign(ecdsa, k.priv, dk.hashBytes(hash))))),
});

const CA1 = await p256();
const CA3 = await p256();
const CB1 = await p256();
const CM1 = await p256();
const CN1 = await p256();
const CX1 = await p256();
const COTHER = await p256(); // a key that belongs to no device

async function device(n, { label, check = null, kind = 'gateway' }) {
  const seed = filled(n);
  const pub = await dk.ed25519PublicKey(seed);
  const rec = { key_id: await dk.keyIdOf(pub), sign_pub: b64u(pub), read_pub: b64u(filled(0x80 + n)), kind, label, keystore: 'software', check };
  return { seed, id: rec.key_id, rec };
}
const A1 = await device(0x11, { label: "Ada's MacBook", check: platformKey(CA1) });
const A2 = await device(0x12, { label: "Ada's Office PC" });
const A3 = await device(0x13, { label: "Ada's old laptop" });
const B1 = await device(0x21, { label: "Ben's MacBook", check: platformKey(CB1) });
const M1 = await device(0x31, { label: "Max's MacBook", check: platformKey(CM1) });
const M2 = await device(0x32, { label: "Max's Office PC" });
const M3 = await device(0x33, { label: "Max's old laptop" });
const N1 = await device(0x41, { label: "Nora's MacBook", check: platformKey(CN1) });
const X1 = await device(0x51, { label: "Xavier's MacBook", check: platformKey(CX1) });

const seedOf = (n) => Uint8Array.from({ length: 16 }, (_, i) => n + i);
const rA = await dk.deriveRootKey(seedOf(0x10));
const rB = await dk.deriveRootKey(seedOf(0x20));
const rM = await dk.deriveRootKey(seedOf(0x30));
const rN = await dk.deriveRootKey(seedOf(0x40));
const rX = await dk.deriveRootKey(seedOf(0x50));

async function build(root, steps) {
  const chain = [];
  for (const s of steps) {
    const last = chain[chain.length - 1];
    const e = dk.buildEntry({ root_did: root.did, seq: chain.length, prev: last ? await dk.entryHash(last) : null, op: s.op, created_at: T0 + chain.length, signer: s.signer ?? 'root', ...s.fields });
    e.sigs = [];
    e.checks = [];
    for (const [by, seed] of s.sigs) e.sigs.push(await dk.signEntry(e, by, seed));
    const h = await dk.entryHash(e);
    for (const [by, mk] of s.checks ?? []) e.checks.push({ by, check: await mk(h) });
    chain.push(e);
  }
  const hashes = [];
  for (const e of chain) hashes.push(await dk.entryHash(e));
  return { chain, hashes };
}
const genesis = (root, d, c) => ({ op: 'genesis', fields: { device: d.rec }, sigs: [['root', root.privateSeed], [d.id, d.seed]], checks: [[d.id, maker(c)]] });

// Ada: 0 genesis A1; 1 add A2 (no check key); 2 add A3 (no check key); 3 A3 gets a check key; 4 A3 leaves
const ada = await build(rA, [
  genesis(rA, A1, CA1),
  { op: 'add', signer: A1.id, fields: { device: A2.rec }, sigs: [[A1.id, A1.seed], [A2.id, A2.seed]], checks: [[A1.id, maker(CA1)]] },
  { op: 'add', signer: A1.id, fields: { device: A3.rec }, sigs: [[A1.id, A1.seed], [A3.id, A3.seed]], checks: [[A1.id, maker(CA1)]] },
  { op: 'set', signer: A1.id, fields: { target: A3.id, check: platformKey(CA3) }, sigs: [[A1.id, A1.seed]], checks: [[A1.id, maker(CA1)], [A3.id, maker(CA3)]] },
  { op: 'remove', signer: A3.id, fields: { target: A3.id }, sigs: [[A3.id, A3.seed]] },
]);
const ben = await build(rB, [genesis(rB, B1, CB1)]);
// Max: 0 genesis M1; 1 add M2 (no check key); 2 add M3 (no check key); 3 M3 leaves
const max = await build(rM, [
  genesis(rM, M1, CM1),
  { op: 'add', signer: M1.id, fields: { device: M2.rec }, sigs: [[M1.id, M1.seed], [M2.id, M2.seed]], checks: [[M1.id, maker(CM1)]] },
  { op: 'add', signer: M1.id, fields: { device: M3.rec }, sigs: [[M1.id, M1.seed], [M3.id, M3.seed]], checks: [[M1.id, maker(CM1)]] },
  { op: 'remove', signer: M3.id, fields: { target: M3.id }, sigs: [[M3.id, M3.seed]] },
]);
const nora = await build(rN, [genesis(rN, N1, CN1)]);
const xav = await build(rX, [genesis(rX, X1, CX1)]);

const roots = { ada: rA.did, ben: rB.did, max: rM.did, nora: rN.did, xav: rX.did };
const built = { ada, ben, max, nora, xav };
const cref = (name, count) => ({ ref: name, count: count ?? built[name].chain.length, expected_root_did: roots[name] });

const sign = async (obj, key) => b64u(await dk.signEd25519(key.seed, dk.signedBytes(obj)));
let nonceN = 0;
const nonce = () => b64u(filled(++nonceN, 16));
const TEAM = 'team-7f3a';
const OTHER_TEAM = 'team-9c01';
const OK = { ok: true };
const cases = [];

// ---- members and lists ------------------------------------------------------
const member = (did, name) => dk.buildTeamMember(did, name);
const byDid = (ms) => [...ms].sort((a, b) => (a.did < b.did ? -1 : 1));
const mAda = await member(rA.did, 'Ada Admin');
const mBen = await member(rB.did, 'Ben Admin');
const mMax = await member(rM.did, 'Max Muster');
const mNora = await member(rN.did, 'Nora Beispiel');

const mkList = (over = {}) =>
  dk.buildMemberList({
    team_id: TEAM, version: 1, prev: null, admin_did: rA.did, members: byDid([mAda]), handover: null,
    key_id: A1.id, chain_seq: 3, chain_head: ada.hashes[3], created_at: T0 + 100, nonce: nonce(), ...over,
  });
const hash = (o) => dk.objectHash(o);
const HAND = (key, built_, seq) => ({ admin_did: roots.ada, key_id: key.id, chain_seq: seq, chain_head: built_.hashes[seq] });
const bHead = { key_id: B1.id, chain_seq: 0, chain_head: ben.hashes[0] };

async function env(list, signers) {
  const sigs = [];
  for (const [key, mk] of signers) {
    const e = { key_id: key.id, sig: await sign(list, key) };
    if (mk) e.check = await mk(await hash(list));
    sigs.push(e);
  }
  return { list, sigs };
}
const SA1 = [[A1, maker(CA1)]];
const SB1 = [[B1, maker(CB1)]];

const L1 = mkList();
const L2 = mkList({ version: 2, prev: await hash(L1), members: byDid([mAda, mBen, mMax]), created_at: T0 + 101 });
const L3 = mkList({ version: 3, prev: await hash(L2), members: byDid([mAda, mBen, mMax, mNora]), created_at: T0 + 102 });
const L3b = mkList({ version: 3, prev: await hash(L2), members: byDid([mAda, mBen, mMax, mNora]), created_at: T0 + 103 }); // another list at version 3
const L4 = mkList({ version: 4, prev: await hash(L3), admin_did: rB.did, members: L3.members, handover: HAND(A1, ada, 3), ...bHead, created_at: T0 + 104 });
const L4x = mkList({ version: 4, prev: await hash(L3), admin_did: rB.did, members: L3.members, handover: null, ...bHead, created_at: T0 + 104 });
const L5 = mkList({ version: 5, prev: await hash(L4), admin_did: rB.did, members: byDid([mAda, mBen, mMax]), ...bHead, created_at: T0 + 105 });
const L6 = mkList({ version: 6, prev: await hash(L5), admin_did: rB.did, members: byDid([mAda, mBen]), ...bHead, created_at: T0 + 106 });
const E1 = await env(L1, SA1);
const E2 = await env(L2, SA1);
const E3 = await env(L3, SA1);
const E3b = await env(L3b, SA1);
const E4 = await env(L4, [...SB1, ...SA1]);
const E4x = await env(L4x, SB1);
const E5 = await env(L5, SB1);
const L5x = mkList({ version: 5, prev: await hash(L4x), admin_did: rB.did, members: L5.members, ...bHead, created_at: T0 + 105 });
const E5x = await env(L5x, SB1);
const E6 = await env(L6, SB1);

async function lcase(id, description, e, o, expect) {
  cases.push({
    id: `list-${id}`,
    description,
    op: 'team-list.verify',
    input: { chain: o.chain ?? cref('ada', 5), envelope: e, prev: o.prev, old_admin_chain: o.old, pin: o.pin, anchored: o.anchored },
    expect,
  });
}
const strip = (x) => JSON.parse(JSON.stringify(x));
// mutate a list after building, then sign it (a well-signed but invalid list)
async function signed(list, signers = SA1) {
  return env(list, signers);
}

await lcase('v1-valid', 'the first list: the admin alone, no prev', E1, { prev: null }, OK);
await lcase('v1-valid-without-prev-context', 'the same list without a prev in the context', E1, {}, OK);
await lcase('v2-valid', 'a member is added', E2, { prev: L1 }, OK);
await lcase('v3-valid', 'another member is added', E3, { prev: L2 }, OK);
await lcase('v4-handover-two-signatures', 'change of admin signed by the new admin (B1) and the old admin (A1), each with its check', E4, { chain: cref('ben'), prev: L3, old: cref('ada', 5) }, OK);
await lcase('v5-same-admin-removes-a-member', 'the new admin removes a member', E5, { chain: cref('ben'), prev: L4 }, OK);
await lcase('valid-name-unicode-nfc', 'a name with umlauts in NFC', await signed(mkList({ members: byDid([await member(rA.did, 'Zoë Müller-Åkesson')]) })), { prev: null }, OK);
await lcase('valid-name-64-characters', 'a name of exactly 64 characters', await signed(mkList({ members: byDid([await member(rA.did, 'n'.repeat(64))]) })), { prev: null }, OK);
await lcase('valid-signer-removed-at-or-below-pin', 'A3 was removed at seq 4 but was admitted with a check key at the named head 3; the version is at the pin', await signed(mkList({ key_id: A3.id }), [[A3, maker(CA3)]]), { prev: null, pin: { version: 1, hash: await hash(L1) } }, OK);

await lcase('wrong-typ', 'typ of another object', await signed(strip({ ...L1, typ: 'suveren-team-anchor' })), { prev: null }, { error: 'MALFORMED' });
await lcase('wrong-v', 'v is 2', await signed({ ...L1, v: 2 }), { prev: null }, { error: 'MALFORMED' });
await lcase('unknown-member', 'extra member in the list', await signed({ ...L1, note: 'x' }), { prev: null }, { error: 'MALFORMED' });
await lcase('missing-member', 'team_id missing', await signed((({ team_id, ...r }) => r)(L1)), { prev: null }, { error: 'MALFORMED' });
await lcase('members-unsorted', 'members not sorted by did', await signed({ ...L3, members: [...L3.members].reverse() }), { prev: L2 }, { error: 'MALFORMED' });
await lcase('members-duplicate', 'the same did twice', await signed({ ...L2, members: [L2.members[0], L2.members[0], L2.members[1]].sort((a, b) => (a.did < b.did ? -1 : 1)) }), { prev: L1 }, { error: 'MALFORMED' });
await lcase('members-empty', 'no members', await signed({ ...L1, members: [] }), { prev: null }, { error: 'MALFORMED' });
await lcase('admin-not-a-member', 'admin_did is not in members', await signed({ ...L2, members: byDid([mBen, mMax]) }), { prev: L1 }, { error: 'MALFORMED' });
await lcase('name-empty', 'empty name', await signed({ ...L1, members: [{ ...mAda, name: '' }] }), { prev: null }, { error: 'MALFORMED' });
await lcase('name-65-characters', 'a name of 65 characters', await signed({ ...L1, members: [{ ...mAda, name: 'n'.repeat(65) }] }), { prev: null }, { error: 'MALFORMED' });
await lcase('name-not-nfc', 'a name with a combining accent (NFD)', await signed({ ...L1, members: [{ ...mAda, name: 'Zoë' }] }), { prev: null }, { error: 'MALFORMED' });
await lcase('name-control-character', 'a name with a newline', await signed({ ...L1, members: [{ ...mAda, name: 'Ada\nAdmin' }] }), { prev: null }, { error: 'MALFORMED' });
await lcase('code-of-another-did', 'the identity code is the code of another person', await signed({ ...L2, members: byDid([mAda, mBen, { ...mMax, code: mNora.code }]) }), { prev: L1 }, { error: 'MALFORMED' });
await lcase('code-not-24-digits', 'identity code in the wrong format', await signed({ ...L1, members: [{ ...mAda, code: '1234' }] }), { prev: null }, { error: 'MALFORMED' });
await lcase('v1-two-members', 'version 1 lists more than the admin', await signed({ ...L2, version: 1, prev: null }), { prev: null }, { error: 'MALFORMED' });
await lcase('v1-with-prev', 'version 1 with a prev', await signed({ ...L1, prev: await hash(L1) }), { prev: null }, { error: 'MALFORMED' });
await lcase('v2-without-prev', 'version 2 with prev null', await signed({ ...L2, prev: null }), { prev: L1 }, { error: 'MALFORMED' });
await lcase('v1-with-handover', 'version 1 with a hand-over', await signed({ ...L1, handover: HAND(A1, ada, 3) }), { prev: null }, { error: 'MALFORMED' });
await lcase('wrong-version', 'version 4 after version 2', await signed({ ...L2, version: 4 }), { prev: L2 }, { error: 'BAD_VERSION' });
await lcase('version-not-above-prev', 'the same version as the previous list', await signed({ ...L2, version: 2, prev: await hash(L2) }), { prev: L2 }, { error: 'BAD_VERSION' });
await lcase('v2-without-prev-context', 'version 2 with an explicit "no earlier list"', E2, { prev: null }, { error: 'BAD_VERSION' });
await lcase('wrong-prev-hash', 'prev is the hash of another list', await signed({ ...L2, prev: await hash(L3) }), { prev: L1 }, { error: 'BAD_PREV' });
await lcase('other-team', 'the previous list belongs to another team', E2, { prev: { ...L1, team_id: OTHER_TEAM } }, { error: 'TEAM_MISMATCH' });
await lcase('admin-change-one-signature', 'admin changes with the new admin alone', E4x, { chain: cref('ben'), prev: L3 }, { error: 'HANDOVER_REQUIRED' });
await lcase('admin-change-handover-names-wrong-admin', 'the hand-over names Xavier, not the previous admin', await signed({ ...L4, handover: { ...L4.handover, admin_did: rX.did, key_id: X1.id, chain_seq: 0, chain_head: xav.hashes[0] } }, [...SB1, [X1, maker(CX1)]]), { chain: cref('ben'), prev: L3, old: cref('xav') }, { error: 'HANDOVER_REQUIRED' });
await lcase('admin-change-second-signature-missing', 'a hand-over with only one entry in sigs', { list: L4, sigs: E4.sigs.slice(0, 1) }, { chain: cref('ben'), prev: L3, old: cref('ada', 5) }, { error: 'MALFORMED' });
await lcase('admin-change-old-chain-missing', 'a hand-over without the old admin chain in the context', E4, { chain: cref('ben'), prev: L3 }, { error: 'MALFORMED' });
await lcase('admin-change-old-signer-without-check-key', 'the old admin signs with A2, a device without a check key', await signed({ ...L4, handover: HAND(A2, ada, 3) }, [...SB1, [A2, null]]), { chain: cref('ben'), prev: L3, old: cref('ada', 5) }, { error: 'CHECK_REQUIRED' });
await lcase('admin-change-old-signer-removed', 'the old admin signs with A3, removed at seq 4, and there is no pin', await signed({ ...L4, handover: HAND(A3, ada, 3) }, [...SB1, [A3, maker(CA3)]]), { chain: cref('ben'), prev: L3, old: cref('ada', 5) }, { error: 'NOT_ACTIVE' });
await lcase('admin-change-signature-by-wrong-chain', 'the hand-over signature is by Xavier\'s device but names the old admin chain', await signed({ ...L4, handover: HAND(A1, ada, 3) }, [...SB1, [X1, maker(CX1)]]), { chain: cref('ben'), prev: L3, old: cref('ada', 5) }, { error: 'MALFORMED' });
await lcase('same-admin-with-handover', 'a hand-over without a change of admin', await signed({ ...L3, handover: HAND(A1, ada, 3) }, [...SA1, ...SA1]), { prev: L2, old: cref('ada', 5) }, { error: 'MALFORMED' });
await lcase('admin-change-anchored', 'one signature is accepted when the verifier holds an anchor naming the new admin', E4x, { chain: cref('ben'), prev: L3, anchored: true }, OK);
await lcase('no-check', 'a signature alone', { list: L1, sigs: [{ key_id: A1.id, sig: await sign(L1, A1) }] }, { prev: null }, { error: 'CHECK_REQUIRED' });
await lcase('check-over-other-object', 'check made over the hash of another list', { list: L1, sigs: [{ key_id: A1.id, sig: await sign(L1, A1), check: await maker(CA1)(await hash(L2)) }] }, { prev: null }, { error: 'CHECK_REQUIRED' });
await lcase('check-by-other-key', 'check made with a key that is not the device check key', { list: L1, sigs: [{ key_id: A1.id, sig: await sign(L1, A1), check: await maker(COTHER)(await hash(L1)) }] }, { prev: null }, { error: 'CHECK_REQUIRED' });
await lcase('check-null', 'check: null counts as missing', { list: L1, sigs: [{ key_id: A1.id, sig: await sign(L1, A1), check: null }] }, { prev: null }, { error: 'CHECK_REQUIRED' });
await lcase('device-without-check-key', 'A2 has no check key: a member list is a grant-class action', await signed({ ...L1, key_id: A2.id }, [[A2, null]]), { prev: null }, { error: 'CHECK_REQUIRED' });
await lcase('check-key-changed-since-named-head', 'A3 got its check key at seq 3; naming head 2 cannot use it', await signed(mkList({ key_id: A3.id, chain_seq: 2, chain_head: ada.hashes[2] }), [[A3, maker(CA3)]]), { prev: null, pin: { version: 1, hash: await hash(L1) } }, { error: 'CHECK_REQUIRED' });
await lcase('signer-removed-no-pin', 'A3 was removed at seq 4; without a pin the signer must be active now', await signed(mkList({ key_id: A3.id }), [[A3, maker(CA3)]]), { prev: null }, { error: 'NOT_ACTIVE' });
await lcase('signer-removed-pin-below-version', 'the pin is below this version, so the signer must be active now', await signed(mkList({ key_id: A3.id, version: 2, prev: await hash(L1), members: L2.members }), [[A3, maker(CA3)]]), { prev: L1, pin: { version: 1, hash: await hash(L1) } }, { error: 'NOT_ACTIVE' });
await lcase('signer-not-admitted-at-named-head', 'A3 was admitted at seq 2 and names head 1', await signed(mkList({ key_id: A3.id, chain_seq: 1, chain_head: ada.hashes[1] }), [[A3, maker(CA3)]]), { prev: null, pin: { version: 1, hash: await hash(L1) } }, { error: 'NOT_ACTIVE' });
await lcase('signer-of-another-chain', 'M1 is not a device of the admin chain', await signed({ ...L1, key_id: M1.id }, [[M1, maker(CM1)]]), { prev: null }, { error: 'NOT_ACTIVE' });
await lcase('wrong-root', 'the list names Ben as admin but the context chain is Ada\'s', await signed({ ...L1, admin_did: rB.did, members: [mBen] }), { prev: null }, { error: 'WRONG_ROOT' });
await lcase('bad-signature', 'a name was changed after signing', { list: { ...L2, members: byDid([mAda, mBen, { ...mMax, name: 'Max Mustermann' }]) }, sigs: E2.sigs }, { prev: L1 }, { error: 'BAD_SIGNATURE' });
await lcase('bad-signature-other-key', 'signature made by another device key', { list: L1, sigs: [{ key_id: A1.id, sig: await sign(L1, A2), check: await maker(CA1)(await hash(L1)) }] }, { prev: null }, { error: 'BAD_SIGNATURE' });
await lcase('fork', 'named head differs from the chain at that seq', await signed(mkList({ chain_head: ada.hashes[2] })), { prev: null }, { error: 'FORK' });
await lcase('chain-ahead', 'chain_seq is beyond the receiver head', await signed(mkList({ chain_seq: 9 })), { prev: null }, { error: 'CHAIN_AHEAD' });
await lcase('extra-signature', 'a second signature without a hand-over', { list: L1, sigs: [...E1.sigs, ...E1.sigs] }, { prev: null }, { error: 'MALFORMED' });
await lcase('signature-for-other-key-only', 'the only signature names a key that is not the list\'s key_id', { list: L1, sigs: [{ ...E1.sigs[0], key_id: A2.id }] }, { prev: null }, { error: 'MALFORMED' });

// ---- anchors -----------------------------------------------------------------
const mkAnchor = (key = M1, over = {}) =>
  dk.buildAnchor({ member_did: rM.did, team_id: TEAM, admin_did: rA.did, version: 1, prev: null, key_id: key.id, chain_seq: 2, chain_head: max.hashes[2], created_at: T0 + 200, nonce: nonce(), ...over });
async function aenv(a, key, mk = maker(CM1), signKey) {
  const e = { anchor: a, sig: await sign(a, signKey ?? key) };
  if (mk) e.check = await mk(await hash(a));
  return e;
}
const AN1 = mkAnchor();
const AN2 = mkAnchor(M1, { version: 2, prev: await hash(AN1), admin_did: rB.did, created_at: T0 + 201 });
const ANC = mkAnchor(M2, { version: 2, prev: await hash(AN1), admin_did: null, created_at: T0 + 202 });
async function acase(id, description, e, o, expect) {
  cases.push({ id: `anchor-${id}`, description, op: 'team-anchor.verify', input: { chain: o.chain ?? cref('max', 4), envelope: e, prev: o.prev, pin: o.pin, expect: o.expect }, expect });
}
await acase('v1-valid', 'Max trusts Ada for the team, touch with the check', await aenv(AN1, M1), { prev: null, expect: { team_id: TEAM, admin_did: rA.did } }, OK);
await acase('v2-valid', 'Max re-anchors to Ben', await aenv(AN2, M1), { prev: AN1, expect: { admin_did: rB.did } }, OK);
await acase('cleared-valid-without-check', 'admin_did null clears the statement; no check needed', await aenv(ANC, M2, null), { prev: AN1 }, OK);
await acase('cleared-with-check', 'a check given for a cleared anchor', await aenv(ANC, M2, maker(CM1)), { prev: AN1 }, { error: 'MALFORMED' });
await acase('no-check', 'signature alone', await aenv(AN1, M1, null), { prev: null }, { error: 'CHECK_REQUIRED' });
await acase('device-without-check-key', 'anchor by a device that holds no check key', await aenv(mkAnchor(M2), M2, maker(CM1)), { prev: null }, { error: 'CHECK_REQUIRED' });
await acase('check-over-other-object', 'check made over another hash', { anchor: AN1, sig: await sign(AN1, M1), check: await maker(CM1)(await hash(AN2)) }, { prev: null }, { error: 'CHECK_REQUIRED' });
await acase('check-by-other-key', 'check made with a key that is not the device check key', await aenv(AN1, M1, maker(COTHER)), { prev: null }, { error: 'CHECK_REQUIRED' });
await acase('wrong-root', 'the anchor names Nora as member but the chain is Max\'s', await aenv(mkAnchor(M1, { member_did: rN.did }), M1), { prev: null }, { error: 'WRONG_ROOT' });
await acase('other-team', 'the caller expects another team', await aenv(AN1, M1), { prev: null, expect: { team_id: OTHER_TEAM } }, { error: 'TEAM_MISMATCH' });
await acase('other-admin', 'the caller expects another admin', await aenv(AN1, M1), { prev: null, expect: { admin_did: rX.did } }, { error: 'TEAM_MISMATCH' });
await acase('self-anchor', 'a member names itself as admin', await aenv(mkAnchor(M1, { admin_did: rM.did }), M1), { prev: null }, { error: 'MALFORMED' });
await acase('v1-with-prev', 'version 1 with a prev', await aenv(mkAnchor(M1, { prev: await hash(AN1) }), M1), { prev: null }, { error: 'MALFORMED' });
await acase('v2-without-prev', 'version 2 with prev null', await aenv(mkAnchor(M1, { version: 2 }), M1), { prev: AN1 }, { error: 'MALFORMED' });
await acase('wrong-version', 'version 3 after 1', await aenv(mkAnchor(M1, { version: 3, prev: await hash(AN1) }), M1), { prev: AN1 }, { error: 'BAD_VERSION' });
await acase('wrong-prev-hash', 'prev is the hash of another anchor', await aenv(mkAnchor(M1, { version: 2, prev: await hash(AN2) }), M1), { prev: AN1 }, { error: 'BAD_PREV' });
await acase('prev-of-another-team', 'prev belongs to another team', await aenv(AN2, M1), { prev: { ...AN1, team_id: OTHER_TEAM } }, { error: 'TEAM_MISMATCH' });
await acase('signer-removed-no-pin', 'M3 was removed at seq 3 and there is no pin', await aenv(mkAnchor(M3), M3, null), { prev: null }, { error: 'NOT_ACTIVE' });
await acase('v2-with-explicit-no-earlier', 'version 2 with "no earlier anchor"', await aenv(AN2, M1), { prev: null }, { error: 'BAD_VERSION' });
await acase('bad-signature', 'the admin was changed after signing', { anchor: { ...AN1, admin_did: rX.did }, sig: await sign(AN1, M1), check: await maker(CM1)(await hash({ ...AN1, admin_did: rX.did })) }, { prev: null }, { error: 'BAD_SIGNATURE' });
await acase('fork', 'named head differs', await aenv(mkAnchor(M1, { chain_head: max.hashes[1] }), M1), { prev: null }, { error: 'FORK' });
await acase('chain-ahead', 'chain_seq beyond the receiver head', await aenv(mkAnchor(M1, { chain_seq: 9 }), M1), { prev: null }, { error: 'CHAIN_AHEAD' });
await acase('wrong-typ', 'typ of a leave', await aenv({ ...AN1, typ: 'suveren-team-leave' }, M1), { prev: null }, { error: 'MALFORMED' });
await acase('unknown-member', 'extra member', await aenv({ ...AN1, note: 'x' }, M1), { prev: null }, { error: 'MALFORMED' });

// ---- leaves ------------------------------------------------------------------
const mkLeave = (key = M1, over = {}) =>
  dk.buildLeave({ member_did: rM.did, team_id: TEAM, list_version: 3, key_id: key.id, chain_seq: 2, chain_head: max.hashes[2], created_at: T0 + 300, nonce: nonce(), ...over });
async function lvcase(id, description, e, o, expect) {
  cases.push({ id: `leave-${id}`, description, op: 'team-leave.verify', input: { chain: o.chain ?? cref('max', 4), envelope: e, team_id: o.team_id ?? TEAM }, expect });
}
const lenv = async (l, key, extra = {}) => ({ leave: l, sig: await sign(l, key), ...extra });
const LV = mkLeave();
await lvcase('valid', 'any active device may leave, no check', await lenv(LV, M1), {}, OK);
await lvcase('valid-device-without-check-key', 'M2 has no check key and may still leave', await lenv(mkLeave(M2), M2), {}, OK);
await lvcase('check-given', 'a check may not be given', await lenv(LV, M1, { check: await maker(CM1)(await hash(LV)) }), {}, { error: 'MALFORMED' });
await lvcase('other-team', 'the caller expects another team', await lenv(LV, M1), { team_id: OTHER_TEAM }, { error: 'TEAM_MISMATCH' });
await lvcase('wrong-root', 'the leave names Nora but the chain is Max\'s', await lenv(mkLeave(M1, { member_did: rN.did }), M1), {}, { error: 'WRONG_ROOT' });
await lvcase('removed-device', 'M3 was removed at seq 3', await lenv(mkLeave(M3), M3), {}, { error: 'NOT_ACTIVE' });
await lvcase('bad-signature', 'signed by another device key', await lenv(LV, M2), {}, { error: 'BAD_SIGNATURE' });
await lvcase('fork', 'named head differs', await lenv(mkLeave(M1, { chain_head: max.hashes[1] }), M1), {}, { error: 'FORK' });
await lvcase('chain-ahead', 'chain_seq beyond the receiver head', await lenv(mkLeave(M1, { chain_seq: 9 }), M1), {}, { error: 'CHAIN_AHEAD' });
await lvcase('wrong-typ', 'typ of an anchor', await lenv({ ...LV, typ: 'suveren-team-anchor' }, M1), {}, { error: 'MALFORMED' });
await lvcase('list-version-zero', 'list_version 0', await lenv(mkLeave(M1, { list_version: 0 }), M1), {}, { error: 'MALFORMED' });

// ---- trust -------------------------------------------------------------------
const AN_MAX_A = await aenv(AN1, M1); // Max trusts Ada
const AN_MAX_B = await aenv(mkAnchor(M1, { admin_did: rB.did, created_at: T0 + 210 }), M1); // Max trusts Ben (v1 of his line)
const mkAnchorFor = async (did, key, mk, c, built_, admin, over = {}) => {
  const a = dk.buildAnchor({ member_did: did, team_id: TEAM, admin_did: admin, version: 1, prev: null, key_id: key.id, chain_seq: 0, chain_head: built_.hashes[0], created_at: T0 + 220, nonce: nonce(), ...over });
  return aenv(a, key, mk);
};
const AN_NORA_A = await mkAnchorFor(rN.did, N1, maker(CN1), CN1, nora, rA.did);
const adminChains = { [rA.did]: cref('ada', 5), [rB.did]: cref('ben'), [rX.did]: cref('xav') };
const dids = (ms) => ms.map((m) => m.did);
async function tcase(id, description, o, expect) {
  cases.push({
    id: `trust-${id}`,
    description,
    op: 'team-trust.verify',
    input: {
      team_id: o.team_id ?? TEAM,
      anchor: o.anchor ?? AN_MAX_A,
      anchor_chain: o.anchorChain ?? cref('max', 4),
      anchor_pin: o.anchorPin,
      versions: o.versions,
      admin_chains: o.adminChains ?? adminChains,
      pin: o.pin,
      leaves: o.leaves,
    },
    expect,
  });
}
const pinOf = async (l) => ({ version: l.version, hash: await hash(l) });
await tcase('after-join', 'Max trusts Ada; list 1 and 2 verify; Max is in list 2', { versions: [E1, E2] }, { ok: true, version: 2, admin_did: rA.did, members: dids(L2.members) });
await tcase('versions-in-any-order', 'the Authority Server serves the versions in another order', { versions: [E3, E1, E2] }, { ok: true, version: 3, admin_did: rA.did, members: dids(L3.members) });
await tcase('duplicate-version-same-hash', 'the same version twice, identical', { versions: [E1, E2, E2] }, { ok: true, version: 2 });
await tcase('follows-handover', 'Max trusts Ada; the admin changes to Ben with both signatures', { versions: [E1, E2, E3, E4] }, { ok: true, version: 4, admin_did: rB.did, members: dids(L4.members) });
await tcase('follows-handover-and-later', 'versions after the hand-over, signed by Ben', { versions: [E1, E2, E3, E4, E5] }, { ok: true, version: 5, admin_did: rB.did, members: dids(L5.members) });
await tcase('start-from-trimmed-history', 'the Authority Server serves only the last versions (Max trusts Ada, list 3 is the first)', { versions: [E3, E4, E5] }, { ok: true, version: 5, admin_did: rB.did });
await tcase('anchor-names-new-admin', 'Max re-anchored to Ben; the list of Ben alone (one signature) is accepted from that anchor on', { anchor: AN_MAX_B, versions: [E1, E2, E3, E4x] }, { ok: true, version: 4, admin_did: rB.did });
await tcase('anchor-names-new-admin-later-versions', 'the same, and a later version signed by Ben', { anchor: AN_MAX_B, versions: [E1, E2, E3, E4x, E5x] }, { ok: true, version: 5, admin_did: rB.did, members: dids(L5.members) });
await tcase('single-signature-change-without-anchor', 'Ben alone changes the admin and Max never anchored Ben: the walk stops at version 3', { versions: [E1, E2, E3, E4x] }, { ok: true, version: 3, admin_did: rA.did });
await tcase('list-by-a-stranger-admin', 'a list by Xavier at version 4 is ignored: version 3', { versions: [E1, E2, E3, await env(mkList({ version: 4, prev: await hash(L3), admin_did: rX.did, members: byDid([mAda, mBen, mMax, mNora, await member(rX.did, 'Xavier Fremd')]), key_id: X1.id, chain_seq: 0, chain_head: xav.hashes[0] }), [[X1, maker(CX1)]])] }, { ok: true, version: 3, admin_did: rA.did });
await tcase('removed-signer-without-pin-stops-the-walk', 'list 3 is signed by A3, removed at seq 4: no pin, so the walk ends at version 2', { versions: [E1, E2, await env(mkList({ version: 3, prev: await hash(L2), members: L3.members, key_id: A3.id }), [[A3, maker(CA3)]])] }, { ok: true, version: 2 });
const L3a3 = mkList({ version: 3, prev: await hash(L2), members: L3.members, key_id: A3.id, created_at: T0 + 150 });
await tcase('removed-signer-at-pin-is-accepted', 'the same list when the verifier already pinned version 3', { versions: [E1, E2, await env(L3a3, [[A3, maker(CA3)]])], pin: await pinOf(L3a3) }, { ok: true, version: 3 });
await tcase('pin-same-version', 'the pin equals the newest version', { versions: [E1, E2, E3], pin: await pinOf(L3) }, { ok: true, version: 3, pin: await pinOf(L3) });
await tcase('pin-lower-linked-by-prev', 'the pin is version 2; version 3 continues from it; the history below is trimmed', { versions: [E3], pin: await pinOf(L2) }, { ok: true, version: 3 });
await tcase('rollback', 'the verifier pinned version 4; the Authority Server serves up to 3', { versions: [E1, E2, E3], pin: await pinOf(L4) }, { error: 'ROLLBACK' });
await tcase('rollback-to-v1', 'the verifier pinned version 3; only version 1 is served', { versions: [E1], pin: await pinOf(L3) }, { error: 'ROLLBACK' });
await tcase('fork-same-version-other-hash', 'the verifier pinned list 3; the Authority Server serves another list 3', { versions: [E1, E2, E3b], pin: await pinOf(L3) }, { error: 'FORK' });
await tcase('fork-two-lists-at-one-version', 'the Authority Server serves two different lists at version 3', { versions: [E1, E2, E3, E3b] }, { error: 'FORK' });
await tcase('fork-history-differs-from-pin', 'the pin is version 2 with another hash; version 3 continues another version 2', { versions: [E3], pin: { version: 2, hash: await hash(L3b) } }, { error: 'FORK' });
await tcase('history-gap', 'the pin is version 1 and only version 3 is served: nothing links 3 to the pin', { versions: [E3], pin: await pinOf(L1) }, { error: 'HISTORY_GAP' });
await tcase('removed-member', 'Nora trusts Ada; version 5 removes her: she is not given an older list', { anchor: AN_NORA_A, anchorChain: cref('nora'), versions: [E1, E2, E3, E4, E5] }, { error: 'NOT_A_MEMBER' });
await tcase('not-in-list-yet', 'Nora anchored but the newest list does not hold her yet', { anchor: AN_NORA_A, anchorChain: cref('nora'), versions: [E1, E2] }, { error: 'NOT_A_MEMBER' });
await tcase('anchor-cleared', 'the member cleared the anchor', { anchor: await aenv(ANC, M2, null), versions: [E1, E2] }, { error: 'NO_TRUST' });
await tcase('anchor-of-another-team', 'the anchor names another team', { anchor: await aenv(mkAnchor(M1, { team_id: OTHER_TEAM }), M1), versions: [E1, E2] }, { error: 'TEAM_MISMATCH' });
await tcase('anchor-of-another-person', 'Max\'s anchor verified against Nora\'s chain', { anchorChain: cref('nora'), versions: [E1, E2] }, { error: 'WRONG_ROOT' });
await tcase('anchor-rollback', 'the verifier pinned anchor version 2 and is given version 1', { anchorPin: { version: 2, hash: await hash(AN2) }, versions: [E1, E2] }, { error: 'ROLLBACK' });
await tcase('list-of-another-team', 'a version belongs to another team', { versions: [E1, await env(mkList({ team_id: OTHER_TEAM, version: 2, prev: await hash(L1), members: L2.members }), SA1)] }, { error: 'TEAM_MISMATCH' });
await tcase('no-list-of-the-anchored-admin', 'only Xavier\'s lists', { versions: [await env(mkList({ admin_did: rX.did, members: [await member(rX.did, 'Xavier Fremd')], key_id: X1.id, chain_seq: 0, chain_head: xav.hashes[0] }), [[X1, maker(CX1)]])] }, { error: 'NO_TRUST' });
await tcase('admin-chain-missing', 'no verified chain given for the admin', { versions: [E1, E2], adminChains: {} }, { error: 'NO_TRUST' });
await tcase('first-list-does-not-verify', 'the first version of the anchored admin has a wrong signature', { versions: [{ list: L1, sigs: [{ key_id: A1.id, sig: await sign(L1, A2), check: await maker(CA1)(await hash(L1)) }] }] }, { error: 'BAD_SIGNATURE' });
await tcase('versions-with-a-gap-end-the-walk', 'version 3 is missing between 2 and 4: the walk ends at 2', { versions: [E1, E2, E4], adminChains }, { ok: true, version: 2 });

const LEAVE_MAX_3 = { env: await lenv(mkLeave(M1, { list_version: 3 }), M1), chain: cref('max', 4) };
await tcase('leave-applies', 'Max left at version 3; Nora (who trusts Ada) sees him gone before the admin signed', { anchor: AN_NORA_A, anchorChain: cref('nora'), versions: [E1, E2, E3], leaves: [LEAVE_MAX_3] }, { ok: true, version: 3, left: [rM.did], members: dids(byDid([mAda, mBen, mNora])) });
await tcase('leave-by-the-member-itself', 'Max sees his own leave: he is out', { versions: [E1, E2, E3], leaves: [LEAVE_MAX_3] }, { error: 'NOT_A_MEMBER' });
await tcase('leave-of-a-later-version-is-ignored', 'a leave from a list version above the accepted one does not apply yet', { anchor: AN_NORA_A, anchorChain: cref('nora'), versions: [E1, E2, E3], leaves: [{ env: await lenv(mkLeave(M1, { list_version: 4 }), M1), chain: cref('max', 4) }] }, { ok: true, version: 3, left: [] });
await tcase('leave-then-removed-and-added-again', 'Max left at version 3 but a later list does not hold him in between: the leave does not apply to a rejoin', { anchor: AN_NORA_A, anchorChain: cref('nora'), versions: [E1, E2, E3, E4, E5, E6, await env(mkList({ version: 7, prev: await hash(L6), admin_did: rB.did, members: byDid([mAda, mBen, mMax, mNora]), ...bHead, created_at: T0 + 107 }), SB1)], leaves: [LEAVE_MAX_3] }, { ok: true, version: 7, left: [] });
await tcase('leave-by-the-admin', 'the admin cannot leave', { anchor: AN_NORA_A, anchorChain: cref('nora'), versions: [E1, E2, E3], leaves: [{ env: await lenv(dk.buildLeave({ member_did: rA.did, team_id: TEAM, list_version: 3, key_id: A1.id, chain_seq: 3, chain_head: ada.hashes[3], created_at: T0 + 301, nonce: nonce() }), A1), chain: cref('ada', 5) }] }, { error: 'ADMIN_CANNOT_LEAVE' });
await tcase('leave-for-another-team', 'a leave of another team', { anchor: AN_NORA_A, anchorChain: cref('nora'), versions: [E1, E2, E3], leaves: [{ env: await lenv(mkLeave(M1, { team_id: OTHER_TEAM }), M1), chain: cref('max', 4) }] }, { error: 'TEAM_MISMATCH' });
await tcase('leave-forged', 'a leave signed by another device key', { anchor: AN_NORA_A, anchorChain: cref('nora'), versions: [E1, E2, E3], leaves: [{ env: await lenv(mkLeave(M1, { list_version: 3 }), M2), chain: cref('max', 4) }] }, { error: 'BAD_SIGNATURE' });

writeFileSync(
  join(here, 'team.json'),
  JSON.stringify(
    {
      suite: 'device-keys/team',
      description: 'DEC-73 (20.21.3): suveren-team-members, suveren-team-anchor, suveren-team-leave and verifyTeamTrust. Chains: ada (first admin), ben (second admin), max and nora (members), xav (a stranger). Lists L1..L6: 1 Ada; 2 adds Ben and Max; 3 adds Nora; 4 hand-over Ada to Ben; 5 Ben removes Nora; 6 Ben removes Max.',
      fixtures: { root_did: rA.did, roots, chains: { ada: ada.chain, ben: ben.chain, max: max.chain, nora: nora.chain, xav: xav.chain } },
      cases,
    },
    null,
    2,
  ) + '\n',
);
console.log('wrote team.json', cases.length, 'cases');

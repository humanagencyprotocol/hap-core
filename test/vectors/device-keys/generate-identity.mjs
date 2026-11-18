/**
 * Generates identity.json: vectors for `suveren-identity-cancel` and `suveren-identity-override`
 * (plan section 10 and 20.1 item 4). Separate from generate.mjs on purpose: running generate.mjs
 * again would change every existing vector (random ECDSA check keys). This file builds its own
 * two chains (a member's old chain and a team admin's chain) and does not touch the other files.
 *
 * RUN ONCE, then commit the output (the P-256 check keys and signatures are random).
 *
 *   pnpm build && node test/vectors/device-keys/generate-identity.mjs
 */
import { writeFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { deviceKeys as dk } from '../../../dist/index.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const subtle = webcrypto.subtle;
const T0 = 1794100000;
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

const CG = await p256(); // member's gateway
const CW = await p256(); // member's second device, from seq 3
const CA = await p256(); // admin's gateway
const CX = await p256(); // a key that belongs to no device

async function device(n, { label, check = null, kind = 'gateway' }) {
  const seed = filled(n);
  const pub = await dk.ed25519PublicKey(seed);
  const rec = { key_id: await dk.keyIdOf(pub), sign_pub: b64u(pub), read_pub: b64u(filled(0x80 + n)), kind, label, keystore: 'software', check };
  return { seed, id: rec.key_id, rec };
}
const G = await device(0x41, { label: "Max's MacBook", check: platformKey(CG) });
const W = await device(0x42, { label: "Max's Office PC" });
const R = await device(0x43, { label: "Max's old laptop" });
const A1 = await device(0x51, { label: "Admin's MacBook", check: platformKey(CA) });
const A2 = await device(0x52, { label: "Admin's Office PC" });

const rootMember = await dk.deriveRootKey(Uint8Array.from({ length: 16 }, (_, i) => 0x30 + i));
const rootAdmin = await dk.deriveRootKey(Uint8Array.from({ length: 16 }, (_, i) => 0x60 + i));
const rootOther = await dk.deriveRootKey(filled(0x77, 16));

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

// member chain: 0 genesis G; 1 add W (no check key); 2 add R; 3 W gets a check key; 4 R leaves
const member = await build(rootMember, [
  { op: 'genesis', fields: { device: G.rec }, sigs: [['root', rootMember.privateSeed], [G.id, G.seed]], checks: [[G.id, maker(CG)]] },
  { op: 'add', signer: G.id, fields: { device: W.rec }, sigs: [[G.id, G.seed], [W.id, W.seed]], checks: [[G.id, maker(CG)]] },
  { op: 'add', signer: G.id, fields: { device: R.rec }, sigs: [[G.id, G.seed], [R.id, R.seed]], checks: [[G.id, maker(CG)]] },
  { op: 'set', signer: G.id, fields: { target: W.id, check: platformKey(CW) }, sigs: [[G.id, G.seed]], checks: [[G.id, maker(CG)], [W.id, maker(CW)]] },
  { op: 'remove', signer: R.id, fields: { target: R.id }, sigs: [[R.id, R.seed]] },
]);
// admin chain: 0 genesis A1; 1 add A2 (no check key)
const admin = await build(rootAdmin, [
  { op: 'genesis', fields: { device: A1.rec }, sigs: [['root', rootAdmin.privateSeed], [A1.id, A1.seed]], checks: [[A1.id, maker(CA)]] },
  { op: 'add', signer: A1.id, fields: { device: A2.rec }, sigs: [[A1.id, A1.seed], [A2.id, A2.seed]], checks: [[A1.id, maker(CA)]] },
]);

const sign = async (obj, key) => b64u(await dk.signEd25519(key.seed, dk.signedBytes(obj)));
const REQ = 'req-7f3a';
const USER = 'user-max-42';
const NOW = T0 + 1000;
const SKEW = 300;
const cases = [];
const mref = (count) => ({ ref: 'member', count });
const aref = (count) => ({ ref: 'admin', count, expected_root_did: rootAdmin.did });

// ---- cancel -------------------------------------------------------------
const mkCancel = (key, over = {}) =>
  dk.buildIdentityCancel({ root_did: rootMember.did, key_id: key.id, request_id: REQ, chain_seq: 4, chain_head: member.hashes[4], issued_at: NOW - 10, ...over });
async function cancel(id, description, key, o, expect) {
  const c = o.mutate ? o.mutate(mkCancel(key, o.over)) : mkCancel(key, o.over);
  const env = { cancel: c, sig: await sign(c, o.signKey ?? key) };
  if (o.maker) env.check = await o.maker(o.checkHash ?? (await dk.objectHash(c)));
  cases.push({
    id: `cancel-${id}`,
    description,
    op: 'identity-cancel.verify',
    input: { chain: mref(o.count ?? 5), envelope: env, request_id: o.requestId ?? REQ, now: o.now ?? NOW, max_skew_seconds: o.skew ?? SKEW },
    expect,
  });
}
const OK = { ok: true };
const G_CHK = { maker: maker(CG) };
await cancel('valid-with-check', 'device with a check key signs, with its check over the object hash', G, G_CHK, OK);
await cancel('valid-device-without-check-key', 'W has no check key at seq 2 (chain of 2 entries): signs without a check', W, { count: 2, over: { chain_seq: 1, chain_head: member.hashes[1] } }, OK);
await cancel('valid-second-device-with-check', 'W has a check key since seq 3: signs with it', W, { maker: maker(CW) }, OK);
await cancel('valid-older-head', 'names an older head that matches the chain, same check key then and now', G, { ...G_CHK, over: { chain_seq: 2, chain_head: member.hashes[2] } }, OK);
await cancel('valid-edge-of-window', 'issued_at exactly max_skew_seconds before now', G, { ...G_CHK, over: { issued_at: NOW - SKEW } }, OK);
await cancel('wrong-typ', 'typ of another object', G, { ...G_CHK, mutate: (c) => ({ ...c, typ: 'suveren-device-signin' }) }, { error: 'MALFORMED' });
await cancel('wrong-v', 'v is 2', G, { ...G_CHK, mutate: (c) => ({ ...c, v: 2 }) }, { error: 'MALFORMED' });
await cancel('unknown-member', 'extra member', G, { ...G_CHK, mutate: (c) => ({ ...c, note: 'x' }) }, { error: 'MALFORMED' });
await cancel('missing-member', 'request_id missing', G, { ...G_CHK, mutate: (c) => { const { request_id, ...rest } = c; return rest; } }, { error: 'MALFORMED' });
await cancel('wrong-request-id', 'signed for another request than the one the AS expects', G, { ...G_CHK, requestId: 'req-other' }, { error: 'REQUEST_MISMATCH' });
await cancel('fork', 'named head hash differs from the chain at that seq', G, { ...G_CHK, over: { chain_head: member.hashes[2] } }, { error: 'FORK' });
await cancel('chain-ahead', 'chain_seq is beyond the receiver head', G, { ...G_CHK, over: { chain_seq: 9 } }, { error: 'CHAIN_AHEAD' });
await cancel('removed-key', 'R was removed at seq 4', R, { over: {} }, { error: 'NOT_ACTIVE' });
await cancel('not-admitted-at-named-head', 'W was admitted at seq 1 and names head 0', W, { maker: maker(CW), over: { chain_seq: 0, chain_head: member.hashes[0] } }, { error: 'NOT_ACTIVE' });
await cancel('missing-check', 'G has a check key; the signature alone is refused', G, {}, { error: 'CHECK_REQUIRED' });
await cancel('check-over-other-object', 'check made over another hash', G, { maker: maker(CG), checkHash: member.hashes[0] }, { error: 'CHECK_REQUIRED' });
await cancel('check-by-other-key', 'check made with a key that is not the device check key', G, { maker: maker(CX) }, { error: 'CHECK_REQUIRED' });
await cancel('check-key-changed-since-named-head', 'W got its check key at seq 3; naming head 2 cannot skip it', W, { maker: maker(CW), over: { chain_seq: 2, chain_head: member.hashes[2] } }, { error: 'CHECK_REQUIRED' });
await cancel('check-given-by-device-without-check-key', 'a device without a check key must not send one', W, { count: 2, maker: maker(CW), over: { chain_seq: 1, chain_head: member.hashes[1] } }, { error: 'MALFORMED' });
await cancel('too-old', 'issued_at 301 seconds before now', G, { ...G_CHK, over: { issued_at: NOW - SKEW - 1 } }, { error: 'STALE' });
await cancel('in-the-future', 'issued_at 301 seconds after now', G, { ...G_CHK, over: { issued_at: NOW + SKEW + 1 } }, { error: 'STALE' });
await cancel('narrow-window', 'a caller window of 5 seconds refuses issued_at 10 seconds ago', G, { ...G_CHK, skew: 5 }, { error: 'STALE' });
await cancel('wrong-root', 'root_did of another person', G, { ...G_CHK, over: { root_did: rootOther.did } }, { error: 'WRONG_ROOT' });
await cancel('bad-signature', 'signature made by another device key', G, { ...G_CHK, signKey: W }, { error: 'BAD_SIGNATURE' });

// ---- override -----------------------------------------------------------
const mkOverride = (key, over = {}) =>
  dk.buildIdentityOverride({ admin_did: rootAdmin.did, key_id: key.id, chain_seq: 1, chain_head: admin.hashes[1], member_user_id: USER, request_id: REQ, issued_at: NOW - 10, ...over });
async function override(id, description, key, o, expect) {
  const x = o.mutate ? o.mutate(mkOverride(key, o.over)) : mkOverride(key, o.over);
  const env = { override: x, sig: await sign(x, o.signKey ?? key) };
  if (o.maker) env.check = await o.maker(o.checkHash ?? (await dk.objectHash(x)));
  cases.push({
    id: `override-${id}`,
    description,
    op: 'identity-override.verify',
    input: { chain: aref(o.count ?? 2), envelope: env, request_id: o.requestId ?? REQ, member_user_id: o.memberUserId ?? USER, now: o.now ?? NOW },
    expect,
  });
}
const A_CHK = { maker: maker(CA) };
await override('valid', "admin's granting device signs with its check over the object hash", A1, A_CHK, OK);
await override('valid-older-head', 'names an older head that matches, same check key then and now', A1, { ...A_CHK, over: { chain_seq: 0, chain_head: admin.hashes[0] } }, OK);
await override('wrong-typ', 'typ of the cancel object', A1, { ...A_CHK, mutate: (x) => ({ ...x, typ: 'suveren-identity-cancel' }) }, { error: 'MALFORMED' });
await override('unknown-member', 'extra member', A1, { ...A_CHK, mutate: (x) => ({ ...x, reason: 'x' }) }, { error: 'MALFORMED' });
await override('missing-member', 'member_user_id missing', A1, { ...A_CHK, mutate: (x) => { const { member_user_id, ...rest } = x; return rest; } }, { error: 'MALFORMED' });
await override('wrong-request-id', 'signed for another request', A1, { ...A_CHK, requestId: 'req-other' }, { error: 'REQUEST_MISMATCH' });
await override('wrong-member', 'signed for another member than the one the AS expects', A1, { ...A_CHK, memberUserId: 'user-someone-else' }, { error: 'REQUEST_MISMATCH' });
await override('fork', 'named head differs', A1, { ...A_CHK, over: { chain_head: admin.hashes[0] } }, { error: 'FORK' });
await override('chain-ahead', 'chain_seq beyond the receiver head', A1, { ...A_CHK, over: { chain_seq: 9 } }, { error: 'CHAIN_AHEAD' });
await override('removed-key', 'key_id is not a device of the admin chain', G, { ...A_CHK }, { error: 'NOT_ACTIVE' });
await override('missing-check', 'signature alone is refused', A1, {}, { error: 'CHECK_REQUIRED' });
await override('check-over-other-object', 'check made over another hash', A1, { maker: maker(CA), checkHash: admin.hashes[0] }, { error: 'CHECK_REQUIRED' });
await override('check-by-other-key', 'check made with a key that is not the device check key', A1, { maker: maker(CX) }, { error: 'CHECK_REQUIRED' });
await override('device-without-check-key', 'A2 has no check key: an override is a grant-class action and needs one', A2, { maker: maker(CA) }, { error: 'CHECK_REQUIRED' });
await override('device-without-check-key-no-check', 'A2 signs without a check', A2, {}, { error: 'CHECK_REQUIRED' });
await override('too-old', 'issued_at 301 seconds before now', A1, { ...A_CHK, over: { issued_at: NOW - 301 } }, { error: 'STALE' });
await override('in-the-future', 'issued_at 301 seconds after now', A1, { ...A_CHK, over: { issued_at: NOW + 301 } }, { error: 'STALE' });
await override('wrong-root', 'admin_did of another person', A1, { ...A_CHK, over: { admin_did: rootOther.did } }, { error: 'WRONG_ROOT' });
await override('member-chain-is-not-admin-chain', 'admin_did names the member, whose chain is not the admin chain', A1, { ...A_CHK, over: { admin_did: rootMember.did } }, { error: 'WRONG_ROOT' });
await override('bad-signature', 'signature by another device key', A1, { ...A_CHK, signKey: A2 }, { error: 'BAD_SIGNATURE' });
{
  const ov = mkOverride(A1);
  cases.push({
    id: 'override-cancel-object-is-refused',
    description: 'a valid cancel object and its signature are not an override',
    op: 'identity-override.verify',
    input: { chain: aref(2), envelope: { override: mkCancel(A1, { root_did: rootAdmin.did, chain_seq: 1, chain_head: admin.hashes[1] }), sig: await sign(mkCancel(A1, { root_did: rootAdmin.did, chain_seq: 1, chain_head: admin.hashes[1] }), A1) }, request_id: REQ, member_user_id: USER, now: NOW },
    expect: { error: 'MALFORMED' },
  });
  void ov;
}

writeFileSync(
  join(here, 'identity.json'),
  JSON.stringify(
    {
      suite: 'device-keys/identity',
      description: 'Plan section 10 and 20.1 item 4: suveren-identity-cancel (member chain) and suveren-identity-override (admin chain). Every case has now = 1794101000, a window of 300 seconds (override: fixed 300).',
      fixtures: { root_did: rootMember.did, chains: { member: member.chain, admin: admin.chain } },
      cases,
    },
    null,
    2,
  ) + '\n',
);
console.log('wrote identity.json', cases.length, 'cases');

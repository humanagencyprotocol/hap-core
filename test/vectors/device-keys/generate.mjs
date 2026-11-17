/**
 * Generates the device-keys test vectors (*.json next to this file).
 *
 * RUN ONCE, then commit the output. Ed25519 and all hashes are deterministic (fixed seeds),
 * but ECDSA P-256 keys and signatures made by WebCrypto are random, so a second run produces
 * different (equally valid) check keys and proofs. Regenerate only on purpose.
 *
 *   pnpm build && node test/vectors/device-keys/generate.mjs
 *
 * It imports the built bundle (dist/index.mjs) and uses the library's own build/sign helpers
 * to produce the inputs; the expected results are written down here by hand, not computed by
 * the code under test (except where the value IS the code's job, e.g. a hash, and then the
 * value is stored so another implementation can compare).
 */
import { writeFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { deviceKeys as dk, canonicalize } from '../../../dist/index.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const subtle = webcrypto.subtle;
const T0 = 1794000000;
const b64u = dk.b64uEncode;
const hex = dk.hexEncode;
const utf8 = dk.utf8;
const ecdsa = { name: 'ECDSA', hash: 'SHA-256' };

const filled = (n, len = 32) => new Uint8Array(len).fill(n);
const seq16 = Uint8Array.from({ length: 16 }, (_, i) => i);

function write(name, obj) {
  writeFileSync(join(here, name), JSON.stringify(obj, null, 2) + '\n');
  console.log('wrote', name, obj.cases.length, 'cases');
}

// ---------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------
async function p256() {
  const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const raw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  return { priv: kp.privateKey, raw };
}
async function signDer(k, data) {
  return dk.ecdsaRawToDer(new Uint8Array(await subtle.sign(ecdsa, k.priv, data)));
}
function platformKey(k) {
  return { type: 'platform', pub: b64u(k.raw) };
}
function webauthnKey(k, rp, credId) {
  return { type: 'webauthn', rp_id: rp, cred_id: b64u(credId), pub: b64u(dk.encodeCoseEc2(k.raw.slice(1, 33), k.raw.slice(33, 65))) };
}
/** Proof makers: (hash) => proof */
function platformMaker(k) {
  return async (hash) => ({ signature: b64u(await signDer(k, dk.hashBytes(hash))) });
}
async function waProof(k, rp, signedHash, o = {}) {
  const rpHash = await dk.sha256(utf8(o.rpForHash ?? rp));
  const authData = dk.concat(rpHash, Uint8Array.of(o.flags ?? 0x05), Uint8Array.of(0, 0, 0, 1));
  const cdj = utf8(
    JSON.stringify({
      type: o.type ?? 'webauthn.get',
      challenge: o.challenge ?? b64u(dk.hashBytes(o.challengeHash ?? signedHash)),
      origin: 'https://' + rp,
    }),
  );
  const sig = await signDer(k, dk.concat(authData, await dk.sha256(cdj)));
  return { authenticatorData: b64u(authData), clientDataJSON: b64u(cdj), signature: b64u(sig) };
}
function webauthnMaker(k, rp, o) {
  return (hash) => waProof(k, rp, hash, o);
}

// ---------------------------------------------------------------------------
// world
// ---------------------------------------------------------------------------
const root1 = await dk.deriveRootKey(seq16);
const root2Seed = Uint8Array.from({ length: 16 }, (_, i) => 0xf0 + i);
const root2 = await dk.deriveRootKey(root2Seed);
const rootOther = await dk.deriveRootKey(filled(0x77, 16));

const CG = await p256();
const CP = await p256();
const CH = await p256();
const CX = await p256();
const RP = 'approve.suveren.ai';
const cgKey = platformKey(CG);
const cpKey = webauthnKey(CP, RP, filled(0xcc, 16));
const chKey = platformKey(CH);

async function device(n, { kind = 'gateway', label, check = null, keystore = 'software' } = {}) {
  const seed = filled(n);
  const pub = await dk.ed25519PublicKey(seed);
  const rec = { key_id: await dk.keyIdOf(pub), sign_pub: b64u(pub), read_pub: b64u(filled(0x80 + n)), kind, label: label ?? `Device ${n}`, keystore, check };
  return { seed, pub, id: rec.key_id, rec };
}
const G = await device(1, { kind: 'gateway', label: "Alice's MacBook", check: cgKey });
const P = await device(2, { kind: 'approve-app', label: "Alice's iPhone", check: cpKey, keystore: 'platform' });
const H = await device(3, { kind: 'gateway', label: 'Office PC' });
const Q = await device(4, { kind: 'gateway', label: 'Laptop 2' });

async function E(prev, op, fields) {
  const last = prev[prev.length - 1];
  return dk.buildEntry({
    root_did: root1.did,
    seq: prev.length,
    prev: last ? await dk.entryHash(last) : null,
    op,
    created_at: T0 + prev.length,
    signer: 'root',
    ...fields,
  });
}
/** sigSpec: [[by, seed]]; chkSpec: [[by, maker]] */
async function fin(entry, sigSpec, chkSpec = []) {
  entry.sigs = [];
  entry.checks = [];
  for (const [by, seed] of sigSpec) entry.sigs.push(await dk.signEntry(entry, by, seed));
  const h = await dk.entryHash(entry);
  for (const [by, maker] of chkSpec) entry.checks.push({ by, check: await maker(h) });
  return entry;
}
const clone = (x) => JSON.parse(JSON.stringify(x));

// ---------------------------------------------------------------------------
// the main chain
// ---------------------------------------------------------------------------
const main = [];
main.push(await fin(await E(main, 'genesis', { device: G.rec }), [['root', root1.privateSeed], [G.id, G.seed]], [[G.id, platformMaker(CG)]]));
main.push(await fin(await E(main, 'add', { signer: G.id, device: P.rec }), [[G.id, G.seed], [P.id, P.seed]], [[G.id, platformMaker(CG)], [P.id, webauthnMaker(CP, RP)]]));
main.push(await fin(await E(main, 'add', { signer: P.id, device: H.rec, ext: { note_from_future: [1, 2], linked: { kind: 'x' } } }), [[P.id, P.seed], [H.id, H.seed]], [[P.id, webauthnMaker(CP, RP)]]));
main.push(await fin(await E(main, 'set', { signer: P.id, target: H.id, check: chKey }), [[P.id, P.seed]], [[P.id, webauthnMaker(CP, RP)], [H.id, platformMaker(CH)]]));
main.push(await fin(await E(main, 'remove', { signer: H.id, target: H.id }), [[H.id, H.seed]]));
main.push(await fin(await E(main, 'rotate-root', { new_root: b64u(root2.publicKey) }), [['root', root1.privateSeed], [P.id, P.seed]], [[P.id, webauthnMaker(CP, RP)]]));
main.push(await fin(await E(main, 'add', { device: Q.rec }), [['root', root2.privateSeed], [Q.id, Q.seed]]));
const mainHashes = [];
for (const e of main) mainHashes.push(await dk.entryHash(e));
const rootDid = root1.did;

const ref = (count, append) => ({ ref: 'main', count, ...(append ? { append } : {}) });
const chainCases = [];
const ok = (id, description, chain, ok_, stored_head) =>
  chainCases.push({ id, description, op: 'chain.verify', input: { chain, ...(stored_head ? { stored_head } : {}) }, expect: { ok: ok_ } });
const bad = (id, description, chain, error, stored_head, expectedRoot) =>
  chainCases.push({ id, description, op: 'chain.verify', input: { chain, ...(stored_head ? { stored_head } : {}), ...(expectedRoot ? { expected_root_did: expectedRoot } : {}) }, expect: { error } });

const okState = (count, active, granting, rootPub) => ({
  head: { seq: count - 1, hash: mainHashes[count - 1] },
  active,
  granting,
  root_pub: b64u(rootPub),
});
ok('main-1-genesis', 'genesis with a device that has a platform check key', ref(1), okState(1, [G.id], [G.id], root1.publicKey));
ok('main-2-add-by-granting-device', 'add by a granting device: its signature and its check, plus the joiner\'s signature and check', ref(2), okState(2, [G.id, P.id].sort(), [G.id, P.id].sort(), root1.publicKey));
ok('main-3-add-no-check-device-with-ext', 'add of a device without a check key, by the phone; entry carries ext with members this verifier does not know', ref(3), okState(3, [G.id, P.id, H.id].sort(), [G.id, P.id].sort(), root1.publicKey));
ok('main-4-set-check', 'set gives the device a check key; the new key proves possession', ref(4), okState(4, [G.id, P.id, H.id].sort(), [G.id, P.id, H.id].sort(), root1.publicKey));
ok('main-5-remove-self', 'a device removes itself with its signature alone', ref(5), okState(5, [G.id, P.id].sort(), [G.id, P.id].sort(), root1.publicKey));
ok('main-6-rotate-root', 'rotate-root: the root key in force and a granting device with its check', ref(6), okState(6, [G.id, P.id].sort(), [G.id, P.id].sort(), root2.publicKey));
ok('main-7-add-by-new-root', 'after rotate-root, "root" means the new root key', ref(7), okState(7, [G.id, P.id, Q.id].sort(), [G.id, P.id].sort(), root2.publicKey));
ok('stored-head-extension', 'the stored head is an ancestor of the chain: accepted', ref(7), okState(7, [G.id, P.id, Q.id].sort(), [G.id, P.id].sort(), root2.publicKey), { seq: 3, hash: mainHashes[3] });

// the rotate-root case the plan asks for: old root signs after rotation
bad(
  'rotate-root-old-root-signs-after',
  'an entry signed by the EARLIER root key after the rotation is refused',
  ref(6, [await fin(await E(main.slice(0, 6), 'add', { device: Q.rec }), [['root', root1.privateSeed], [Q.id, Q.seed]])]),
  'NOT_AUTHORISED',
);
bad('rotate-root-without-granting-device', 'rotate-root signed by the root alone', ref(5, [await fin(await E(main.slice(0, 5), 'rotate-root', { new_root: b64u(root2.publicKey) }), [['root', root1.privateSeed]])]), 'NOT_AUTHORISED');
bad(
  'rotate-root-co-signer-without-check',
  'rotate-root whose co-signing device made no check',
  ref(5, [await fin(await E(main.slice(0, 5), 'rotate-root', { new_root: b64u(root2.publicKey) }), [['root', root1.privateSeed], [P.id, P.seed]])]),
  'CHECK_REQUIRED',
);
bad('rotate-root-to-used-key', 'rotate-root to the key already in force', ref(5, [await fin(await E(main.slice(0, 5), 'rotate-root', { new_root: b64u(root1.publicKey) }), [['root', root1.privateSeed], [P.id, P.seed]], [[P.id, webauthnMaker(CP, RP)]])]), 'KEY_REUSED');

// MALFORMED
{
  const e = clone(main[1]);
  e.note = 'x';
  bad('malformed-extra-member', 'an entry with an extra member `note` is invalid', ref(1, [e]), 'MALFORMED');
  const m = clone(main[1]);
  delete m.ext;
  bad('malformed-missing-member', 'an entry without `ext`', ref(1, [m]), 'MALFORMED');
  const t = clone(main[1]);
  t.typ = 'suveren-chain-entryx';
  bad('malformed-unknown-typ', 'unknown typ', ref(1, [t]), 'MALFORMED');
  const v = clone(main[1]);
  v.v = 2;
  bad('malformed-unknown-v', 'unknown v is refused (DEC-49 only drops forward-compatibility rules)', ref(1, [v]), 'MALFORMED');
  const nul = await fin(await E(main.slice(0, 1), 'add', { signer: G.id, device: { ...P.rec, label: 'x'.repeat(65) } }), [[G.id, G.seed], [P.id, P.seed]], [[G.id, platformMaker(CG)], [P.id, webauthnMaker(CP, RP)]]);
  bad('malformed-label-too-long', 'device label of 65 characters', ref(1, [nul]), 'MALFORMED');
  const dev = await fin(await E(main.slice(0, 1), 'remove', { signer: G.id, target: P.id, device: P.rec }), [[G.id, G.seed]]);
  bad('malformed-device-on-remove', 'remove must carry device: null', ref(1, [dev]), 'MALFORMED');
  bad('malformed-empty-chain', 'no entries', { ref: 'main', count: 0 }, 'MALFORMED');
}
bad('wrong-root', 'entries of another root DID', ref(2), 'WRONG_ROOT', null, rootOther.did);
{
  const e = await E(main.slice(0, 1), 'add', { signer: G.id, device: P.rec });
  e.seq = 5;
  await fin(e, [[G.id, G.seed], [P.id, P.seed]], [[G.id, platformMaker(CG)], [P.id, webauthnMaker(CP, RP)]]);
  bad('bad-seq', 'seq does not equal the position', ref(1, [e]), 'BAD_SEQ');
  const e2 = await E(main.slice(0, 1), 'add', { signer: G.id, device: P.rec });
  e2.prev = mainHashes[1];
  await fin(e2, [[G.id, G.seed], [P.id, P.seed]], [[G.id, platformMaker(CG)], [P.id, webauthnMaker(CP, RP)]]);
  bad('bad-prev', 'prev is not the hash of the entry before', ref(1, [e2]), 'BAD_PREV');
  const e3 = await E(main.slice(0, 1), 'genesis', { device: P.rec });
  await fin(e3, [['root', root1.privateSeed], [P.id, P.seed]], [[P.id, webauthnMaker(CP, RP)]]);
  bad('bad-op-second-genesis', 'genesis at seq 1', ref(1, [e3]), 'BAD_OP');
  const e4 = await E([], 'add', { device: G.rec });
  await fin(e4, [['root', root1.privateSeed], [G.id, G.seed]], [[G.id, platformMaker(CG)]]);
  bad('bad-op-first-not-genesis', 'the first entry is an add', { ref: 'main', count: 0, append: [e4] }, 'BAD_OP');
  const e5 = await fin(await E(main.slice(0, 1), 'add', { signer: G.id, device: { ...P.rec, key_id: b64u(filled(9)) } }), [[G.id, G.seed], [P.id, P.seed]], [[G.id, platformMaker(CG)], [P.id, webauthnMaker(CP, RP)]]);
  bad('bad-key-id', 'key_id is not base64url(sha256(sign_pub))', ref(1, [e5]), 'BAD_KEY_ID');
  const e6 = await fin(await E(main.slice(0, 1), 'add', { signer: G.id, device: { ...P.rec, read_pub: G.rec.read_pub } }), [[G.id, G.seed], [P.id, P.seed]], [[G.id, platformMaker(CG)], [P.id, webauthnMaker(CP, RP)]]);
  bad('key-reused-read-pub', 'the new device reuses the reading key of an earlier device', ref(1, [e6]), 'KEY_REUSED');
  const e7 = await fin(await E(main.slice(0, 5), 'add', { signer: P.id, device: { ...H.rec, label: 'Office PC again' } }), [[P.id, P.seed], [H.id, H.seed]], [[P.id, webauthnMaker(CP, RP)]]);
  bad('key-reused-after-removal', 'a removed device\'s keys cannot be admitted again', ref(5, [e7]), 'KEY_REUSED');
  const e8 = await fin(await E(main.slice(0, 1), 'add', { signer: G.id, device: P.rec }), [[G.id, G.seed]], [[G.id, platformMaker(CG)], [P.id, webauthnMaker(CP, RP)]]);
  bad('no-possession-device-signature', 'the new device did not sign', ref(1, [e8]), 'NO_POSSESSION');
  const e9 = await fin(await E(main.slice(0, 1), 'add', { signer: G.id, device: P.rec }), [[G.id, G.seed], [P.id, P.seed]], [[G.id, platformMaker(CG)]]);
  bad('no-possession-device-check', 'the new device has a check key but made no check', ref(1, [e9]), 'NO_POSSESSION');
  const e9b = await fin(await E(main.slice(0, 1), 'add', { signer: G.id, device: P.rec }), [[G.id, G.seed], [P.id, P.seed]], [[G.id, platformMaker(CG)], [P.id, webauthnMaker(CP, RP, { challengeHash: mainHashes[0] })]]);
  bad('no-possession-device-check-wrong-object', 'the new device\'s check is over another object', ref(1, [e9b]), 'NO_POSSESSION');
  const e10 = await fin(await E(main.slice(0, 1), 'add', { signer: b64u(filled(5)), device: P.rec }), [[b64u(filled(5)), G.seed], [P.id, P.seed]], [[P.id, webauthnMaker(CP, RP)]]);
  bad('not-authorised-unknown-signer', 'signer is not an active device', ref(1, [e10]), 'NOT_AUTHORISED');
  const e11 = await fin(await E(main.slice(0, 1), 'add', { signer: G.id, device: P.rec }), [[G.id, P.seed], [P.id, P.seed]], [[G.id, platformMaker(CG)], [P.id, webauthnMaker(CP, RP)]]);
  bad('not-authorised-wrong-signer-signature', 'the admitter\'s signature is by another key', ref(1, [e11]), 'NOT_AUTHORISED');
  const e12 = await fin(await E(main.slice(0, 5), 'add', { signer: H.id, device: Q.rec }), [[H.id, H.seed], [Q.id, Q.seed]], [[H.id, platformMaker(CH)]]);
  bad('not-authorised-removed-device', 'a removed device admits a device', ref(5, [e12]), 'NOT_AUTHORISED');
  const e13 = await fin(await E(main.slice(0, 1), 'reset', { signer: G.id, device: Q.rec }), [[G.id, G.seed], [Q.id, Q.seed]], [[G.id, platformMaker(CG)]]);
  bad('not-authorised-reset-not-by-root', 'reset must be signed by the root key', ref(1, [e13]), 'NOT_AUTHORISED');
  const e14 = await fin(await E(main.slice(0, 1), 'add', { signer: G.id, device: P.rec }), [[G.id, G.seed], [P.id, P.seed]], [[P.id, webauthnMaker(CP, RP)]]);
  bad('check-required-add-without-check', 'a granting device signs an add with its device key and no check', ref(1, [e14]), 'CHECK_REQUIRED');
  const e15 = await fin(await E(main.slice(0, 1), 'add', { signer: G.id, device: P.rec }), [[G.id, G.seed], [P.id, P.seed]], [[G.id, platformMaker(CG)], [P.id, webauthnMaker(CP, RP)]]);
  e15.checks[0] = { by: G.id, check: await platformMaker(CG)(mainHashes[0]) };
  bad('check-required-check-over-other-object', 'the admitter\'s check is over another object', ref(1, [e15]), 'CHECK_REQUIRED');
  const e16 = await fin(await E(main.slice(0, 3), 'remove', { signer: H.id, target: P.id }), [[H.id, H.seed]]);
  bad('check-required-device-without-check-key', 'a device without a check key removes another device', ref(3, [e16]), 'CHECK_REQUIRED');
  const e17 = await fin(await E(main.slice(0, 2), 'remove', { signer: G.id, target: b64u(filled(6)) }), [[G.id, G.seed]], [[G.id, platformMaker(CG)]]);
  bad('bad-target-unknown', 'remove of a key id that was never in the chain', ref(2, [e17]), 'BAD_TARGET');
  const e18 = await fin(await E(main.slice(0, 5), 'remove', { signer: 'root', target: H.id }), [['root', root1.privateSeed]]);
  bad('bad-target-already-removed', 'remove of a device already removed', ref(5, [e18]), 'BAD_TARGET');
  const e19 = await fin(await E(main.slice(0, 3), 'set', { signer: P.id, target: H.id, check: chKey }), [[P.id, P.seed]], [[P.id, webauthnMaker(CP, RP)]]);
  bad('no-possession-set-without-new-check', 'set gives a device a check key it did not prove', ref(3, [e19]), 'NO_POSSESSION');
  const e20 = await fin(await E(main.slice(0, 3), 'set', { signer: H.id, target: H.id, check: chKey }), [[H.id, H.seed]], [[H.id, platformMaker(CH)]]);
  bad('check-required-self-set', 'a device cannot give itself a check key with its own signature alone', ref(3, [e20]), 'CHECK_REQUIRED');
}

// reset (positive and the effect on the earlier devices)
{
  const e = await fin(await E(main.slice(0, 5), 'reset', { device: Q.rec }), [['root', root1.privateSeed], [Q.id, Q.seed]]);
  ok('reset-removes-all-earlier-devices', 'reset by the root: every earlier device is removed, the new device admitted; no granting device is required afterwards', ref(5, [e]), {
    head: { seq: 5, hash: await dk.entryHash(e) },
    active: [Q.id],
    granting: [],
    root_pub: b64u(root1.publicKey),
  });
}

// smaller own chains
const small = []; // G, H(no check)
small.push(await fin(await E(small, 'genesis', { device: G.rec }), [['root', root1.privateSeed], [G.id, G.seed]], [[G.id, platformMaker(CG)]]));
small.push(await fin(await E(small, 'add', { device: H.rec }), [['root', root1.privateSeed], [H.id, H.seed]]));
{
  const rm = await fin(await E(small, 'remove', { signer: G.id, target: G.id }), [[G.id, G.seed]]);
  bad('no-granting-device-remove-last', 'the last granting device removes itself', { entries: [...small, rm] }, 'NO_GRANTING_DEVICE');
  const rm2 = await fin(await E(small, 'remove', { signer: 'root', target: G.id }), [['root', root1.privateSeed]]);
  bad('no-granting-device-root-removes-last', 'even the root cannot remove the last granting device', { entries: [...small, rm2] }, 'NO_GRANTING_DEVICE');
  const st = await fin(await E(small, 'set', { signer: G.id, target: G.id, check: null }), [[G.id, G.seed]], [[G.id, platformMaker(CG)]]);
  bad('no-granting-device-drop-check', 'the last granting device drops its check key', { entries: [...small, st] }, 'NO_GRANTING_DEVICE');
  const noGrant = [await fin(await E([], 'genesis', { device: H.rec }), [['root', root1.privateSeed], [H.id, H.seed]])];
  const rm3 = await fin(await E(noGrant, 'remove', { signer: 'root', target: H.id }), [['root', root1.privateSeed]]);
  ok('chain-without-granting-device-changed-by-root', 'a chain that never had a granting device is changed by the root key alone', { entries: [...noGrant, rm3] }, {
    head: { seq: 1, hash: await dk.entryHash(rm3) },
    active: [],
    granting: [],
    root_pub: b64u(root1.publicKey),
  });
}
{
  // six active devices
  const six = [await fin(await E([], 'genesis', { device: G.rec }), [['root', root1.privateSeed], [G.id, G.seed]], [[G.id, platformMaker(CG)]])];
  const extra = [];
  for (let n = 10; n < 15; n++) {
    const d = await device(n);
    extra.push(d);
    six.push(await fin(await E(six, 'add', { device: d.rec }), [['root', root1.privateSeed], [d.id, d.seed]]));
  }
  const five = six.slice(0, 5);
  const fiveHash = await dk.entryHash(five[4]);
  ok('five-active-devices', 'five active devices are allowed', { entries: five }, { head: { seq: 4, hash: fiveHash }, active: [G.id, ...extra.slice(0, 4).map((d) => d.id)].sort(), granting: [G.id], root_pub: b64u(root1.publicKey) });
  bad('too-many-devices', 'a sixth active device', { entries: six }, 'TOO_MANY_DEVICES');
}

// stored head
bad('rollback', 'the verifier stored seq 6, the chain served has 4 entries', ref(4), 'ROLLBACK', { seq: 6, hash: mainHashes[6] });
bad('rollback-empty', 'the AS serves nothing but a head is stored', { ref: 'main', count: 0 }, 'ROLLBACK', { seq: 0, hash: mainHashes[0] });
{
  const forked = clone(main.slice(0, 2));
  const f2 = await fin(await E(forked, 'add', { signer: G.id, device: { ...H.rec, label: 'Fork device' } }), [[G.id, G.seed], [H.id, H.seed]], [[G.id, platformMaker(CG)]]);
  bad('fork', 'the entry at the stored head\'s seq is a different entry', { entries: [...forked, f2] }, 'FORK', { seq: 2, hash: mainHashes[2] });
}

write('chain.json', {
  suite: 'device-keys/chain',
  description: 'Plan 3.3: chain verification. All chains use expected_root_did = fixtures.root_did unless the case gives another. Inputs: chain = {ref:"main", count, append} (first `count` entries of fixtures.chains.main, then `append`) or {entries}.',
  fixtures: {
    root_did: rootDid,
    chains: { main },
    devices: { G: G.id, P: P.id, H: H.id, Q: Q.id },
  },
  cases: chainCases,
});

// ---------------------------------------------------------------------------
// checks
// ---------------------------------------------------------------------------
{
  const cases = [];
  const hash = mainHashes[3];
  const other = mainHashes[4];
  const c = (id, description, check_key, proof, valid, h = hash) => cases.push({ id, description, op: 'check.verify', input: { check_key, hash: h, proof }, expect: { valid } });
  c('platform-valid', 'ECDSA P-256 over the 32 digest bytes; DER signature; SEC1 uncompressed key', chKey, await platformMaker(CH)(hash), true);
  c('platform-wrong-hash', 'signature over another hash', chKey, await platformMaker(CH)(other), false);
  c('platform-wrong-key', 'signature by another key', chKey, await platformMaker(CX)(hash), false);
  const raw = new Uint8Array(await subtle.sign(ecdsa, CH.priv, dk.hashBytes(hash)));
  c('platform-raw-signature-refused', 'raw r||s is not accepted on the wire; DER only', chKey, { signature: b64u(raw) }, false);
  const der = dk.ecdsaRawToDer(raw);
  c('platform-der-trailing-byte', 'DER with a trailing byte', chKey, { signature: b64u(dk.concat(der, Uint8Array.of(0))) }, false);
  c('platform-missing-proof-member', 'proof of the wrong type for a platform key', chKey, { authenticatorData: 'AA', clientDataJSON: 'AA', signature: 'AA' }, false);
  c('platform-key-not-uncompressed', 'pub is not a 65-byte 0x04 point', { type: 'platform', pub: b64u(CH.raw.slice(1)) }, await platformMaker(CH)(hash), false);

  c('webauthn-valid', 'passkey assertion: UP+UV, webauthn.get, challenge = hash bytes, ES256 over authData||sha256(clientDataJSON)', cpKey, await waProof(CP, RP, hash), true);
  c('webauthn-no-uv', 'user-verified flag not set (flags = UP only)', cpKey, await waProof(CP, RP, hash, { flags: 0x01 }), false);
  c('webauthn-no-up', 'user-present flag not set (flags = UV only)', cpKey, await waProof(CP, RP, hash, { flags: 0x04 }), false);
  c('webauthn-wrong-rp-hash', 'rpIdHash is for another relying party', cpKey, await waProof(CP, RP, hash, { rpForHash: 'evil.example' }), false);
  c('webauthn-wrong-type', 'clientDataJSON.type is webauthn.create', cpKey, await waProof(CP, RP, hash, { type: 'webauthn.create' }), false);
  c('webauthn-wrong-challenge', 'challenge is the hash of another object', cpKey, await waProof(CP, RP, hash, { challengeHash: other }), false);
  c('webauthn-challenge-hex-not-base64url', 'challenge written as the hash string instead of base64url bytes', cpKey, await waProof(CP, RP, hash, { challenge: hash }), false);
  c('webauthn-wrong-key', 'signature by another passkey', cpKey, await waProof(CX, RP, hash), false);
  c('webauthn-verified-for-other-hash', 'valid assertion presented for another hash', cpKey, await waProof(CP, RP, hash), false, other);
  const badCose = { ...cpKey, pub: b64u(Uint8Array.from([0xa5, 0x01, 0x02, 0x03, 0x27, 0x20, 0x01, 0x21, 0x58, 0x20, ...CP.raw.slice(1, 33), 0x22, 0x58, 0x20, ...CP.raw.slice(33, 65)])) };
  c('webauthn-cose-wrong-alg', 'COSE key with alg -8 instead of -7', badCose, await waProof(CP, RP, hash), false);
  write('checks.json', { suite: 'device-keys/checks', description: 'Plan 3.1 checks: platform and webauthn. Encodings: DER signatures; platform pub = SEC1 uncompressed point, base64url; webauthn pub = COSE_Key CBOR, base64url.', cases });
}
{
  // DER helper vectors
  const cases = [];
  const r = new Uint8Array(32).fill(0x11);
  const s = new Uint8Array(32).fill(0xf2);
  const rs = dk.concat(r, s);
  const derOk = dk.ecdsaRawToDer(rs);
  cases.push({ id: 'der-roundtrip-high-bit', op: 'ecdsa.der_to_raw', input: { der_hex: hex(derOk) }, expect: { raw_hex: hex(rs) } });
  cases.push({ id: 'der-leading-zero-r', op: 'ecdsa.der_to_raw', input: { der_hex: hex(dk.ecdsaRawToDer(dk.concat(dk.concat(Uint8Array.of(0, 0), r.slice(2)), s))) }, expect: { raw_hex: hex(dk.concat(dk.concat(Uint8Array.of(0, 0), r.slice(2)), s)) } });
  cases.push({ id: 'der-non-minimal-padding', op: 'ecdsa.der_to_raw', input: { der_hex: '3008020200110202' + '0011' }, expect: { error: 'MALFORMED' } });
  cases.push({ id: 'der-negative-integer', op: 'ecdsa.der_to_raw', input: { der_hex: '3006020180020101' }, expect: { error: 'MALFORMED' } });
  cases.push({ id: 'der-trailing-bytes', op: 'ecdsa.der_to_raw', input: { der_hex: hex(dk.concat(derOk, Uint8Array.of(0))) }, expect: { error: 'MALFORMED' } });
  write('der.json', { suite: 'device-keys/der', description: 'Strict DER ECDSA signature parsing', cases });
}

// ---------------------------------------------------------------------------
// encoding, recovery, key id, strict ed25519
// ---------------------------------------------------------------------------
{
  const cases = [];
  cases.push({ id: 'b64u-decode-ok', op: 'b64u.decode', input: { text: 'AQID_-A' }, expect: { hex: '010203ffe0' } });
  cases.push({ id: 'b64u-padding-refused', op: 'b64u.decode', input: { text: 'AQID_-A=' }, expect: { error: 'MALFORMED' } });
  cases.push({ id: 'b64u-standard-alphabet-refused', op: 'b64u.decode', input: { text: 'AQID/+A' }, expect: { error: 'MALFORMED' } });
  cases.push({ id: 'b64u-non-canonical-trailing-bits', op: 'b64u.decode', input: { text: 'AQIE_-B' }, expect: { error: 'MALFORMED' } });
  cases.push({ id: 'b64u-bad-length', op: 'b64u.decode', input: { text: 'A' }, expect: { error: 'MALFORMED' } });
  const obj = { z: 1, a: ['é', { b: null, a: true }], typ: 'x', v: 1, sigs: [{ by: 'x' }], checks: [], sig: 'dropped' };
  cases.push({
    id: 'signed-bytes-exclude-sig-sigs-checks',
    op: 'signed_bytes',
    input: { object: obj },
    expect: { bytes_utf8: '{"a":["é",{"a":true,"b":null}],"typ":"x","v":1,"z":1}', hash: await dk.objectHash(obj) },
  });
  cases.push({ id: 'entry-hash', description: 'hash of main entry 0', op: 'signed_bytes', input: { object: main[0] }, expect: { hash: mainHashes[0] } });
  cases.push({ id: 'key-id', op: 'key_id', input: { sign_pub_hex: hex(G.pub) }, expect: { key_id: G.id } });
  write('encoding.json', { suite: 'device-keys/encoding', description: 'base64url, signed bytes, entry hash, key id', cases });
}
{
  const cases = [];
  const code = await dk.encodeRecoveryCode(seq16);
  cases.push({
    id: 'derive-seed-00-0f',
    description: 'seed 000102..0f',
    op: 'recovery.derive',
    input: { code },
    expect: { seed_hex: hex(seq16), root_private_hex: hex(root1.privateSeed), root_public_hex: hex(root1.publicKey), did: root1.did },
  });
  cases.push({ id: 'encode-seed-00-0f', op: 'recovery.encode', input: { seed_hex: hex(seq16) }, expect: { code } });
  cases.push({ id: 'lowercase-and-spaces-accepted', op: 'recovery.derive', input: { code: 'sv1-' + code.slice(4).toLowerCase().replace(/-/g, ' ') }, expect: { seed_hex: hex(seq16), root_private_hex: hex(root1.privateSeed), root_public_hex: hex(root1.publicKey), did: root1.did } });
  const allFF = Uint8Array.from({ length: 16 }, () => 0xff);
  cases.push({ id: 'encode-seed-ff', op: 'recovery.encode', input: { seed_hex: hex(allFF) }, expect: { code: await dk.encodeRecoveryCode(allFF) } });
  const flip = code.slice(0, 5) + (code[5] === '2' ? '3' : '2') + code.slice(6);
  cases.push({ id: 'checksum-detects-typo', op: 'recovery.derive', input: { code: flip }, expect: { error: 'BAD_CHECKSUM' } });
  cases.push({ id: 'prefix-required', op: 'recovery.derive', input: { code: code.slice(4) }, expect: { error: 'BAD_RECOVERY_CODE' } });
  cases.push({ id: 'too-short', op: 'recovery.derive', input: { code: code.slice(0, -2) }, expect: { error: 'BAD_RECOVERY_CODE' } });
  cases.push({ id: 'letter-u-not-in-alphabet', op: 'recovery.derive', input: { code: code.slice(0, 5) + 'U' + code.slice(6) }, expect: { error: 'BAD_RECOVERY_CODE' } });
  const lastCh = code[code.length - 1];
  cases.push({ id: 'non-zero-pad-bit', description: 'last character carries one pad bit, which must be zero', op: 'recovery.derive', input: { code: code.slice(0, -1) + 'ABCDEFGHJKMNPQRSTVWXYZ0123456789'[('0123456789ABCDEFGHJKMNPQRSTVWXYZ'.indexOf(lastCh) ^ 1)] }, expect: { error: 'BAD_RECOVERY_CODE' } });
  write('recovery.json', { suite: 'device-keys/recovery', description: 'Plan 2.1', cases });
}
{
  const cases = [];
  // RFC 8032 section 7.1 TEST 1 and 2
  const t1 = {
    pk: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    msg: '',
    sig: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  };
  const t2 = {
    pk: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    msg: '72',
    sig: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
  };
  for (const [n, t] of [['1', t1], ['2', t2]]) cases.push({ id: `rfc8032-test-${n}`, description: `RFC 8032 7.1 TEST ${n}`, op: 'ed25519.verify', input: { public_key_hex: t.pk, message_hex: t.msg, signature_hex: t.sig }, expect: { valid: true } });
  const sigBytes = dk.hexDecode(t1.sig);
  // S + L
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sigBytes[i]);
  const s2 = s + L;
  const mall = sigBytes.slice();
  for (let i = 0; i < 32; i++) mall[32 + i] = Number((s2 >> BigInt(8 * i)) & 0xffn);
  cases.push({ id: 'non-canonical-S', description: 'RFC 8032 TEST 1 with S replaced by S + L: same point equation, refused', op: 'ed25519.verify', input: { public_key_hex: t1.pk, message_hex: t1.msg, signature_hex: hex(mall) }, expect: { valid: false } });
  cases.push({ id: 'tampered-message', op: 'ed25519.verify', input: { public_key_hex: t2.pk, message_hex: '73', signature_hex: t2.sig }, expect: { valid: false } });
  const identity = '01' + '00'.repeat(31);
  const zeroS = '00'.repeat(32);
  cases.push({ id: 'small-order-key-identity', description: 'public key = identity point, R = identity, S = 0: verifies any message under ZIP-215, refused here', op: 'ed25519.verify', input: { public_key_hex: identity, message_hex: '616263', signature_hex: identity + zeroS }, expect: { valid: false } });
  const ncIdentity = 'ee' + 'ff'.repeat(30) + '7f';
  cases.push({ id: 'non-canonical-point-key', description: 'public key = identity encoded with y = p + 1', op: 'ed25519.verify', input: { public_key_hex: ncIdentity, message_hex: '616263', signature_hex: identity + zeroS }, expect: { valid: false } });
  cases.push({ id: 'small-order-key-order-4', description: 'public key = point of order 4 (y = 0)', op: 'ed25519.verify', input: { public_key_hex: '00'.repeat(32), message_hex: '616263', signature_hex: identity + zeroS }, expect: { valid: false } });
  cases.push({ id: 'non-canonical-R', description: 'RFC 8032 TEST 1 signature with R replaced by the non-canonical identity', op: 'ed25519.verify', input: { public_key_hex: t1.pk, message_hex: t1.msg, signature_hex: ncIdentity + zeroS }, expect: { valid: false } });
  cases.push({ id: 'short-signature', op: 'ed25519.verify', input: { public_key_hex: t1.pk, message_hex: t1.msg, signature_hex: t1.sig.slice(2) }, expect: { valid: false } });
  write('ed25519-strict.json', { suite: 'device-keys/ed25519-strict', description: 'Plan section 2, rule 4. The small-order and non-canonical cases are accepted by a ZIP-215 verifier; they MUST be refused.', cases });
}

// ---------------------------------------------------------------------------
// objects: sign-in, decision, grant, receipt (against the main chain)
// ---------------------------------------------------------------------------
{
  const AUD = 'ab'.repeat(32);
  const cref = (count) => ({ ref: 'main', count });
  const nonce32 = b64u(filled(0x31));
  const nonce16 = b64u(filled(0x32, 16));
  const cases = [];
  const sign = async (obj, key) => b64u(await dk.signEd25519(key.seed, dk.signedBytes(obj)));
  const head5 = { chain_seq: 4, chain_head: mainHashes[4] };
  const mkSignin = (key, over = {}) => dk.buildSignin({ aud: AUD, root_did: rootDid, key_id: key.id, nonce: nonce32, ...head5, issued_at: T0 + 100, ...over });
  const si = async (id, description, key, over, ctx, expect, signKey) => {
    const s = mkSignin(key, over);
    cases.push({ id: `signin-${id}`, description, op: 'signin.verify', input: { chain: cref(5), envelope: { signin: s, sig: await sign(s, signKey ?? key) }, aud: AUD, now: T0 + 130, ...ctx }, expect });
  };
  await si('valid-granting-device', 'sign-in by an active device at the head', G, {}, {}, { ok: true });
  await si('valid-older-head', 'the device names an older head that matches the chain', P, { chain_seq: 3, chain_head: mainHashes[3] }, {}, { ok: true });
  await si('removed-device', 'the device was removed at seq 4', H, {}, {}, { error: 'NOT_ACTIVE' });
  await si('wrong-aud', 'aud is another Authority Server key', G, { aud: 'cd'.repeat(32) }, {}, { error: 'BAD_AUD' });
  await si('stale', 'issued_at 400 seconds before now', G, { issued_at: T0 - 270 }, {}, { error: 'STALE' });
  await si('wrong-root', 'root_did of another person', G, { root_did: rootOther.did }, {}, { error: 'WRONG_ROOT' });
  await si('fork', 'the named head hash is not the chain\'s hash at that seq', G, { chain_head: mainHashes[3] }, {}, { error: 'FORK' });
  await si('chain-ahead', 'chain_seq is beyond the receiver\'s head', G, { chain_seq: 9 }, {}, { error: 'CHAIN_AHEAD' });
  await si('signed-by-other-key', 'signature made with another device\'s key', G, {}, {}, { error: 'BAD_SIGNATURE' }, P);
  {
    const s = mkSignin(G);
    s.extra = 1;
    cases.push({ id: 'signin-extra-member', op: 'signin.verify', input: { chain: cref(5), envelope: { signin: s, sig: await sign(s, G) }, aud: AUD, now: T0 + 130 }, expect: { error: 'MALFORMED' } });
  }

  const mkDec = (key, over = {}) =>
    dk.buildDecision({
      approver_did: rootDid,
      key_id: key.id,
      ...head5,
      proposal_id: 'prop-1',
      mandate_id: 'mand-1',
      action: 'send_email',
      action_type: 'send',
      decision: 'commit',
      content_hash: 'sha256:' + '11'.repeat(32),
      proposal_content_hash: 'sha256:' + '22'.repeat(32),
      decided_at: T0 + 200,
      nonce: nonce16,
      ...over,
    });
  const dec = async (id, description, key, over, expectOpt, expect, signKey, count = 5) => {
    const d = mkDec(key, over);
    cases.push({ id: `decision-${id}`, description, op: 'decision.verify', input: { chain: cref(count), envelope: { decision: d, sig: await sign(d, signKey ?? key) }, ...(expectOpt ? { expect: expectOpt } : {}) }, expect });
  };
  await dec('commit-by-gateway-no-check', 'every active device may commit, with no check', G, {}, { proposal_id: 'prop-1', action: 'send_email' }, { ok: true });
  await dec('commit-by-phone', 'commit by the phone', P, {}, null, { ok: true });
  await dec('reject', 'reject by any active device', P, { decision: 'reject' }, null, { ok: true });
  await dec('withdraw', 'withdraw by any active device', G, { decision: 'withdraw' }, null, { ok: true });
  await dec('device-without-check-key', 'a device without a check key still decides', H, { chain_seq: 2, chain_head: mainHashes[2] }, null, { ok: true }, undefined, 3);
  await dec('removed-device', 'removed devices decide nothing', H, {}, null, { error: 'NOT_ACTIVE' });
  await dec('mismatch-proposal', 'proposal_content_hash differs from the proposal\'s', G, {}, { proposal_content_hash: 'sha256:' + '33'.repeat(32) }, { error: 'PROPOSAL_MISMATCH' });
  await dec('wrong-approver', 'approver_did is not the chain\'s root DID', G, { approver_did: rootOther.did }, null, { error: 'WRONG_ROOT' });
  await dec('bad-signature', 'signature made by another device', G, {}, null, { error: 'BAD_SIGNATURE' }, P);
  await dec('unknown-decision-value', 'decision is not commit, reject or withdraw', G, { decision: 'maybe' }, null, { error: 'MALFORMED' });
  await dec('older-head-accepted', 'an older head that matches is accepted while the signer is still active', P, { chain_seq: 3, chain_head: mainHashes[3] }, null, { ok: true });
  await dec('device-not-yet-admitted-at-named-head', 'the signer was admitted after the head it names', P, { chain_seq: 0, chain_head: mainHashes[0] }, null, { error: 'NOT_ACTIVE' });
  await dec('fork', 'named head hash differs', G, { chain_head: mainHashes[2] }, null, { error: 'FORK' });

  const mf = { profile_id: 'email@0.9', profile_hash: 'sha256:' + 'aa'.repeat(32), bounds_hash: 'sha256:' + 'bb'.repeat(32), scope_hash: 'sha256:' + 'cc'.repeat(32), commitment_mode: 'review', above_cap_approvers: [rootDid], above_cap_approvals: 1, expires_at: T0 + 100000 };
  const mkGrant = (key, over = {}, fields = mf) =>
    dk.buildGrant({ op: 'grant', owner_did: rootDid, key_id: key.id, ...head5, mandate_id: 'mand-1', mandate_version: 2, granted_at: T0 + 300, nonce: nonce16, ...over }, fields);
  const gr = async (id, description, key, maker, over, expect, o = {}) => {
    const g = mkGrant(key, over, o.fields ?? mf);
    const hash = await dk.objectHash(g);
    const env = { grant: g, sig: await sign(g, o.signKey ?? key) };
    if (maker) env.check = await maker(o.checkHash ?? hash);
    cases.push({ id: `grant-${id}`, description, op: 'grant.verify', input: { chain: cref(o.count ?? 5), envelope: env, mandate_fields: o.mandateFields ?? mf }, expect });
    return g;
  };
  const gA = await gr('by-computer-with-platform-check', 'grant: device signature and platform check over the grant hash', G, platformMaker(CG), {}, { ok: true });
  await gr('by-phone-with-webauthn-check', 'grant by the phone with its passkey', P, webauthnMaker(CP, RP), { op: 'change', mandate_version: 3 }, { ok: true });
  await gr('no-check', 'device signature alone is refused', G, null, {}, { error: 'CHECK_REQUIRED' });
  await gr('check-over-other-object', 'check over another object', G, platformMaker(CG), {}, { error: 'CHECK_REQUIRED' }, { checkHash: mainHashes[0] });
  await gr('check-by-other-key', 'check made with another device\'s check key', G, platformMaker(CX), {}, { error: 'CHECK_REQUIRED' });
  await gr('device-without-check-key', 'device H has no check key at seq 2', H, platformMaker(CH), { chain_seq: 2, chain_head: mainHashes[2] }, { error: 'CHECK_REQUIRED' }, { count: 3 });
  await gr('check-key-changed-since-named-head', 'H got its check key at seq 3; a grant naming head 2 cannot use it', H, platformMaker(CH), { chain_seq: 2, chain_head: mainHashes[2] }, { error: 'CHECK_REQUIRED' }, { count: 4 });
  await gr('older-head-same-check-key', 'older head, same check key then and now', P, webauthnMaker(CP, RP), { chain_seq: 3, chain_head: mainHashes[3] }, { ok: true });
  await gr('revoke-without-check', 'revoke by any active device needs no check', H, null, { op: 'revoke', chain_seq: 2, chain_head: mainHashes[2] }, { ok: true }, { count: 3 });
  await gr('revoke-by-removed-device', 'a removed device cannot revoke', H, null, { op: 'revoke' }, { error: 'NOT_ACTIVE' });
  await gr('mandate-field-differs', 'the grant carries another bounds_hash than the mandate', G, platformMaker(CG), {}, { error: 'GRANT_MISMATCH' }, { fields: { ...mf, bounds_hash: 'sha256:' + 'dd'.repeat(32) } });
  await gr('wrong-owner', 'owner_did is another person', G, platformMaker(CG), { owner_did: rootOther.did }, { error: 'WRONG_ROOT' });
  await gr('bad-signature', 'device signature by another key', G, platformMaker(CG), {}, { error: 'BAD_SIGNATURE' }, { signKey: P });
  await gr('fork', 'named head differs', G, platformMaker(CG), { chain_head: mainHashes[0] }, { error: 'FORK' });

  const mkReceipt = (key, over = {}) => dk.buildReceipt({ mandate_id: 'mand-1', mandate_version: 2, grant_hash: undefined, key_id: key.id, ...head5, received_at: T0 + 400, ...over });
  const gh = await dk.grantHash(gA);
  const rc = async (id, description, key, over, withGrant, expect, signKey) => {
    const r = mkReceipt(key, { grant_hash: gh, ...over });
    cases.push({
      id: `receipt-${id}`,
      description,
      op: 'receipt.verify',
      input: { chain: cref(5), envelope: { receipt: r, sig: await sign(r, signKey ?? key) }, ...(withGrant ? { grant: gA, grant_mandate_fields: mf } : {}) },
      expect,
    });
  };
  await rc('valid', 'receipt signed by the receiving gateway, matches the grant', G, {}, true, { ok: true });
  await rc('valid-without-grant', 'receipt checked on its own', G, {}, false, { ok: true });
  await rc('wrong-grant-hash', 'grant_hash is of another grant', G, { grant_hash: 'sha256:' + '00'.repeat(32) }, true, { error: 'GRANT_MISMATCH' });
  await rc('wrong-version', 'mandate_version differs from the grant', G, { mandate_version: 1 }, true, { error: 'GRANT_MISMATCH' });
  await rc('removed-device', 'receipt by a removed device', H, {}, false, { error: 'NOT_ACTIVE' });
  await rc('bad-signature', 'signature by another key', G, {}, false, { error: 'BAD_SIGNATURE' }, P);

  write('objects.json', {
    suite: 'device-keys/objects',
    description: 'Plan 4.1, 4.2, 4.4: sign-in, decision, mandate grant, receipt, verified against a prefix of the main chain (count = number of entries).',
    fixtures: { root_did: rootDid, chains: { main } },
    cases,
  });
}

// ---------------------------------------------------------------------------
// pairing and identity code
// ---------------------------------------------------------------------------
{
  const cases = [];
  const secret = filled(0x42);
  const pairing = await dk.derivePairing(secret);
  cases.push({ id: 'derive', op: 'pairing.derive', input: { secret: b64u(secret) }, expect: { pairing_id: pairing.pairingId, mac_key_hex: hex(pairing.macKey) } });
  const asKey = 'ef'.repeat(32);
  const qrAdmitter = { v: 1, as_url: 'https://suveren.ai', as_key: asKey, shown_by: 'admitter', secret: b64u(secret), root_did: rootDid, head: { seq: 3, hash: mainHashes[3] }, key_id: G.id, expires_at: T0 + 600 };
  const qrJoiner = { v: 1, as_url: 'https://suveren.ai', as_key: asKey, shown_by: 'joiner', secret: b64u(secret), root_did: null, head: null, key_id: null, expires_at: T0 + 600 };
  const textA = dk.encodePairingQr(qrAdmitter);
  const textJ = dk.encodePairingQr(qrJoiner);
  cases.push({ id: 'qr-admitter', op: 'pairing.qr.decode', input: { text: textA, now: T0 + 10 }, expect: { qr: qrAdmitter, text: textA } });
  cases.push({ id: 'qr-joiner', op: 'pairing.qr.decode', input: { text: textJ, now: T0 + 10 }, expect: { qr: qrJoiner, text: textJ } });
  cases.push({ id: 'qr-expired', op: 'pairing.qr.decode', input: { text: textA, now: T0 + 601 }, expect: { error: 'QR_EXPIRED' } });
  cases.push({ id: 'qr-wrong-prefix', op: 'pairing.qr.decode', input: { text: textA.replace('SUVEREN-PAIR-1:', 'SUVEREN-PAIR-2:') }, expect: { error: 'MALFORMED' } });
  const body = JSON.stringify({ ...qrAdmitter }); // insertion order, not JCS order
  cases.push({ id: 'qr-not-canonical-json', description: 'members not in JCS order', op: 'pairing.qr.decode', input: { text: 'SUVEREN-PAIR-1:' + b64u(utf8(body)) }, expect: { error: 'MALFORMED' } });
  cases.push({ id: 'qr-unknown-member', op: 'pairing.qr.decode', input: { text: 'SUVEREN-PAIR-1:' + b64u(utf8(canonicalize({ ...qrAdmitter, extra: 1 }))) }, expect: { error: 'MALFORMED' } });
  cases.push({ id: 'qr-joiner-with-root', description: 'a joiner QR carries no chain facts', op: 'pairing.qr.decode', input: { text: 'SUVEREN-PAIR-1:' + b64u(utf8(canonicalize({ ...qrJoiner, root_did: rootDid }))) }, expect: { error: 'MALFORMED' } });

  const bodyHello = { root_did: rootDid, head: { seq: 3, hash: mainHashes[3] }, key_id: G.id, as_key: asKey };
  const hello = await dk.buildPairingMessage(pairing.macKey, 'hello', bodyHello);
  cases.push({ id: 'mac-hello', description: 'mac = HMAC-SHA256(mac_key, "hello" || 0x00 || JCS(body)), base64url', op: 'pairing.message.verify', input: { mac_key_hex: hex(pairing.macKey), message: hello }, expect: { ok: true } });
  cases.push({ id: 'mac-wrong', op: 'pairing.message.verify', input: { mac_key_hex: hex(pairing.macKey), message: { ...hello, mac: b64u(filled(1)) } }, expect: { error: 'BAD_MAC' } });
  cases.push({ id: 'mac-body-changed', op: 'pairing.message.verify', input: { mac_key_hex: hex(pairing.macKey), message: { ...hello, body: { ...bodyHello, key_id: P.id } } }, expect: { error: 'BAD_MAC' } });
  cases.push({ id: 'mac-kind-changed', description: 'the kind is under the MAC', op: 'pairing.message.verify', input: { mac_key_hex: hex(pairing.macKey), message: { ...hello, kind: 'done' } }, expect: { error: 'MALFORMED' } });
  cases.push({ id: 'mac-other-key', op: 'pairing.message.verify', input: { mac_key_hex: hex(filled(7)), message: hello }, expect: { error: 'BAD_MAC' } });
  const rJ = filled(0x51);
  const rA = filled(0x61);
  const entry = main[1];
  const joinerSig = dk.b64uDecode(entry.sigs.find((s) => s.by === P.id).sig);
  const c = await dk.pairingCommitment(entry, joinerSig, rJ);
  const commitMsg = await dk.buildPairingMessage(pairing.macKey, 'commit', { c });
  cases.push({ id: 'commit-message', op: 'pairing.message.verify', input: { mac_key_hex: hex(pairing.macKey), message: commitMsg }, expect: { ok: true } });
  cases.push({ id: 'commit-value', description: 'c = sha256(signed bytes of the entry || joiner_sig || r_j)', op: 'pairing.commitment', input: { entry, joiner_sig: b64u(joinerSig), r_j: b64u(rJ) }, expect: { c } });
  cases.push({ id: 'commit-value-other-r', op: 'pairing.commitment', input: { entry, joiner_sig: b64u(joinerSig), r_j: b64u(filled(0x52)) }, expect: { differs_from: c } });
  const code = await dk.comparisonCode(pairing.macKey, entry, rJ, rA);
  cases.push({ id: 'comparison-code', description: '6 digits from HMAC(mac_key, "code" || 0x00 || signed bytes || r_j || r_a)', op: 'pairing.code', input: { mac_key_hex: hex(pairing.macKey), entry, r_j: b64u(rJ), r_a: b64u(rA) }, expect: { code } });
  cases.push({ id: 'comparison-code-other-challenge', op: 'pairing.code', input: { mac_key_hex: hex(pairing.macKey), entry, r_j: b64u(rJ), r_a: b64u(filled(0x62)) }, expect: { differs_from: code } });
  const doneRefused = await dk.buildPairingMessage(pairing.macKey, 'done', { refused: 'CHAIN_HEAD_MOVED' });
  cases.push({ id: 'done-refused', op: 'pairing.message.verify', input: { mac_key_hex: hex(pairing.macKey), message: doneRefused }, expect: { ok: true } });
  cases.push({ id: 'open-body-missing-member', op: 'pairing.message.verify', input: { mac_key_hex: hex(pairing.macKey), message: await dk.buildPairingMessage(pairing.macKey, 'open', { entry, sig: b64u(joinerSig) }) }, expect: { error: 'MALFORMED' } });

  cases.push({ id: 'identity-code-root1', op: 'identity.code', input: { root_did: root1.did }, expect: { code: await dk.identityCode(root1.did) } });
  cases.push({ id: 'identity-code-root2', op: 'identity.code', input: { root_did: root2.did }, expect: { code: await dk.identityCode(root2.did) } });
  write('pairing.json', { suite: 'device-keys/pairing', description: 'Plan 4.3 and the identity code of 4.4', fixtures: { root_did: rootDid }, cases });
}

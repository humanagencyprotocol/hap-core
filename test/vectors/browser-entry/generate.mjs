/**
 * Writes browser-entry.json: what a page verifies with `@humanagencyp/hap-core/browser`, with the
 * answers the Node build gives. Ed25519 and SHA-256 are deterministic, so a second run writes the
 * same file. Run after `pnpm build`:  node test/vectors/browser-entry/generate.mjs
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as ed from '@noble/ed25519';
import * as hap from '../../../dist/index.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const seed = (b) => new Uint8Array(32).fill(b);
const AS_SEED = seed(7);
const OTHER_SEED = seed(9);
const OWNER_SEED = seed(11);
const asPub = await ed.getPublicKeyAsync(AS_SEED);
const otherPub = await ed.getPublicKeyAsync(OTHER_SEED);
const ownerPub = await ed.getPublicKeyAsync(OWNER_SEED);
const AS_DID = hap.encodeDidKey(asPub);
const OTHER_DID = hap.encodeDidKey(otherPub);
const OWNER_DID = hap.encodeDidKey(ownerPub);
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

const profile = {
  id: 'email@0.8', version: '0.8', name: 'Email', description: 'Fixture for the browser-entry vectors',
  boundsSchema: {
    actionTypes: ['send'], keyOrder: ['profile', 'recipient_max', 'amount_max', 'send_daily_max'],
    fields: {
      profile: { type: 'string', required: true },
      recipient_max: { type: 'number', required: false, boundType: { kind: 'per_transaction', of: 'recipient_count' } },
      amount_max: { type: 'number', required: false, boundType: { kind: 'cumulative_sum', of: 'amount', window: 'daily' } },
      send_daily_max: { type: 'number', required: false, boundType: { kind: 'cumulative_count', window: 'daily' } },
    },
  },
  scopeSchema: { keyOrder: ['allowed_domains'], fields: { allowed_domains: { type: 'string', required: false, constraint: { enforceable: ['subset'] } } } },
  executionContextSchema: { fields: { recipient_count: { type: 'number' }, amount: { type: 'number' } } },
};
const H = (c) => `sha256:${c.repeat(64)}`;
const ISSUED = 1_800_000_000;
const EXPIRES = ISSUED + 3600;
const basePayload = {
  mandate_id: 'mnd_browser_vectors_1', version: '0.8', profile_id: profile.id,
  profile_hash: hap.computeProfileHash(profile),
  bounds_hash: H('1'), scope_hash: H('2'), execution_context_hash: H('3'),
  gate_content_hashes: { intent: H('4') },
  issuer: AS_DID, mandate_owners: [{ did: OWNER_DID }], commitment_mode: 'review',
  issued_at: ISSUED, expires_at: EXPIRES,
};
const blobOf = async (payload, key = AS_SEED, opts) => hap.encodeMandateBlob(await hap.signMandate(payload, key, opts));
const kid = AS_DID.slice('did:key:'.length);

const good = await blobOf(basePayload, AS_SEED, { kid });
const goodMandate = hap.decodeMandateBlob(good);
const tampered = hap.encodeMandateBlob({ ...goodMandate, payload: { ...goodMandate.payload, expires_at: EXPIRES + 1 } });
const standardB64Sig = hap.encodeMandateBlob({ ...goodMandate, signature: goodMandate.signature.replace(/-/g, '+').replace(/_/g, '/') + (goodMandate.signature.includes('-') || goodMandate.signature.includes('_') ? '' : '+') });
const wrongKid = await blobOf(basePayload, AS_SEED, { kid: OTHER_DID.slice('did:key:'.length) });
const signedByOther = await blobOf({ ...basePayload, issuer: OTHER_DID }, OTHER_SEED);
const twoOwners = await blobOf({ ...basePayload, mandate_owners: [{ did: OWNER_DID }, { did: OTHER_DID }] });
const oldVersion = await blobOf({ ...basePayload, version: '0.6' });

async function expectOf(fn) {
  try { const v = await fn(); return { ok: v.mandate_id }; } catch (e) { return { error: e.code ?? String(e.message).split(':')[0] }; }
}
const verifyCases = [];
const add = async (id, blob, pinned, now) => verifyCases.push({ id, op: 'verifyMandate', input: { blob, pinned_did: pinned, now }, expect: await expectOf(() => hap.verifyMandate(blob, { trustedIssuers: [pinned], now })) });
await add('valid mandate, pinned key', good, AS_DID, ISSUED + 10);
await add('valid mandate, at expires_at + 300 (skew)', good, AS_DID, EXPIRES + 300);
await add('expired past expires_at + 300', good, AS_DID, EXPIRES + 301);
await add('another pinned key', good, OTHER_DID, ISSUED + 10);
await add('signed by another key that names itself as issuer', signedByOther, AS_DID, ISSUED + 10);
await add('payload changed after signing', tampered, AS_DID, ISSUED + 10);
await add('header kid names another key', wrongKid, AS_DID, ISSUED + 10);
await add('standard base64 signature', standardB64Sig, AS_DID, ISSUED + 10);
await add('two mandate owners', twoOwners, AS_DID, ISSUED + 10);
await add('unsupported version', oldVersion, AS_DID, ISSUED + 10);
await add('not base64url', 'abc+/=', AS_DID, ISSUED + 10);
await add('base64url but not JSON', hap.toBase64Url(new TextEncoder().encode('not json')), AS_DID, ISSUED + 10);
for (const c of verifyCases) if (!c.expect.ok && !c.expect.error) throw new Error(`no expectation for ${c.id}`);

const entry = { did: OWNER_DID, nonce: 'bm9uY2Utbm9uY2Utbm9uY2U', binding: 'raw', signing_surface: 'gateway' };
const withApprovers = { ...basePayload, commitment_mode: 'review_above_cap', above_cap_caps: { amount_max: 500 }, above_cap_approvers: [OTHER_DID], above_cap_approvals: 1, intent_disclosure_hash: H('5'), disclose_fields: ['amount'] };
const projectionCases = [];
for (const [id, payload] of [['review mandate', basePayload], ['above-cap mandate with intent disclosure', withApprovers]]) {
  const p = hap.buildMandateProjection(payload, entry);
  projectionCases.push({ id, op: 'buildMandateProjection', input: { payload, entry }, expect: { projection: p, signing_bytes_sha256: hap.sha256Hex(hap.projectionSigningBytes(p)) } });
}
projectionCases.push({ id: 'v0.8 entry without binding', op: 'buildMandateProjection', input: { payload: basePayload, entry: { did: OWNER_DID, nonce: entry.nonce } }, expect: { error: 'OWNER_SIGNATURE_INVALID' } });

const exec = { recipient_count: 3, amount: 120.5, _note: 'advisory', subject: 'not read by a bound', nothing: null };
const hashCases = [
  { id: 'profile hash', op: 'computeProfileHash', input: { profile }, expect: { value: hap.computeProfileHash(profile) } },
  { id: 'profile hash ignores key order', op: 'computeProfileHash', input: { profile: Object.fromEntries(Object.entries(profile).reverse()) }, expect: { value: hap.computeProfileHash(profile) } },
  { id: 'bound-read fields', op: 'boundReadFields', input: { profile }, expect: { value: [...hap.boundReadFields(profile)].sort() } },
  { id: 'wire execution context', op: 'wireExecutionContext', input: { execution: exec, profile }, expect: { value: hap.wireExecutionContext(exec, profile) } },
  { id: 'did:key of an Ed25519 key', op: 'encodeDidKey', input: { public_key_hex: hex(asPub) }, expect: { value: AS_DID } },
  { id: 'sha256 of UTF-8 text', op: 'sha256Hex', input: { text: 'Grüße, 日本語 😀' }, expect: { value: hap.sha256Hex('Grüße, 日本語 😀') } },
  { id: 'sha256 across a block boundary', op: 'sha256Hex', input: { text: 'x'.repeat(119) }, expect: { value: hap.sha256Hex('x'.repeat(119)) } },
  { id: 'base64url round trip', op: 'base64url', input: { hex: 'fbff00ff10' }, expect: { value: hap.toBase64Url(new Uint8Array([0xfb, 0xff, 0x00, 0xff, 0x10])) } },
];

const out = {
  description: 'What a page verifies with @humanagencyp/hap-core/browser; expectations from the Node build. Fixture keys are seeds 7 (Authority Server), 9 (another key) and 11 (owner).',
  cases: [...verifyCases, ...projectionCases, ...hashCases],
};
writeFileSync(join(here, 'browser-entry.json'), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote ${out.cases.length} cases`);

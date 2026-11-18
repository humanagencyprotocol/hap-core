/**
 * Signed objects other than chain entries: sign-in (4.1), decision (4.2), mandate grant and
 * receipt (4.4). Each is verified against a chain already verified with `verifyChain`.
 *
 * Checks that need the Authority Server's own state (nonce store, replay store, session
 * limits, whether the approver may decide the proposal) are NOT here.
 *
 * @experimental
 */
import { fail } from './errors';
import { b64uBytes, b64uDecode, b64uEncode, hashBytes, jcs, objectHash, sameMembers, signedBytes } from './encoding';
import { signEd25519, verifyEd25519 } from './keys';
import { verifyCheck, type CheckProof, validateCheckProof } from './checks';
import { type ChainState, checkKeyAt, checkKeysEqual, isActive } from './chain';

function isObj(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}
function isInt(x: unknown): x is number {
  return typeof x === 'number' && Number.isSafeInteger(x) && x >= 0;
}
function str(x: unknown, what: string): string {
  if (typeof x !== 'string' || x.length === 0) return fail('MALFORMED', `${what} must be a non-empty string`);
  return x;
}
function exactMembers(o: Record<string, unknown>, keys: string[], what: string): void {
  if (!sameMembers(o, keys)) {
    fail('MALFORMED', `${what}: members must be exactly ${keys.join(', ')}`);
  }
}

/** Sign any object (without its `sig`) with a device or root seed; returns base64url. @experimental */
export async function signObject(obj: object, privateSeed: Uint8Array): Promise<string> {
  return b64uEncode(await signEd25519(privateSeed, signedBytes(obj)));
}

async function verifyObjectSig(obj: object, signPub: string, sig: unknown): Promise<boolean> {
  try {
    return await verifyEd25519(b64uDecode(signPub), signedBytes(obj), b64uBytes(sig, 64, 'sig'));
  } catch {
    return false;
  }
}

/**
 * Head check of 3.3 rule 3: the entry at `chain_seq` must have hash `chain_head`.
 * FORK if it differs; CHAIN_AHEAD if `chain_seq` is beyond the receiver's head (fetch the
 * chain first).
 * @experimental
 */
export function checkNamedHead(chain: ChainState, seq: number, head: string): void {
  if (seq > chain.head.seq) fail('CHAIN_AHEAD', 'fetch the chain first');
  if (chain.hashes[seq] !== head) fail('FORK', 'named head differs from the verified chain');
}

// ---------------------------------------------------------------------------
// 4.1 sign-in
// ---------------------------------------------------------------------------

/** @experimental */
export const SIGNIN_TYP = 'suveren-device-signin';
/** @experimental */
export interface Signin {
  typ: typeof SIGNIN_TYP;
  v: 1;
  aud: string;
  root_did: string;
  key_id: string;
  nonce: string;
  chain_seq: number;
  chain_head: string;
  issued_at: number;
}

/** @experimental */
export function buildSignin(f: Omit<Signin, 'typ' | 'v'>): Signin {
  return { typ: SIGNIN_TYP, v: 1, ...f };
}

/** Maximum clock difference for `issued_at`, seconds (4.1). @experimental */
export const SIGNIN_MAX_SKEW = 300;

/** @experimental */
export function validateSignin(o: unknown): Signin {
  if (!isObj(o)) return fail('MALFORMED', 'signin must be an object');
  exactMembers(o, ['typ', 'v', 'aud', 'root_did', 'key_id', 'nonce', 'chain_seq', 'chain_head', 'issued_at'], 'signin');
  if (o.typ !== SIGNIN_TYP || o.v !== 1) return fail('MALFORMED', 'typ or v');
  str(o.aud, 'aud');
  str(o.root_did, 'root_did');
  b64uBytes(o.key_id, 32, 'key_id');
  b64uBytes(o.nonce, 32, 'nonce');
  if (!isInt(o.chain_seq) || !isInt(o.issued_at)) return fail('MALFORMED', 'integers');
  hashBytes(o.chain_head);
  return o as unknown as Signin;
}

/**
 * Verify `{ signin, sig }` against a verified chain: `aud`, `issued_at` window, root DID,
 * `key_id` active, signature, head check. The AS-only checks (nonce issued for this key_id,
 * under 60 seconds, single use) are not done here.
 * Errors: MALFORMED, BAD_AUD, STALE, WRONG_ROOT, NOT_ACTIVE, BAD_SIGNATURE, FORK, CHAIN_AHEAD.
 * @experimental
 */
export async function verifySignin(
  env: { signin: unknown; sig: unknown },
  ctx: { aud: string; now: number; chain: ChainState },
): Promise<Signin> {
  const s = validateSignin(env?.signin);
  if (s.aud !== ctx.aud) return fail('BAD_AUD');
  if (Math.abs(ctx.now - s.issued_at) > SIGNIN_MAX_SKEW) return fail('STALE');
  if (s.root_did !== ctx.chain.root_did) return fail('WRONG_ROOT');
  if (!isActive(ctx.chain, s.key_id)) return fail('NOT_ACTIVE');
  if (!(await verifyObjectSig(s, ctx.chain.devices[s.key_id].sign_pub, env.sig))) return fail('BAD_SIGNATURE');
  checkNamedHead(ctx.chain, s.chain_seq, s.chain_head);
  return s;
}

// ---------------------------------------------------------------------------
// 4.2 decision
// ---------------------------------------------------------------------------

/** @experimental */
export const DECISION_TYP = 'suveren-device-decision';
/** @experimental */
export type DecisionKind = 'commit' | 'reject' | 'withdraw';
/** @experimental */
export interface Decision {
  typ: typeof DECISION_TYP;
  v: 1;
  approver_did: string;
  key_id: string;
  chain_seq: number;
  chain_head: string;
  proposal_id: string;
  mandate_id: string;
  action: string;
  action_type: string;
  decision: DecisionKind;
  content_hash: string;
  proposal_content_hash: string;
  decided_at: number;
  nonce: string;
}

/** @experimental */
export function buildDecision(f: Omit<Decision, 'typ' | 'v'>): Decision {
  return { typ: DECISION_TYP, v: 1, ...f };
}

/** @experimental */
export function validateDecision(o: unknown): Decision {
  if (!isObj(o)) return fail('MALFORMED', 'decision must be an object');
  exactMembers(
    o,
    ['typ', 'v', 'approver_did', 'key_id', 'chain_seq', 'chain_head', 'proposal_id', 'mandate_id', 'action', 'action_type', 'decision', 'content_hash', 'proposal_content_hash', 'decided_at', 'nonce'],
    'decision',
  );
  if (o.typ !== DECISION_TYP || o.v !== 1) return fail('MALFORMED', 'typ or v');
  for (const k of ['approver_did', 'proposal_id', 'mandate_id', 'action', 'action_type']) str(o[k], k);
  b64uBytes(o.key_id, 32, 'key_id');
  if (!isInt(o.chain_seq) || !isInt(o.decided_at)) return fail('MALFORMED', 'integers');
  hashBytes(o.chain_head);
  hashBytes(o.content_hash);
  hashBytes(o.proposal_content_hash);
  b64uBytes(o.nonce, 16, 'nonce');
  if (o.decision !== 'commit' && o.decision !== 'reject' && o.decision !== 'withdraw') return fail('MALFORMED', 'decision');
  return o as unknown as Decision;
}

/** What the verifier knows about the proposal; every member is required and must equal. @experimental */
export interface DecisionExpectation {
  proposal_id: string;
  mandate_id: string;
  action: string;
  action_type: string;
  proposal_content_hash: string;
}

const DECISION_EXPECT = ['proposal_id', 'mandate_id', 'action', 'action_type', 'proposal_content_hash'] as const;

/**
 * Verify `{ decision, sig }` against a verified chain (4.2): signature under `key_id`'s
 * signing key; `key_id` active at the chain's head (every active device may sign a commit,
 * reject or withdraw, with no check); the named head (3.3 rule 3; an older head is accepted
 * if it matches and the device was already admitted at that seq); `approver_did` is the
 * chain's root DID; the five proposal members equal `expect` (required).
 * Not done here: replay of `(approver_did, nonce)`, session limits, "may decide this proposal".
 * Errors: MALFORMED, WRONG_ROOT, NOT_ACTIVE, BAD_SIGNATURE, FORK, CHAIN_AHEAD, PROPOSAL_MISMATCH.
 * @experimental
 */
export async function verifyDecision(
  env: { decision: unknown; sig: unknown },
  ctx: { chain: ChainState; expect: DecisionExpectation },
): Promise<Decision> {
  const ex = ctx.expect as unknown as Record<string, unknown> | undefined;
  if (!ex || DECISION_EXPECT.some((k) => typeof ex[k] !== 'string' || (ex[k] as string).length === 0)) {
    return fail('MALFORMED', `ctx.expect must give ${DECISION_EXPECT.join(', ')}`);
  }
  const d = validateDecision(env?.decision);
  if (d.approver_did !== ctx.chain.root_did) return fail('WRONG_ROOT');
  if (!isActive(ctx.chain, d.key_id)) return fail('NOT_ACTIVE');
  const dev = ctx.chain.devices[d.key_id];
  if (!(await verifyObjectSig(d, dev.sign_pub, env.sig))) return fail('BAD_SIGNATURE');
  checkNamedHead(ctx.chain, d.chain_seq, d.chain_head);
  if (dev.added_seq > d.chain_seq) return fail('NOT_ACTIVE', 'device was not admitted at the named head');
  for (const k of DECISION_EXPECT) {
    if ((d as unknown as Record<string, unknown>)[k] !== ex[k]) return fail('PROPOSAL_MISMATCH', k);
  }
  return d;
}

// ---------------------------------------------------------------------------
// 4.4 mandate grant and receipt
// ---------------------------------------------------------------------------

/** @experimental */
export const GRANT_TYP = 'suveren-mandate-grant';
const GRANT_BASE = ['typ', 'v', 'op', 'owner_did', 'key_id', 'chain_seq', 'chain_head', 'mandate_id', 'mandate_version', 'granted_at', 'nonce'];

/**
 * A mandate grant. Besides the fixed members, it carries the mandate's own fields (profile
 * hash, bounds hash, scope hash, above-cap approvers, ...) flat, exactly as the caller
 * passes them in `fields`. Which fields those are comes from the mandate projection, not from
 * this module; `verifyGrant` therefore requires the verifier's own copy of them.
 * @experimental
 */
export type MandateGrant = {
  typ: typeof GRANT_TYP;
  v: 1;
  op: 'grant' | 'change' | 'revoke';
  owner_did: string;
  key_id: string;
  chain_seq: number;
  chain_head: string;
  mandate_id: string;
  mandate_version: number;
  granted_at: number;
  nonce: string;
} & Record<string, unknown>;

/** Fixed grant members, and the names stripped from signed bytes (`sig`, `sigs`, `checks`). */
function isReservedGrantName(k: string): boolean {
  return GRANT_BASE.includes(k) || k === 'sig' || k === 'sigs' || k === 'checks';
}

/** Build a grant: fixed members plus `fields` (which must not reuse a fixed name). @experimental */
export function buildGrant(base: Omit<MandateGrant, 'typ' | 'v'>, fields: Record<string, unknown> = {}): MandateGrant {
  for (const k of Object.keys(fields)) if (isReservedGrantName(k)) return fail('MALFORMED', `field ${k} is reserved`);
  return { ...fields, typ: GRANT_TYP, v: 1, ...base } as MandateGrant;
}

/** @experimental */
export function validateGrant(o: unknown, mandateFields: Record<string, unknown>): MandateGrant {
  if (!isObj(o)) return fail('MALFORMED', 'grant must be an object');
  for (const k of Object.keys(mandateFields)) if (isReservedGrantName(k)) return fail('MALFORMED', `field ${k} is reserved`);
  exactMembers(o, [...GRANT_BASE, ...Object.keys(mandateFields)], 'grant');
  if (o.typ !== GRANT_TYP || o.v !== 1) return fail('MALFORMED', 'typ or v');
  if (o.op !== 'grant' && o.op !== 'change' && o.op !== 'revoke') return fail('MALFORMED', 'op');
  str(o.owner_did, 'owner_did');
  str(o.mandate_id, 'mandate_id');
  b64uBytes(o.key_id, 32, 'key_id');
  if (!isInt(o.chain_seq) || !isInt(o.mandate_version) || !isInt(o.granted_at)) return fail('MALFORMED', 'integers');
  hashBytes(o.chain_head);
  b64uBytes(o.nonce, 16, 'nonce');
  for (const [k, v] of Object.entries(mandateFields)) {
    if (isReservedGrantName(k)) return fail('MALFORMED', `field ${k} is reserved`);
    if (jcs({ x: o[k] }) !== jcs({ x: v })) {
      return fail('GRANT_MISMATCH', `mandate field ${k} differs`);
    }
  }
  return o as unknown as MandateGrant;
}

/** Hash of a grant (its signed bytes); the `grant_hash` of a receipt. @experimental */
export function grantHash(grant: MandateGrant): Promise<string> {
  return objectHash(grant);
}

/**
 * What the caller wants to read the grant as. Without it a `revoke` (which needs no check)
 * could be read as a grant, and a grant of one mandate replayed for another.
 * @experimental
 */
export interface GrantExpectation {
  /** The ops the caller accepts, e.g. `['grant', 'change']`, or `['revoke']` when it reads a revocation. */
  ops: ('grant' | 'change' | 'revoke')[];
  mandate_id: string;
  mandate_version: number;
}

/**
 * Verify `{ grant, sig, check }` against a verified chain (4.4).
 *  - `grant` and `change`: the device must be active with a check key, and the check over
 *    the grant hash must verify; a grant with the signature alone is `CHECK_REQUIRED`. An older
 *    named head is accepted when the device's check key then equals its check key now.
 *  - `revoke`: any active device, no check.
 * `expect` is required: the grant's `op` must be in `expect.ops`, and its `mandate_id` and
 * `mandate_version` must equal the caller's. `mandateFields` are the mandate's fields as the verifier computed them; the grant must carry
 * exactly these besides the fixed members, with equal values (GRANT_MISMATCH).
 * Errors: MALFORMED, WRONG_ROOT, NOT_ACTIVE, BAD_SIGNATURE, CHECK_REQUIRED, FORK, CHAIN_AHEAD,
 * GRANT_MISMATCH.
 * @experimental
 */
export async function verifyGrant(
  env: { grant: unknown; sig: unknown; check?: unknown },
  ctx: { chain: ChainState; mandateFields: Record<string, unknown>; expect: GrantExpectation },
): Promise<MandateGrant> {
  const ex = ctx.expect as unknown as Record<string, unknown> | undefined;
  if (
    !ex ||
    !Array.isArray(ex.ops) ||
    ex.ops.length === 0 ||
    ex.ops.some((o) => o !== 'grant' && o !== 'change' && o !== 'revoke') ||
    typeof ex.mandate_id !== 'string' ||
    ex.mandate_id.length === 0 ||
    !isInt(ex.mandate_version)
  ) {
    return fail('MALFORMED', 'ctx.expect must give ops, mandate_id and mandate_version');
  }
  const g = validateGrant(env?.grant, ctx.mandateFields);
  if (!(ex.ops as string[]).includes(g.op)) return fail('GRANT_MISMATCH', `op ${g.op} is not one the caller expects`);
  if (g.mandate_id !== ex.mandate_id) return fail('GRANT_MISMATCH', 'mandate_id');
  if (g.mandate_version !== ex.mandate_version) return fail('GRANT_MISMATCH', 'mandate_version');
  if (g.owner_did !== ctx.chain.root_did) return fail('WRONG_ROOT');
  if (!isActive(ctx.chain, g.key_id)) return fail('NOT_ACTIVE');
  const dev = ctx.chain.devices[g.key_id];
  if (!(await verifyObjectSig(g, dev.sign_pub, env.sig))) return fail('BAD_SIGNATURE');
  checkNamedHead(ctx.chain, g.chain_seq, g.chain_head);
  if (dev.added_seq > g.chain_seq) return fail('NOT_ACTIVE', 'device was not admitted at the named head');
  if (g.op !== 'revoke') {
    if (!dev.check) return fail('CHECK_REQUIRED');
    if (!checkKeysEqual(checkKeyAt(ctx.chain, g.key_id, g.chain_seq), dev.check)) return fail('CHECK_REQUIRED', 'check key changed since the named head');
    if (env.check === undefined || env.check === null) return fail('CHECK_REQUIRED');
    let proof: CheckProof;
    try {
      proof = validateCheckProof(dev.check.type, env.check);
    } catch {
      return fail('CHECK_REQUIRED', 'malformed check');
    }
    if (!(await verifyCheck(dev.check, await objectHash(g), proof))) return fail('CHECK_REQUIRED', 'check does not verify');
  }
  return g;
}

/** @experimental */
export const RECEIPT_TYP = 'suveren-mandate-receipt';
/** @experimental */
export interface MandateReceipt {
  typ: typeof RECEIPT_TYP;
  v: 1;
  mandate_id: string;
  mandate_version: number;
  grant_hash: string;
  key_id: string;
  chain_seq: number;
  chain_head: string;
  received_at: number;
}

/** @experimental */
export function buildReceipt(f: Omit<MandateReceipt, 'typ' | 'v'>): MandateReceipt {
  return { typ: RECEIPT_TYP, v: 1, ...f };
}

/** @experimental */
export function validateReceipt(o: unknown): MandateReceipt {
  if (!isObj(o)) return fail('MALFORMED', 'receipt must be an object');
  exactMembers(o, ['typ', 'v', 'mandate_id', 'mandate_version', 'grant_hash', 'key_id', 'chain_seq', 'chain_head', 'received_at'], 'receipt');
  if (o.typ !== RECEIPT_TYP || o.v !== 1) return fail('MALFORMED', 'typ or v');
  str(o.mandate_id, 'mandate_id');
  b64uBytes(o.key_id, 32, 'key_id');
  if (!isInt(o.mandate_version) || !isInt(o.chain_seq) || !isInt(o.received_at)) return fail('MALFORMED', 'integers');
  hashBytes(o.grant_hash);
  hashBytes(o.chain_head);
  return o as unknown as MandateReceipt;
}

/**
 * Verify `{ receipt, sig }` (signed by the receiving gateway's device key) against a verified
 * chain. When `grant` is given, `grant_hash`, `mandate_id` and `mandate_version` must match it.
 * Errors: MALFORMED, NOT_ACTIVE, BAD_SIGNATURE, FORK, CHAIN_AHEAD, GRANT_MISMATCH.
 * @experimental
 */
export async function verifyReceipt(
  env: { receipt: unknown; sig: unknown },
  ctx: { chain: ChainState; grant?: MandateGrant },
): Promise<MandateReceipt> {
  const r = validateReceipt(env?.receipt);
  if (!isActive(ctx.chain, r.key_id)) return fail('NOT_ACTIVE');
  const dev = ctx.chain.devices[r.key_id];
  if (!(await verifyObjectSig(r, dev.sign_pub, env.sig))) return fail('BAD_SIGNATURE');
  checkNamedHead(ctx.chain, r.chain_seq, r.chain_head);
  if (ctx.grant) {
    if (r.grant_hash !== (await grantHash(ctx.grant))) return fail('GRANT_MISMATCH', 'grant_hash');
    if (r.mandate_id !== ctx.grant.mandate_id || r.mandate_version !== ctx.grant.mandate_version) {
      return fail('GRANT_MISMATCH', 'mandate id or version');
    }
  }
  return r;
}

// ---------------------------------------------------------------------------
// New root DID: cancel (section 10, DEC-33) and override (20.1 item 4, DEC-41)
// ---------------------------------------------------------------------------

/**
 * The verified check of a signed identity object, shared by cancel and override.
 * `required`: the object is a grant-class action, so the device MUST have a check key.
 * Otherwise (cancel) the check is required exactly when the device has a check key, and
 * refused when it has none (DEC-47, strict reading). Either way the device's check key at
 * the named head must equal its check key now (as for a mandate grant).
 */
async function verifyIdentityCheck(
  obj: { key_id: string; chain_seq: number },
  env: { check?: unknown },
  chain: ChainState,
  required: boolean,
): Promise<void> {
  const dev = chain.devices[obj.key_id];
  if (!checkKeysEqual(checkKeyAt(chain, obj.key_id, obj.chain_seq), dev.check)) {
    return fail('CHECK_REQUIRED', 'check key changed since the named head');
  }
  const given = env.check !== undefined && env.check !== null;
  if (!dev.check) {
    if (required) return fail('CHECK_REQUIRED', 'this action needs a device with a check key');
    if (given) return fail('MALFORMED', 'the device has no check key, so no check may be given');
    return;
  }
  if (!given) return fail('CHECK_REQUIRED');
  let proof: CheckProof;
  try {
    proof = validateCheckProof(dev.check.type, env.check);
  } catch {
    return fail('CHECK_REQUIRED', 'malformed check');
  }
  if (!(await verifyCheck(dev.check, await objectHash(obj), proof))) return fail('CHECK_REQUIRED', 'check does not verify');
}

/** Maximum clock difference for `issued_at` of an override, seconds (same as sign-in). @experimental */
export const IDENTITY_OVERRIDE_MAX_SKEW = SIGNIN_MAX_SKEW;
/** Maximum clock difference for `issued_at` of a cancel, seconds (same as sign-in). @experimental */
export const IDENTITY_CANCEL_MAX_SKEW = SIGNIN_MAX_SKEW;

/** A request id is base64url of at least 16 bytes (128 bits). */
function requestIdOk(x: unknown, what: string): string {
  const s = str(x, what);
  let bytes: Uint8Array;
  try {
    bytes = b64uDecode(s);
  } catch {
    return fail('MALFORMED', `${what} must be base64url`);
  }
  if (bytes.length < 16 || b64uEncode(bytes) !== s) return fail('MALFORMED', `${what} must be base64url of at least 16 bytes`);
  return s;
}

/** @experimental */
export const IDENTITY_CANCEL_TYP = 'suveren-identity-cancel';
/** @experimental */
export interface IdentityCancel {
  typ: typeof IDENTITY_CANCEL_TYP;
  v: 1;
  aud: string;
  root_did: string;
  key_id: string;
  request_id: string;
  chain_seq: number;
  chain_head: string;
  issued_at: number;
}

/** @experimental */
export function buildIdentityCancel(f: Omit<IdentityCancel, 'typ' | 'v'>): IdentityCancel {
  return { typ: IDENTITY_CANCEL_TYP, v: 1, ...f };
}

/** @experimental */
export function validateIdentityCancel(o: unknown): IdentityCancel {
  if (!isObj(o)) return fail('MALFORMED', 'identity cancel must be an object');
  exactMembers(o, ['typ', 'v', 'aud', 'root_did', 'key_id', 'request_id', 'chain_seq', 'chain_head', 'issued_at'], 'identity cancel');
  if (o.typ !== IDENTITY_CANCEL_TYP || o.v !== 1) return fail('MALFORMED', 'typ or v');
  str(o.aud, 'aud');
  str(o.root_did, 'root_did');
  requestIdOk(o.request_id, 'request_id');
  b64uBytes(o.key_id, 32, 'key_id');
  if (!isInt(o.chain_seq) || !isInt(o.issued_at)) return fail('MALFORMED', 'integers');
  hashBytes(o.chain_head);
  return o as unknown as IdentityCancel;
}

/**
 * Verify `{ cancel, sig, check? }`: a device of the OLD chain cancels a pending request for a
 * new root DID. Checks, in this order: ctx complete (`chain`, `aud`, `requestId`, `now`; else
 * MALFORMED); shape (`request_id` is base64url of at least 16 bytes); `aud` equals `ctx.aud`
 * (the Authority Server's own public key, BAD_AUD); `request_id` equals `ctx.requestId`;
 * `issued_at` within 300 seconds of `ctx.now` (`IDENTITY_CANCEL_MAX_SKEW`); `root_did` is the
 * chain's root; `key_id` active at the chain's head; strict signature; named head; the device
 * was admitted at the named head; the check: required and valid when the device has a check key
 * (over `objectHash(cancel)`), refused when it has none.
 * Not done here (AS state): that the request is still pending, and replay. The AS MUST key
 * replay on the object (its hash), never on the check bytes: a WebAuthn or platform check is
 * not deterministic, so a replayed object can carry a fresh check.
 * Errors: MALFORMED, BAD_AUD, REQUEST_MISMATCH, STALE, WRONG_ROOT, NOT_ACTIVE, BAD_SIGNATURE,
 * FORK, CHAIN_AHEAD, CHECK_REQUIRED.
 * @experimental
 */
export async function verifyIdentityCancel(
  env: { cancel: unknown; sig: unknown; check?: unknown },
  ctx: { chain: ChainState; aud: string; requestId: string; now: number },
): Promise<IdentityCancel> {
  if (
    !ctx ||
    !ctx.chain ||
    typeof ctx.aud !== 'string' ||
    ctx.aud.length === 0 ||
    typeof ctx.requestId !== 'string' ||
    ctx.requestId.length === 0 ||
    !isInt(ctx.now)
  ) {
    return fail('MALFORMED', 'ctx must give chain, aud, requestId and now');
  }
  const c = validateIdentityCancel(env?.cancel);
  if (c.aud !== ctx.aud) return fail('BAD_AUD');
  if (c.request_id !== ctx.requestId) return fail('REQUEST_MISMATCH', 'request_id');
  if (Math.abs(ctx.now - c.issued_at) > IDENTITY_CANCEL_MAX_SKEW) return fail('STALE');
  if (c.root_did !== ctx.chain.root_did) return fail('WRONG_ROOT');
  if (!isActive(ctx.chain, c.key_id)) return fail('NOT_ACTIVE');
  const dev = ctx.chain.devices[c.key_id];
  if (!(await verifyObjectSig(c, dev.sign_pub, env.sig))) return fail('BAD_SIGNATURE');
  checkNamedHead(ctx.chain, c.chain_seq, c.chain_head);
  if (dev.added_seq > c.chain_seq) return fail('NOT_ACTIVE', 'device was not admitted at the named head');
  await verifyIdentityCheck(c, env, ctx.chain, false);
  return c;
}

/** @experimental */
export const IDENTITY_OVERRIDE_TYP = 'suveren-identity-override';
/** @experimental */
export interface IdentityOverride {
  typ: typeof IDENTITY_OVERRIDE_TYP;
  v: 1;
  aud: string;
  admin_did: string;
  key_id: string;
  chain_seq: number;
  chain_head: string;
  member_user_id: string;
  request_id: string;
  issued_at: number;
}

/** @experimental */
export function buildIdentityOverride(f: Omit<IdentityOverride, 'typ' | 'v'>): IdentityOverride {
  return { typ: IDENTITY_OVERRIDE_TYP, v: 1, ...f };
}

/** @experimental */
export function validateIdentityOverride(o: unknown): IdentityOverride {
  if (!isObj(o)) return fail('MALFORMED', 'identity override must be an object');
  exactMembers(
    o,
    ['typ', 'v', 'aud', 'admin_did', 'key_id', 'chain_seq', 'chain_head', 'member_user_id', 'request_id', 'issued_at'],
    'identity override',
  );
  if (o.typ !== IDENTITY_OVERRIDE_TYP || o.v !== 1) return fail('MALFORMED', 'typ or v');
  str(o.aud, 'aud');
  str(o.admin_did, 'admin_did');
  str(o.member_user_id, 'member_user_id');
  requestIdOk(o.request_id, 'request_id');
  b64uBytes(o.key_id, 32, 'key_id');
  if (!isInt(o.chain_seq) || !isInt(o.issued_at)) return fail('MALFORMED', 'integers');
  hashBytes(o.chain_head);
  return o as unknown as IdentityOverride;
}

/**
 * Verify `{ override, sig, check }`: a team admin's granting device ends a cancel loop
 * (DEC-41). `ctx.adminChain` is the ADMIN's chain, verified by the caller with `verifyChain`
 * against the admin's root DID from the AS's own storage (never a DID taken from the object).
 * Checks, in this order: ctx complete (`adminChain`, `aud`, `requestId`, `memberUserId`, `now`;
 * else MALFORMED); shape (`request_id` is base64url of at least 16 bytes); `aud` equals
 * `ctx.aud` (BAD_AUD); `request_id` and `member_user_id` equal the caller's (REQUEST_MISMATCH);
 * `issued_at` within 300 seconds of `ctx.now` (`IDENTITY_OVERRIDE_MAX_SKEW`, STALE);
 * `admin_did` is the admin chain's root; `key_id` active; strict signature; named head;
 * admitted at the named head; the device has a check key, equal at the named head and now, and
 * the check over `objectHash(override)` is present and valid (always required: a grant-class
 * action).
 * Not done here (AS state, 20.1). The AS MUST also refuse when `admin_did` equals the member's
 * own root DID (the admin is not the member; `member_user_id` alone does not show it), and
 * check that the admin is a team admin of the member's team, that an earlier request of the
 * member was cancelled, that the request is still pending, and replay. Replay MUST be keyed on
 * the object (its hash), never on the check bytes: a check is not deterministic, so a replayed
 * object can carry a fresh one.
 * Errors: MALFORMED, BAD_AUD, REQUEST_MISMATCH, STALE, WRONG_ROOT, NOT_ACTIVE, BAD_SIGNATURE,
 * FORK, CHAIN_AHEAD, CHECK_REQUIRED.
 * @experimental
 */
export async function verifyIdentityOverride(
  env: { override: unknown; sig: unknown; check?: unknown },
  ctx: { adminChain: ChainState; aud: string; requestId: string; memberUserId: string; now: number },
): Promise<IdentityOverride> {
  if (
    !ctx ||
    !ctx.adminChain ||
    typeof ctx.aud !== 'string' ||
    ctx.aud.length === 0 ||
    typeof ctx.requestId !== 'string' ||
    ctx.requestId.length === 0 ||
    typeof ctx.memberUserId !== 'string' ||
    ctx.memberUserId.length === 0 ||
    !isInt(ctx.now)
  ) {
    return fail('MALFORMED', 'ctx must give adminChain, aud, requestId, memberUserId and now');
  }
  const o = validateIdentityOverride(env?.override);
  if (o.aud !== ctx.aud) return fail('BAD_AUD');
  if (o.request_id !== ctx.requestId) return fail('REQUEST_MISMATCH', 'request_id');
  if (o.member_user_id !== ctx.memberUserId) return fail('REQUEST_MISMATCH', 'member_user_id');
  if (Math.abs(ctx.now - o.issued_at) > IDENTITY_OVERRIDE_MAX_SKEW) return fail('STALE');
  if (o.admin_did !== ctx.adminChain.root_did) return fail('WRONG_ROOT');
  if (!isActive(ctx.adminChain, o.key_id)) return fail('NOT_ACTIVE');
  const dev = ctx.adminChain.devices[o.key_id];
  if (!(await verifyObjectSig(o, dev.sign_pub, env.sig))) return fail('BAD_SIGNATURE');
  checkNamedHead(ctx.adminChain, o.chain_seq, o.chain_head);
  if (dev.added_seq > o.chain_seq) return fail('NOT_ACTIVE', 'device was not admitted at the named head');
  await verifyIdentityCheck(o, env, ctx.adminChain, true);
  return o;
}

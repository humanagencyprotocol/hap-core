/**
 * Teams: who is a colleague (DEC-73). Three signed objects and three verifiers.
 *
 *  - `suveren-team-members`: a versioned member list, signed by a granting device of the
 *    team admin (computer or phone), each signature with its check. A change of admin carries
 *    two signatures (old and new admin).
 *  - `suveren-team-anchor`: a member's own statement "I trust this admin for this team", signed
 *    by a granting device of the member with its check (a touch). The root of trust of every
 *    device of that member. The admin has no anchor.
 *  - `suveren-team-leave`: a member says "I am out of this team", signed by any active device of
 *    the member, no check (it only removes power).
 *
 * Encoding as everywhere in device-keys: the signed bytes are JCS of the object without its
 * `sig`, `sigs` and `checks` members; the check is made over the object hash. None of these is a
 * `HAP-approval` or an owner signature, and none goes into a ticket.
 *
 * Pure functions, no I/O. Everything that needs the Authority Server's state (is this version the
 * head, replay, whether an added member has an anchor) is not here.
 *
 * @experimental
 */
import { fail } from './errors';
import { b64uBytes, b64uDecode, hashBytes, objectHash, sameMembers, signedBytes } from './encoding';
import { verifyEd25519 } from './keys';
import { verifyCheck, validateCheckProof, type CheckProof } from './checks';
import { type ChainState, checkKeyAt, checkKeysEqual } from './chain';
import { checkNamedHead } from './objects';
import { identityCode } from './pairing';

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
const DID_KEY = /^did:key:z[1-9A-HJ-NP-Za-km-z]{8,128}$/;
const TEAM_ID = /^[A-Za-z0-9._:-]{1,128}$/;
function did(x: unknown, what: string): string {
  if (typeof x !== 'string' || !DID_KEY.test(x)) return fail('MALFORMED', `${what} must be a did:key`);
  return x;
}
function teamId(x: unknown): string {
  if (typeof x !== 'string' || !TEAM_ID.test(x)) return fail('MALFORMED', 'team_id must be 1 to 128 characters of A-Z a-z 0-9 . _ : -');
  return x;
}
function exactMembers(o: Record<string, unknown>, keys: string[], what: string): void {
  if (!sameMembers(o, keys)) fail('MALFORMED', `${what}: members must be exactly ${keys.join(', ')}`);
}

/** Maximum number of members in one list. @experimental */
export const TEAM_MAX_MEMBERS = 500;
/** Maximum length of a member name, in characters (code points). @experimental */
export const TEAM_MAX_NAME = 64;

/** The highest `(version, hash)` a verifier accepted for a team (or for one member's anchor line). @experimental */
export interface TeamPin {
  version: number;
  hash: string;
}

/**
 * Rollback rule: a lower version than the pin is `ROLLBACK`; the same version with another hash
 * is `FORK`. Higher is fine here (see `verifyTeamTrust` for the link back to the pin).
 * @experimental
 */
export function checkTeamPin(version: number, hash: string, pin: TeamPin | undefined | null): void {
  if (pin === undefined || pin === null) return;
  if (!isObj(pin) || !isInt(pin.version)) return fail('MALFORMED', 'pin must be { version, hash }');
  hashBytes(pin.hash);
  if (version < pin.version) return fail('ROLLBACK', `version ${version} is below the pinned ${pin.version}`);
  if (version === pin.version && hash !== pin.hash) return fail('FORK', `version ${version} has another hash than the pinned one`);
}

// ---------------------------------------------------------------------------
// shared signer check
// ---------------------------------------------------------------------------

async function sigOk(obj: object, signPub: string, sig: unknown): Promise<boolean> {
  try {
    return await verifyEd25519(b64uDecode(signPub), signedBytes(obj), b64uBytes(sig, 64, 'sig'));
  } catch {
    return false;
  }
}

interface Named {
  key_id: string;
  chain_seq: number;
  chain_head: string;
}

/**
 * One signer: the device, its signature and, when `needCheck`, its check.
 *  - `strict`: the device is active at the verifier's head now, and its check key now equals the
 *    one at the named head (as for a mandate grant).
 *  - not strict (the version is at or below the verifier's pin): the device was admitted at the
 *    named head and not removed at or before it; its check key at the named head is used.
 * Errors: MALFORMED, NOT_ACTIVE, BAD_SIGNATURE, FORK, CHAIN_AHEAD, CHECK_REQUIRED.
 */
async function verifySigner(
  obj: object,
  who: Named,
  sig: unknown,
  check: unknown,
  chain: ChainState,
  opts: { needCheck: boolean; strict: boolean },
): Promise<void> {
  const dev = chain.devices[who.key_id];
  if (!dev) return fail('NOT_ACTIVE', 'not a device of this chain');
  if (opts.strict) {
    if (dev.removed_seq !== null) return fail('NOT_ACTIVE', 'device is removed');
  } else if (dev.removed_seq !== null && dev.removed_seq <= who.chain_seq) {
    return fail('NOT_ACTIVE', 'device was removed at or before the named head');
  }
  if (!(await sigOk(obj, dev.sign_pub, sig))) return fail('BAD_SIGNATURE');
  checkNamedHead(chain, who.chain_seq, who.chain_head);
  if (dev.added_seq > who.chain_seq) return fail('NOT_ACTIVE', 'device was not admitted at the named head');
  const given = check !== undefined && check !== null;
  if (!opts.needCheck) {
    if (given) return fail('MALFORMED', 'no check may be given');
    return;
  }
  const ck = checkKeyAt(chain, who.key_id, who.chain_seq);
  if (!ck) return fail('CHECK_REQUIRED', 'the device had no check key at the named head');
  if (opts.strict && !checkKeysEqual(ck, dev.check)) return fail('CHECK_REQUIRED', 'check key changed since the named head');
  if (!given) return fail('CHECK_REQUIRED');
  let proof: CheckProof;
  try {
    proof = validateCheckProof(ck.type, check);
  } catch {
    return fail('CHECK_REQUIRED', 'malformed check');
  }
  if (!(await verifyCheck(ck, await objectHash(obj), proof))) return fail('CHECK_REQUIRED', 'check does not verify');
}

// ---------------------------------------------------------------------------
// A. member list
// ---------------------------------------------------------------------------

/** @experimental */
export const TEAM_MEMBERS_TYP = 'suveren-team-members';

/** A member as the admin saw and confirmed it. `code` is the identity code the admin typed at the join. @experimental */
export interface TeamMember {
  did: string;
  name: string;
  code: string;
}

/** The second signer of a change of admin: a device of the OLD admin's chain. @experimental */
export interface TeamHandover extends Named {
  admin_did: string;
}

/** @experimental */
export interface MemberList {
  typ: typeof TEAM_MEMBERS_TYP;
  v: 1;
  team_id: string;
  version: number;
  prev: string | null;
  admin_did: string;
  members: TeamMember[];
  handover: TeamHandover | null;
  key_id: string;
  chain_seq: number;
  chain_head: string;
  created_at: number;
  nonce: string;
}

/** One signature of a list with its check. @experimental */
export interface ListSig {
  key_id: string;
  sig: string;
  check?: unknown;
}

/** @experimental */
export interface MemberListEnvelope {
  list: MemberList;
  sigs: ListSig[];
}

/** Build a member (computes the identity code of `did`). @experimental */
export async function buildTeamMember(did: string, name: string): Promise<TeamMember> {
  return { did, name, code: await identityCode(did) };
}

/** @experimental */
export function buildMemberList(f: Omit<MemberList, 'typ' | 'v'>): MemberList {
  return { typ: TEAM_MEMBERS_TYP, v: 1, ...f };
}

function validateName(name: unknown): string {
  const s = str(name, 'name');
  if (s.normalize('NFC') !== s) return fail('MALFORMED', 'name must be NFC');
  if ([...s].length > TEAM_MAX_NAME) return fail('MALFORMED', `name is longer than ${TEAM_MAX_NAME} characters`);
  if (/[\p{C}\p{Zl}\p{Zp}]/u.test(s)) return fail('MALFORMED', 'name must be plain text');
  return s;
}

function validateNamed(o: unknown, what: string, extra: string[] = []): Record<string, unknown> {
  if (!isObj(o)) return fail('MALFORMED', `${what} must be an object`);
  exactMembers(o, [...extra, 'key_id', 'chain_seq', 'chain_head'], what);
  b64uBytes(o.key_id, 32, 'key_id');
  if (!isInt(o.chain_seq)) return fail('MALFORMED', 'chain_seq');
  hashBytes(o.chain_head);
  return o;
}

/**
 * Shape of a list: exact members; `members` sorted by `did` (code-unit order), no duplicate DID,
 * 1 to 500 entries, each `{ did, name, code }`; `admin_did` is a member; version 1 has `prev`
 * null, no hand-over and the admin as the only member. The identity codes are checked by
 * `verifyMemberList` (they need a hash).
 * @experimental
 */
export function validateMemberList(o: unknown): MemberList {
  if (!isObj(o)) return fail('MALFORMED', 'member list must be an object');
  exactMembers(
    o,
    ['typ', 'v', 'team_id', 'version', 'prev', 'admin_did', 'members', 'handover', 'key_id', 'chain_seq', 'chain_head', 'created_at', 'nonce'],
    'member list',
  );
  if (o.typ !== TEAM_MEMBERS_TYP || o.v !== 1) return fail('MALFORMED', 'typ or v');
  teamId(o.team_id);
  did(o.admin_did, 'admin_did');
  if (!isInt(o.version) || o.version < 1) return fail('MALFORMED', 'version must be an integer of at least 1');
  if (!isInt(o.chain_seq) || !isInt(o.created_at)) return fail('MALFORMED', 'integers');
  b64uBytes(o.key_id, 32, 'key_id');
  hashBytes(o.chain_head);
  b64uBytes(o.nonce, 16, 'nonce');
  if (o.prev !== null) hashBytes(o.prev);
  if (o.handover !== null) {
    const h = validateNamed(o.handover, 'handover', ['admin_did']);
    did(h.admin_did, 'handover.admin_did');
    if (h.admin_did === o.admin_did) return fail('MALFORMED', 'handover names the same admin');
  }
  if (!Array.isArray(o.members) || o.members.length < 1 || o.members.length > TEAM_MAX_MEMBERS) {
    return fail('MALFORMED', `members must be 1 to ${TEAM_MAX_MEMBERS} entries`);
  }
  let last: string | null = null;
  let adminSeen = false;
  for (const m of o.members) {
    if (!isObj(m)) return fail('MALFORMED', 'member must be an object');
    exactMembers(m, ['did', 'name', 'code'], 'member');
    const mdid = did(m.did, 'member did');
    validateName(m.name);
    if (typeof m.code !== 'string' || !/^\d{4}( \d{4}){5}$/.test(m.code)) return fail('MALFORMED', 'member code');
    if (last !== null && mdid <= last) return fail('MALFORMED', mdid === last ? 'duplicate member did' : 'members are not sorted by did');
    last = mdid;
    if (mdid === o.admin_did) adminSeen = true;
  }
  if (!adminSeen) return fail('MALFORMED', 'admin_did is not a member');
  if (o.version === 1) {
    if (o.prev !== null) return fail('MALFORMED', 'version 1 has no prev');
    if (o.handover !== null) return fail('MALFORMED', 'version 1 has no hand-over');
    if (o.members.length !== 1) return fail('MALFORMED', 'version 1 lists the admin alone');
  } else if (o.prev === null) {
    return fail('MALFORMED', 'prev is required above version 1');
  }
  return o as unknown as MemberList;
}

/** Hash of a list (its signed bytes): the identity of the version. @experimental */
export function memberListHash(list: MemberList): Promise<string> {
  return objectHash(list);
}

/** What `verifyMemberList` needs. @experimental */
export interface MemberListContext {
  /** The verified chain of `list.admin_did` (the admin who signs). */
  chain: ChainState;
  /**
   * The list before this one (already validated), or `null` for version 1. REQUIRED (unless
   * `first`): `version`, `prev` and the change-of-admin rule are checked against it.
   */
  prev?: MemberList | null;
  /**
   * The first list the verifier holds: its predecessor is not available, so `version`, `prev` and
   * the admin rule are NOT checked (the member's anchor and the pin carry that). Exactly one of
   * `prev` and `first: true` MUST be given, else MALFORMED.
   */
  first?: boolean;
  /** The verified chain of the OLD admin; required when the list carries a hand-over. */
  oldAdminChain?: ChainState;
  /**
   * The verifier's pin. A list that IS the pinned version (same version, same hash) is not
   * re-verified against the admin's head now (the re-sign rule): its signer needs only to have
   * been admitted at the named head. Does not itself refuse; use `checkTeamPin`.
   */
  pin?: TeamPin | null;
  /**
   * The caller has hash-linked this list to a strictly valid later list or to the pin, so the
   * signer needs only to have been admitted at the named head (a device removed since does not
   * matter: the later list endorses this one).
   */
  linked?: boolean;
  /**
   * The verifier holds a member anchor naming `list.admin_did`: a change of admin with ONE
   * signature (no hand-over) is accepted for this list, because the members' own statements
   * stand in for the old admin.
   */
  anchored?: boolean;
}

/**
 * Verify `{ list, sigs }` (20.21.3 A). In this order: shape; ctx; `admin_did` is the chain's
 * root; the identity codes (`code` equals `identityCode(did)`); with `prev`: same `team_id`,
 * `version` is `prev.version + 1`, `prev` is `prev`'s hash, and the admin rule (a list whose
 * `admin_did` differs from `prev`'s needs a hand-over naming `prev`'s admin, unless
 * `ctx.anchored`; a list with the same admin has none); the signatures: exactly one for
 * `key_id`, and when there is a hand-over a second one for the hand-over's `key_id`; each is a
 * granting device (signature, named head, check over the object hash, see `verifySigner`).
 * Errors: MALFORMED, WRONG_ROOT, BAD_VERSION, BAD_PREV, TEAM_MISMATCH, HANDOVER_REQUIRED,
 * NOT_ACTIVE, BAD_SIGNATURE, CHECK_REQUIRED, FORK, CHAIN_AHEAD.
 * @experimental
 */
export async function verifyMemberList(env: { list: unknown; sigs: unknown }, ctx: MemberListContext): Promise<MemberList> {
  if (!ctx || !ctx.chain) return fail('MALFORMED', 'ctx must give chain');
  const l = validateMemberList(env?.list);
  if (l.admin_did !== ctx.chain.root_did) return fail('WRONG_ROOT');
  for (const m of l.members) {
    if (m.code !== (await identityCode(m.did))) return fail('MALFORMED', `identity code of ${m.did} does not match`);
  }
  if (ctx.first !== true && ctx.prev === undefined) return fail('MALFORMED', 'ctx.prev (null or a list) or ctx.first is required');
  if (ctx.first === true && ctx.prev !== undefined) return fail('MALFORMED', 'ctx.first and ctx.prev are exclusive');
  const prev = ctx.prev ?? null;
  if (ctx.first !== true && prev === null && l.version !== 1) return fail('BAD_VERSION', 'no earlier list given for a version above 1');
  if (prev) {
    if (prev.team_id !== l.team_id) return fail('TEAM_MISMATCH');
    if (l.version !== prev.version + 1) return fail('BAD_VERSION', `version must be ${prev.version + 1}`);
    if (l.prev !== (await memberListHash(prev))) return fail('BAD_PREV');
    if (l.admin_did !== prev.admin_did) {
      if (l.handover === null) {
        if (!ctx.anchored) return fail('HANDOVER_REQUIRED', 'a change of admin needs the old and the new admin');
      } else if (l.handover.admin_did !== prev.admin_did) {
        return fail('HANDOVER_REQUIRED', 'the hand-over must name the previous admin');
      }
    } else if (l.handover !== null) {
      return fail('MALFORMED', 'a hand-over without a change of admin');
    }
  }
  const sigs = env?.sigs;
  const want = l.handover ? 2 : 1;
  if (!Array.isArray(sigs) || sigs.length !== want) return fail('MALFORMED', `sigs must hold exactly ${want} signature(s)`);
  const entry = (keyId: string): ListSig => {
    const e = sigs.filter((s) => isObj(s) && s.key_id === keyId);
    if (e.length !== 1) return fail('MALFORMED', 'sigs must hold one signature per signer');
    const o = e[0] as Record<string, unknown>;
    if (!Object.keys(o).every((k) => k === 'key_id' || k === 'sig' || k === 'check')) return fail('MALFORMED', 'sig entry members');
    return o as unknown as ListSig;
  };
  const pinned = !!ctx.pin && l.version === ctx.pin.version && (await memberListHash(l)) === ctx.pin.hash;
  const strict = !(pinned || ctx.linked === true);
  const main = entry(l.key_id);
  await verifySigner(l, l, main.sig, main.check, ctx.chain, { needCheck: true, strict });
  if (l.handover) {
    if (!ctx.oldAdminChain) return fail('MALFORMED', 'ctx.oldAdminChain is required for a hand-over');
    if (l.handover.admin_did !== ctx.oldAdminChain.root_did) return fail('WRONG_ROOT', 'oldAdminChain is not the old admin');
    if (l.handover.key_id === l.key_id) return fail('MALFORMED', 'the two signers must be different devices');
    const second = entry(l.handover.key_id);
    await verifySigner(l, l.handover, second.sig, second.check, ctx.oldAdminChain, { needCheck: true, strict });
  }
  return l;
}

// ---------------------------------------------------------------------------
// B. anchor
// ---------------------------------------------------------------------------

/** @experimental */
export const TEAM_ANCHOR_TYP = 'suveren-team-anchor';

/** @experimental */
export interface TeamAnchor {
  typ: typeof TEAM_ANCHOR_TYP;
  v: 1;
  member_did: string;
  team_id: string;
  /** The admin this person trusts for this team; `null` clears the statement (left the team). */
  admin_did: string | null;
  version: number;
  prev: string | null;
  key_id: string;
  chain_seq: number;
  chain_head: string;
  created_at: number;
  nonce: string;
}

/** @experimental */
export function buildAnchor(f: Omit<TeamAnchor, 'typ' | 'v'>): TeamAnchor {
  return { typ: TEAM_ANCHOR_TYP, v: 1, ...f };
}

/** @experimental */
export function validateAnchor(o: unknown): TeamAnchor {
  if (!isObj(o)) return fail('MALFORMED', 'anchor must be an object');
  exactMembers(o, ['typ', 'v', 'member_did', 'team_id', 'admin_did', 'version', 'prev', 'key_id', 'chain_seq', 'chain_head', 'created_at', 'nonce'], 'anchor');
  if (o.typ !== TEAM_ANCHOR_TYP || o.v !== 1) return fail('MALFORMED', 'typ or v');
  did(o.member_did, 'member_did');
  teamId(o.team_id);
  if (o.admin_did !== null) {
    did(o.admin_did, 'admin_did');
    if (o.admin_did === o.member_did) return fail('MALFORMED', 'a member cannot anchor itself');
  }
  if (!isInt(o.version) || o.version < 1) return fail('MALFORMED', 'version must be an integer of at least 1');
  if (!isInt(o.chain_seq) || !isInt(o.created_at)) return fail('MALFORMED', 'integers');
  b64uBytes(o.key_id, 32, 'key_id');
  hashBytes(o.chain_head);
  b64uBytes(o.nonce, 16, 'nonce');
  if (o.prev !== null) hashBytes(o.prev);
  if (o.version === 1 && o.prev !== null) return fail('MALFORMED', 'version 1 has no prev');
  if (o.version > 1 && o.prev === null) return fail('MALFORMED', 'prev is required above version 1');
  return o as unknown as TeamAnchor;
}

/** Hash of an anchor (its signed bytes). @experimental */
export function anchorHash(a: TeamAnchor): Promise<string> {
  return objectHash(a);
}

/** @experimental */
export interface AnchorContext {
  /** The verified chain of `member_did`. */
  chain: ChainState;
  /** The earlier anchor of this member for this team (already validated); `version` and `prev` are checked against it. */
  prev?: TeamAnchor | null;
  /**
   * The verifier's pin of this member's anchor line: a lower version is `ROLLBACK`, the same
   * version with another hash is `FORK`; an anchor at the pin is not re-verified against the head now.
   */
  pin?: TeamPin | null;
  /** What the caller wants to read: the team (and the admin) this anchor must name. */
  expect?: { team_id?: string; admin_did?: string | null };
}

/**
 * Verify `{ anchor, sig, check }` against the member's chain: shape; `member_did` is the chain's
 * root; `expect`; with `prev`: `version` and `prev`; the signature of a granting device (active at
 * the head now, or admitted at the named head when the version is at or below the pin) with its
 * check over the object hash: a touch. An anchor with `admin_did` null clears the statement; it
 * needs no check (it removes power) and a check may not be given.
 * Errors: MALFORMED, WRONG_ROOT, TEAM_MISMATCH, BAD_VERSION, BAD_PREV, ROLLBACK, NOT_ACTIVE,
 * BAD_SIGNATURE, CHECK_REQUIRED, FORK, CHAIN_AHEAD.
 * @experimental
 */
export async function verifyAnchor(env: { anchor: unknown; sig: unknown; check?: unknown }, ctx: AnchorContext): Promise<TeamAnchor> {
  if (!ctx || !ctx.chain) return fail('MALFORMED', 'ctx must give chain');
  const a = validateAnchor(env?.anchor);
  if (a.member_did !== ctx.chain.root_did) return fail('WRONG_ROOT');
  if (ctx.expect) {
    if (ctx.expect.team_id !== undefined && a.team_id !== ctx.expect.team_id) return fail('TEAM_MISMATCH', 'team_id');
    if (ctx.expect.admin_did !== undefined && a.admin_did !== ctx.expect.admin_did) return fail('TEAM_MISMATCH', 'admin_did');
  }
  if (ctx.prev) {
    if (ctx.prev.team_id !== a.team_id || ctx.prev.member_did !== a.member_did) return fail('TEAM_MISMATCH', 'prev is another line');
    if (a.version !== ctx.prev.version + 1) return fail('BAD_VERSION', `version must be ${ctx.prev.version + 1}`);
    if (a.prev !== (await anchorHash(ctx.prev))) return fail('BAD_PREV');
  } else if (ctx.prev === null && a.version !== 1) {
    return fail('BAD_VERSION', 'no earlier anchor given for a version above 1');
  }
  checkTeamPin(a.version, await anchorHash(a), ctx.pin);
  const strict = !(ctx.pin && a.version <= ctx.pin.version);
  await verifySigner(a, a, env.sig, env.check, ctx.chain, { needCheck: a.admin_did !== null, strict });
  return a;
}

// ---------------------------------------------------------------------------
// C. leave
// ---------------------------------------------------------------------------

/** @experimental */
export const TEAM_LEAVE_TYP = 'suveren-team-leave';

/** @experimental */
export interface TeamLeave {
  typ: typeof TEAM_LEAVE_TYP;
  v: 1;
  member_did: string;
  team_id: string;
  /** The list version the member was in when leaving. */
  list_version: number;
  key_id: string;
  chain_seq: number;
  chain_head: string;
  created_at: number;
  nonce: string;
}

/** @experimental */
export function buildLeave(f: Omit<TeamLeave, 'typ' | 'v'>): TeamLeave {
  return { typ: TEAM_LEAVE_TYP, v: 1, ...f };
}

/** @experimental */
export function validateLeave(o: unknown): TeamLeave {
  if (!isObj(o)) return fail('MALFORMED', 'leave must be an object');
  exactMembers(o, ['typ', 'v', 'member_did', 'team_id', 'list_version', 'key_id', 'chain_seq', 'chain_head', 'created_at', 'nonce'], 'leave');
  if (o.typ !== TEAM_LEAVE_TYP || o.v !== 1) return fail('MALFORMED', 'typ or v');
  did(o.member_did, 'member_did');
  teamId(o.team_id);
  if (!isInt(o.list_version) || o.list_version < 1) return fail('MALFORMED', 'list_version');
  if (!isInt(o.chain_seq) || !isInt(o.created_at)) return fail('MALFORMED', 'integers');
  b64uBytes(o.key_id, 32, 'key_id');
  hashBytes(o.chain_head);
  b64uBytes(o.nonce, 16, 'nonce');
  return o as unknown as TeamLeave;
}

/**
 * Verify `{ leave, sig }` against the member's chain: shape; `member_did` is the chain's root;
 * `expect.team_id` (required); any device active at the head, signature, named head; NO check
 * (a leave only removes power, and a check may not be given).
 * Errors: MALFORMED, WRONG_ROOT, TEAM_MISMATCH, NOT_ACTIVE, BAD_SIGNATURE, FORK, CHAIN_AHEAD.
 * @experimental
 */
export async function verifyLeave(
  env: { leave: unknown; sig: unknown; check?: unknown },
  ctx: { chain: ChainState; expect: { team_id: string } },
): Promise<TeamLeave> {
  if (!ctx || !ctx.chain || !ctx.expect || typeof ctx.expect.team_id !== 'string' || ctx.expect.team_id.length === 0) {
    return fail('MALFORMED', 'ctx must give chain and expect.team_id');
  }
  const x = validateLeave(env?.leave);
  if (x.member_did !== ctx.chain.root_did) return fail('WRONG_ROOT');
  if (x.team_id !== ctx.expect.team_id) return fail('TEAM_MISMATCH', 'team_id');
  await verifySigner(x, x, env.sig, env.check, ctx.chain, { needCheck: false, strict: true });
  return x;
}

// ---------------------------------------------------------------------------
// what a member's device runs
// ---------------------------------------------------------------------------

/** Most list versions and most leaves one `verifyTeamTrust` call takes. @experimental */
export const TEAM_TRUST_MAX_VERSIONS = 256;
/** @experimental */
export const TEAM_TRUST_MAX_LEAVES = 1000;

/** @experimental */
export interface TeamTrustInput {
  team_id: string;
  /** The member's own anchor, verified here against `anchorChain`. */
  anchor: { anchor: unknown; sig: unknown; check?: unknown };
  anchorChain: ChainState;
  /** The verifier's pin of the anchor line, if any. */
  anchorPin?: TeamPin | null;
  /** List versions as the Authority Server carries them (any order, at most 256). Each is verified here. */
  versions: { list: unknown; sigs: unknown }[];
  /** Verified chains of the admins, by root DID. Must hold every admin that signs a version taken into account. */
  adminChains: Record<string, ChainState>;
  /** The verifier's pin for this team: highest `(version, hash)` it accepted. */
  pin?: TeamPin | null;
  /** Leaves of members, each with the verified chain of its member (at most 1000). */
  leaves?: { env: { leave: unknown; sig: unknown }; chain: ChainState }[];
}

/** @experimental */
export interface TeamTrust {
  team_id: string;
  admin_did: string;
  version: number;
  hash: string;
  /** The members at `version`, minus those who left; includes the admin. */
  members: TeamMember[];
  /** DIDs of members whose own `leave` was applied. */
  left: string[];
  /** What the verifier stores as its pin for this team. */
  pin: TeamPin;
  /**
   * The lowest served version above `version` that was refused, with the code, or null. A gateway
   * SHOULD warn or refuse when this is set: the Authority Server served something newer that does
   * not verify (a removed signer, a foreign admin, a broken signature, a missing version).
   */
  rejected: { version: number; code: string } | null;
  /** Leaves that were not applied, by their index in `input.leaves`, with the reason. */
  skipped_leaves: { index: number; code: string }[];
}

function codeOf(e: unknown): string {
  const c = (e as { code?: unknown } | null)?.code;
  return typeof c === 'string' ? c : 'MALFORMED';
}

function chainLike(x: unknown, what: string): ChainState {
  if (!isObj(x) || typeof x.root_did !== 'string' || !isObj(x.devices) || !isObj(x.head) || !Array.isArray(x.hashes)) {
    return fail('MALFORMED', `${what} must be a verified chain`);
  }
  return x as unknown as ChainState;
}

function checkTrustInput(input: TeamTrustInput): void {
  if (!isObj(input)) return fail('MALFORMED', 'input must be an object');
  teamId(input.team_id);
  if (!isObj(input.anchor) || !isObj((input.anchor as Record<string, unknown>).anchor)) return fail('MALFORMED', 'anchor must be { anchor, sig, check? }');
  chainLike(input.anchorChain, 'anchorChain');
  if (!Array.isArray(input.versions) || input.versions.length > TEAM_TRUST_MAX_VERSIONS) {
    return fail('MALFORMED', `versions must be an array of at most ${TEAM_TRUST_MAX_VERSIONS}`);
  }
  for (const v of input.versions) {
    if (!isObj(v) || !isObj(v.list) || !Array.isArray(v.sigs)) return fail('MALFORMED', 'a version must be { list, sigs }');
  }
  if (!isObj(input.adminChains)) return fail('MALFORMED', 'adminChains must be an object');
  for (const k of Object.keys(input.adminChains)) chainLike(input.adminChains[k], 'adminChains entry');
  if (input.leaves !== undefined) {
    if (!Array.isArray(input.leaves) || input.leaves.length > TEAM_TRUST_MAX_LEAVES) {
      return fail('MALFORMED', `leaves must be an array of at most ${TEAM_TRUST_MAX_LEAVES}`);
    }
    for (const l of input.leaves) {
      if (!isObj(l) || !isObj(l.env)) return fail('MALFORMED', 'a leave must be { env, chain }');
      chainLike(l.chain, 'leave chain');
    }
  }
  for (const p of [input.pin, input.anchorPin]) {
    if (p === undefined || p === null) continue;
    if (!isObj(p) || !isInt(p.version)) return fail('MALFORMED', 'pin must be { version, hash }');
    hashBytes(p.hash);
  }
}

/**
 * Trust of one member's device in one team (20.21.3). The member's anchor names an admin. From
 * the first list signed by that admin ("start"), versions are followed upward: each must verify
 * against its predecessor (`verifyMemberList`; a change of admin needs the old and the new admin,
 * unless the list is the start), and each admin that signs needs a chain in `adminChains`.
 *
 * The result is the highest version that verifies, with these rules:
 *  - A signer removed since needs no re-check on a version that a later, strictly valid version
 *    hash-links to (the later list endorses it). The newest accepted version must be strictly
 *    valid (signer active now) or equal the pin.
 *  - A refused newer version is reported in `rejected`; the result is the version before it.
 *  - The pin: `ROLLBACK` below it, `FORK` at the same version with another hash. The walk must be
 *    linked to the pin: either the start is at or below the pin version (the walk then holds the
 *    pinned version with the pinned hash), or every version from the pin to the start is present
 *    with `prev` equal to the previous hash and the pinned hash at the bottom (signatures are not
 *    needed on that segment). Otherwise `HISTORY_GAP` (fetch more versions) or `FORK`.
 *  - The anchor's member must be in the list (`NOT_A_MEMBER`: a removed member is not given an
 *    older list).
 *  - Each leave is applied or skipped on its own (`skipped_leaves`): a leave applies if its
 *    `list_version` is not above the result and the member stays listed without a gap from there
 *    to the result; a leave of the admin is skipped as `ADMIN_CANNOT_LEAVE`.
 * Errors: everything of `verifyMemberList` and `verifyAnchor` (a refusal of the first list is
 * thrown as it is), plus MALFORMED (input shape, caps), NO_TRUST, TEAM_MISMATCH, NOT_A_MEMBER,
 * ROLLBACK, FORK, HISTORY_GAP.
 * @experimental
 */
export async function verifyTeamTrust(input: TeamTrustInput): Promise<TeamTrust> {
  checkTrustInput(input);
  const own = (o: Record<string, ChainState>, k: string): ChainState | undefined => (Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined);
  const anchor = await verifyAnchor(input.anchor, { chain: input.anchorChain, pin: input.anchorPin, expect: { team_id: input.team_id } });
  if (anchor.admin_did === null) return fail('NO_TRUST', 'the anchor is cleared');
  const adminDid = anchor.admin_did;
  const pin = input.pin ?? undefined;

  // shapes, order, two different lists at one version
  const all: { list: MemberList; hash: string; env: { list: unknown; sigs: unknown } }[] = [];
  for (const e of input.versions) {
    const list = validateMemberList(e.list);
    if (list.team_id !== input.team_id) return fail('TEAM_MISMATCH', 'a version belongs to another team');
    all.push({ list, hash: await memberListHash(list), env: e });
  }
  all.sort((a, b) => a.list.version - b.list.version);
  const seen: typeof all = [];
  for (const x of all) {
    const last = seen[seen.length - 1];
    if (last && last.list.version === x.list.version) {
      if (last.hash !== x.hash) return fail('FORK', `two different lists at version ${x.list.version}`);
      continue;
    }
    seen.push(x);
  }

  const start = seen.findIndex((x) => x.list.admin_did === adminDid);
  if (start < 0) return fail('NO_TRUST', 'no list signed by the admin this member trusts');

  // 1. walk upward, each list verified with the re-sign relaxation (linked)
  type Step = { chain: ChainState; oldAdminChain?: ChainState; prev?: MemberList; first?: boolean; anchored: boolean };
  const steps: Step[] = [];
  let lastOk = -1;
  let walkError: unknown = null;
  for (let i = start; i < seen.length; i++) {
    const { list, env } = seen[i];
    try {
      const before = i > 0 ? seen[i - 1] : undefined;
      const adjacent = before && before.list.version === list.version - 1 ? before.list : undefined;
      if (!adjacent && i > start) return fail('BAD_VERSION', 'a version is missing');
      const chain = own(input.adminChains, list.admin_did);
      if (!chain) return fail('NO_TRUST', `no verified chain for admin ${list.admin_did}`);
      const oldChain = list.handover ? own(input.adminChains, list.handover.admin_did) : undefined;
      if (list.handover && !oldChain) return fail('NO_TRUST', 'no verified chain for the old admin');
      const step: Step = adjacent ? { chain, oldAdminChain: oldChain, prev: adjacent, anchored: i === start } : { chain, oldAdminChain: oldChain, first: true, anchored: i === start };
      await verifyMemberList(env, { ...step, pin, linked: true });
      steps[i] = step;
      lastOk = i;
    } catch (e) {
      walkError = e;
      break;
    }
  }
  if (lastOk < 0) throw walkError ?? fail('NO_TRUST', 'no version verifies');

  // 2. the newest accepted version is strictly valid (signer active now) or is the pin; older ones are endorsed by hash
  let accepted = -1;
  const strictError: Record<number, unknown> = {};
  for (let j = lastOk; j >= start; j--) {
    if (pin && seen[j].list.version === pin.version && seen[j].hash === pin.hash) {
      accepted = j;
      break;
    }
    try {
      await verifyMemberList(seen[j].env, { ...steps[j], pin, linked: false });
      accepted = j;
      break;
    } catch (e) {
      strictError[j] = e;
    }
  }
  if (accepted < 0) throw strictError[lastOk];
  const best = seen[accepted];

  // 3. pin: rollback, fork, and the hash link from the pin to the walk
  if (pin) {
    checkTeamPin(best.list.version, best.hash, pin);
    if (seen[start].list.version <= pin.version) {
      const at = seen.slice(start, accepted + 1).find((x) => x.list.version === pin.version);
      if (at && at.hash !== pin.hash) return fail('FORK', 'the history differs from the pinned version');
      if (!at && best.list.version > pin.version) return fail('HISTORY_GAP', 'the pinned version is not in the walked versions');
    } else {
      let cur = seen[start];
      while (cur.list.version > pin.version + 1) {
        const pred = seen.find((x) => x.list.version === cur.list.version - 1);
        if (!pred) return fail('HISTORY_GAP', 'versions from the pinned one to the start are missing');
        if (cur.list.prev !== pred.hash) return fail('FORK', 'the history does not link up');
        cur = pred;
      }
      if (cur.list.prev !== pin.hash) return fail('FORK', 'the history does not continue from the pinned version');
    }
  }

  if (!best.list.members.some((m) => m.did === anchor.member_did)) return fail('NOT_A_MEMBER');

  // what was refused above the result
  let rejected: TeamTrust['rejected'] = null;
  if (accepted + 1 <= lastOk) rejected = { version: seen[accepted + 1].list.version, code: codeOf(strictError[accepted + 1]) };
  else if (lastOk + 1 < seen.length) rejected = { version: seen[lastOk + 1].list.version, code: codeOf(walkError) };

  // leaves, one by one
  const left: string[] = [];
  const skipped: { index: number; code: string }[] = [];
  const leaves = input.leaves ?? [];
  for (let idx = 0; idx < leaves.length; idx++) {
    try {
      const x = await verifyLeave(leaves[idx].env, { chain: leaves[idx].chain, expect: { team_id: input.team_id } });
      if (x.list_version > best.list.version) throw Object.assign(new Error('NOT_APPLICABLE'), { code: 'NOT_APPLICABLE' });
      let continuous = true;
      for (let v = x.list_version; v <= best.list.version && continuous; v++) {
        const at = seen.slice(start, accepted + 1).find((s) => s.list.version === v);
        if (!at) throw Object.assign(new Error('HISTORY_GAP'), { code: 'HISTORY_GAP' });
        if (!at.list.members.some((m) => m.did === x.member_did)) continuous = false;
      }
      if (!continuous) throw Object.assign(new Error('NOT_APPLICABLE'), { code: 'NOT_APPLICABLE' });
      if (x.member_did === best.list.admin_did) throw Object.assign(new Error('ADMIN_CANNOT_LEAVE'), { code: 'ADMIN_CANNOT_LEAVE' });
      if (!left.includes(x.member_did)) left.push(x.member_did);
    } catch (e) {
      skipped.push({ index: idx, code: codeOf(e) });
    }
  }
  if (left.includes(anchor.member_did)) return fail('NOT_A_MEMBER', 'this member has left');

  return {
    team_id: input.team_id,
    admin_did: best.list.admin_did,
    version: best.list.version,
    hash: best.hash,
    members: best.list.members.filter((m) => !left.includes(m.did)),
    left,
    pin: { version: best.list.version, hash: best.hash },
    rejected,
    skipped_leaves: skipped,
  };
}

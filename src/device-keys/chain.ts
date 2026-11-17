/**
 * The device chain: entry format (plan 3.1), build/sign helpers, and `verifyChain` (3.3).
 *
 * @experimental
 */
import { decodeDidKey } from '../did-key';
import { fail } from './errors';
import { b64uBytes, b64uEncode, hashBytes, jcs, objectHash, sameMembers, signedBytes, sha256Hash } from './encoding';
import { signEd25519, verifyEd25519, keyIdOf } from './keys';
import { type CheckKey, type CheckProof, validateCheckKey, validateCheckProof, verifyCheck } from './checks';
import { b64uDecode } from './encoding';

/** @experimental */
export const ENTRY_TYP = 'suveren-chain-entry';
/** Most active devices a chain may have (3.3). @experimental */
export const MAX_ACTIVE_DEVICES = 5;

/** @experimental */
export type ChainOp = 'genesis' | 'add' | 'remove' | 'set' | 'reset' | 'rotate-root';
const OPS: readonly string[] = ['genesis', 'add', 'remove', 'set', 'reset', 'rotate-root'];

/** @experimental */
export interface DeviceRecord {
  key_id: string;
  sign_pub: string;
  read_pub: string;
  kind: 'gateway' | 'approve-app';
  label: string;
  keystore: 'platform' | 'software';
  check: CheckKey | null;
}

/** @experimental */
export interface ChainEntry {
  typ: typeof ENTRY_TYP;
  v: 1;
  root_did: string;
  seq: number;
  prev: string | null;
  op: ChainOp;
  device: DeviceRecord | null;
  target: string | null;
  check: CheckKey | null;
  new_root: string | null;
  ext: Record<string, unknown> | null;
  created_at: number;
  signer: string;
  sigs: { by: string; sig: string }[];
  checks: { by: string; check: CheckProof }[];
}

/** @experimental */
export interface DeviceState extends DeviceRecord {
  added_seq: number;
  removed_seq: number | null;
  /** The check key in force from each seq on (first element: the key it was admitted with). */
  check_history: { seq: number; check: CheckKey | null }[];
}

/** Result of a successful `verifyChain`. @experimental */
export interface ChainState {
  /** The expected (first) root DID. */
  root_did: string;
  /** Base64url of the root public key in force at the head (after any `rotate-root`). */
  root_pub: string;
  head: { seq: number; hash: string };
  /** Entry hash of every entry, by seq. */
  hashes: string[];
  /** Every device that ever appeared, active or removed. */
  devices: Record<string, DeviceState>;
}

/** @experimental */
export interface StoredHead {
  seq: number;
  hash: string;
}

// ---------------------------------------------------------------------------
// shape validation
// ---------------------------------------------------------------------------

function isObj(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}
function exact(o: Record<string, unknown>, keys: string[], what: string): void {
  if (!sameMembers(o, keys)) fail('MALFORMED', `${what}: members must be exactly ${keys.join(', ')}`);
}
function isInt(x: unknown): x is number {
  return typeof x === 'number' && Number.isSafeInteger(x) && x >= 0;
}

/** Device label rule (3.1): 1-64 characters, NFC, no control characters. @experimental */
export function isValidLabel(label: unknown): label is string {
  if (typeof label !== 'string') return false;
  const n = Array.from(label).length;
  if (n < 1 || n > 64) return false;
  if (label.normalize('NFC') !== label) return false;
  // no control (Cc), format (Cf: zero-width, bidi controls, BOM, tags), line or paragraph separators
  return !/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(label);
}

/** Validate the device record of an entry. Throws MALFORMED. @experimental */
export function validateDevice(d: unknown): DeviceRecord {
  if (!isObj(d)) return fail('MALFORMED', 'device must be an object');
  exact(d, ['key_id', 'sign_pub', 'read_pub', 'kind', 'label', 'keystore', 'check'], 'device');
  b64uBytes(d.key_id, 32, 'device.key_id');
  b64uBytes(d.sign_pub, 32, 'device.sign_pub');
  b64uBytes(d.read_pub, 32, 'device.read_pub');
  if (d.read_pub === d.sign_pub) return fail('MALFORMED', 'device.read_pub must differ from device.sign_pub');
  if (d.kind !== 'gateway' && d.kind !== 'approve-app') return fail('MALFORMED', 'device.kind');
  if (d.keystore !== 'platform' && d.keystore !== 'software') return fail('MALFORMED', 'device.keystore');
  if (!isValidLabel(d.label)) return fail('MALFORMED', 'device.label');
  return {
    key_id: d.key_id as string,
    sign_pub: d.sign_pub as string,
    read_pub: d.read_pub as string,
    kind: d.kind,
    label: d.label,
    keystore: d.keystore,
    check: d.check === null ? null : validateCheckKey(d.check),
  };
}

/** Upper bound for one proof string (a WebAuthn assertion is well under 2 KB). */
const MAX_PROOF_STRING = 4096;

/** A proof is an object of at most 3 string members, each at most 4096 characters. */
function validateProofShape(p: unknown): void {
  if (!isObj(p)) return fail('MALFORMED', 'checks.check');
  const keys = Object.keys(p);
  if (keys.length < 1 || keys.length > 3) return fail('MALFORMED', 'checks.check members');
  for (const k of keys) {
    const v = p[k];
    if (typeof v !== 'string' || v.length > MAX_PROOF_STRING) return fail('MALFORMED', 'checks.check member');
  }
}

/** Validate the exact member set and types of a chain entry. Throws MALFORMED. @experimental */
export function validateEntryShape(e: unknown): ChainEntry {
  if (!isObj(e)) return fail('MALFORMED', 'entry must be an object');
  exact(
    e,
    ['typ', 'v', 'root_did', 'seq', 'prev', 'op', 'device', 'target', 'check', 'new_root', 'ext', 'created_at', 'signer', 'sigs', 'checks'],
    'entry',
  );
  if (e.typ !== ENTRY_TYP) return fail('MALFORMED', 'typ');
  if (e.v !== 1) return fail('MALFORMED', 'v');
  if (typeof e.root_did !== 'string') return fail('MALFORMED', 'root_did');
  if (!isInt(e.seq)) return fail('MALFORMED', 'seq');
  if (e.prev !== null) hashBytes(e.prev);
  if (typeof e.op !== 'string' || !OPS.includes(e.op)) return fail('MALFORMED', 'op');
  if (!isInt(e.created_at)) return fail('MALFORMED', 'created_at');
  if (typeof e.signer !== 'string' || e.signer.length === 0) return fail('MALFORMED', 'signer');
  if (e.ext !== null && !isObj(e.ext)) return fail('MALFORMED', 'ext');

  const op = e.op as ChainOp;
  const hasDevice = op === 'genesis' || op === 'add' || op === 'reset';
  if (hasDevice) validateDevice(e.device);
  else if (e.device !== null) return fail('MALFORMED', 'device must be null for this op');
  const hasTarget = op === 'remove' || op === 'set';
  if (hasTarget) b64uBytes(e.target, 32, 'target');
  else if (e.target !== null) return fail('MALFORMED', 'target must be null for this op');
  if (op === 'set') {
    if (e.check !== null) validateCheckKey(e.check);
  } else if (e.check !== null) return fail('MALFORMED', 'check must be null for this op');
  if (op === 'rotate-root') b64uBytes(e.new_root, 32, 'new_root');
  else if (e.new_root !== null) return fail('MALFORMED', 'new_root must be null for this op');

  if (!Array.isArray(e.sigs) || e.sigs.length < 1 || e.sigs.length > 2) return fail('MALFORMED', 'sigs must hold 1 or 2');
  const sigBy = new Set<string>();
  for (const s of e.sigs) {
    if (!isObj(s)) return fail('MALFORMED', 'sigs element');
    exact(s, ['by', 'sig'], 'sigs element');
    if (typeof s.by !== 'string' || sigBy.has(s.by)) return fail('MALFORMED', 'sigs.by');
    sigBy.add(s.by);
    b64uBytes(s.sig, 64, 'sigs.sig');
  }
  if (!Array.isArray(e.checks) || e.checks.length > 2) return fail('MALFORMED', 'checks must hold 0 to 2');
  const chkBy = new Set<string>();
  for (const c of e.checks) {
    if (!isObj(c)) return fail('MALFORMED', 'checks element');
    exact(c, ['by', 'check'], 'checks element');
    if (typeof c.by !== 'string' || chkBy.has(c.by)) return fail('MALFORMED', 'checks.by');
    chkBy.add(c.by);
    validateProofShape(c.check);
  }
  return e as unknown as ChainEntry;
}

// ---------------------------------------------------------------------------
// build and sign helpers
// ---------------------------------------------------------------------------

/** Fields of `buildEntry`; everything not given is `null` (or `[]`). @experimental */
export type EntryInit = Pick<ChainEntry, 'root_did' | 'seq' | 'prev' | 'op' | 'created_at' | 'signer'> &
  Partial<Pick<ChainEntry, 'device' | 'target' | 'check' | 'new_root' | 'ext'>>;

/** An unsigned entry (empty `sigs` and `checks`). @experimental */
export function buildEntry(init: EntryInit): ChainEntry {
  return {
    typ: ENTRY_TYP,
    v: 1,
    root_did: init.root_did,
    seq: init.seq,
    prev: init.prev,
    op: init.op,
    device: init.device ?? null,
    target: init.target ?? null,
    check: init.check ?? null,
    new_root: init.new_root ?? null,
    ext: init.ext ?? null,
    created_at: init.created_at,
    signer: init.signer,
    sigs: [],
    checks: [],
  };
}

/** The entry hash (`"sha256:" + hex`) over the signed bytes. @experimental */
export function entryHash(entry: ChainEntry): Promise<string> {
  return objectHash(entry);
}

/** The signed bytes of an entry (no `sigs`, no `checks`). @experimental */
export function entrySignedBytes(entry: ChainEntry): Uint8Array {
  return signedBytes(entry);
}

/** Sign an entry with an Ed25519 private seed. `by` is `"root"` or a key id. @experimental */
export async function signEntry(entry: ChainEntry, by: string, privateSeed: Uint8Array): Promise<{ by: string; sig: string }> {
  return { by, sig: b64uEncode(await signEd25519(privateSeed, signedBytes(entry))) };
}

/** A device record for `genesis` / `add` / `reset` with its key id computed. @experimental */
export async function buildDeviceRecord(
  d: Omit<DeviceRecord, 'key_id' | 'check'> & { check?: CheckKey | null },
  signPub: Uint8Array,
): Promise<DeviceRecord> {
  return { ...d, sign_pub: d.sign_pub, key_id: await keyIdOf(signPub), check: d.check ?? null };
}

// ---------------------------------------------------------------------------
// state helpers
// ---------------------------------------------------------------------------

/** True iff `keyId` is active at the head of `state`. @experimental */
export function isActive(state: ChainState, keyId: string): boolean {
  const d = state.devices[keyId];
  return d !== undefined && d.removed_seq === null;
}

/** Active devices at the head. @experimental */
export function activeDevices(state: ChainState): DeviceState[] {
  return Object.values(state.devices).filter((d) => d.removed_seq === null);
}

/** Active devices that hold a check key (the "granting devices"). @experimental */
export function grantingDevices(state: ChainState): DeviceState[] {
  return activeDevices(state).filter((d) => d.check !== null);
}

/** The check key `keyId` had once entry `seq` was applied; null if none or not yet admitted. @experimental */
export function checkKeyAt(state: ChainState, keyId: string, seq: number): CheckKey | null {
  const d = state.devices[keyId];
  if (!d) return null;
  let found: CheckKey | null = null;
  for (const h of d.check_history) if (h.seq <= seq) found = h.check;
  return found;
}

function sameCheckKey(a: CheckKey | null, b: CheckKey | null): boolean {
  return jcs(a ?? null) === jcs(b ?? null);
}
export { sameCheckKey as checkKeysEqual };

// ---------------------------------------------------------------------------
// verifyChain (3.3)
// ---------------------------------------------------------------------------

/** @experimental */
export interface VerifyChainInput {
  /** From the verifier's own storage or a signed mandate; never from the chain itself. */
  expectedRootDid: string;
  entries: unknown[];
  /** The head this verifier accepted before, for the same root DID. */
  storedHead?: StoredHead | null;
}

/** A stored head must be `{ seq: non-negative integer, hash: "sha256:" + 64 lowercase hex }`. */
function validateStoredHead(h: unknown): StoredHead | null {
  if (h === undefined || h === null) return null;
  if (!isObj(h) || !sameMembers(h, ['seq', 'hash'])) return fail('MALFORMED', 'storedHead must be { seq, hash }');
  if (!isInt(h.seq)) return fail('MALFORMED', 'storedHead.seq');
  hashBytes(h.hash);
  return { seq: h.seq, hash: h.hash as string };
}

/** The `by` values an entry may carry in `sigs` and `checks`; anything else is refused. */
function allowedBy(e: ChainEntry): { sigs: Set<string>; checks: Set<string> } {
  const sigs = new Set<string>();
  const checks = new Set<string>();
  const d = e.device;
  if (e.op === 'genesis' || e.op === 'add' || e.op === 'reset') {
    const dev = d as DeviceRecord;
    sigs.add(e.signer).add(dev.key_id);
    if (dev.check) checks.add(dev.key_id);
    if (e.signer !== 'root') checks.add(e.signer);
  } else if (e.op === 'remove') {
    sigs.add(e.signer);
    if (e.signer !== 'root' && e.signer !== e.target) checks.add(e.signer);
  } else if (e.op === 'set') {
    sigs.add(e.signer);
    if (e.signer !== 'root') checks.add(e.signer);
    if (e.check) checks.add(e.target as string);
  } else {
    // rotate-root: the root key and one granting device, which may check
    sigs.add('root');
    for (const s of e.sigs) {
      if (s.by !== 'root') {
        sigs.add(s.by);
        checks.add(s.by);
      }
    }
  }
  return { sigs, checks };
}

/**
 * Verify a chain per plan 3.3. Returns the device state at the head or throws a
 * `DeviceKeysError` with one of: MALFORMED, WRONG_ROOT, BAD_SEQ, BAD_PREV, BAD_OP,
 * BAD_KEY_ID, KEY_REUSED, NO_POSSESSION, NOT_AUTHORISED, CHECK_REQUIRED, BAD_TARGET,
 * NO_GRANTING_DEVICE, TOO_MANY_DEVICES, ROLLBACK, FORK.
 *
 * The caller stores `state.head` after success.
 * @experimental
 */
export async function verifyChain(input: VerifyChainInput): Promise<ChainState> {
  const { expectedRootDid, entries } = input;
  const storedHead = validateStoredHead(input.storedHead);
  let rootPubBytes: Uint8Array;
  try {
    rootPubBytes = decodeDidKey(expectedRootDid);
  } catch {
    return fail('MALFORMED', 'expected root DID is not a key-bearing did:key');
  }
  if (!Array.isArray(entries) || entries.length === 0) {
    if (storedHead) return fail('ROLLBACK', 'no entries');
    return fail('MALFORMED', 'a chain has at least one entry');
  }

  const devices: Record<string, DeviceState> = {};
  const seen = new Set<string>([b64uEncode(rootPubBytes)]);
  let rootPub = b64uEncode(rootPubBytes);
  const hashes: string[] = [];

  for (let i = 0; i < entries.length; i++) {
    const e = validateEntryShape(entries[i]);
    if (e.root_did !== expectedRootDid) return fail('WRONG_ROOT');
    if (e.seq !== i) return fail('BAD_SEQ', `entry ${i} has seq ${e.seq}`);
    if (e.prev !== (i === 0 ? null : hashes[i - 1])) return fail('BAD_PREV');
    if ((e.op === 'genesis') !== (i === 0)) return fail('BAD_OP');

    /** Refuse signatures and checks this entry does not need (nothing unverified rides along). */
    const refuseExtras = (): void => {
      const allowed = allowedBy(e);
      if (e.sigs.some((s) => !allowed.sigs.has(s.by))) fail('MALFORMED', 'a signature this entry does not need');
      if (e.checks.some((c) => !allowed.checks.has(c.by))) fail('MALFORMED', 'a check this entry does not need');
    };
    const bytes = signedBytes(e);
    const h = await sha256Hash(bytes);
    const sigOf = (by: string) => e.sigs.find((s) => s.by === by);
    const chkOf = (by: string) => e.checks.find((c) => c.by === by);
    const verifySig = async (pub: string, by: string): Promise<boolean> => {
      const s = sigOf(by);
      return !!s && (await verifyEd25519(b64uDecode(pub), bytes, b64uDecode(s.sig)));
    };

    /** A granting device: active, check key set, signature and check valid. */
    const evalGranter = async (k: string): Promise<'ok' | 'NOT_AUTHORISED' | 'CHECK_REQUIRED'> => {
      const d = devices[k];
      if (!d || d.removed_seq !== null) return 'NOT_AUTHORISED';
      if (!(await verifySig(d.sign_pub, k))) return 'NOT_AUTHORISED';
      const c = chkOf(k);
      if (!d.check || !c || !(await verifyCheck(d.check, h, c.check))) return 'CHECK_REQUIRED';
      return 'ok';
    };
    const evalAdmitter = async (): Promise<'ok' | 'NOT_AUTHORISED' | 'CHECK_REQUIRED'> => {
      if (e.signer === 'root') return (await verifySig(rootPub, 'root')) ? 'ok' : 'NOT_AUTHORISED';
      return evalGranter(e.signer);
    };

    const hadGranter = Object.values(devices).some((d) => d.removed_seq === null && d.check !== null);

    if (e.op === 'genesis' || e.op === 'add' || e.op === 'reset') {
      const d = e.device as DeviceRecord;
      if (d.key_id !== (await keyIdOf(b64uDecode(d.sign_pub)))) return fail('BAD_KEY_ID');
      if (seen.has(d.key_id) || seen.has(d.sign_pub) || seen.has(d.read_pub)) return fail('KEY_REUSED');
      refuseExtras();
      if (!(await verifySig(d.sign_pub, d.key_id))) return fail('NO_POSSESSION', 'device signature');
      if (d.check) {
        const c = chkOf(d.key_id);
        if (!c || !(await verifyCheck(d.check, h, c.check))) return fail('NO_POSSESSION', 'device check');
      }
      if ((e.op === 'genesis' || e.op === 'reset') && e.signer !== 'root') return fail('NOT_AUTHORISED', 'root must sign');
      const a = await evalAdmitter();
      if (a !== 'ok') return fail(a);
      if (e.op === 'reset') {
        for (const k of Object.keys(devices)) if (devices[k].removed_seq === null) devices[k].removed_seq = i;
      }
      devices[d.key_id] = { ...d, added_seq: i, removed_seq: null, check_history: [{ seq: i, check: d.check }] };
      seen.add(d.key_id);
      seen.add(d.sign_pub);
      seen.add(d.read_pub);
    } else if (e.op === 'remove') {
      refuseExtras();
      const t = e.target as string;
      const td = devices[t];
      if (!td || td.removed_seq !== null) return fail('BAD_TARGET');
      const selfOk = e.signer === t && (await verifySig(td.sign_pub, t));
      if (!selfOk) {
        const a = await evalAdmitter();
        if (a !== 'ok') return fail(a);
      }
      td.removed_seq = i;
    } else if (e.op === 'set') {
      refuseExtras();
      const t = e.target as string;
      const td = devices[t];
      if (!td || td.removed_seq !== null) return fail('BAD_TARGET');
      const a = await evalAdmitter();
      if (a !== 'ok') return fail(a);
      if (e.check) {
        const c = chkOf(t);
        if (!c || !(await verifyCheck(e.check, h, c.check))) return fail('NO_POSSESSION', 'new check key');
      }
      td.check = e.check;
      td.check_history.push({ seq: i, check: e.check });
    } else {
      // rotate-root
      refuseExtras();
      if (e.signer !== 'root' || !(await verifySig(rootPub, 'root'))) return fail('NOT_AUTHORISED', 'root must sign');
      const others = e.sigs.filter((s) => s.by !== 'root');
      if (others.length !== 1) return fail('NOT_AUTHORISED', 'one granting device must co-sign');
      const g = await evalGranter(others[0].by);
      if (g !== 'ok') return fail(g);
      const nr = e.new_root as string;
      if (seen.has(nr) || nr === rootPub) return fail('KEY_REUSED');
      seen.add(rootPub);
      seen.add(nr);
      rootPub = nr; // in force from entry i + 1
    }

    if (e.op !== 'reset' && hadGranter && !Object.values(devices).some((d) => d.removed_seq === null && d.check !== null)) {
      return fail('NO_GRANTING_DEVICE');
    }
    if (Object.values(devices).filter((d) => d.removed_seq === null).length > MAX_ACTIVE_DEVICES) {
      return fail('TOO_MANY_DEVICES');
    }
    hashes.push(h);
  }

  if (storedHead) {
    if (entries.length <= storedHead.seq) return fail('ROLLBACK');
    if (hashes[storedHead.seq] !== storedHead.hash) return fail('FORK');
  }

  return {
    root_did: expectedRootDid,
    root_pub: rootPub,
    head: { seq: entries.length - 1, hash: hashes[hashes.length - 1] },
    hashes,
    devices,
  };
}

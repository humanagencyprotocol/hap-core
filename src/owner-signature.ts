/**
 * Owner Signatures (v0.7) — the `HAP-mandate-projection` object, the
 * `HAP-approval` object, and their verification.
 *
 * Renamed from `mandate.ts` (protocol.md → *Migration from v0.6*: the
 * owner-signed projection's `typ` moves from `"HAP-mandate"` to
 * `"HAP-mandate-projection"`, disambiguating it from the AS-signed mandate
 * itself, which now legitimately owns the name `"HAP-mandate"`).
 *
 * The human signs BEFORE the AS does, so they cannot sign the finished
 * mandate (`mandate_id`/`issued_at` do not exist yet). They sign a mandate
 * PROJECTION: a canonical object every field of which is known at approval
 * time and reconstructible from the finished mandate — so a verifier
 * rebuilds it from the mandate it already holds and checks the signature
 * with the key carried in the owner's DID. No side channel, no second
 * fetch, no key directory. See protocol.md → "Owner Signatures".
 *
 * Verification here requires NO trust in the AS. What it cannot do is tell
 * the verifier WHOSE key signed — confirming the DID belongs to the
 * expected person is the out-of-band step (protocol.md → "Verification
 * procedure" step 5), and it is the honest cost of cold verification.
 */

import * as ed from '@noble/ed25519';
import type { Mandate, MandatePayload, MandateOwnerEntry, OwnerSignatureBinding, ProfileOwnerSignatureFloor } from './types';
import { canonicalize } from './canonicalize';
import { decodeDidKey } from './did-key';
import { toBase64Url, fromBase64Url } from './base64url';
import type { HapErrorCode } from './errors';

/** The object the owner signs — a canonical projection of the mandate.
 * Field absence is defined, not incidental (protocol.md → *The signed
 * object: HAP-mandate-projection*): each conditional field is included
 * exactly when the mandate carries it and omitted otherwise. */
export interface MandateProjection {
  typ: 'HAP-mandate-projection';
  /** Projection/canonicalization version. A verifier MUST pin it. */
  version: '0.7';
  profile_id: string;
  /** Covered deliberately: the owner signs the profile's BYTES, not only its id. */
  profile_hash: string;
  /** The signing owner's own DID. MUST equal the carrying mandate's `mandate_owners[0].did`. */
  owner_did: string;
  bounds_hash: string;
  scope_hash: string;
  execution_context_hash: string;
  gate_content_hashes: Record<string, string>;
  /** Included iff the mandate carries one — binds ciphertext AND the
   * frozen approver set, the swap this mechanism exists to stop. */
  intent_disclosure_hash?: string;
  commitment_mode: string;
  /** Included together, iff `commitment_mode === "review_above_cap"`. */
  above_cap_caps?: Record<string, number>;
  above_cap_approvers?: string[];
  /** Included iff the mandate narrows the profile's disclose_fields. */
  disclose_fields?: string[];
  /** The replay defence: the human signs how long the authority lives. */
  expires_at: number;
  nonce: string;
}

/** Per-action approval, signed by the owner in `review` mode. Signing a
 * `reject` matters as much as a `commit`: a rejection the AS can discard is
 * a rejection that never happened. */
export interface ApprovalObject {
  typ: 'HAP-approval';
  version: '0.7';
  proposal_id: string;
  /** Renamed from `attestation_id` in v0.7. */
  mandate_id: string;
  decision: 'commit' | 'reject';
  /** What was approved: the ticket's contentHash where the profile binds
   * content; otherwise sha256 over the JCS of the proposal's argument set. */
  content_hash: string;
  decided_at: number;
  nonce: string;
}

/** Renamed from `MandateError` in v0.7 — carries a canonical {@link HapErrorCode}. */
export class OwnerSignatureError extends Error {
  constructor(public code: HapErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = 'OwnerSignatureError';
  }
}

/**
 * Rebuild the projection a given `mandate_owners` entry signed, from the
 * mandate's own signed fields. Field absence is defined, not incidental:
 * `intent_disclosure_hash`, `above_cap_caps`/`above_cap_approvers`, and
 * `disclose_fields` are included iff the mandate carries them.
 */
export function buildMandateProjection(
  payload: MandatePayload,
  entry: Pick<MandateOwnerEntry, 'did' | 'nonce'>,
): MandateProjection {
  const {
    profile_id, profile_hash, bounds_hash, scope_hash, execution_context_hash,
    gate_content_hashes, commitment_mode, expires_at,
  } = payload;
  if (!profile_hash || !bounds_hash || !scope_hash || !commitment_mode) {
    throw new OwnerSignatureError(
      'MALFORMED_MANDATE',
      'mandate projection requires profile_hash, bounds_hash, scope_hash and commitment_mode',
    );
  }
  const projection: MandateProjection = {
    typ: 'HAP-mandate-projection',
    version: '0.7',
    profile_id,
    profile_hash,
    owner_did: entry.did,
    bounds_hash,
    scope_hash,
    execution_context_hash,
    gate_content_hashes,
    commitment_mode,
    expires_at,
    nonce: entry.nonce!,
  };
  if (payload.intent_disclosure_hash !== undefined) {
    projection.intent_disclosure_hash = payload.intent_disclosure_hash;
  }
  if (payload.commitment_mode === 'review_above_cap') {
    projection.above_cap_caps = payload.above_cap_caps;
    projection.above_cap_approvers = payload.above_cap_approvers;
  }
  if (payload.disclose_fields !== undefined) {
    projection.disclose_fields = payload.disclose_fields;
  }
  return projection;
}

/** The exact bytes an owner signs: RFC 8785 (JCS) canonical UTF-8. Renamed
 * from `mandateSigningBytes` in v0.7. */
export function projectionSigningBytes(projection: MandateProjection): Uint8Array {
  return new TextEncoder().encode(canonicalize(projection));
}

/** The exact bytes an owner signs for a per-action approval. */
export function approvalSigningBytes(approval: ApprovalObject): Uint8Array {
  return new TextEncoder().encode(canonicalize(approval));
}

/**
 * Sign a mandate projection with a raw Ed25519 private key — the `raw`
 * binding: tests and CI only, no custody claim. WebAuthn (`webauthn`) and
 * wallet (`eudi`) bindings sign the same bytes through their own custody;
 * they are implemented by the platforms that hold those keys, not here.
 */
export async function signMandateProjection(
  projection: MandateProjection,
  privateKey: Uint8Array,
): Promise<string> {
  return toBase64Url(await ed.signAsync(projectionSigningBytes(projection), privateKey));
}

/** Sign an approval object with a raw Ed25519 private key (`raw` binding). */
export async function signApproval(approval: ApprovalObject, privateKey: Uint8Array): Promise<string> {
  return toBase64Url(await ed.signAsync(approvalSigningBytes(approval), privateKey));
}

/**
 * Verify ONE `mandate_owners` entry against the mandate that carries it.
 *
 * Steps (protocol.md → "Verification procedure", step 4 of 6): the entry
 * names this mandate's sole owner, its signing DID is key-bearing,
 * projection reconstruction, Ed25519 over JCS bytes. The DID is
 * authoritative over `alg` — a disagreement is `OWNER_SIGNATURE_INVALID`,
 * never a fallback to the claimed algorithm.
 *
 * What this deliberately does NOT verify: that the DID belongs to the
 * person the verifier expects (out-of-band, step 5) and the AS's own
 * signature over the mandate (`verifyMandateSignature`, step 1).
 */
export async function verifyOwnerSignature(mandate: Mandate, entry: MandateOwnerEntry): Promise<void> {
  const owners = mandate.payload.mandate_owners ?? [];
  if (!owners.some((o) => o.did === entry.did)) {
    throw new OwnerSignatureError('OWNER_SIGNATURE_INVALID', `signing DID ${entry.did} is not this mandate's mandate_owners`);
  }
  if (entry.alg !== undefined && entry.alg !== 'EdDSA') {
    // The only key type a did:key carries in this protocol version is Ed25519;
    // an entry claiming otherwise disagrees with its own DID.
    throw new OwnerSignatureError('OWNER_SIGNATURE_INVALID', `alg ${entry.alg} disagrees with the DID's key type (DID is authoritative)`);
  }
  if (!entry.signature || !entry.nonce) {
    throw new OwnerSignatureError('OWNER_SIGNATURE_INVALID', `mandate_owners entry for ${entry.did} carries no signature to verify`);
  }

  let publicKey: Uint8Array;
  try {
    publicKey = decodeDidKey(entry.did);
  } catch (err) {
    throw new OwnerSignatureError('OWNER_SIGNATURE_INVALID', (err as Error).message);
  }

  const projection = buildMandateProjection(mandate.payload, entry);
  const ok = await ed
    .verifyAsync(fromBase64Url(entry.signature), projectionSigningBytes(projection), publicKey)
    .catch(() => false);
  if (!ok) {
    throw new OwnerSignatureError('OWNER_SIGNATURE_INVALID', `owner signature by ${entry.did} does not verify`);
  }
}

/** Verify every co-signing `mandate_owners` entry a mandate carries (i.e.
 * every entry that carries a signature). Resolves to the verified entries;
 * a mandate with none resolves to `[]` — nothing to check, nothing claimed. */
export async function verifyOwnerSignatures(mandate: Mandate): Promise<MandateOwnerEntry[]> {
  const entries = (mandate.payload.mandate_owners ?? []).filter((e) => e.signature !== undefined);
  for (const entry of entries) {
    await verifyOwnerSignature(mandate, entry);
  }
  return entries;
}

/** Verify an approval signature against a signer's key-bearing DID. */
export async function verifyApproval(approval: ApprovalObject, signature: string, signerDid: string): Promise<void> {
  let publicKey: Uint8Array;
  try {
    publicKey = decodeDidKey(signerDid);
  } catch (err) {
    throw new OwnerSignatureError('OWNER_SIGNATURE_INVALID', (err as Error).message);
  }
  const ok = await ed.verifyAsync(fromBase64Url(signature), approvalSigningBytes(approval), publicKey).catch(() => false);
  if (!ok) {
    throw new OwnerSignatureError('APPROVAL_SIGNATURE_INVALID', `approval signature by ${signerDid} does not verify`);
  }
}

/** Signature-assurance ranking for `OwnerSignatureBinding`, weakest first —
 * protocol.md → *Owner Signatures* → "binding" table ordering (raw < webauthn < eudi). */
const BINDING_RANK: Record<OwnerSignatureBinding, number> = { raw: 0, webauthn: 1, eudi: 2 };

/**
 * Enforce a profile's `ownerSignature` floor (protocol.md → *Owner
 * Signatures* → "Where the requirement lives" — the profile-floor tier,
 * checkable without trusting the AS: `profile_id`/`profile_hash` are in the
 * signed payload AND in the owner-signed projection).
 *
 * An unknown `binding` value is treated as rank 0 (weakest) rather than
 * rejected outright — "an AS MUST NOT reject a mandate_owners entry solely
 * because it does not recognize its binding value" extends naturally to a
 * verifier ranking it, since crediting an unrecognized binding with
 * unearned strength would be the more dangerous failure mode.
 *
 * @throws OwnerSignatureError `OWNER_SIGNATURE_REQUIRED` when the floor is
 * unmet — "MUST fail, not warn" (protocol.md, same section).
 */
export function checkOwnerSignatureRequirement(
  payload: MandatePayload,
  floor: ProfileOwnerSignatureFloor | undefined,
): void {
  if (!floor?.required) return;
  const entry = payload.mandate_owners[0];
  const signed = entry?.signature !== undefined && entry?.binding !== undefined;
  if (!signed) {
    throw new OwnerSignatureError(
      'OWNER_SIGNATURE_REQUIRED',
      'this profile requires an owner signature and mandate_owners[0] carries none',
    );
  }
  const minRank = floor.minBinding ? BINDING_RANK[floor.minBinding] : 0;
  const haveRank = BINDING_RANK[entry!.binding as OwnerSignatureBinding] ?? 0;
  if (haveRank < minRank) {
    throw new OwnerSignatureError(
      'OWNER_SIGNATURE_REQUIRED',
      `this profile requires binding >= "${floor.minBinding}", mandate_owners[0] carries "${entry!.binding}"`,
    );
  }
}

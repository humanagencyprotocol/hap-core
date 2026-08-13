/**
 * Owner Mandate Signatures (HAP v0.6) — the `HAP-mandate` projection, the
 * `HAP-approval` object, and their verification.
 *
 * The human signs BEFORE the AS does, so they cannot sign the finished
 * attestation (`attestation_id`/`issued_at` do not exist yet). They sign a
 * mandate PROJECTION: a canonical object every field of which is known at
 * approval time and reconstructible from the finished attestation — so a
 * verifier rebuilds it from the attestation it already holds and checks the
 * signature with the key carried in the owner's DID. No side channel, no
 * second fetch, no key directory. See protocol.md → "Owner Mandate Signatures".
 *
 * Verification here requires NO trust in the AS. What it cannot do is tell the
 * verifier WHOSE key signed — confirming the DID belongs to the expected
 * person is the out-of-band step (protocol.md → "Identity DIDs vs signing
 * DIDs"), and it is the honest cost of cold verification.
 */

import * as ed from '@noble/ed25519';
import type { Attestation, AttestationPayload, OwnerMandate } from './types';
import { canonicalize } from './canonicalize';
import { decodeDidKey } from './did-key';

/** The object the owner signs — a canonical projection of the mandate. */
export interface MandateProjection {
  typ: 'HAP-mandate';
  /** Projection/canonicalization version. A verifier MUST pin it. */
  version: '0.6';
  profile_id: string;
  /** The signing owner's own DID. MUST be a member of `resolved_owners`. */
  owner_did: string;
  bounds_hash: string;
  context_hash: string;
  execution_context_hash: string;
  gate_content_hashes: Record<string, string>;
  /** Included iff the attestation carries one — binds ciphertext AND the
   * frozen approver set, the swap this mechanism exists to stop. */
  intent_disclosure_hash?: string;
  commitment_mode: string;
  /** The replay defence: the human signs how long the authority lives. */
  expires_at: number;
  nonce: string;
}

/** Per-action approval, signed by the owner in `review` mode. Signing a
 * `reject` matters as much as a `commit`: a rejection the AS can discard is a
 * rejection that never happened. */
export interface ApprovalObject {
  typ: 'HAP-approval';
  version: '0.6';
  proposal_id: string;
  attestation_id: string;
  decision: 'commit' | 'reject';
  /** What was approved: the receipt's contentHash where the profile binds
   * content; otherwise sha256 over the JCS of the proposal's argument set. */
  content_hash: string;
  decided_at: number;
  nonce: string;
}

export class MandateError extends Error {
  constructor(
    public code:
      | 'MANDATE_SIGNATURE_INVALID'
      | 'APPROVAL_SIGNATURE_INVALID'
      | 'NOT_KEY_BEARING'
      | 'OWNER_NOT_RESOLVED'
      | 'MALFORMED_ATTESTATION',
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = 'MandateError';
  }
}

/**
 * Rebuild the projection a given `owner_mandates` entry signed, from the
 * attestation's own signed fields. Field absence is defined, not incidental:
 * `intent_disclosure_hash` is included iff the attestation carries one.
 */
export function buildMandateProjection(
  payload: AttestationPayload,
  entry: Pick<OwnerMandate, 'did' | 'nonce'>,
): MandateProjection {
  const { profile_id, bounds_hash, context_hash, execution_context_hash, gate_content_hashes, commitment_mode, expires_at } = payload;
  if (!bounds_hash || !context_hash || !commitment_mode) {
    throw new MandateError('MALFORMED_ATTESTATION', 'mandate projection requires bounds_hash, context_hash and commitment_mode');
  }
  const projection: MandateProjection = {
    typ: 'HAP-mandate',
    version: '0.6',
    profile_id,
    owner_did: entry.did,
    bounds_hash,
    context_hash,
    execution_context_hash,
    gate_content_hashes,
    commitment_mode,
    expires_at,
    nonce: entry.nonce,
  };
  if (payload.intent_disclosure_hash !== undefined) {
    projection.intent_disclosure_hash = payload.intent_disclosure_hash;
  }
  return projection;
}

/** The exact bytes an owner signs: RFC 8785 (JCS) canonical UTF-8. */
export function mandateSigningBytes(projection: MandateProjection): Uint8Array {
  return new TextEncoder().encode(canonicalize(projection));
}

/** The exact bytes an owner signs for a per-action approval. */
export function approvalSigningBytes(approval: ApprovalObject): Uint8Array {
  return new TextEncoder().encode(canonicalize(approval));
}

function base64urlToBytes(s: string): Uint8Array {
  const base64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const padding = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
  return new Uint8Array(Buffer.from(base64 + padding, 'base64'));
}

function bytesToBase64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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
  const sig = await ed.signAsync(mandateSigningBytes(projection), privateKey);
  return bytesToBase64url(sig);
}

/** Sign an approval object with a raw Ed25519 private key (`raw` binding). */
export async function signApproval(approval: ApprovalObject, privateKey: Uint8Array): Promise<string> {
  const sig = await ed.signAsync(approvalSigningBytes(approval), privateKey);
  return bytesToBase64url(sig);
}

/**
 * Verify ONE `owner_mandates` entry against the attestation that carries it.
 *
 * Steps (protocol.md → "Verification procedure", steps 4 of 6): membership in
 * `resolved_owners`, key-bearing DID, projection reconstruction, Ed25519 over
 * JCS bytes. The DID is authoritative over `alg` — a disagreement is
 * MANDATE_SIGNATURE_INVALID, never a fallback to the claimed algorithm.
 *
 * What this deliberately does NOT verify: that the DID belongs to the person
 * the verifier expects (out-of-band, step 5) and the AS's own signature over
 * the attestation (verifyAttestationSignature, step 1).
 */
export async function verifyOwnerMandate(attestation: Attestation, entry: OwnerMandate): Promise<void> {
  const owners = attestation.payload.resolved_owners ?? [];
  if (!owners.includes(entry.did)) {
    throw new MandateError('OWNER_NOT_RESOLVED', `signing DID ${entry.did} is not in resolved_owners`);
  }
  if (entry.alg !== 'EdDSA') {
    // The only key type a did:key carries in this protocol version is Ed25519;
    // an entry claiming otherwise disagrees with its own DID.
    throw new MandateError('MANDATE_SIGNATURE_INVALID', `alg ${entry.alg} disagrees with the DID's key type (DID is authoritative)`);
  }
  let publicKey: Uint8Array;
  try {
    publicKey = decodeDidKey(entry.did);
  } catch (err) {
    throw new MandateError('NOT_KEY_BEARING', (err as Error).message);
  }

  const projection = buildMandateProjection(attestation.payload, entry);
  const ok = await ed.verifyAsync(base64urlToBytes(entry.signature), mandateSigningBytes(projection), publicKey);
  if (!ok) {
    throw new MandateError('MANDATE_SIGNATURE_INVALID', `owner mandate signature by ${entry.did} does not verify`);
  }
}

/** Verify every `owner_mandates` entry an attestation carries. Resolves to the
 * verified entries; an attestation with none resolves to `[]` (the v0.5
 * posture — nothing to check, and nothing claimed). */
export async function verifyOwnerMandates(attestation: Attestation): Promise<OwnerMandate[]> {
  const entries = attestation.payload.owner_mandates ?? [];
  for (const entry of entries) {
    await verifyOwnerMandate(attestation, entry);
  }
  return entries;
}

/** Verify an approval signature against a signer's key-bearing DID. */
export async function verifyApproval(approval: ApprovalObject, signature: string, signerDid: string): Promise<void> {
  let publicKey: Uint8Array;
  try {
    publicKey = decodeDidKey(signerDid);
  } catch (err) {
    throw new MandateError('NOT_KEY_BEARING', (err as Error).message);
  }
  const ok = await ed.verifyAsync(base64urlToBytes(signature), approvalSigningBytes(approval), publicKey);
  if (!ok) {
    throw new MandateError('APPROVAL_SIGNATURE_INVALID', `approval signature by ${signerDid} does not verify`);
  }
}

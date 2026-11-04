/**
 * Mandate tickets — the wire type, signing, holder-side verification, and
 * (v0.8) the Gatekeeper's check that a ticket answers the request it sent.
 *
 * Ticket payloads are camelCase on the wire (unlike the snake_case mandate
 * payload) — a shipped inconsistency the spec documents rather than breaks
 * (protocol.md → *Migration from v0.6*, "Unchanged on purpose").
 */

import { HapError } from './errors';
import * as ed from '@noble/ed25519';
import type { ContentBinding, Mandate, Subject } from './types';
import { canonicalize } from './canonicalize';
import { toBase64Url, fromBase64Url } from './base64url';
import { decodeDidKey } from './did-key';
import { assertSupportedVersion } from './versions';
import { verifyApproval, OwnerSignatureError, type ApprovalObject } from './owner-signature';

/** Clock-skew tolerance and freshness window (Mandate rule 9; Ticket rule 4). */
export const TICKET_FRESHNESS_SECONDS = 300;

/** One verified approval carried by a ticket. */
export interface ApprovalSignatureEntry {
  alg: 'EdDSA' | 'ES256';
  signature: string;
  nonce: string;
  decided_at: number;
}

/** v0.8 — an above-cap approver's entry in `approvalSignatures`. */
export interface ApproverSignatureEntry extends ApprovalSignatureEntry {
  approver_did: string;
}

/** Signed mandate ticket — protocol.md → *Ticket Payload Schema*. */
export interface TicketPayload {
  id: string;
  /** The mandate this ticket was issued under (new in v0.7). Audit and
   * chain-of-custody only — `boundsHash` remains the AS's lookup key. */
  mandateId: string;
  groupId: string | null;
  userId?: string;
  boundsHash: string;
  profileId: string;
  /** Downstream tool name. Audit metadata only — never a dispatch key. */
  action: string;
  /** Semantic category — drives cumulative bucketing and bounds dispatch. */
  actionType: string;
  executionContext: Record<string, unknown>;
  cumulativeState?: Record<string, unknown>;
  /** The mandate's plaintext bounds object, exactly as the AS enforced them
   * for this ticket (new in v0.7 — required). */
  limits: Record<string, unknown>;
  /** Protocol version of the ticket — the version of the mandate it was
   * issued under (new in v0.7). */
  version: string;
  /** The AS DID, as in the mandate (new in v0.7). */
  issuer: string;
  timestamp: number;
  /** v0.8 — copied verbatim from the request, so the ticket names the single
   * request it answers. Present exactly when the request carried one
   * (synchronous path). */
  idempotencyKey?: string;
  /** Hash of the bound content, computed by the Gatekeeper, copied
   * verbatim by the AS. The AS never sees the content. */
  contentHash?: string;
  /** The binding declaration echoed into the signed ticket, so a
   * verifier knows exactly what `contentHash` covers. */
  contentBinding?: Pick<ContentBinding, 'version' | 'kind' | 'fields' | 'required_fields' | 'appliesTo'>;
  /** Disclosed subset of the mandate's identity overlay. */
  subjects?: Subject[];
  /** Review path: the proposal this ticket executed. */
  proposalId?: string;
  /** v0.8, review path: the proposal's content fingerprint, copied verbatim
   * from the proposal the AS compared it against. */
  proposalContentHash?: string;
  /** Review path: the owner's HAP-approval signature for the executed
   * proposal, as the object itself — never a hash of it, which a holder
   * could check only by asking the AS. */
  approvalSignature?: ApprovalSignatureEntry;
  /** v0.8, above-cap path: one entry per approver signature the AS verified. */
  approvalSignatures?: ApproverSignatureEntry[];
  /** Ed25519 over the JCS-canonical payload (this field excluded), base64url. */
  signature: string;
}

/**
 * Sign a ticket payload with the Authority Server's Ed25519 private key —
 * the same key used for mandates.
 */
export async function signTicket(
  payload: Omit<TicketPayload, 'signature'>,
  privateKey: Uint8Array,
): Promise<TicketPayload> {
  const signature = toBase64Url(await ed.signAsync(new TextEncoder().encode(canonicalize(payload)), privateKey));
  return { ...payload, signature };
}

/**
 * The structural rules that keep a ticket, a projection and a mandate
 * payload apart (protocol.md → *Ticket Payload Schema*, "Signature"): a
 * ticket verifier MUST require `id`, `mandateId`, `actionType`, `timestamp`
 * and `issuer`, MUST reject an object carrying `typ` (a projection can never
 * be accepted as a ticket), and MUST reject `mandate_id` or `issued_at`.
 * @throws HapError `INVALID_SIGNATURE`
 */
export function assertTicketShape(ticket: Record<string, unknown>): void {
  if ('typ' in ticket) {
    throw new HapError('INVALID_SIGNATURE', 'a ticket carries no typ — an object with one is a projection, not a ticket');
  }
  if ('mandate_id' in ticket || 'issued_at' in ticket) {
    throw new HapError('INVALID_SIGNATURE', 'a ticket carries no mandate_id or issued_at — this object is a mandate payload');
  }
  for (const required of ['id', 'mandateId', 'actionType', 'timestamp', 'issuer'] as const) {
    if (ticket[required] === undefined) {
      throw new HapError('INVALID_SIGNATURE', `ticket is missing required field ${required}`);
    }
  }
}

/**
 * Verify a ticket's AS signature: strip `signature`, JCS-canonicalize the
 * rest, Ed25519-verify against the key resolved from `issuer` — never
 * against a key offered alongside the ticket (protocol.md → *Ticket
 * Verification* step 1). This is holder-side verification — it needs the
 * COMPLETE ticket; a redacted public view cannot be re-verified this way
 * (see `ticket-projection.ts` for the view that can).
 *
 * Content is checked separately: where `contentHash` is present, recompute
 * it from the held artifact via the content-binding module and compare.
 *
 * @param opts.trustedIssuers When supplied, an `issuer` not in this list is
 * rejected before any cryptography runs.
 * @throws HapError `INVALID_SIGNATURE` when verification fails;
 * `VERSION_UNSUPPORTED` for a version this package cannot read.
 */
export async function verifyTicketSignature(
  ticket: TicketPayload,
  opts?: { trustedIssuers?: readonly string[] },
): Promise<void> {
  assertTicketShape(ticket as unknown as Record<string, unknown>);
  assertSupportedVersion(ticket.version, 'ticket');
  const { signature, ...unsigned } = ticket;
  if (!signature) {
    throw new HapError('INVALID_SIGNATURE', 'ticket carries no signature');
  }
  if (opts?.trustedIssuers && !opts.trustedIssuers.includes(ticket.issuer)) {
    throw new HapError('INVALID_SIGNATURE', `issuer ${JSON.stringify(ticket.issuer)} is not a trusted Authority Server`);
  }

  let publicKey: Uint8Array;
  try {
    publicKey = decodeDidKey(ticket.issuer);
  } catch (err) {
    throw new HapError('INVALID_SIGNATURE', `cannot resolve a key from issuer ${JSON.stringify(ticket.issuer)}: ${(err as Error).message}`);
  }

  const bytes = new TextEncoder().encode(canonicalize(unsigned));
  let sigBytes: Uint8Array;
  try {
    sigBytes = fromBase64Url(signature);
  } catch (err) {
    throw new HapError('INVALID_SIGNATURE', `${(err as Error).message}`);
  }

  const ok = await ed.verifyAsync(sigBytes, bytes, publicKey).catch(() => false);
  if (!ok) {
    throw new HapError('INVALID_SIGNATURE', 'ticket signature verification failed');
  }
}

// ─── The request a ticket answers (v0.8) ─────────────────────────────────────

/** The fields of a ticket request a Gatekeeper compares with the ticket it
 * receives (protocol.md → *Ticket Payload Schema*, rule 4). */
export interface TicketRequestEcho {
  profileId: string;
  actionType: string;
  boundsHash: string;
  executionContext: Record<string, unknown>;
  mandateId?: string;
  idempotencyKey?: string;
  contentHash?: string;
  contentBinding?: TicketPayload['contentBinding'];
  proposalId?: string;
  proposalContentHash?: string;
}

const ECHOED_FIELDS = [
  'profileId', 'actionType', 'boundsHash', 'executionContext',
  'contentHash', 'contentBinding', 'proposalId', 'proposalContentHash',
] as const;

/**
 * v0.8 — the Gatekeeper's half of "a ticket names the request it answers":
 * every echoed field equals what was sent, the `idempotencyKey` it sent is
 * the one the ticket carries, `mandateId` and `version` are the verified
 * mandate's, and a fresh ticket's `timestamp` lies within
 * {@link TICKET_FRESHNESS_SECONDS}. A replay (`idempotent: true`, unsigned)
 * is exempt from freshness only; the caller passes `replay: true` and then
 * applies *One execution per ticket*, rule 2.
 *
 * Does NOT verify the signature — call {@link verifyTicketSignature} first.
 * @throws HapError `TICKET_REQUEST_MISMATCH`
 */
export function verifyTicketAgainstRequest(
  ticket: TicketPayload,
  request: TicketRequestEcho,
  opts: { mandate?: Mandate; now?: number; replay?: boolean } = {},
): void {
  for (const field of ECHOED_FIELDS) {
    const sent = request[field];
    const got = ticket[field];
    if (sent === undefined && got === undefined) continue;
    if (sent === undefined || got === undefined || canonicalize(sent) !== canonicalize(got)) {
      throw new HapError('TICKET_REQUEST_MISMATCH', `ticket ${field} differs from the request's`);
    }
  }
  if (request.idempotencyKey !== undefined && ticket.idempotencyKey !== request.idempotencyKey) {
    throw new HapError(
      'TICKET_REQUEST_MISMATCH',
      ticket.idempotencyKey === undefined
        ? 'ticket carries no idempotencyKey although the request sent one'
        : 'ticket idempotencyKey differs from the one the request sent',
    );
  }
  const expectedMandateId = opts.mandate?.payload.mandate_id ?? request.mandateId;
  if (expectedMandateId !== undefined && ticket.mandateId !== expectedMandateId) {
    throw new HapError('TICKET_REQUEST_MISMATCH', `ticket mandateId ${ticket.mandateId} is not the mandate this request was made under`);
  }
  if (opts.mandate && ticket.version !== opts.mandate.payload.version) {
    throw new HapError('TICKET_REQUEST_MISMATCH', `ticket version ${ticket.version} differs from its mandate's ${opts.mandate.payload.version}`);
  }
  if (!opts.replay) {
    const now = opts.now ?? Math.floor(Date.now() / 1000);
    if (Math.abs(now - ticket.timestamp) > TICKET_FRESHNESS_SECONDS) {
      throw new HapError('TICKET_REQUEST_MISMATCH', `ticket timestamp ${ticket.timestamp} is outside the freshness window at ${now}`);
    }
  }
}

// ─── Approvals carried by a ticket ───────────────────────────────────────────

/**
 * Rebuild the `HAP-approval` a decider signed, from the ticket and the
 * mandate it names (protocol.md → *Ticket Payload Schema*, `approvalSignature`):
 * `typ` and `version`; `proposal_id` and `mandate_id` from `proposalId` and
 * `mandateId`; `action` and `action_type` (v0.8) from `action` and
 * `actionType`; `proposal_content_hash` from `proposalContentHash`;
 * `content_hash` from `contentHash` where a binding applies to this action
 * (the AS copies one only then), else `proposalContentHash`; `decision`
 * `"commit"`; `approver_did` as given; `decided_at` and `nonce` from the
 * entry.
 */
export function reconstructApproval(
  ticket: TicketPayload,
  entry: ApprovalSignatureEntry,
  approverDid: string,
): ApprovalObject {
  if (!ticket.proposalId) {
    throw new HapError('APPROVAL_SIGNATURE_INVALID', 'ticket carries an approval signature but no proposalId');
  }
  if (ticket.version === '0.7') {
    if (!ticket.contentHash) {
      throw new HapError('APPROVAL_SIGNATURE_INVALID', 'a v0.7 approval without a content binding is not reconstructible from the ticket alone');
    }
    return {
      typ: 'HAP-approval',
      version: '0.7',
      proposal_id: ticket.proposalId,
      mandate_id: ticket.mandateId,
      decision: 'commit',
      content_hash: ticket.contentHash,
      decided_at: entry.decided_at,
      nonce: entry.nonce,
    };
  }
  if (!ticket.proposalContentHash) {
    throw new HapError('APPROVAL_SIGNATURE_INVALID', 'a v0.8 review-path ticket carries proposalContentHash');
  }
  return {
    typ: 'HAP-approval',
    version: '0.8',
    approver_did: approverDid,
    proposal_id: ticket.proposalId,
    mandate_id: ticket.mandateId,
    action: ticket.action,
    action_type: ticket.actionType,
    decision: 'commit',
    content_hash: ticket.contentHash ?? ticket.proposalContentHash,
    proposal_content_hash: ticket.proposalContentHash,
    decided_at: entry.decided_at,
    nonce: entry.nonce,
  };
}

/** What a ticket's approvals, once verified, establish. */
export interface VerifiedApprovals {
  /** The Mandate Owner's DID, when `approvalSignature` verified. */
  owner?: string;
  /** Distinct above-cap approver DIDs whose `approvalSignatures` entries verified. */
  approvers: string[];
}

/**
 * Verify every approval a ticket carries against the mandate it names
 * (protocol.md → *Ticket Payload Schema*, rule 4): `approvalSignature`
 * under the Mandate Owner's DID; each `approvalSignatures` entry under its
 * `approver_did`, which MUST be in the signed `above_cap_approvers` and
 * MUST NOT be the Mandate Owner (the proposer never counts). Whether the
 * verified set is ENOUGH is {@link approvalsSufficient}, so a verifier can
 * report what it found and a policy can decide.
 *
 * @throws HapError `APPROVAL_SIGNATURE_INVALID`
 */
export async function verifyTicketApprovals(ticket: TicketPayload, mandate: Mandate): Promise<VerifiedApprovals> {
  if (ticket.mandateId !== mandate.payload.mandate_id) {
    throw new HapError('APPROVAL_SIGNATURE_INVALID', 'the mandate supplied is not the one the ticket names');
  }
  const ownerDid = mandate.payload.mandate_owners[0]?.did;
  const result: VerifiedApprovals = { approvers: [] };
  try {
    if (ticket.approvalSignature) {
      const approval = reconstructApproval(ticket, ticket.approvalSignature, ownerDid);
      await verifyApproval(approval, ticket.approvalSignature.signature, ownerDid);
      result.owner = ownerDid;
    }
    const signed = new Set(mandate.payload.above_cap_approvers ?? []);
    for (const entry of ticket.approvalSignatures ?? []) {
      if (!signed.has(entry.approver_did)) {
        throw new HapError('APPROVAL_SIGNATURE_INVALID', `approver ${entry.approver_did} is not in the mandate's signed above_cap_approvers`);
      }
      if (entry.approver_did === ownerDid) {
        throw new HapError('APPROVAL_SIGNATURE_INVALID', 'the proposer never counts as an above-cap approver');
      }
      const approval = reconstructApproval(ticket, entry, entry.approver_did);
      await verifyApproval(approval, entry.signature, entry.approver_did);
      if (!result.approvers.includes(entry.approver_did)) result.approvers.push(entry.approver_did);
    }
  } catch (err) {
    if (err instanceof OwnerSignatureError) throw new HapError(err.code, err.message);
    throw err;
  }
  return result;
}

/**
 * Whether the verified approvals satisfy what the mandate requires for a
 * decision above a cap: at least `above_cap_approvals` distinct approvers
 * (v0.7: every signed approver), plus the owner's own approval in `review`.
 */
export function approvalsSufficient(mandate: Mandate, verified: VerifiedApprovals, aboveCap: boolean): boolean {
  const p = mandate.payload;
  const ownerNeeded = p.commitment_mode === 'review';
  if (ownerNeeded && !verified.owner) return false;
  if (!aboveCap) return true;
  const required = p.version === '0.7'
    ? (p.above_cap_approvers ?? []).length
    : (p.above_cap_approvals ?? 1);
  return verified.approvers.length >= required;
}

/**
 * A redacted public view of a ticket (protocol.md → *Ticket Disclosure Is
 * Declared*). Hides `userId`, `cumulativeState`, and `limits`, and narrows
 * `executionContext` to the governing `disclose_fields`. NOT independently
 * re-verifiable — since v0.8 a verifiable public view is the separately
 * signed `HAP-ticket-projection` (`ticket-projection.ts`); a view that is
 * not one MUST NOT be presented as independently verified.
 */
export function publicTicketView(
  ticket: TicketPayload,
  governingDiscloseFields: readonly string[] = [],
): Omit<TicketPayload, 'userId' | 'cumulativeState' | 'limits'> {
  const { userId: _userId, cumulativeState: _cumulativeState, limits: _limits, executionContext, ...rest } = ticket;
  const allowed = new Set(governingDiscloseFields);
  const disclosedExecutionContext: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(executionContext)) {
    if (allowed.has(key)) disclosedExecutionContext[key] = value;
  }
  return { ...rest, executionContext: disclosedExecutionContext };
}

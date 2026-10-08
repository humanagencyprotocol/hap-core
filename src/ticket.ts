/**
 * Mandate tickets (v0.7) — the wire type, signing, and holder-side
 * verification. Renamed from `receipt.ts` (protocol.md → *Mandate Tickets*:
 * "v0.4 introduced the object under the name execution receipt; v0.7 renames
 * it because the tense was wrong — a receipt follows payment, and the ticket
 * must come first").
 *
 * Ticket payloads are camelCase on the wire (unlike the snake_case mandate
 * payload) — a shipped inconsistency the spec documents rather than breaks
 * (protocol.md → *Migration from v0.6*, "Unchanged on purpose").
 */

import * as ed from '@noble/ed25519';
import type { ContentBinding, Subject } from './types';
import { canonicalize } from './canonicalize';
import { toBase64Url, fromBase64Url } from './base64url';
import { decodeDidKey } from './did-key';

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
  /** Review path: the owner's HAP-approval signature for the executed
   * proposal, as the object itself — never a hash of it, which a holder
   * could check only by asking the AS. */
  approvalSignature?: { alg: 'EdDSA' | 'ES256'; signature: string; nonce: string; decided_at: number };
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
 * Verify a ticket's AS signature: strip `signature`, JCS-canonicalize the
 * rest, Ed25519-verify against the key resolved from `issuer` — never
 * against a key offered alongside the ticket (protocol.md → *Ticket
 * Verification* step 1). This is holder-side verification — it needs the
 * COMPLETE ticket; a redacted public view cannot be re-verified this way
 * (see {@link publicTicketView}).
 *
 * Content is checked separately: where `contentHash` is present, recompute
 * it from the held artifact via the content-binding module and compare.
 *
 * @param opts.trustedIssuers When supplied, an `issuer` not in this list is
 * rejected before any cryptography runs.
 * @throws Error prefixed `INVALID_SIGNATURE:` when verification fails.
 */
export async function verifyTicketSignature(
  ticket: TicketPayload,
  opts?: { trustedIssuers?: readonly string[] },
): Promise<void> {
  const { signature, ...unsigned } = ticket;
  if (!signature) {
    throw new Error('INVALID_SIGNATURE: ticket carries no signature');
  }
  if (opts?.trustedIssuers && !opts.trustedIssuers.includes(ticket.issuer)) {
    throw new Error(`INVALID_SIGNATURE: issuer ${JSON.stringify(ticket.issuer)} is not a trusted Authority Server`);
  }

  let publicKey: Uint8Array;
  try {
    publicKey = decodeDidKey(ticket.issuer);
  } catch (err) {
    throw new Error(`INVALID_SIGNATURE: cannot resolve a key from issuer ${JSON.stringify(ticket.issuer)}: ${(err as Error).message}`);
  }

  const bytes = new TextEncoder().encode(canonicalize(unsigned));
  let sigBytes: Uint8Array;
  try {
    sigBytes = fromBase64Url(signature);
  } catch (err) {
    throw new Error(`INVALID_SIGNATURE: ${(err as Error).message}`);
  }

  const ok = await ed.verifyAsync(sigBytes, bytes, publicKey).catch(() => false);
  if (!ok) {
    throw new Error('INVALID_SIGNATURE: ticket signature verification failed');
  }
}

/**
 * A redacted public view of a ticket (new in v0.7 — protocol.md → *Ticket
 * Disclosure Is Declared*, *Ticket Verification*). Hides `userId`,
 * `cumulativeState`, and `limits` unconditionally, and narrows
 * `executionContext` to exactly the keys named by `governingDiscloseFields`
 * (the mandate's `disclose_fields` where present, otherwise the profile's).
 *
 * Disclose NOTHING by default: an empty or absent `governingDiscloseFields`
 * strips `executionContext` entirely. "The holder is the verifier" — this
 * view is NOT independently re-verifiable against `signature` (it is missing
 * signed fields); a "signature valid" indicator on a page showing only this
 * view is the AS re-verifying its own signature, and implementations MUST
 * NOT present it as independently verified.
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

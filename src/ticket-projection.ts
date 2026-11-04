/**
 * Public ticket projection — `HAP-ticket-projection` (protocol.md → *Public
 * ticket projection*, new in v0.8, specification-led).
 *
 * A ticket is one signature over every field, so a redacted view cannot be
 * re-verified. Where a ticket is shown to parties other than its holder —
 * a public page, a machine verifier at an effector, an auditor — the AS
 * serves a public-only subset, separately signed by the same key, so the
 * public view verifies on its own. It never widens what the ticket
 * discloses: `executionContext` carries only the governing
 * `disclose_fields`, and `userId`, `cumulativeState`, `limits` and `action`
 * never appear.
 */

import * as ed from '@noble/ed25519';
import { canonicalize } from './canonicalize';
import { toBase64Url, fromBase64Url } from './base64url';
import { decodeDidKey } from './did-key';
import { HapError } from './errors';
import type { Mandate, MandateOwnerEntry, Subject } from './types';
import type { TicketPayload } from './ticket';
import { verifyOwnerSignature, OwnerSignatureError } from './owner-signature';

/** The AS may not let a projection be accepted as authorization later than
 * this after the ticket's timestamp (rule 3). */
export const PROJECTION_MAX_VALIDITY_SECONDS = 86_400;

export interface TicketProjection {
  typ: 'HAP-ticket-projection';
  version: string;
  id: string;
  mandateId: string;
  issuer: string;
  timestamp: number;
  /** Set by the AS at projection time; governs acceptance as authorization, not evidence. */
  valid_until: number;
  profileId: string;
  actionType: string;
  boundsHash: string;
  contentHash?: string;
  contentBinding?: TicketPayload['contentBinding'];
  subjects?: Subject[];
  /** Exactly the governing `disclose_fields` the ticket carries; absent when none. */
  executionContext?: Record<string, unknown>;
  /** The mandate's `mandate_owners` entry, present exactly when it carries a signature. */
  owner?: MandateOwnerEntry;
  signature: string;
}

/**
 * Build the projection of a ticket (rule 1). `discloseFields` is the
 * governing list — the mandate's `disclose_fields` where present, else the
 * profile's; nothing when neither declares one.
 */
export function buildTicketProjection(
  ticket: TicketPayload,
  mandate: Mandate,
  opts: { validUntil: number; discloseFields?: readonly string[] },
): Omit<TicketProjection, 'signature'> {
  if (ticket.mandateId !== mandate.payload.mandate_id) {
    throw new HapError('MALFORMED_TICKET_REQUEST', 'the mandate supplied is not the one the ticket names');
  }
  if (opts.validUntil > ticket.timestamp + PROJECTION_MAX_VALIDITY_SECONDS) {
    throw new HapError('MALFORMED_TICKET_REQUEST', `valid_until MUST NOT end later than ${PROJECTION_MAX_VALIDITY_SECONDS}s after the ticket's timestamp`);
  }
  const projection: Omit<TicketProjection, 'signature'> = {
    typ: 'HAP-ticket-projection',
    version: ticket.version,
    id: ticket.id,
    mandateId: ticket.mandateId,
    issuer: ticket.issuer,
    timestamp: ticket.timestamp,
    valid_until: opts.validUntil,
    profileId: ticket.profileId,
    actionType: ticket.actionType,
    boundsHash: ticket.boundsHash,
  };
  if (ticket.contentHash !== undefined) projection.contentHash = ticket.contentHash;
  if (ticket.contentBinding !== undefined) projection.contentBinding = ticket.contentBinding;
  if (ticket.subjects !== undefined) projection.subjects = ticket.subjects;
  const disclosed: Record<string, unknown> = {};
  for (const field of opts.discloseFields ?? []) {
    if (ticket.executionContext[field] !== undefined) disclosed[field] = ticket.executionContext[field];
  }
  if (Object.keys(disclosed).length > 0) projection.executionContext = disclosed;
  const owner = mandate.payload.mandate_owners[0];
  if (owner?.signature !== undefined) projection.owner = owner;
  return projection;
}

/** Sign a projection with the key that signed its ticket (rule 2). */
export async function signTicketProjection(
  projection: Omit<TicketProjection, 'signature'>,
  privateKey: Uint8Array,
): Promise<TicketProjection> {
  const signature = toBase64Url(await ed.signAsync(new TextEncoder().encode(canonicalize(projection)), privateKey));
  return { ...projection, signature };
}

/**
 * Verify a projection on its own: `typ` required, signature under the key
 * `issuer` names. With `asAuthorization`, a projection past `valid_until`
 * is refused (rule 3); as evidence it is not.
 * @throws HapError `INVALID_SIGNATURE`, `POLICY_UNMET` (validity window)
 */
export async function verifyTicketProjection(
  projection: TicketProjection,
  opts: { trustedIssuers?: readonly string[]; now?: number; asAuthorization?: boolean } = {},
): Promise<void> {
  if (projection.typ !== 'HAP-ticket-projection') {
    throw new HapError('INVALID_SIGNATURE', 'a projection verifier requires typ "HAP-ticket-projection"');
  }
  for (const k of ['userId', 'cumulativeState', 'limits', 'action'] as const) {
    if (k in projection) throw new HapError('INVALID_SIGNATURE', `a projection MUST NOT carry ${k}`);
  }
  if (opts.trustedIssuers && !opts.trustedIssuers.includes(projection.issuer)) {
    throw new HapError('INVALID_SIGNATURE', `issuer ${JSON.stringify(projection.issuer)} is not a trusted Authority Server`);
  }
  const { signature, ...unsigned } = projection;
  if (!signature) throw new HapError('INVALID_SIGNATURE', 'projection carries no signature');
  let publicKey: Uint8Array;
  try {
    publicKey = decodeDidKey(projection.issuer);
  } catch (err) {
    throw new HapError('INVALID_SIGNATURE', `cannot resolve a key from issuer ${JSON.stringify(projection.issuer)}: ${(err as Error).message}`);
  }
  let sigBytes: Uint8Array;
  try {
    sigBytes = fromBase64Url(signature);
  } catch (err) {
    throw new HapError('INVALID_SIGNATURE', (err as Error).message);
  }
  const ok = await ed.verifyAsync(sigBytes, new TextEncoder().encode(canonicalize(unsigned)), publicKey).catch(() => false);
  if (!ok) throw new HapError('INVALID_SIGNATURE', 'projection signature verification failed');
  if (opts.asAuthorization) {
    const now = opts.now ?? Math.floor(Date.now() / 1000);
    if (now > projection.valid_until) {
      throw new HapError('POLICY_UNMET', `projection presented after valid_until ${projection.valid_until}`);
    }
  }
}

/**
 * Verify the projection's `owner` entry against the mandate obtained through
 * the third-party verification API (rule 4): the entry is the mandate's
 * own, and its signature verifies over the projection rebuilt from the
 * mandate. The projection alone cannot establish this.
 * @throws HapError `OWNER_SIGNATURE_INVALID`
 */
export async function verifyProjectionOwner(projection: TicketProjection, mandate: Mandate): Promise<void> {
  if (!projection.owner) {
    throw new HapError('OWNER_SIGNATURE_INVALID', 'projection carries no owner entry');
  }
  if (projection.mandateId !== mandate.payload.mandate_id) {
    throw new HapError('OWNER_SIGNATURE_INVALID', 'the mandate supplied is not the one the projection names');
  }
  const own = mandate.payload.mandate_owners[0];
  if (!own || canonicalize(own) !== canonicalize(projection.owner)) {
    throw new HapError('OWNER_SIGNATURE_INVALID', 'projection owner entry differs from the mandate\'s mandate_owners entry');
  }
  try {
    await verifyOwnerSignature(mandate, projection.owner);
  } catch (err) {
    if (err instanceof OwnerSignatureError) throw new HapError(err.code, err.message);
    throw err;
  }
}

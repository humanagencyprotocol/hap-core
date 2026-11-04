/**
 * Conformance vectors — payload-signatures.json, v0.8 and v0.7.
 *
 * v0.8 (what this package issues): the mandate, the synchronous ticket
 * (`idempotencyKey`), the review-path ticket (`proposalId`,
 * `proposalContentHash`, `approvalSignature`), the owner's projection (plain
 * and above-cap with `above_cap_approvals`), the approval (`approver_did`,
 * `action`, `action_type`, `proposal_content_hash`), the co-signed mandate,
 * the public ticket projection, and the JCS edge cases. The three chains are
 * the point: cosigned ↔ projection, review ticket ↔ approval, projection ↔
 * ticket + mandate.
 *
 * v0.7 (what this package still verifies as evidence, under v0.7 rules):
 * the six v0.7 cases, through the same functions.
 *
 * Uses the published RFC 8032 §7.1 test keys named in the vector files —
 * never hardcoded here, so a change to the published keys cannot go
 * unnoticed.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize } from '../../src/canonicalize';
import { signMandate, verifyMandateSignature, verifyMandate, encodeMandateBlob } from '../../src/mandate';
import {
  signTicket, verifyTicketSignature, verifyTicketApprovals, reconstructApproval, verifyTicketAgainstRequest,
} from '../../src/ticket';
import {
  buildTicketProjection, signTicketProjection, verifyTicketProjection, verifyProjectionOwner,
} from '../../src/ticket-projection';
import {
  buildMandateProjection,
  projectionSigningBytes,
  signMandateProjection,
  signApproval,
  verifyOwnerSignature,
  verifyApproval,
  type ApprovalObject,
} from '../../src/owner-signature';
import { VECTORS_DIR, VECTORS_DIR_07, haveVectors, requireVectors } from './_spec-dir';
import type { Mandate, MandatePayload } from '../../src/types';
import type { TicketPayload } from '../../src/ticket';
import type { TicketProjection } from '../../src/ticket-projection';
import type { MandateProjection } from '../../src/owner-signature';

interface SignatureCase {
  id: string;
  signed_by: 'authority_server' | 'mandate_owner';
  key: 'as' | 'owner';
  note?: string;
  chains_to?: string;
  payload: Record<string, unknown>;
  canonical: string;
  signature: string;
}

interface KeyInfo {
  did: string;
  public_key_hex: string;
  seed_hex: string;
}

interface VectorFile {
  keys: { owner: KeyInfo; as: KeyInfo };
  cases: SignatureCase[];
}

requireVectors();

function load(dir: string): { file: VectorFile; seeds: { as: Uint8Array; owner: Uint8Array }; caseById: (id: string) => SignatureCase } {
  const file = JSON.parse(readFileSync(join(dir, 'payload-signatures.json'), 'utf8')) as VectorFile;
  const seeds = {
    as: Uint8Array.from(Buffer.from(file.keys.as.seed_hex, 'hex')),
    owner: Uint8Array.from(Buffer.from(file.keys.owner.seed_hex, 'hex')),
  };
  const caseById = (id: string) => {
    const c = file.cases.find((x) => x.id === id);
    if (!c) throw new Error(`no case ${id} in ${dir}`);
    return c;
  };
  return { file, seeds, caseById };
}

describe.skipIf(!haveVectors)('conformance vectors — payload-signatures (v0.8)', () => {
  const { file, seeds, caseById } = load(VECTORS_DIR);

  it('loaded the v0.8 set with all nine cases', () => {
    const ids = file.cases.map((c) => c.id);
    for (const id of [
      'mandate-payload', 'ticket-payload', 'mandate-projection', 'mandate-cosigned',
      'mandate-projection-above-cap', 'approval', 'ticket-payload-review', 'ticket-projection', 'jcs-edge-cases',
    ]) {
      expect(ids).toContain(id);
    }
    for (const c of file.cases) expect((c.payload as { version: string }).version).toBe('0.8');
  });

  it('every case: our canonical bytes equal the published ones', () => {
    for (const c of file.cases) {
      expect(canonicalize(c.payload), c.id).toBe(c.canonical);
    }
  });

  it('jcs-edge-cases: escapes, UTF-16 key order, number forms, null, empties', () => {
    const vc = caseById('jcs-edge-cases');
    expect(canonicalize(vc.payload)).toBe(vc.canonical);
    // The astral key (U+1F600, surrogates D83D DE00) sorts BEFORE U+E000
    // under UTF-16 code units — the opposite of code-point order.
    expect(vc.canonical.indexOf('"😀"')).toBeLessThan(vc.canonical.indexOf('""') === -1 ? Infinity : vc.canonical.indexOf('""'));
  });

  it('a lone surrogate is refused, never signed', () => {
    expect(() => canonicalize({ s: 'a\uD800b' })).toThrow(/surrogate/);
  });

  it('mandate-payload: signs under the AS key, verifiable via its own issuer, accepted by verifyMandate', async () => {
    const vc = caseById('mandate-payload');
    const payload = vc.payload as unknown as MandatePayload;
    const mandate = await signMandate(payload, seeds.as);
    expect(mandate.signature).toBe(vc.signature);
    const vectorMandate: Mandate = { header: { typ: 'HAP-mandate', alg: 'EdDSA' }, payload, signature: vc.signature };
    await expect(verifyMandateSignature(vectorMandate)).resolves.toBeUndefined();
    await expect(verifyMandate(encodeMandateBlob(vectorMandate), { now: payload.issued_at + 60 })).resolves.toEqual(payload);
  });

  it('ticket-payload: signs under the AS key; null groupId signed as null; idempotencyKey inside the signature', async () => {
    const vc = caseById('ticket-payload');
    const payload = vc.payload as unknown as Omit<TicketPayload, 'signature'>;
    expect(payload.groupId).toBeNull();
    expect(payload.idempotencyKey).toBeDefined();
    const ticket = await signTicket(payload, seeds.as);
    expect(ticket.signature).toBe(vc.signature);
    await expect(verifyTicketSignature(ticket)).resolves.toBeUndefined();

    // v0.8: the Gatekeeper checks the ticket answers its request.
    const request = {
      profileId: payload.profileId, actionType: payload.actionType, boundsHash: payload.boundsHash,
      executionContext: payload.executionContext, idempotencyKey: payload.idempotencyKey, mandateId: payload.mandateId,
    };
    expect(() => verifyTicketAgainstRequest(ticket, request, { now: payload.timestamp + 10 })).not.toThrow();
    expect(() => verifyTicketAgainstRequest(ticket, { ...request, idempotencyKey: 'another' }, { now: payload.timestamp })).toThrow(/TICKET_REQUEST_MISMATCH/);
    expect(() => verifyTicketAgainstRequest(ticket, { ...request, executionContext: { amount: 13 } }, { now: payload.timestamp })).toThrow(/TICKET_REQUEST_MISMATCH/);
    expect(() => verifyTicketAgainstRequest(ticket, request, { now: payload.timestamp + 1000 })).toThrow(/TICKET_REQUEST_MISMATCH/);
    expect(() => verifyTicketAgainstRequest(ticket, request, { now: payload.timestamp + 1000, replay: true })).not.toThrow();
  });

  it('a ticket verifier rejects a projection, and a mandate payload', async () => {
    const proj = caseById('ticket-projection');
    await expect(verifyTicketSignature({ ...(proj.payload as object), signature: proj.signature } as unknown as TicketPayload)).rejects.toThrow(/INVALID_SIGNATURE/);
    const m = caseById('mandate-payload');
    await expect(verifyTicketSignature({ ...(m.payload as object), signature: m.signature } as unknown as TicketPayload)).rejects.toThrow(/INVALID_SIGNATURE/);
  });

  it('mandate-projection: the owner signs the projection, with binding, signing_surface and subjects_disclosed', async () => {
    const vc = caseById('mandate-projection');
    const projection = vc.payload as unknown as MandateProjection;
    expect(projection.binding).toBe('webauthn');
    expect(projection.subjects_disclosed).toBe(false);
    const sig = await signMandateProjection(projection, seeds.owner);
    expect(sig).toBe(vc.signature);
  });

  it('mandate-projection-above-cap: caps, approvers AND the count are signed', async () => {
    const vc = caseById('mandate-projection-above-cap');
    const projection = vc.payload as unknown as MandateProjection;
    expect(projection.above_cap_approvals).toBe(1);
    const sig = await signMandateProjection(projection, seeds.owner);
    expect(sig).toBe(vc.signature);
    // A projection built to the v0.7 field list does not reconstruct.
    const { above_cap_approvals: _n, ...v07shape } = projection;
    expect(await signMandateProjection(v07shape as MandateProjection, seeds.owner)).not.toBe(vc.signature);
  });

  it('approval: the owner signs the HAP-approval with approver_did, action, action_type and proposal_content_hash', async () => {
    const vc = caseById('approval');
    const approval = vc.payload as unknown as ApprovalObject;
    expect(approval.approver_did).toBe(file.keys.owner.did);
    expect(approval.action_type).toBe('charge');
    const sig = await signApproval(approval, seeds.owner);
    expect(sig).toBe(vc.signature);
    await expect(verifyApproval(approval, sig, file.keys.owner.did)).resolves.toBeUndefined();
    // An approval for another operation does not verify for this one.
    await expect(verifyApproval({ ...approval, action: 'delete_payment_link' }, sig, file.keys.owner.did)).rejects.toThrow(/APPROVAL_SIGNATURE_INVALID/);
  });

  it('mandate-cosigned: the inner owner signature is byte-identical to the standalone projection, rebuilt from the mandate alone', async () => {
    const vc = caseById('mandate-cosigned');
    expect(vc.chains_to).toBe('mandate-projection');
    const payload = vc.payload as unknown as MandatePayload;
    const mandate = await signMandate(payload, seeds.as);
    expect(mandate.signature).toBe(vc.signature);

    const entry = payload.mandate_owners[0];
    const rebuilt = buildMandateProjection(payload, entry);
    const projectionVector = caseById('mandate-projection');
    expect(canonicalize(rebuilt)).toBe(projectionVector.canonical);
    expect(Buffer.from(projectionSigningBytes(rebuilt)).toString('utf8')).toBe(projectionVector.canonical);
    expect(entry.signature).toBe(projectionVector.signature);
    await expect(verifyOwnerSignature(mandate, entry)).resolves.toBeUndefined();

    // v0.8: an AS that restates the binding label breaks the owner's signature.
    const restated: Mandate = { ...mandate, payload: { ...payload, mandate_owners: [{ ...entry, binding: 'eudi' }] } };
    await expect(verifyOwnerSignature(restated, restated.payload.mandate_owners[0])).rejects.toThrow(/OWNER_SIGNATURE_INVALID/);
    // …and so does attaching the owner's name.
    const named: Mandate = { ...mandate, payload: { ...payload, subjects: [{ did: entry.did, assurance: 'high', method: 'as_vouched', trust_root: 'as', verifier: 'did:web:as', disclose: { name: 'X' } }] } };
    await expect(verifyOwnerSignature(named, entry)).rejects.toThrow(/OWNER_SIGNATURE_INVALID/);
  });

  it('ticket-payload-review: signs under the AS key; its approvalSignature is the approval case, rebuilt from ticket + mandate', async () => {
    const vc = caseById('ticket-payload-review');
    const payload = vc.payload as unknown as Omit<TicketPayload, 'signature'>;
    const ticket = await signTicket(payload, seeds.as);
    expect(ticket.signature).toBe(vc.signature);
    await expect(verifyTicketSignature(ticket)).resolves.toBeUndefined();

    const approvalVector = caseById('approval');
    expect(ticket.approvalSignature!.signature).toBe(approvalVector.signature);

    const cosigned = caseById('mandate-cosigned');
    const mandate: Mandate = { header: { typ: 'HAP-mandate', alg: 'EdDSA' }, payload: cosigned.payload as unknown as MandatePayload, signature: cosigned.signature };
    const rebuilt = reconstructApproval(ticket, ticket.approvalSignature!, mandate.payload.mandate_owners[0].did);
    expect(canonicalize(rebuilt)).toBe(approvalVector.canonical);
    const verified = await verifyTicketApprovals(ticket, mandate);
    expect(verified.owner).toBe(file.keys.owner.did);
    expect(verified.approvers).toEqual([]);

    // A relabelled operation breaks the chain: the AS shows one tool and
    // issues a ticket for another.
    const relabelled = await signTicket({ ...payload, action: 'delete_payment_link' }, seeds.as);
    await expect(verifyTicketApprovals(relabelled, mandate)).rejects.toThrow(/APPROVAL_SIGNATURE_INVALID/);
  });

  it('ticket-projection: public fields from the review ticket, owner entry from the co-signed mandate, same AS key', async () => {
    const vc = caseById('ticket-projection');
    const projection = { ...(vc.payload as object), signature: vc.signature } as TicketProjection;
    await expect(verifyTicketProjection(projection, { now: projection.timestamp + 10, asAuthorization: true })).resolves.toBeUndefined();
    await expect(verifyTicketProjection(projection, { now: projection.valid_until + 1, asAuthorization: true })).rejects.toThrow(/POLICY_UNMET/);
    // As evidence, the window does not apply.
    await expect(verifyTicketProjection(projection, { now: projection.valid_until + 1 })).resolves.toBeUndefined();

    const review = caseById('ticket-payload-review');
    const ticket = { ...(review.payload as object), signature: review.signature } as TicketPayload;
    const cosigned = caseById('mandate-cosigned');
    const mandate: Mandate = { header: { typ: 'HAP-mandate', alg: 'EdDSA' }, payload: cosigned.payload as unknown as MandatePayload, signature: cosigned.signature };
    const built = buildTicketProjection(ticket, mandate, { validUntil: projection.valid_until });
    expect(canonicalize(built)).toBe(vc.canonical);
    const signed = await signTicketProjection(built, seeds.as);
    expect(signed.signature).toBe(vc.signature);
    await expect(verifyProjectionOwner(projection, mandate)).resolves.toBeUndefined();
  });

  it('rejects a standard-base64 rendering of a valid signature (base64url is strict — no +/=)', async () => {
    const vc = caseById('mandate-payload');
    const payload = vc.payload as unknown as MandatePayload;
    const notBase64Url = '+' + vc.signature.slice(1) + '==';
    const badMandate: Mandate = { header: { typ: 'HAP-mandate', alg: 'EdDSA' }, payload, signature: notBase64Url };
    await expect(verifyMandateSignature(badMandate)).rejects.toThrow();
  });
});

describe.skipIf(!haveVectors)('conformance vectors — payload-signatures (v0.7, verified as evidence)', () => {
  const { file, seeds, caseById } = load(VECTORS_DIR_07);

  it('loaded the v0.7 set with its six cases', () => {
    const ids = file.cases.map((c) => c.id);
    for (const id of ['mandate-payload', 'ticket-payload', 'mandate-cosigned', 'mandate-projection', 'mandate-projection-above-cap', 'approval']) {
      expect(ids).toContain(id);
    }
  });

  it('mandate-payload (0.7): still signs and verifies under v0.7 rules', async () => {
    const vc = caseById('mandate-payload');
    const payload = vc.payload as unknown as MandatePayload;
    expect(payload.version).toBe('0.7');
    const mandate = await signMandate(payload, seeds.as);
    expect(mandate.signature).toBe(vc.signature);
    await expect(verifyMandate(encodeMandateBlob(mandate), { now: payload.issued_at + 60 })).resolves.toEqual(payload);
  });

  it('ticket-payload (0.7): verifies, and carries no idempotencyKey — not refused for lacking one', async () => {
    const vc = caseById('ticket-payload');
    const payload = vc.payload as unknown as Omit<TicketPayload, 'signature'>;
    const ticket = await signTicket(payload, seeds.as);
    expect(ticket.signature).toBe(vc.signature);
    await expect(verifyTicketSignature(ticket)).resolves.toBeUndefined();
    expect(ticket.idempotencyKey).toBeUndefined();
    const request = {
      profileId: payload.profileId, actionType: payload.actionType, boundsHash: payload.boundsHash,
      executionContext: payload.executionContext, contentHash: payload.contentHash, contentBinding: payload.contentBinding,
    };
    expect(() => verifyTicketAgainstRequest(ticket, request, { now: payload.timestamp })).not.toThrow();
  });

  it('mandate-cosigned (0.7): the owner signature verifies over the v0.7 projection (no binding / signing_surface / subjects_disclosed)', async () => {
    const vc = caseById('mandate-cosigned');
    const payload = vc.payload as unknown as MandatePayload;
    const mandate = await signMandate(payload, seeds.as);
    expect(mandate.signature).toBe(vc.signature);
    const entry = payload.mandate_owners[0];
    const rebuilt = buildMandateProjection(payload, entry);
    expect(rebuilt.version).toBe('0.7');
    expect(rebuilt.binding).toBeUndefined();
    expect(canonicalize(rebuilt)).toBe(caseById('mandate-projection').canonical);
    await expect(verifyOwnerSignature(mandate, entry)).resolves.toBeUndefined();
  });

  it('mandate-projection-above-cap (0.7): caps and approvers, no count', async () => {
    const vc = caseById('mandate-projection-above-cap');
    const projection = vc.payload as unknown as MandateProjection;
    expect(projection.above_cap_approvals).toBeUndefined();
    expect(await signMandateProjection(projection, seeds.owner)).toBe(vc.signature);
  });

  it('approval (0.7): the owner signs the v0.7 HAP-approval', async () => {
    const vc = caseById('approval');
    const approval = vc.payload as unknown as ApprovalObject;
    expect(approval.approver_did).toBeUndefined();
    expect(await signApproval(approval, seeds.owner)).toBe(vc.signature);
    await expect(verifyApproval(approval, vc.signature, file.keys.owner.did)).resolves.toBeUndefined();
  });
});

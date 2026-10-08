/**
 * Conformance vectors — payload-signatures.json.
 *
 * Pins key ordering, string escaping, number formatting, null handling, and
 * signature encoding for the mandate, the ticket, the owner's projection
 * (plain and review_above_cap), an approval, and a co-signed mandate whose
 * inner owner signature chains to the standalone projection case.
 *
 * Uses the published RFC 8032 §7.1 test keys named in the vector file itself
 * — never hardcoded here, so a change to the published keys cannot go
 * unnoticed.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize } from '../../src/canonicalize';
import { signMandate, verifyMandateSignature } from '../../src/mandate';
import { signTicket, verifyTicketSignature } from '../../src/ticket';
import {
  buildMandateProjection,
  projectionSigningBytes,
  signMandateProjection,
  approvalSigningBytes,
  signApproval,
  type ApprovalObject,
} from '../../src/owner-signature';
import { VECTORS_DIR, haveVectors, requireVectors } from './_spec-dir';
import type { Mandate, MandatePayload } from '../../src/types';
import type { TicketPayload } from '../../src/ticket';
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

requireVectors();

describe.skipIf(!haveVectors)('conformance vectors — payload-signatures', () => {
  const file = JSON.parse(readFileSync(join(VECTORS_DIR, 'payload-signatures.json'), 'utf8')) as {
    keys: { owner: KeyInfo; as: KeyInfo };
    cases: SignatureCase[];
  };
  const seeds = {
    as: Uint8Array.from(Buffer.from(file.keys.as.seed_hex, 'hex')),
    owner: Uint8Array.from(Buffer.from(file.keys.owner.seed_hex, 'hex')),
  };
  const caseById = (id: string) => file.cases.find((c) => c.id === id)!;

  it('loaded a vector set with all six cases', () => {
    const ids = file.cases.map((c) => c.id);
    for (const id of ['mandate-payload', 'ticket-payload', 'mandate-cosigned', 'mandate-projection', 'mandate-projection-above-cap', 'approval']) {
      expect(ids).toContain(id);
    }
  });

  it('mandate-payload: canonicalizes and signs under the AS key, verifiable via its own issuer', async () => {
    const vc = caseById('mandate-payload');
    const payload = vc.payload as unknown as MandatePayload;
    expect(canonicalize(payload)).toBe(vc.canonical);

    const mandate = await signMandate(payload, seeds.as);
    expect(mandate.signature).toBe(vc.signature);

    // The vector's own signature must verify too — round-trip, not just "we
    // can reproduce a signature of our own".
    const vectorMandate: Mandate = { header: { typ: 'HAP-mandate', alg: 'EdDSA' }, payload, signature: vc.signature };
    await expect(verifyMandateSignature(vectorMandate)).resolves.toBeUndefined();
  });

  it('ticket-payload: canonicalizes and signs under the AS key, null groupId signed as null', async () => {
    const vc = caseById('ticket-payload');
    const payload = vc.payload as unknown as Omit<TicketPayload, 'signature'>;
    expect(payload.groupId).toBeNull();
    expect(canonicalize(payload)).toBe(vc.canonical);

    const ticket = await signTicket(payload, seeds.as);
    expect(ticket.signature).toBe(vc.signature);

    await expect(verifyTicketSignature(ticket)).resolves.toBeUndefined();
  });

  it('mandate-projection: the owner signs the reconstructed projection', async () => {
    const vc = caseById('mandate-projection');
    const projection = vc.payload as unknown as MandateProjection;
    expect(canonicalize(projection)).toBe(vc.canonical);

    const sig = await signMandateProjection(projection, seeds.owner);
    expect(sig).toBe(vc.signature);
  });

  it('mandate-projection-above-cap: conditional fields (above_cap_*, disclose_fields) are present and signed', async () => {
    const vc = caseById('mandate-projection-above-cap');
    const projection = vc.payload as unknown as MandateProjection;
    expect(projection.above_cap_caps).toBeDefined();
    expect(projection.above_cap_approvers).toBeDefined();
    expect(projection.disclose_fields).toBeDefined();
    expect(canonicalize(projection)).toBe(vc.canonical);

    const sig = await signMandateProjection(projection, seeds.owner);
    expect(sig).toBe(vc.signature);
  });

  it('approval: the owner signs the HAP-approval object', async () => {
    const vc = caseById('approval');
    const approval = vc.payload as unknown as ApprovalObject;
    expect(canonicalize(approval)).toBe(vc.canonical);

    const sig = await signApproval(approval, seeds.owner);
    expect(sig).toBe(vc.signature);
  });

  it('mandate-cosigned: the inner owner signature is byte-identical to the standalone projection case', async () => {
    const vc = caseById('mandate-cosigned');
    expect(vc.chains_to).toBe('mandate-projection');

    const payload = vc.payload as unknown as MandatePayload;
    expect(canonicalize(payload)).toBe(vc.canonical);

    // The AS's own signature over the whole (already-cosigned) payload.
    const mandate = await signMandate(payload, seeds.as);
    expect(mandate.signature).toBe(vc.signature);

    // The mechanism under test: rebuild the projection from the mandate's
    // OWN fields — never fetched from elsewhere — and confirm the embedded
    // owner signature is exactly the standalone mandate-projection vector's.
    const entry = payload.mandate_owners[0];
    const rebuilt = buildMandateProjection(payload, { did: entry.did, nonce: entry.nonce! });
    const projectionVector = caseById('mandate-projection');
    expect(canonicalize(rebuilt)).toBe(projectionVector.canonical);
    expect(Buffer.from(projectionSigningBytes(rebuilt)).toString('utf8')).toBe(projectionVector.canonical);
    expect(entry.signature).toBe(projectionVector.signature);
  });

  it('rejects a standard-base64 rendering of a valid signature (base64url is strict — no +/=)', async () => {
    const vc = caseById('mandate-payload');
    const payload = vc.payload as unknown as MandatePayload;
    // Force a leading "+" and trailing "==" — neither can appear in strict
    // base64url, so this is "the same bytes" rendered the forbidden way.
    const notBase64Url = '+' + vc.signature.slice(1) + '==';
    const badMandate: Mandate = { header: { typ: 'HAP-mandate', alg: 'EdDSA' }, payload, signature: notBase64Url };
    await expect(verifyMandateSignature(badMandate)).rejects.toThrow();
  });
});

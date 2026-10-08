/**
 * Owner Signatures (v0.7) — projection reconstruction, signing (raw binding),
 * and verification with no trust in the AS.
 *
 * The tamper cases are the point: each one flips a field a compromised AS
 * would most like to flip (mode, expiry, approver-set hash) and asserts the
 * owner's signature stops verifying — the exact forgeries the mechanism
 * exists to make impossible.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as ed from '@noble/ed25519';
import type { Mandate, MandatePayload, MandateOwnerEntry } from '../src/types';
import { encodeDidKey } from '../src/did-key';
import {
  buildMandateProjection,
  projectionSigningBytes,
  signMandateProjection,
  verifyOwnerSignature,
  verifyOwnerSignatures,
  signApproval,
  verifyApproval,
  checkOwnerSignatureRequirement,
  type ApprovalObject,
} from '../src/owner-signature';
import { canonicalize } from '../src/canonicalize';

let priv: Uint8Array;
let did: string;

function payload(overrides: Partial<MandatePayload> = {}): MandatePayload {
  return {
    mandate_id: 'mandate-1',
    version: '0.7',
    profile_id: 'email@0.7',
    bounds_hash: 'sha256:' + 'a'.repeat(64),
    scope_hash: 'sha256:' + 'b'.repeat(64),
    execution_context_hash: 'sha256:' + 'c'.repeat(64),
    profile_hash: 'sha256:' + '5'.repeat(64),
    issuer: 'did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT',
    mandate_owners: [{ did }],
    gate_content_hashes: { intent: 'sha256:' + 'd'.repeat(64) },
    commitment_mode: 'review',
    issued_at: 1_767_139_200,
    expires_at: 1_767_225_600,
    ...overrides,
  };
}

async function signedEntry(p: MandatePayload, nonce = 'nonce-1'): Promise<MandateOwnerEntry> {
  const projection = buildMandateProjection(p, { did, nonce });
  return {
    did,
    alg: 'EdDSA',
    signature: await signMandateProjection(projection, priv),
    signed_at: p.issued_at - 60,
    nonce,
    binding: 'raw',
    signing_surface: 'gatekeeper_local',
  };
}

function mandate(p: MandatePayload, ownerEntry: MandateOwnerEntry): Mandate {
  return {
    header: { typ: 'HAP-mandate', alg: 'EdDSA' },
    payload: { ...p, mandate_owners: [ownerEntry] },
    signature: 'as-signature-not-under-test',
  };
}

beforeAll(async () => {
  priv = ed.utils.randomPrivateKey();
  did = encodeDidKey(await ed.getPublicKeyAsync(priv));
});

describe('HAP-mandate-projection', () => {
  it('a signed projection reconstructed from the mandate verifies with the key in the DID', async () => {
    const p = payload();
    const entry = await signedEntry(p);
    await expect(verifyOwnerSignature(mandate(p, entry), entry)).resolves.toBeUndefined();
  });

  it('projection omits conditional fields iff the mandate carries none (defined absence)', () => {
    const without = buildMandateProjection(payload(), { did, nonce: 'n' });
    expect('intent_disclosure_hash' in without).toBe(false);
    expect('above_cap_caps' in without).toBe(false);
    expect('disclose_fields' in without).toBe(false);

    const withHash = buildMandateProjection(
      payload({ intent_disclosure_hash: 'sha256:' + 'e'.repeat(64) }),
      { did, nonce: 'n' },
    );
    expect(withHash.intent_disclosure_hash).toBe('sha256:' + 'e'.repeat(64));
    // and the two canonical forms differ — absence is part of the signed bytes
    expect(canonicalize(without)).not.toBe(canonicalize(withHash));
  });

  it('above_cap_caps/above_cap_approvers are included together, iff commitment_mode is review_above_cap', () => {
    const projection = buildMandateProjection(
      payload({ commitment_mode: 'review_above_cap', above_cap_caps: { amount_max: 50 }, above_cap_approvers: ['did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT'] }),
      { did, nonce: 'n' },
    );
    expect(projection.above_cap_caps).toEqual({ amount_max: 50 });
    expect(projection.above_cap_approvers).toEqual(['did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT']);
  });

  it('disclose_fields is included iff the mandate narrows disclosure', () => {
    const without = buildMandateProjection(payload(), { did, nonce: 'n' });
    expect(without.disclose_fields).toBeUndefined();
    const narrowed = buildMandateProjection(payload({ disclose_fields: ['currency'] }), { did, nonce: 'n' });
    expect(narrowed.disclose_fields).toEqual(['currency']);
  });

  it('TAMPER: flipping commitment_mode review→automatic breaks the signature', async () => {
    const p = payload({ commitment_mode: 'review' });
    const entry = await signedEntry(p);
    const flipped = mandate(payload({ commitment_mode: 'automatic' }), entry);
    await expect(verifyOwnerSignature(flipped, entry)).rejects.toThrow(/OWNER_SIGNATURE_INVALID/);
  });

  it('TAMPER: extending expires_at breaks the signature (the replay defence)', async () => {
    const p = payload();
    const entry = await signedEntry(p);
    const extended = mandate(payload({ expires_at: p.expires_at + 86_400 }), entry);
    await expect(verifyOwnerSignature(extended, entry)).rejects.toThrow(/OWNER_SIGNATURE_INVALID/);
  });

  it('TAMPER: swapping intent_disclosure_hash (the frozen approver set) breaks the signature', async () => {
    const p = payload({ intent_disclosure_hash: 'sha256:' + 'e'.repeat(64) });
    const entry = await signedEntry(p);
    const swapped = mandate(payload({ intent_disclosure_hash: 'sha256:' + 'f'.repeat(64) }), entry);
    await expect(verifyOwnerSignature(swapped, entry)).rejects.toThrow(/OWNER_SIGNATURE_INVALID/);
  });

  it('TAMPER: raising an above_cap cap breaks the signature', async () => {
    const p = payload({ commitment_mode: 'review_above_cap', above_cap_caps: { amount_max: 50 }, above_cap_approvers: [did] });
    const entry = await signedEntry(p);
    const raised = mandate(payload({ commitment_mode: 'review_above_cap', above_cap_caps: { amount_max: 5000 }, above_cap_approvers: [did] }), entry);
    await expect(verifyOwnerSignature(raised, entry)).rejects.toThrow(/OWNER_SIGNATURE_INVALID/);
  });

  it("rejects a signing DID that is not this mandate's registered owner", async () => {
    const p = payload();
    const entry = await signedEntry(p); // signed by `did`
    // The mandate's OWN mandate_owners entry names a different DID entirely —
    // `entry` (what we are asked to verify) does not match it.
    const foreign = mandate(p, { did: 'did:key:z6MkOtherOwner' });
    await expect(verifyOwnerSignature(foreign, entry)).rejects.toThrow(/OWNER_SIGNATURE_INVALID/);
  });

  it('rejects a non-key-bearing signing DID structurally — there is no public_key to fall back to', async () => {
    const entry: MandateOwnerEntry = { ...(await signedEntry(payload())), did: 'did:key:1a2b3c4d' };
    const m = mandate(payload({ mandate_owners: [entry] }), entry);
    await expect(verifyOwnerSignature(m, entry)).rejects.toThrow(/OWNER_SIGNATURE_INVALID/);
  });

  it('the DID is authoritative over alg — a disagreeing alg is invalid, never a fallback', async () => {
    const p = payload();
    const entry = { ...(await signedEntry(p)), alg: 'ES256' as const };
    await expect(verifyOwnerSignature(mandate(p, entry), entry)).rejects.toThrow(/OWNER_SIGNATURE_INVALID/);
  });

  it('verifyOwnerSignatures: no co-signing entry resolves to [] — nothing claimed', async () => {
    const m = { header: { typ: 'HAP-mandate', alg: 'EdDSA' }, payload: payload(), signature: 's' } as Mandate;
    await expect(verifyOwnerSignatures(m)).resolves.toEqual([]);
  });

  it('projectionSigningBytes is the UTF-8 JCS bytes of the projection', () => {
    const projection = buildMandateProjection(payload(), { did, nonce: 'n' });
    expect(Buffer.from(projectionSigningBytes(projection)).toString('utf8')).toBe(canonicalize(projection));
  });
});

describe('HAP-approval', () => {
  const approval: ApprovalObject = {
    typ: 'HAP-approval',
    version: '0.7',
    proposal_id: 'prop-1',
    mandate_id: 'mandate-1',
    decision: 'commit',
    content_hash: 'sha256:' + '9'.repeat(64),
    decided_at: 1_767_139_260,
    nonce: 'n-appr',
  };

  it('sign → verify round-trips, and a reject signs as strongly as a commit', async () => {
    for (const decision of ['commit', 'reject'] as const) {
      const obj = { ...approval, decision };
      const sig = await signApproval(obj, priv);
      await expect(verifyApproval(obj, sig, did)).resolves.toBeUndefined();
    }
  });

  it('TAMPER: changing content_hash after signing breaks the approval', async () => {
    const sig = await signApproval(approval, priv);
    const tampered = { ...approval, content_hash: 'sha256:' + '8'.repeat(64) };
    await expect(verifyApproval(tampered, sig, did)).rejects.toThrow(/APPROVAL_SIGNATURE_INVALID/);
  });

  it('TAMPER: a discarded reject cannot be replayed as a commit', async () => {
    const sig = await signApproval({ ...approval, decision: 'reject' }, priv);
    await expect(verifyApproval({ ...approval, decision: 'commit' }, sig, did)).rejects.toThrow(/APPROVAL_SIGNATURE_INVALID/);
  });
});

describe('checkOwnerSignatureRequirement (profile floor)', () => {
  const unsigned = payload();
  const signed = payload({ mandate_owners: [{ did, alg: 'EdDSA', signature: 's', signed_at: 1, nonce: 'n', binding: 'webauthn' }] });

  it('no floor, or floor not required → never throws', () => {
    expect(() => checkOwnerSignatureRequirement(unsigned, undefined)).not.toThrow();
    expect(() => checkOwnerSignatureRequirement(unsigned, { required: false })).not.toThrow();
  });

  it('required floor with no signature present → OWNER_SIGNATURE_REQUIRED', () => {
    expect(() => checkOwnerSignatureRequirement(unsigned, { required: true })).toThrow(/OWNER_SIGNATURE_REQUIRED/);
  });

  it('required floor met by a signature at or above minBinding → passes', () => {
    expect(() => checkOwnerSignatureRequirement(signed, { required: true, minBinding: 'webauthn' })).not.toThrow();
    expect(() => checkOwnerSignatureRequirement(signed, { required: true, minBinding: 'raw' })).not.toThrow();
  });

  it('required floor NOT met because the binding is weaker than minBinding → OWNER_SIGNATURE_REQUIRED', () => {
    expect(() => checkOwnerSignatureRequirement(signed, { required: true, minBinding: 'eudi' })).toThrow(/OWNER_SIGNATURE_REQUIRED/);
  });
});

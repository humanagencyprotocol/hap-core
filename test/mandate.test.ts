/**
 * Owner Mandate Signatures — projection reconstruction, signing (raw binding),
 * and verification with no trust in the AS.
 *
 * The tamper cases are the point: each one flips a field a compromised AS
 * would most like to flip (mode, expiry, approver-set hash) and asserts the
 * owner's signature stops verifying — the exact forgeries the mechanism
 * exists to make impossible.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as ed from '@noble/ed25519';
import type { Attestation, AttestationPayload, OwnerMandate } from '../src/types';
import { encodeDidKey } from '../src/did-key';
import {
  buildMandateProjection,
  mandateSigningBytes,
  signMandateProjection,
  verifyOwnerMandate,
  verifyOwnerMandates,
  signApproval,
  verifyApproval,
  type ApprovalObject,
} from '../src/mandate';
import { canonicalize } from '../src/canonicalize';

let priv: Uint8Array;
let did: string;

function payload(overrides: Partial<AttestationPayload> = {}): AttestationPayload {
  return {
    attestation_id: 'att-1',
    version: '0.6',
    profile_id: 'email@0.5',
    bounds_hash: 'sha256:' + 'a'.repeat(64),
    context_hash: 'sha256:' + 'b'.repeat(64),
    execution_context_hash: 'sha256:' + 'c'.repeat(64),
    resolved_owners: [did],
    gate_content_hashes: { intent: 'sha256:' + 'd'.repeat(64) },
    commitment_mode: 'review',
    issued_at: 1_767_139_200,
    expires_at: 1_767_225_600,
    ...overrides,
  };
}

async function signedEntry(p: AttestationPayload, nonce = 'nonce-1'): Promise<OwnerMandate> {
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

function attestation(p: AttestationPayload, entries: OwnerMandate[]): Attestation {
  return {
    header: { typ: 'HAP-attestation', alg: 'EdDSA' },
    payload: { ...p, owner_mandates: entries },
    signature: 'as-signature-not-under-test',
  };
}

beforeAll(async () => {
  priv = ed.utils.randomPrivateKey();
  did = encodeDidKey(await ed.getPublicKeyAsync(priv));
});

describe('HAP-mandate', () => {
  it('a signed projection reconstructed from the attestation verifies with the key in the DID', async () => {
    const p = payload();
    const entry = await signedEntry(p);
    await expect(verifyOwnerMandate(attestation(p, [entry]), entry)).resolves.toBeUndefined();
  });

  it('projection omits intent_disclosure_hash iff the attestation carries none (defined absence)', () => {
    const without = buildMandateProjection(payload(), { did, nonce: 'n' });
    expect('intent_disclosure_hash' in without).toBe(false);
    const withHash = buildMandateProjection(
      payload({ intent_disclosure_hash: 'sha256:' + 'e'.repeat(64) }),
      { did, nonce: 'n' },
    );
    expect(withHash.intent_disclosure_hash).toBe('sha256:' + 'e'.repeat(64));
    // and the two canonical forms differ — absence is part of the signed bytes
    expect(canonicalize(without)).not.toBe(canonicalize(withHash));
  });

  it('TAMPER: flipping commitment_mode review→automatic breaks the signature', async () => {
    const p = payload({ commitment_mode: 'review' });
    const entry = await signedEntry(p);
    const flipped = attestation(payload({ commitment_mode: 'automatic' }), [entry]);
    await expect(verifyOwnerMandate(flipped, entry)).rejects.toThrow(/MANDATE_SIGNATURE_INVALID/);
  });

  it('TAMPER: extending expires_at breaks the signature (the replay defence)', async () => {
    const p = payload();
    const entry = await signedEntry(p);
    const extended = attestation(payload({ expires_at: p.expires_at + 86_400 }), [entry]);
    await expect(verifyOwnerMandate(extended, entry)).rejects.toThrow(/MANDATE_SIGNATURE_INVALID/);
  });

  it('TAMPER: swapping intent_disclosure_hash (the frozen approver set) breaks the signature', async () => {
    const p = payload({ intent_disclosure_hash: 'sha256:' + 'e'.repeat(64) });
    const entry = await signedEntry(p);
    const swapped = attestation(payload({ intent_disclosure_hash: 'sha256:' + 'f'.repeat(64) }), [entry]);
    await expect(verifyOwnerMandate(swapped, entry)).rejects.toThrow(/MANDATE_SIGNATURE_INVALID/);
  });

  it('rejects a signing DID that is not in resolved_owners', async () => {
    const p = payload();
    const entry = await signedEntry(p);
    const foreign = attestation(payload({ resolved_owners: ['did:key:z6MkOtherOwner'] }), [entry]);
    await expect(verifyOwnerMandate(foreign, entry)).rejects.toThrow(/OWNER_NOT_RESOLVED/);
  });

  it('rejects a non-key-bearing signing DID structurally — there is no public_key to fall back to', async () => {
    const p = payload({ resolved_owners: ['did:key:1a2b3c4d'] });
    const entry: OwnerMandate = { ...(await signedEntry(payload())), did: 'did:key:1a2b3c4d' };
    await expect(verifyOwnerMandate(attestation(p, [entry]), entry)).rejects.toThrow(/NOT_KEY_BEARING/);
  });

  it('the DID is authoritative over alg — a disagreeing alg is invalid, never a fallback', async () => {
    const p = payload();
    const entry = { ...(await signedEntry(p)), alg: 'ES256' as const };
    await expect(verifyOwnerMandate(attestation(p, [entry]), entry)).rejects.toThrow(/MANDATE_SIGNATURE_INVALID/);
  });

  it('verifyOwnerMandates: none present resolves to [] — the v0.5 posture, nothing claimed', async () => {
    const att = { header: { typ: 'HAP-attestation', alg: 'EdDSA' }, payload: payload(), signature: 's' } as Attestation;
    await expect(verifyOwnerMandates(att)).resolves.toEqual([]);
  });
});

describe('HAP-approval', () => {
  const approval: ApprovalObject = {
    typ: 'HAP-approval',
    version: '0.6',
    proposal_id: 'prop-1',
    attestation_id: 'att-1',
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

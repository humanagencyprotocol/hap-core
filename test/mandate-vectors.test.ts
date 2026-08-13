/**
 * Mandate-projection conformance vector (governance.md → Reference
 * Conformance, "Mandate-projection vectors — new in v0.6").
 *
 * A pinned (payload → canonical bytes → signature) triple so an INDEPENDENT
 * implementation can confirm canonicalization and signing parity — the same
 * role canonicalize.test.ts's signing vector plays for attestations. The key
 * is RFC 8032 §7.1 test vector 1's secret key; Ed25519 signing is
 * deterministic, so any correct implementation reproduces these exact bytes.
 *
 * If this test breaks, the projection's canonical form changed — which is a
 * BREAKING protocol change requiring a new projection version, not a test fix.
 */
import { describe, it, expect } from 'vitest';
import * as ed from '@noble/ed25519';
import type { AttestationPayload } from '../src/types';
import { encodeDidKey } from '../src/did-key';
import { buildMandateProjection, mandateSigningBytes, signMandateProjection } from '../src/mandate';

const PRIVATE_KEY_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const DID = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw';

const PAYLOAD: AttestationPayload = {
  attestation_id: 'vector-att-1',
  version: '0.6',
  profile_id: 'email@0.5',
  bounds_hash: 'sha256:' + '1'.repeat(64),
  context_hash: 'sha256:' + '2'.repeat(64),
  execution_context_hash: 'sha256:' + '3'.repeat(64),
  resolved_owners: [DID],
  gate_content_hashes: { intent: 'sha256:' + '4'.repeat(64) },
  commitment_mode: 'review',
  issued_at: 1767139200,
  expires_at: 1767225600,
};

const CANONICAL =
  '{"bounds_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111",' +
  '"commitment_mode":"review",' +
  '"context_hash":"sha256:2222222222222222222222222222222222222222222222222222222222222222",' +
  '"execution_context_hash":"sha256:3333333333333333333333333333333333333333333333333333333333333333",' +
  '"expires_at":1767225600,' +
  '"gate_content_hashes":{"intent":"sha256:4444444444444444444444444444444444444444444444444444444444444444"},' +
  '"nonce":"vector-nonce-1",' +
  '"owner_did":"did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",' +
  '"profile_id":"email@0.5",' +
  '"typ":"HAP-mandate",' +
  '"version":"0.6"}';

const SIGNATURE_B64URL =
  'yG3vlIubf7AeWUaBPwYPH9xRFg7bMxP9mHLGu5dv11h50k1rtS_TkKdUFMWv875E8r6jgca7S9HVA5K5IZx2DA';

describe('mandate-projection conformance vector', () => {
  it('the RFC 8032 test key encodes to the pinned DID', async () => {
    const pub = await ed.getPublicKeyAsync(Uint8Array.from(Buffer.from(PRIVATE_KEY_HEX, 'hex')));
    expect(encodeDidKey(pub)).toBe(DID);
  });

  it('the projection canonicalizes to the pinned bytes', () => {
    const projection = buildMandateProjection(PAYLOAD, { did: DID, nonce: 'vector-nonce-1' });
    expect(Buffer.from(mandateSigningBytes(projection)).toString('utf8')).toBe(CANONICAL);
  });

  it('signing the pinned bytes with the pinned key yields the pinned signature (deterministic Ed25519)', async () => {
    const projection = buildMandateProjection(PAYLOAD, { did: DID, nonce: 'vector-nonce-1' });
    const sig = await signMandateProjection(projection, Uint8Array.from(Buffer.from(PRIVATE_KEY_HEX, 'hex')));
    expect(sig).toBe(SIGNATURE_B64URL);
  });
});

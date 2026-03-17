/**
 * Test helpers — generate valid attestations for Gatekeeper tests.
 */

import * as ed from '@noble/ed25519';
import { computeFrameHash } from '../src/frame';
import { encodeAttestationBlob } from '../src/attestation';
import type { AgentFrameParams, AgentProfile, Attestation, AttestationPayload } from '../src/types';

export interface TestKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
}

/**
 * Generate an Ed25519 keypair for testing.
 */
export async function generateTestKeyPair(): Promise<TestKeyPair> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return {
    privateKey,
    publicKey,
    publicKeyHex: Buffer.from(publicKey).toString('hex'),
  };
}

/**
 * Create a signed attestation blob for testing.
 */
export async function createTestAttestation(opts: {
  keyPair: TestKeyPair;
  frame: AgentFrameParams;
  profile: AgentProfile;
  domain: string;
  expiresAt?: number;
  did?: string;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const frameHashValue = computeFrameHash(opts.frame, opts.profile);

  const payload: AttestationPayload = {
    attestation_id: `sha256:test-${Date.now()}`,
    version: '0.3',
    profile_id: opts.profile.id,
    frame_hash: frameHashValue,
    execution_context_hash: 'sha256:test-context',
    resolved_domains: [{ domain: opts.domain, did: opts.did ?? 'did:key:test' }],
    gate_content_hashes: {
      problem: 'sha256:test-problem',
      objective: 'sha256:test-objective',
      tradeoffs: 'sha256:test-tradeoffs',
    },
    issued_at: now,
    expires_at: opts.expiresAt ?? now + 3600,
  };

  const payloadJson = JSON.stringify(payload);
  const payloadBytes = new TextEncoder().encode(payloadJson);
  const signature = await ed.signAsync(payloadBytes, opts.keyPair.privateKey);
  const signatureBase64 = Buffer.from(signature).toString('base64');

  const attestation: Attestation = {
    header: { typ: 'HAP-attestation', alg: 'EdDSA' },
    payload,
    signature: signatureBase64,
  };

  return encodeAttestationBlob(attestation);
}

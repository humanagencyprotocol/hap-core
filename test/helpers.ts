/**
 * Test helpers — generate signed v0.7 mandates for Gatekeeper tests.
 */

import * as ed from '@noble/ed25519';
import { computeBoundsHash, computeScopeHash } from '../src/frame';
import { computeProfileHash } from '../src/profile';
import { signMandate, encodeMandateBlob } from '../src/mandate';
import { encodeDidKey } from '../src/did-key';
import type {
  AgentBoundsParams,
  AgentScopeParams,
  AgentProfile,
  MandatePayload,
  SignableCommitmentMode,
} from '../src/types';

export interface TestKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  /** Key-bearing did:key for this keypair — usable as a mandate `issuer` or
   * a `mandate_owners[].did`. */
  did: string;
}

/**
 * Generate an Ed25519 keypair for testing.
 */
export async function generateTestKeyPair(): Promise<TestKeyPair> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey, did: encodeDidKey(publicKey) };
}

/** A fixed-shape `sha256:`-prefixed placeholder — never checked for
 * provenance by the Gatekeeper, only for format and equality. */
function dummyHash(seed: string): string {
  return 'sha256:' + seed.repeat(64).slice(0, 64);
}

/**
 * Create a signed v0.7 mandate blob for testing.
 *
 * @param opts.keyPair The AS signing keypair — signs the mandate.
 * @param opts.issuerDid Override `payload.issuer` to something OTHER than
 * `keyPair.did` — the one way to construct a mandate whose signature does
 * not match its claimed issuer, for `INVALID_SIGNATURE` tests.
 * @param opts.ownerDid The Mandate Owner's DID (defaults to `keyPair.did` —
 * fine for tests that don't exercise owner co-signing).
 */
export async function createTestMandate(opts: {
  keyPair: TestKeyPair;
  bounds: AgentBoundsParams;
  profile: AgentProfile;
  scope?: AgentScopeParams;
  issuerDid?: string;
  ownerDid?: string;
  expiresAt?: number;
  commitmentMode?: SignableCommitmentMode | 'review_above_cap';
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const scope = opts.scope ?? {};

  const payload: MandatePayload = {
    mandate_id: `test-mandate-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    version: '0.7',
    profile_id: opts.profile.id,
    bounds_hash: computeBoundsHash(opts.bounds, opts.profile),
    scope_hash: computeScopeHash(scope, opts.profile),
    execution_context_hash: dummyHash('3'),
    profile_hash: computeProfileHash(opts.profile),
    issuer: opts.issuerDid ?? opts.keyPair.did,
    mandate_owners: [{ did: opts.ownerDid ?? opts.keyPair.did }],
    gate_content_hashes: { intent: dummyHash('4') },
    commitment_mode: opts.commitmentMode ?? 'automatic',
    issued_at: now,
    expires_at: opts.expiresAt ?? now + 3600,
  };

  const mandate = await signMandate(payload, opts.keyPair.privateKey);
  return encodeMandateBlob(mandate);
}

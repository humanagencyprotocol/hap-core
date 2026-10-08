/**
 * Conformance vectors — required-refusals.json.
 *
 * "The set that matters most: refusal is where the safety lives." This file
 * covers every row this package (hap-core: profile validation, Gatekeeper
 * local checks, version negotiation, owner-signature verification) can
 * decide on its own. Rows that require live Authority Server state — mandate
 * storage and lookup, cumulative ticket history, idempotency records, group
 * configuration, proposal lifecycle — are out of scope for a library with no
 * server and no store, and are named explicitly in the skip table at the
 * bottom rather than silently omitted.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verify } from '../../src/gatekeeper';
import { registerProfile, clearProfiles } from '../../src/profiles';
import { validateProfile, checkDiscloseSubset, computeProfileHash } from '../../src/profile';
import { canonicalBounds, computeBoundsHash } from '../../src/frame';
import { negotiateVersion } from '../../src/versions';
import { checkOwnerSignatureRequirement, verifyOwnerSignature } from '../../src/owner-signature';
import { signMandate, encodeMandateBlob } from '../../src/mandate';
import { encodeDidKey } from '../../src/did-key';
import * as ed from '@noble/ed25519';
import { VECTORS_DIR, haveVectors, requireVectors } from './_spec-dir';
import type { AgentProfile, MandatePayload, Mandate } from '../../src/types';

interface RefusalRow {
  id: string;
  situation: string;
  expected_error: string;
  note?: string;
}

requireVectors();

describe.skipIf(!haveVectors)('conformance vectors — required-refusals (hap-core-decidable rows)', () => {
  const file = JSON.parse(readFileSync(join(VECTORS_DIR, 'required-refusals.json'), 'utf8')) as {
    ticket_request_refusals: RefusalRow[];
    mandate_request_refusals: RefusalRow[];
    fail_closed_situations: Array<{ id: string; situation: string; required_behaviour: string }>;
  };
  const row = (id: string): RefusalRow => {
    const found = [...file.ticket_request_refusals, ...file.mandate_request_refusals].find((r) => r.id === id);
    if (!found) throw new Error(`required-refusals.json no longer has a row "${id}" — update this test`);
    return found;
  };

  it('every row this suite exercises still names the code this suite expects', () => {
    expect(row('no-action-type').expected_error).toBe('INVALID_ACTION_TYPE');
    expect(row('over-per-transaction-bound').expected_error).toBe('BOUND_EXCEEDED');
    expect(row('applies-to-unregistered').expected_error).toBe('PROFILE_INVALID');
    expect(row('count-bound-without-applies-to').expected_error).toBe('PROFILE_INVALID');
    expect(row('bound-without-bound-type').expected_error).toBe('PROFILE_INVALID');
    expect(row('applies-to-on-per-transaction').expected_error).toBe('PROFILE_INVALID');
    expect(row('disclose-not-a-subset').expected_error).toBe('MALFORMED_MANDATE');
    expect(row('raw-newline-in-value').expected_error).toBe('BOUNDS_INVALID_VALUE');
    expect(row('bounds-hash-mismatch').expected_error).toBe('BOUNDS_HASH_MISMATCH');
    expect(row('owner-signature-required').expected_error).toBe('OWNER_SIGNATURE_REQUIRED');
    expect(row('owner-signature-invalid').expected_error).toBe('OWNER_SIGNATURE_INVALID');
    expect(row('no-common-version').expected_error).toBe('VERSION_UNSUPPORTED');
  });

  // ── Profile validation (src/profile.ts → validateProfile) ──────────────────

  const baseProfile = (overrides: Partial<AgentProfile> = {}): AgentProfile => ({
    id: 'vector/refusals@0.7',
    version: '0.7',
    description: 'synthetic',
    executionContextSchema: { fields: {} },
    requiredGates: [],
    ttl: { default: 3600, max: 86400 },
    retention_minimum: 0,
    ...overrides,
  });

  it('applies-to-unregistered → PROFILE_INVALID', () => {
    const profile = baseProfile({
      boundsSchema: {
        actionTypes: ['charge'],
        keyOrder: ['profile', 'amount_max'],
        fields: {
          profile: { type: 'string', required: true },
          amount_max: {
            type: 'number', required: true,
            boundType: { kind: 'per_transaction', of: 'amount' },
            appliesTo: ['refund'], // "refund" is not registered
          },
        },
      },
    });
    const errors = validateProfile(profile);
    // appliesTo on a per_transaction bound is itself a separate violation
    // (applies-to-on-per-transaction) — use a cumulative bound instead so
    // only the unregistered-member violation is exercised.
    const cumulativeProfile = baseProfile({
      boundsSchema: {
        actionTypes: ['charge'],
        keyOrder: ['profile', 'amount_daily_max'],
        fields: {
          profile: { type: 'string', required: true },
          amount_daily_max: {
            type: 'number', required: true,
            boundType: { kind: 'cumulative_sum', of: 'amount', window: 'daily' },
            appliesTo: ['refund'],
          },
        },
      },
    });
    expect(validateProfile(cumulativeProfile).some((e) => e.code === 'PROFILE_INVALID')).toBe(true);
    expect(errors.some((e) => e.code === 'PROFILE_INVALID')).toBe(true); // also invalid, for the other reason
  });

  it('count-bound-without-applies-to → PROFILE_INVALID', () => {
    const profile = baseProfile({
      boundsSchema: {
        actionTypes: ['write', 'delete'],
        keyOrder: ['profile', 'write_daily_max'],
        fields: {
          profile: { type: 'string', required: true },
          write_daily_max: { type: 'number', required: true, boundType: { kind: 'cumulative_count', window: 'daily' } },
        },
      },
    });
    const errors = validateProfile(profile);
    expect(errors.some((e) => e.code === 'PROFILE_INVALID' && /appliesTo/.test(e.message))).toBe(true);
  });

  it('bound-without-bound-type → PROFILE_INVALID', () => {
    const profile = baseProfile({
      boundsSchema: {
        keyOrder: ['profile', 'amount_max'],
        fields: {
          profile: { type: 'string', required: true },
          amount_max: { type: 'number', required: true },
        },
      },
    });
    const errors = validateProfile(profile);
    expect(errors.some((e) => e.code === 'PROFILE_INVALID' && /boundType/.test(e.message))).toBe(true);
  });

  it('applies-to-on-per-transaction → PROFILE_INVALID', () => {
    const profile = baseProfile({
      boundsSchema: {
        actionTypes: ['charge', 'refund'],
        keyOrder: ['profile', 'amount_max'],
        fields: {
          profile: { type: 'string', required: true },
          amount_max: {
            type: 'number', required: true,
            boundType: { kind: 'per_transaction', of: 'amount' },
            appliesTo: ['charge'],
          },
        },
      },
    });
    const errors = validateProfile(profile);
    expect(errors.some((e) => e.code === 'PROFILE_INVALID' && /appliesTo MUST NOT/.test(e.message))).toBe(true);
  });

  // ── Mandate structure (src/profile.ts, src/frame.ts) ────────────────────────

  it('disclose-not-a-subset → MALFORMED_MANDATE', () => {
    expect(() => checkDiscloseSubset(['secret_field'], ['amount'])).toThrow(/MALFORMED_MANDATE/);
  });

  it('raw-newline-in-value → BOUNDS_INVALID_VALUE', () => {
    const profile = baseProfile({
      boundsSchema: {
        keyOrder: ['profile', 'note'],
        fields: {
          profile: { type: 'string', required: true },
          note: { type: 'string', required: false, boundType: { kind: 'per_transaction', of: 'note' } },
        },
      },
    });
    let code: unknown;
    try {
      canonicalBounds({ profile: profile.id, note: 'one\ntwo' }, profile);
    } catch (err) {
      code = (err as { code?: string }).code;
    }
    expect(code).toBe('BOUNDS_INVALID_VALUE');
  });

  // ── Gatekeeper local checks (src/gatekeeper.ts → verify) ────────────────────

  describe('gatekeeper.verify', () => {
    let keyPair: { privateKey: Uint8Array; did: string };
    const profile: AgentProfile = baseProfile({
      id: 'vector/gatekeeper-refusals@0.7',
      boundsSchema: {
        actionTypes: ['charge', 'refund'],
        keyOrder: ['profile', 'amount_max'],
        fields: {
          profile: { type: 'string', required: true },
          amount_max: { type: 'number', required: true, boundType: { kind: 'per_transaction', of: 'amount' } },
        },
      },
    });

    beforeAll(async () => {
      clearProfiles();
      registerProfile(profile.id, profile);
      const privateKey = ed.utils.randomPrivateKey();
      const did = encodeDidKey(await ed.getPublicKeyAsync(privateKey));
      keyPair = { privateKey, did };
    });

    async function mandateFor(bounds: Record<string, string | number>): Promise<string> {
      const payload: MandatePayload = {
        mandate_id: 'm-1', version: '0.7', profile_id: profile.id,
        bounds_hash: computeBoundsHash(bounds, profile),
        scope_hash: 'sha256:' + 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        execution_context_hash: 'sha256:' + 'c'.repeat(64),
        profile_hash: computeProfileHash(profile),
        issuer: keyPair.did,
        mandate_owners: [{ did: keyPair.did }],
        gate_content_hashes: { intent: 'sha256:' + 'd'.repeat(64) },
        commitment_mode: 'automatic',
        issued_at: Math.floor(Date.now() / 1000) - 10,
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      };
      const mandate: Mandate = await signMandate(payload, keyPair.privateKey);
      return encodeMandateBlob(mandate);
    }

    it('no-action-type → INVALID_ACTION_TYPE', async () => {
      const bounds = { profile: profile.id, amount_max: 100 };
      const blob = await mandateFor(bounds);
      const result = await verify({ bounds, mandates: [blob], execution: { amount: 50 } }); // no action_type
      expect(result.approved).toBe(false);
      if (!result.approved) expect(result.errors[0].code).toBe('INVALID_ACTION_TYPE');
    });

    it('over-per-transaction-bound → BOUND_EXCEEDED, never a cumulative or generic code', async () => {
      const bounds = { profile: profile.id, amount_max: 100 };
      const blob = await mandateFor(bounds);
      const result = await verify({ bounds, mandates: [blob], execution: { amount: 150, action_type: 'charge' } });
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some((e) => e.code === 'BOUND_EXCEEDED')).toBe(true);
        expect(result.errors.some((e) => e.code === 'CUMULATIVE_LIMIT_EXCEEDED')).toBe(false);
      }
    });

    it('bounds-hash-mismatch → BOUNDS_HASH_MISMATCH', async () => {
      const attestedBounds = { profile: profile.id, amount_max: 200 };
      const blob = await mandateFor(attestedBounds);
      const verifyBounds = { profile: profile.id, amount_max: 100 }; // different from what was signed
      const result = await verify({ bounds: verifyBounds, mandates: [blob], execution: { amount: 50, action_type: 'charge' } });
      expect(result.approved).toBe(false);
      if (!result.approved) expect(result.errors.some((e) => e.code === 'BOUNDS_HASH_MISMATCH')).toBe(true);
    });
  });

  // ── Version negotiation (src/versions.ts) ───────────────────────────────────

  it('no-common-version → VERSION_UNSUPPORTED', () => {
    expect(() => negotiateVersion(['0.5', '0.6'], ['0.7'])).toThrow(/VERSION_UNSUPPORTED/);
  });

  // ── Owner signatures (src/owner-signature.ts) ───────────────────────────────

  it('owner-signature-required → OWNER_SIGNATURE_REQUIRED', () => {
    const payload = {
      mandate_owners: [{ did: 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw' }],
    } as unknown as MandatePayload;
    expect(() => checkOwnerSignatureRequirement(payload, { required: true, minBinding: 'webauthn' }))
      .toThrow(/OWNER_SIGNATURE_REQUIRED/);
    // No floor declared, or floor not required → no refusal.
    expect(() => checkOwnerSignatureRequirement(payload, undefined)).not.toThrow();
    expect(() => checkOwnerSignatureRequirement(payload, { required: false })).not.toThrow();
  });

  it('owner-signature-invalid → OWNER_SIGNATURE_INVALID', async () => {
    const privateKey = ed.utils.randomPrivateKey();
    const did = encodeDidKey(await ed.getPublicKeyAsync(privateKey));
    const payload: MandatePayload = {
      mandate_id: 'm-2', version: '0.7', profile_id: 'p@0.1',
      bounds_hash: 'sha256:' + '1'.repeat(64), scope_hash: 'sha256:' + '2'.repeat(64),
      execution_context_hash: 'sha256:' + '3'.repeat(64), profile_hash: 'sha256:' + '5'.repeat(64),
      issuer: 'did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT',
      mandate_owners: [{ did, alg: 'EdDSA', signature: 'not-a-real-signature-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', signed_at: 1, nonce: 'n', binding: 'raw' }],
      gate_content_hashes: { intent: 'sha256:' + '4'.repeat(64) },
      commitment_mode: 'review', issued_at: 1_767_139_200, expires_at: 1_767_225_600,
    };
    const mandate: Mandate = { header: { typ: 'HAP-mandate', alg: 'EdDSA' }, payload, signature: 'as-sig-not-under-test' };
    await expect(verifyOwnerSignature(mandate, payload.mandate_owners[0])).rejects.toThrow(/OWNER_SIGNATURE_INVALID/);
  });

  // ── AS-only rows: Phase 1 ────────────────────────────────────────────────────
  //
  // Every remaining row requires live Authority Server state this package
  // does not model: a mandate store keyed by boundsHash, ticket history for
  // cumulative totals and idempotency, group/approver configuration, and the
  // proposal lifecycle. hap-core supplies the primitives (hashing, signing,
  // verification) the AS composes into these checks; the checks themselves
  // belong to suveren-as (or any other Authority Server implementation).
  const AS_ONLY_TICKET_ROWS = [
    'unknown-bounds-hash',       // MANDATE_NOT_FOUND — AS mandate store lookup
    'expired-mandate',           // MANDATE_EXPIRED — AS-authoritative mandate record
    'revoked-mandate',           // MANDATE_REVOKED — AS revocation list
    'over-cumulative-bound',     // CUMULATIVE_LIMIT_EXCEEDED — AS ticket history (by design, Gatekeeper never decides this)
    'review-without-proposal',   // PROPOSAL_REQUIRED — AS proposal lifecycle
    'above-cap',                 // APPROVAL_REQUIRED — AS group cap configuration
    'missing-idempotency-key',   // IDEMPOTENCY_KEY_REQUIRED — AS ticket-issuance request validation
    'reused-idempotency-key',    // IDEMPOTENCY_MISMATCH — AS idempotency store
    'retired-identifier',        // MALFORMED_TICKET_REQUEST — AS wire-request validation
    'unknown-profile',           // PROFILE_NOT_FOUND (ticket path) — AS profile-bytes retention
    'coverage-insufficient',     // COVERAGE_INSUFFICIENT — AS group/approver coverage
  ] as const;

  const AS_ONLY_MANDATE_ROWS = [
    'profile-hash-mismatch',        // PROFILE_HASH_MISMATCH — AS's own provisioned profile bytes
    'missing-scope-hash',           // MALFORMED_MANDATE — AS mandate-REQUEST schema validation
    'bounds-hash-only',              // MALFORMED_MANDATE — AS mandate-REQUEST schema validation
    'owner-not-approver',            // OWNER_NOT_APPROVER — AS group configuration (who is a required approver)
    'cosigned-without-expires-at',   // MALFORMED_MANDATE — AS mandate-REQUEST schema validation
    'expires-at-without-signature',  // MALFORMED_MANDATE — AS mandate-REQUEST schema validation
    'expires-at-beyond-profile-max', // MALFORMED_MANDATE — AS mandate-REQUEST schema validation (profile ttl.max)
    'nonce-reused',                   // MALFORMED_MANDATE — AS nonce-replay store
  ] as const;

  it('every AS-only row named above still exists in the vector file (names a real row, not a stale one)', () => {
    for (const id of AS_ONLY_TICKET_ROWS) expect(file.ticket_request_refusals.some((r) => r.id === id), id).toBe(true);
    for (const id of AS_ONLY_MANDATE_ROWS) expect(file.mandate_request_refusals.some((r) => r.id === id), id).toBe(true);
  });

  it('every row in the vector file is accounted for — decided here, or named AS-only above', () => {
    const decidedHere = new Set([
      'no-action-type', 'over-per-transaction-bound', 'applies-to-unregistered',
      'count-bound-without-applies-to', 'bound-without-bound-type', 'applies-to-on-per-transaction',
      'disclose-not-a-subset', 'raw-newline-in-value', 'bounds-hash-mismatch',
      'owner-signature-required', 'owner-signature-invalid', 'no-common-version',
    ]);
    const allRows = [
      ...file.ticket_request_refusals.map((r) => r.id),
      ...file.mandate_request_refusals.map((r) => r.id),
    ];
    const unaccounted = allRows.filter(
      (id) => !decidedHere.has(id) && !AS_ONLY_TICKET_ROWS.includes(id as never) && !AS_ONLY_MANDATE_ROWS.includes(id as never),
    );
    expect(unaccounted, `unaccounted required-refusals rows: ${unaccounted.join(', ')}`).toEqual([]);
  });

  // `fail_closed_situations` (as-unreachable, unarchivable-ticket, read-window
  // and read-governance denials, unmanifested-tool, commitment-mode
  // disagreement) describe GATEWAY/EXECUTOR runtime behaviour — network
  // reachability, local archive writes, tool-manifest loading — none of
  // which hap-core implements or has state for. They belong to suveren-gateway.
  it('fail_closed_situations rows are all gateway/AS runtime behaviour, out of hap-core scope', () => {
    expect(file.fail_closed_situations.length).toBeGreaterThan(0);
  });
});

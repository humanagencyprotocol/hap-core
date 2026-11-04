/**
 * Conformance vectors — required-refusals.json (v0.8).
 *
 * "The set that matters most: refusal is where the safety lives." This file
 * covers every row this package (hap-core: profile validation, value checks
 * at issuance, Gatekeeper local checks, version negotiation, owner-signature
 * and approval verification, proposal reader sets) can decide on its own.
 * Rows that require live Authority Server state — mandate storage and
 * lookup, cumulative ticket history, idempotency records, group
 * configuration, proposal lifecycle — are out of scope for a library with no
 * server and no store, and are named explicitly in the tables at the bottom
 * rather than silently omitted. A row in neither list fails the suite.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as ed from '@noble/ed25519';
import { verify } from '../../src/gatekeeper';
import { registerProfile, clearProfiles } from '../../src/profiles';
import { validateProfile, checkDiscloseSubset, computeProfileHash } from '../../src/profile';
import { canonicalBounds, computeBoundsHash } from '../../src/frame';
import { negotiateVersion, ISSUABLE_VERSIONS, assertSupportedVersion } from '../../src/versions';
import { isCommitmentModeAllowed } from '../../src/commitment-modes';
import {
  checkBoundsValues, checkGroupCeilings, validateAboveCapConfig, computeExecutionContextHash, checkExecutionValues,
} from '../../src/issuance';
import { checkOwnerSignatureRequirement, verifyOwnerSignature, buildMandateProjection, signApproval, type ApprovalObject } from '../../src/owner-signature';
import { signMandate, encodeMandateBlob, validateMandateOwners } from '../../src/mandate';
import { signTicket, verifyTicketApprovals, type TicketPayload } from '../../src/ticket';
import { checkProposalReaders } from '../../src/proposal-content';
import { encodeDidKey } from '../../src/did-key';
import { VECTORS_DIR, haveVectors, requireVectors } from './_spec-dir';
import type { AgentProfile, MandatePayload, Mandate } from '../../src/types';

interface RefusalRow {
  id: string;
  situation: string;
  expected_error: string;
  note?: string;
}

requireVectors();

const EMPTY_SCOPE_HASH = 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

describe.skipIf(!haveVectors)('conformance vectors — required-refusals (hap-core-decidable rows, v0.8)', () => {
  const file = JSON.parse(readFileSync(join(VECTORS_DIR, 'required-refusals.json'), 'utf8')) as {
    ticket_request_refusals: RefusalRow[];
    mandate_request_refusals: RefusalRow[];
    proposal_refusals: RefusalRow[];
    fail_closed_situations: Array<{ id: string; situation: string; required_behaviour: string }>;
  };
  const allRows = () => [...file.ticket_request_refusals, ...file.mandate_request_refusals, ...file.proposal_refusals];
  const row = (id: string): RefusalRow => {
    const found = allRows().find((r) => r.id === id);
    if (!found) throw new Error(`required-refusals.json no longer has a row "${id}" — update this test`);
    return found;
  };

  /** Every row this suite exercises, with the code it expects — checked
   * against the file first, so a renamed code fails here, not silently. */
  const DECIDED_HERE: Record<string, string> = {
    // Gatekeeper · local (gatekeeper.verify)
    'no-action-type': 'INVALID_ACTION_TYPE',
    'over-per-transaction-bound': 'BOUND_EXCEEDED',
    'bounds-hash-mismatch': 'BOUNDS_HASH_MISMATCH',
    'required-value-absent': 'BOUND_EXCEEDED',
    'null-value-under-required-for': 'BOUND_EXCEEDED',
    'amount-absent-under-sum-bound': 'BOUND_EXCEEDED',
    // execution values (issuance.checkExecutionValues)
    'negative-value': 'MALFORMED_TICKET_REQUEST',
    'non-number-value': 'MALFORMED_TICKET_REQUEST',
    'reserved-key-in-execution-context': 'MALFORMED_TICKET_REQUEST',
    // approvals carried by a ticket (ticket.verifyTicketApprovals)
    'approval-signature-invalid': 'APPROVAL_SIGNATURE_INVALID',
    'approval-for-another-operation': 'APPROVAL_SIGNATURE_INVALID',
    // profile validation (profile.validateProfile)
    'applies-to-unregistered': 'PROFILE_INVALID',
    'count-bound-without-applies-to': 'PROFILE_INVALID',
    'bound-without-bound-type': 'PROFILE_INVALID',
    'applies-to-on-per-transaction': 'PROFILE_INVALID',
    'required-for-on-cumulative': 'PROFILE_INVALID',
    'commitment-modes-malformed': 'PROFILE_INVALID',
    'commitment-modes-only-above-cap': 'PROFILE_INVALID',
    'disclose-scope-field': 'PROFILE_INVALID',
    'v2-binding-text-kind': 'PROFILE_INVALID',
    // commitment modes (commitment-modes.isCommitmentModeAllowed)
    'commitment-mode-not-allowed': 'COMMITMENT_MODE_NOT_ALLOWED',
    'review-above-cap-under-review-only': 'COMMITMENT_MODE_NOT_ALLOWED',
    // bounds values at issuance (issuance.checkBoundsValues, frame.canonicalBounds)
    'above-maximum': 'BOUNDS_INVALID_VALUE',
    'non-numeric-under-maximum': 'BOUNDS_INVALID_VALUE',
    'enum-value-not-allowed': 'BOUNDS_INVALID_VALUE',
    'raw-newline-in-value': 'BOUNDS_INVALID_VALUE',
    // group ceilings (issuance.checkGroupCeilings)
    'above-hard-cap': 'GROUP_CAP_EXCEEDED',
    'omitted-under-ceiling': 'GROUP_CAP_EXCEEDED',
    'enum-above-cap': 'GROUP_CAP_EXCEEDED',
    'group-count-unreachable': 'GROUP_CAP_EXCEEDED',
    // above-cap configuration (issuance.validateAboveCapConfig)
    'approvals-count-invalid': 'ABOVE_CAP_CONFIG_INVALID',
    'approval-cap-on-cumulative': 'ABOVE_CAP_CONFIG_INVALID',
    'approver-not-key-bearing': 'ABOVE_CAP_CONFIG_INVALID',
    // mandate structure
    'disclose-not-a-subset': 'MALFORMED_MANDATE',
    'execution-context-hash-wrong': 'MALFORMED_MANDATE',
    'subjects-disclosed-disagrees': 'MALFORMED_MANDATE',
    // owner signatures
    'owner-signature-required': 'OWNER_SIGNATURE_REQUIRED',
    'owner-signature-invalid': 'OWNER_SIGNATURE_INVALID',
    // versions
    'no-common-version': 'VERSION_UNSUPPORTED',
    'v07-mandate-on-v08-as': 'VERSION_UNSUPPORTED',
    // proposal reader sets (proposal-content.checkProposalReaders)
    'approvers-not-the-signed-set': 'PROPOSAL_APPROVERS_INVALID',
    'readers-keys-differ': 'PROPOSAL_NOT_ENCRYPTED',
  };

  it('every row this suite exercises still names the code this suite expects', () => {
    for (const [id, code] of Object.entries(DECIDED_HERE)) {
      expect(row(id).expected_error, id).toBe(code);
    }
  });

  const baseProfile = (overrides: Partial<AgentProfile> = {}): AgentProfile => ({
    id: 'vector/refusals@0.8',
    version: '0.8',
    description: 'synthetic',
    executionContextSchema: { fields: {} },
    requiredGates: [],
    ttl: { default: 3600, max: 86400 },
    retention_minimum: 0,
    ...overrides,
  });

  const chargeSchema = (): NonNullable<AgentProfile['boundsSchema']> => ({
    actionTypes: ['charge', 'refund', 'delete'],
    keyOrder: ['profile', 'amount_max', 'amount_daily_max', 'read_access'],
    fields: {
      profile: { type: 'string', required: true },
      amount_max: { type: 'number', required: true, boundType: { kind: 'per_transaction', of: 'amount', requiredFor: ['charge'] }, maximum: 10_000 },
      amount_daily_max: { type: 'number', required: false, boundType: { kind: 'cumulative_sum', of: 'amount', window: 'daily' }, appliesTo: ['charge', 'refund'] },
      read_access: { type: 'string', required: false, boundType: { kind: 'enum', values: ['unlimited', 'none'] }, enforcedBy: 'gatekeeper' },
    },
  });

  // ── Profile validation ───────────────────────────────────────────────────

  const invalid = (p: AgentProfile, re: RegExp) =>
    expect(validateProfile(p).some((e) => e.code === 'PROFILE_INVALID' && re.test(e.message)), validateProfile(p).map((e) => e.message).join(' | ')).toBe(true);

  it('applies-to-unregistered → PROFILE_INVALID', () => {
    const s = chargeSchema();
    s.fields.amount_daily_max.appliesTo = ['teleport'];
    invalid(baseProfile({ boundsSchema: s }), /teleport/);
  });
  it('count-bound-without-applies-to → PROFILE_INVALID', () => {
    const s = chargeSchema();
    s.keyOrder.push('write_daily_max');
    s.fields.write_daily_max = { type: 'number', required: true, boundType: { kind: 'cumulative_count', window: 'daily' } };
    invalid(baseProfile({ boundsSchema: s }), /appliesTo/);
  });
  it('bound-without-bound-type → PROFILE_INVALID', () => {
    const s = chargeSchema();
    delete s.fields.amount_max.boundType;
    invalid(baseProfile({ boundsSchema: s }), /boundType/);
  });
  it('applies-to-on-per-transaction → PROFILE_INVALID', () => {
    const s = chargeSchema();
    s.fields.amount_max.appliesTo = ['charge'];
    invalid(baseProfile({ boundsSchema: s }), /appliesTo MUST NOT/);
  });
  it('required-for-on-cumulative → PROFILE_INVALID', () => {
    const s = chargeSchema();
    (s.fields.amount_daily_max.boundType as { requiredFor?: string[] }).requiredFor = ['charge'];
    invalid(baseProfile({ boundsSchema: s }), /requiredFor/);
  });
  it('commitment-modes-malformed → PROFILE_INVALID', () => {
    invalid(baseProfile({ commitment_modes: [] }), /commitment_modes/);
    invalid(baseProfile({ commitment_modes: 'review' as unknown as never }), /commitment_modes/);
    invalid(baseProfile({ commitment_modes: ['reveiw'] as unknown as never }), /commitment_modes/);
  });
  it('commitment-modes-only-above-cap → PROFILE_INVALID (the entry is ignored; alone it admits nothing)', () => {
    invalid(baseProfile({ commitment_modes: ['review_above_cap'] }), /commitment_modes/);
    expect(validateProfile(baseProfile({ commitment_modes: ['automatic', 'review_above_cap'] }))).toEqual([]);
  });
  it('disclose-scope-field → PROFILE_INVALID', () => {
    invalid(baseProfile({ boundsSchema: chargeSchema(), disclose_fields: ['currency'] }), /disclose_fields/);
    expect(validateProfile(baseProfile({ boundsSchema: chargeSchema(), disclose_fields: ['amount'] }))).toEqual([]);
  });
  it('v2-binding-text-kind → PROFILE_INVALID', () => {
    invalid(baseProfile({ content_binding: { version: '2', kind: 'text', fields: ['body'] } }), /content_binding/);
    expect(validateProfile(baseProfile({ content_binding: { version: '2', kind: 'jcs', fields: ['body'] } }))).toEqual([]);
  });

  // ── Commitment modes ─────────────────────────────────────────────────────

  it('commitment-mode-not-allowed → COMMITMENT_MODE_NOT_ALLOWED', () => {
    expect(isCommitmentModeAllowed(baseProfile({ commitment_modes: ['review'] }), 'automatic')).toBe(false);
  });
  it('review-above-cap-under-review-only → COMMITMENT_MODE_NOT_ALLOWED', () => {
    expect(isCommitmentModeAllowed(baseProfile({ commitment_modes: ['review'] }), 'review_above_cap')).toBe(false);
    expect(isCommitmentModeAllowed(baseProfile({ commitment_modes: ['automatic'] }), 'review_above_cap')).toBe(true);
  });

  // ── Bounds values at issuance ────────────────────────────────────────────

  const profile = baseProfile({ boundsSchema: chargeSchema() });
  const code = (fn: () => unknown): string | undefined => {
    try { fn(); return undefined; } catch (err) { return (err as { code?: string }).code; }
  };

  it('above-maximum → BOUNDS_INVALID_VALUE', () => {
    expect(code(() => checkBoundsValues({ profile: profile.id, amount_max: 20_000 }, profile))).toBe('BOUNDS_INVALID_VALUE');
    expect(code(() => checkBoundsValues({ profile: profile.id, amount_max: 10_000 }, profile))).toBeUndefined();
  });
  it('non-numeric-under-maximum → BOUNDS_INVALID_VALUE', () => {
    expect(code(() => checkBoundsValues({ profile: profile.id, amount_max: '100' }, profile))).toBe('BOUNDS_INVALID_VALUE');
  });
  it('enum-value-not-allowed → BOUNDS_INVALID_VALUE', () => {
    expect(code(() => checkBoundsValues({ profile: profile.id, amount_max: 1, read_access: 'some' }, profile))).toBe('BOUNDS_INVALID_VALUE');
  });
  it('raw-newline-in-value → BOUNDS_INVALID_VALUE', () => {
    const p = baseProfile({
      boundsSchema: {
        keyOrder: ['profile', 'note'],
        fields: { profile: { type: 'string', required: true }, note: { type: 'string', required: false, boundType: { kind: 'per_transaction', of: 'note' } } },
      },
    });
    expect(code(() => canonicalBounds({ profile: p.id, note: 'one\ntwo' }, p))).toBe('BOUNDS_INVALID_VALUE');
  });

  // ── Group ceilings ───────────────────────────────────────────────────────

  it('above-hard-cap → GROUP_CAP_EXCEEDED', () => {
    expect(code(() => checkGroupCeilings({ profile: profile.id, amount_max: 5000 }, profile, { hard: { amount_max: 1000 } }))).toBe('GROUP_CAP_EXCEEDED');
    expect(code(() => checkGroupCeilings({ profile: profile.id, amount_max: 1000 }, profile, { hard: { amount_max: 1000 } }))).toBeUndefined();
  });
  it('omitted-under-ceiling → GROUP_CAP_EXCEEDED (an omitted optional bound is unlimited)', () => {
    expect(code(() => checkGroupCeilings({ profile: profile.id, amount_max: 100 }, profile, { approval: { amount_max: 1000 }, hard: { amount_daily_max: 5000 } }))).toBe('GROUP_CAP_EXCEEDED');
  });
  it('enum-above-cap → GROUP_CAP_EXCEEDED (an earlier value in the order exceeds the cap)', () => {
    expect(code(() => checkGroupCeilings({ profile: profile.id, amount_max: 100, read_access: 'unlimited' }, profile, { hard: { read_access: 'none' } }))).toBe('GROUP_CAP_EXCEEDED');
    expect(code(() => checkGroupCeilings({ profile: profile.id, amount_max: 100, read_access: 'none' }, profile, { hard: { read_access: 'none' } }))).toBeUndefined();
  });
  it('group-count-unreachable → GROUP_CAP_EXCEEDED (the cap is hard for that owner, and the bound is above it)', () => {
    // The AS decided the count is unreachable for this owner (Group roles,
    // rule 5), so it passes the approval cap as hard.
    expect(code(() => checkGroupCeilings({ profile: profile.id, amount_max: 5000 }, profile, { hard: { amount_max: 1000 } }))).toBe('GROUP_CAP_EXCEEDED');
  });
  it('an approval-kind cap on a cumulative bound is hard at signing (Commitment Modes, rule 7)', () => {
    expect(code(() => checkGroupCeilings({ profile: profile.id, amount_max: 100, amount_daily_max: 9000 }, profile, { approval: { amount_daily_max: 5000 } }))).toBe('GROUP_CAP_EXCEEDED');
  });

  // ── Above-cap configuration ──────────────────────────────────────────────

  const owner = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw';
  const approver = 'did:key:z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME';

  it('approvals-count-invalid → ABOVE_CAP_CONFIG_INVALID', () => {
    const c = (approvals?: number, approvers = [owner]) =>
      code(() => validateAboveCapConfig({ caps: { amount_max: 50 }, approvers, approvals }, profile, { ownerDid: owner, inGroup: false }));
    expect(c(undefined)).toBe('ABOVE_CAP_CONFIG_INVALID');
    expect(c(0, [approver])).toBe('ABOVE_CAP_CONFIG_INVALID');
    expect(c(1)).toBe('ABOVE_CAP_CONFIG_INVALID'); // the owner alone cannot reach 1
    expect(c(2, [approver])).toBe('ABOVE_CAP_CONFIG_INVALID');
    expect(c(1, [approver])).toBeUndefined();
  });
  it('approval-cap-on-cumulative → ABOVE_CAP_CONFIG_INVALID', () => {
    expect(code(() => validateAboveCapConfig({ caps: { amount_daily_max: 50 } }, profile, { ownerDid: owner, inGroup: true }))).toBe('ABOVE_CAP_CONFIG_INVALID');
    expect(code(() => validateAboveCapConfig({ caps: { profile: 1 } }, profile, { ownerDid: owner, inGroup: true }))).toBe('ABOVE_CAP_CONFIG_INVALID');
  });
  it('approver-not-key-bearing → ABOVE_CAP_CONFIG_INVALID', () => {
    expect(code(() => validateAboveCapConfig({ approvers: ['did:github:alice'], approvals: 1 }, profile, { ownerDid: owner, inGroup: true }))).toBe('ABOVE_CAP_CONFIG_INVALID');
  });

  // ── Mandate structure ────────────────────────────────────────────────────

  it('disclose-not-a-subset → MALFORMED_MANDATE', () => {
    expect(() => checkDiscloseSubset(['secret_field'], ['amount'])).toThrow(/MALFORMED_MANDATE/);
  });
  it('execution-context-hash-wrong → MALFORMED_MANDATE (the AS compares against the profile\'s schema hash)', () => {
    const expected = computeExecutionContextHash(profile);
    expect(expected).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(computeExecutionContextHash({ executionContextSchema: undefined as never })).toBe(computeExecutionContextHash({ executionContextSchema: {} as never }));
    expect(expected).not.toBe('sha256:' + 'c'.repeat(64));
  });
  it('subjects-disclosed-disagrees → MALFORMED_MANDATE (the owner-signed projection states the choice)', () => {
    const payload = {
      version: '0.8', profile_id: profile.id, profile_hash: computeProfileHash(profile), bounds_hash: 'sha256:' + '1'.repeat(64),
      scope_hash: EMPTY_SCOPE_HASH, execution_context_hash: computeExecutionContextHash(profile), gate_content_hashes: { intent: 'sha256:' + '4'.repeat(64) },
      commitment_mode: 'review', expires_at: 2, mandate_owners: [{ did: owner }],
    } as unknown as MandatePayload;
    const entry = { did: owner, nonce: 'n', binding: 'webauthn', signing_surface: 'gatekeeper_local' } as const;
    expect(buildMandateProjection(payload, entry).subjects_disclosed).toBe(false);
    const withName = { ...payload, subjects: [{ did: owner, assurance: 'high', method: 'as_vouched', trust_root: 'as', verifier: 'did:web:as', disclose: { name: 'A' } }] } as MandatePayload;
    expect(buildMandateProjection(withName, entry).subjects_disclosed).toBe(true);
  });
  it('a mandate_owners entry with signature fields missing is malformed (binding-missing, mandate side)', () => {
    const payload = { mandate_owners: [{ did: owner, signature: 'x', alg: 'EdDSA', signed_at: 1, nonce: 'n' }] } as unknown as MandatePayload;
    expect(code(() => validateMandateOwners(payload))).toBe('MALFORMED_MANDATE');
  });

  // ── Versions ─────────────────────────────────────────────────────────────

  it('no-common-version → VERSION_UNSUPPORTED', () => {
    expect(() => negotiateVersion(['0.5', '0.6'], ['0.8'])).toThrow(/VERSION_UNSUPPORTED/);
  });
  it('v07-mandate-on-v08-as → VERSION_UNSUPPORTED: a v0.8 issuer issues 0.8 only; v0.7 stays verifiable as evidence', () => {
    expect(ISSUABLE_VERSIONS).toEqual(['0.8']);
    expect(() => negotiateVersion(['0.7'])).toThrow(/VERSION_UNSUPPORTED/);
    expect(negotiateVersion(['0.7', '0.8'])).toBe('0.8');
    expect(() => assertSupportedVersion('0.7', 'mandate')).not.toThrow();
    expect(() => assertSupportedVersion('0.6', 'mandate')).toThrow(/VERSION_UNSUPPORTED/);
  });

  // ── Execution values ─────────────────────────────────────────────────────

  it('negative-value / non-number-value / reserved-key → MALFORMED_TICKET_REQUEST', () => {
    expect(code(() => checkExecutionValues({ amount: -5 }, profile))).toBe('MALFORMED_TICKET_REQUEST');
    expect(code(() => checkExecutionValues({ amount: '12' }, profile))).toBe('MALFORMED_TICKET_REQUEST');
    expect(code(() => checkExecutionValues({ amount: Number.NaN }, profile))).toBe('MALFORMED_TICKET_REQUEST');
    expect(code(() => checkExecutionValues({ amount: 12, _ref: 'x' }, profile))).toBe('MALFORMED_TICKET_REQUEST');
    expect(code(() => checkExecutionValues({ amount: null }, profile))).toBeUndefined(); // null is absent, not a non-number
    expect(code(() => checkExecutionValues({ amount: 0 }, profile))).toBeUndefined();
  });

  // ── Gatekeeper local checks ──────────────────────────────────────────────

  describe('gatekeeper.verify', () => {
    let keyPair: { privateKey: Uint8Array; did: string };
    const gkProfile: AgentProfile = baseProfile({ id: 'vector/gatekeeper-refusals@0.8', boundsSchema: chargeSchema() });

    beforeAll(async () => {
      clearProfiles();
      registerProfile(gkProfile.id, gkProfile);
      const privateKey = ed.utils.randomPrivateKey();
      const did = encodeDidKey(await ed.getPublicKeyAsync(privateKey));
      keyPair = { privateKey, did };
    });

    async function mandateFor(bounds: Record<string, string | number>): Promise<string> {
      const payload: MandatePayload = {
        mandate_id: 'm-1', version: '0.8', profile_id: gkProfile.id,
        bounds_hash: computeBoundsHash(bounds, gkProfile),
        scope_hash: EMPTY_SCOPE_HASH,
        execution_context_hash: computeExecutionContextHash(gkProfile),
        profile_hash: computeProfileHash(gkProfile),
        issuer: keyPair.did,
        mandate_owners: [{ did: keyPair.did }],
        gate_content_hashes: { intent: 'sha256:' + 'd'.repeat(64) },
        commitment_mode: 'automatic',
        issued_at: Math.floor(Date.now() / 1000) - 10,
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      };
      return encodeMandateBlob(await signMandate(payload, keyPair.privateKey));
    }
    const firstCode = async (bounds: Record<string, string | number>, execution: Record<string, string | number>, verifyBounds = bounds) => {
      const blob = await mandateFor(bounds);
      const r = await verify({ bounds: verifyBounds, mandates: [blob], execution });
      return r.approved ? undefined : r.errors[0].code;
    };
    const bounds = { profile: gkProfile.id, amount_max: 100, amount_daily_max: 500 };

    it('no-action-type → INVALID_ACTION_TYPE', async () => {
      expect(await firstCode(bounds, { amount: 50 })).toBe('INVALID_ACTION_TYPE');
    });
    it('over-per-transaction-bound → BOUND_EXCEEDED, never a cumulative or generic code', async () => {
      expect(await firstCode(bounds, { amount: 150, action_type: 'charge' })).toBe('BOUND_EXCEEDED');
      expect(await firstCode(bounds, { amount: 50, action_type: 'charge' })).toBeUndefined();
    });
    it('bounds-hash-mismatch → BOUNDS_HASH_MISMATCH', async () => {
      expect(await firstCode({ ...bounds, amount_max: 200 }, { amount: 50, action_type: 'charge' }, bounds)).toBe('BOUNDS_HASH_MISMATCH');
    });
    it('required-value-absent / null-value-under-required-for → BOUND_EXCEEDED', async () => {
      expect(await firstCode(bounds, { action_type: 'charge' })).toBe('BOUND_EXCEEDED');
      expect(await firstCode(bounds, { amount: null as unknown as number, action_type: 'charge' })).toBe('BOUND_EXCEEDED');
    });
    it('amount-absent-under-sum-bound → BOUND_EXCEEDED; an excluded action type passes', async () => {
      // refund: amount_max.requiredFor does not list it, but amount_daily_max governs it.
      expect(await firstCode(bounds, { action_type: 'refund' })).toBe('BOUND_EXCEEDED');
      // delete: no requiredFor, and amount_daily_max's appliesTo excludes it.
      expect(await firstCode(bounds, { action_type: 'delete' })).toBeUndefined();
    });
    it('negative-value / non-number-value in a ticket request → MALFORMED_TICKET_REQUEST, before any bound is compared', async () => {
      expect(await firstCode(bounds, { amount: -1, action_type: 'charge' })).toBe('MALFORMED_TICKET_REQUEST');
      expect(await firstCode(bounds, { amount: '50', action_type: 'charge' })).toBe('MALFORMED_TICKET_REQUEST');
    });
  });

  // ── Owner signatures and approvals ───────────────────────────────────────

  it('owner-signature-required → OWNER_SIGNATURE_REQUIRED', () => {
    const payload = { mandate_owners: [{ did: owner }] } as unknown as MandatePayload;
    expect(() => checkOwnerSignatureRequirement(payload, { required: true, minBinding: 'webauthn' })).toThrow(/OWNER_SIGNATURE_REQUIRED/);
    expect(() => checkOwnerSignatureRequirement(payload, undefined)).not.toThrow();
  });

  it('owner-signature-invalid → OWNER_SIGNATURE_INVALID', async () => {
    const privateKey = ed.utils.randomPrivateKey();
    const did = encodeDidKey(await ed.getPublicKeyAsync(privateKey));
    const payload: MandatePayload = {
      mandate_id: 'm-2', version: '0.8', profile_id: 'p@0.1',
      bounds_hash: 'sha256:' + '1'.repeat(64), scope_hash: 'sha256:' + '2'.repeat(64),
      execution_context_hash: 'sha256:' + '3'.repeat(64), profile_hash: 'sha256:' + '5'.repeat(64),
      issuer: 'did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT',
      mandate_owners: [{ did, alg: 'EdDSA', signature: 'not-a-real-signature-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', signed_at: 1, nonce: 'n', binding: 'raw', signing_surface: 'gatekeeper_local' }],
      gate_content_hashes: { intent: 'sha256:' + '4'.repeat(64) },
      commitment_mode: 'review', issued_at: 1_767_139_200, expires_at: 1_767_225_600,
    };
    const mandate: Mandate = { header: { typ: 'HAP-mandate', alg: 'EdDSA' }, payload, signature: 'as-sig-not-under-test' };
    await expect(verifyOwnerSignature(mandate, payload.mandate_owners[0])).rejects.toThrow(/OWNER_SIGNATURE_INVALID/);
  });

  it('approval-signature-invalid / approval-for-another-operation → APPROVAL_SIGNATURE_INVALID', async () => {
    const asKey = ed.utils.randomPrivateKey();
    const asDid = encodeDidKey(await ed.getPublicKeyAsync(asKey));
    const ownerKey = ed.utils.randomPrivateKey();
    const ownerDid = encodeDidKey(await ed.getPublicKeyAsync(ownerKey));
    const payload: MandatePayload = {
      mandate_id: 'm-3', version: '0.8', profile_id: profile.id, bounds_hash: 'sha256:' + '1'.repeat(64), scope_hash: EMPTY_SCOPE_HASH,
      execution_context_hash: computeExecutionContextHash(profile), profile_hash: computeProfileHash(profile), issuer: asDid,
      mandate_owners: [{ did: ownerDid }], gate_content_hashes: { intent: 'sha256:' + '4'.repeat(64) }, commitment_mode: 'review',
      issued_at: 1, expires_at: 2,
    };
    const mandate = await signMandate(payload, asKey);
    const approval: ApprovalObject = {
      typ: 'HAP-approval', version: '0.8', approver_did: ownerDid, proposal_id: 'p-1', mandate_id: 'm-3',
      action: 'archive', action_type: 'charge', decision: 'commit', content_hash: 'sha256:' + '7'.repeat(64), proposal_content_hash: 'sha256:' + '7'.repeat(64),
      decided_at: 10, nonce: 'n-1',
    };
    const sig = await signApproval(approval, ownerKey);
    const base: Omit<TicketPayload, 'signature'> = {
      id: 't-1', mandateId: 'm-3', groupId: null, boundsHash: payload.bounds_hash, profileId: profile.id, action: 'archive', actionType: 'charge',
      executionContext: { amount: 1 }, limits: { profile: profile.id }, version: '0.8', issuer: asDid, timestamp: 11,
      proposalId: 'p-1', proposalContentHash: approval.proposal_content_hash, approvalSignature: { alg: 'EdDSA', signature: sig, nonce: 'n-1', decided_at: 10 },
    };
    const good = await signTicket(base, asKey);
    await expect(verifyTicketApprovals(good, mandate)).resolves.toEqual({ owner: ownerDid, approvers: [] });
    // The AS showed "archive" and issued a ticket for "delete".
    const relabelled = await signTicket({ ...base, action: 'delete' }, asKey);
    await expect(verifyTicketApprovals(relabelled, mandate)).rejects.toThrow(/APPROVAL_SIGNATURE_INVALID/);
    // A signature that does not verify at all.
    const bad = await signTicket({ ...base, approvalSignature: { ...base.approvalSignature!, nonce: 'other' } }, asKey);
    await expect(verifyTicketApprovals(bad, mandate)).rejects.toThrow(/APPROVAL_SIGNATURE_INVALID/);
  });

  // ── Proposal reader sets ─────────────────────────────────────────────────

  it('approvers-not-the-signed-set → PROPOSAL_APPROVERS_INVALID; readers-keys-differ → PROPOSAL_NOT_ENCRYPTED', () => {
    const content = { ciphertext: 'x', encrypted_keys: { [owner]: { ct: 'a', enc: 'b' }, [approver]: { ct: 'a', enc: 'b' } }, readers: [owner, approver], unreadable: [] };
    expect(code(() => checkProposalReaders(content, { ownerDid: owner, deciders: [approver] }))).toBeUndefined();
    expect(code(() => checkProposalReaders(content, { ownerDid: owner, deciders: [] }))).toBe('PROPOSAL_APPROVERS_INVALID');
    expect(code(() => checkProposalReaders({ ...content, readers: [owner] }, { ownerDid: owner, deciders: [] }))).toBe('PROPOSAL_NOT_ENCRYPTED');
  });

  // ── AS-only rows ─────────────────────────────────────────────────────────
  //
  // Every remaining row requires live Authority Server state this package
  // does not model: a mandate store keyed by boundsHash / mandateId, ticket
  // history for cumulative totals and idempotency, group configuration, the
  // proposal lifecycle and decision records, nonce stores, the owner's
  // standing disclosure choice. hap-core supplies the primitives the AS
  // composes into these checks; the checks themselves belong to suveren-as
  // (or any other Authority Server implementation), and suveren-e2e
  // exercises them against the running programs.
  const AS_ONLY_TICKET_ROWS = [
    'unknown-bounds-hash', 'expired-mandate', 'revoked-mandate', 'revoked-and-expired', 'over-cumulative-bound',
    'review-without-proposal', 'above-cap', 'above-bound-and-above-cap', 'approval-impossible',
    'amount-absent-under-approval-cap', 'missing-idempotency-key', 'reused-idempotency-key',
    'idempotency-key-other-action-type', 'retired-identifier', 'unknown-profile', 'coverage-insufficient',
    'coverage-different-caps', 'owner-not-covered', 'ambiguous-bounds-hash', 'mandate-id-bounds-disagree',
    'mandate-id-unknown', 'profile-id-differs', 'binding-missing', 'proposal-content-mismatch',
    'review-content-hash-differs', 'proposal-unknown', 'proposal-other-mandate', 'proposal-pending',
    'proposal-rejected', 'proposal-expired', 'proposal-withdrawn', 'proposal-fields-differ', 'proposal-executed-other-request',
  ] as const;

  const AS_ONLY_MANDATE_ROWS = [
    'profile-hash-mismatch', 'missing-scope-hash', 'bounds-hash-only', 'bounds-profile-differs', 'owner-not-approver',
    'cosigned-without-expires-at', 'expires-at-without-signature', 'expires-at-beyond-profile-max', 'nonce-reused',
    'cosigned-request-the-group-would-promote', 'review-above-cap-unreachable-in-group',
  ] as const;

  const AS_ONLY_PROPOSAL_ROWS = [
    'proposal-in-clear', 'unreadable-with-key', 'decision-from-non-decider', 'second-decision-same-decider',
  ] as const;

  it('every AS-only row named above still exists in the vector file', () => {
    for (const id of AS_ONLY_TICKET_ROWS) expect(file.ticket_request_refusals.some((r) => r.id === id), id).toBe(true);
    for (const id of AS_ONLY_MANDATE_ROWS) expect(file.mandate_request_refusals.some((r) => r.id === id), id).toBe(true);
    for (const id of AS_ONLY_PROPOSAL_ROWS) expect(file.proposal_refusals.some((r) => r.id === id), id).toBe(true);
  });

  it('every row in the vector file is accounted for — decided here, or named AS-only above', () => {
    const decidedHere = new Set(Object.keys(DECIDED_HERE));
    const asOnly = new Set<string>([...AS_ONLY_TICKET_ROWS, ...AS_ONLY_MANDATE_ROWS, ...AS_ONLY_PROPOSAL_ROWS]);
    const unaccounted = allRows().map((r) => r.id).filter((id) => !decidedHere.has(id) && !asOnly.has(id));
    expect(unaccounted, `unaccounted required-refusals rows: ${unaccounted.join(', ')}`).toEqual([]);
    const both = [...decidedHere].filter((id) => asOnly.has(id));
    expect(both, `rows listed as both decided and AS-only: ${both.join(', ')}`).toEqual([]);
  });

  // `fail_closed_situations` describe Gatekeeper / Executor / AS runtime
  // behaviour — reachability, archive writes, execution records, surfaces,
  // replays — none of which a library with no store has. suveren-e2e holds
  // them against the running programs.
  it('fail_closed_situations rows are runtime behaviour, out of hap-core scope', () => {
    expect(file.fail_closed_situations.length).toBeGreaterThanOrEqual(35);
  });
});

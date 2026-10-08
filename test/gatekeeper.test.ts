import { describe, it, expect, beforeAll } from 'vitest';
import { verify } from '../src/gatekeeper';
import { registerProfile } from '../src/profiles';
import { CHARGE_PROFILE_V4, EMAIL_PROFILE_V4 } from './fixtures';
import { generateTestKeyPair, createTestMandate, type TestKeyPair } from './helpers';
import type { AgentBoundsParams } from '../src/types';

describe('gatekeeper', () => {
  let keyPair: TestKeyPair;
  let wrongKeyPair: TestKeyPair;

  beforeAll(async () => {
    registerProfile(CHARGE_PROFILE_V4.id, CHARGE_PROFILE_V4);
    registerProfile(EMAIL_PROFILE_V4.id, EMAIL_PROFILE_V4);
    keyPair = await generateTestKeyPair();
    wrongKeyPair = await generateTestKeyPair();
  });

  describe('bounds + scope — charge@0.7', () => {
    const routineBounds: AgentBoundsParams = {
      profile: CHARGE_PROFILE_V4.id,
      amount_max: 80,
      amount_daily_max: 500,
      amount_monthly_max: 5000,
      transaction_count_daily_max: 10,
    };
    const routineScope = { currency: 'EUR', action_type: 'charge' };

    it('approves a payment within bounds', async () => {
      const blob = await createTestMandate({ keyPair, bounds: routineBounds, scope: routineScope, profile: CHARGE_PROFILE_V4 });
      const result = await verify({
        bounds: routineBounds, scope: routineScope, mandates: [blob],
        execution: { amount: 50, currency: 'EUR', action_type: 'charge' },
      });
      expect(result.approved).toBe(true);
    });

    it('approves at exactly the max amount', async () => {
      const blob = await createTestMandate({ keyPair, bounds: routineBounds, scope: routineScope, profile: CHARGE_PROFILE_V4 });
      const result = await verify({
        bounds: routineBounds, scope: routineScope, mandates: [blob],
        execution: { amount: 80, currency: 'EUR', action_type: 'charge' },
      });
      expect(result.approved).toBe(true);
    });

    it('rejects a payment exceeding amount_max — BOUND_EXCEEDED', async () => {
      const blob = await createTestMandate({ keyPair, bounds: routineBounds, scope: routineScope, profile: CHARGE_PROFILE_V4 });
      const result = await verify({
        bounds: routineBounds, scope: routineScope, mandates: [blob],
        execution: { amount: 120, currency: 'EUR', action_type: 'charge' },
      });
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some((e) => e.code === 'BOUND_EXCEEDED' && e.field === 'amount')).toBe(true);
      }
    });

    it('rejects a currency outside the scope — BOUND_EXCEEDED', async () => {
      const blob = await createTestMandate({ keyPair, bounds: routineBounds, scope: routineScope, profile: CHARGE_PROFILE_V4 });
      const result = await verify({
        bounds: routineBounds, scope: routineScope, mandates: [blob],
        execution: { amount: 5, currency: 'USD', action_type: 'charge' },
      });
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some((e) => e.code === 'BOUND_EXCEEDED' && e.field === 'currency')).toBe(true);
      }
    });

    it('rejects an expired mandate — TTL_EXPIRED', async () => {
      const pastExpiry = Math.floor(Date.now() / 1000) - 1000;
      const blob = await createTestMandate({ keyPair, bounds: routineBounds, scope: routineScope, profile: CHARGE_PROFILE_V4, expiresAt: pastExpiry });
      const result = await verify({
        bounds: routineBounds, scope: routineScope, mandates: [blob],
        execution: { amount: 5, currency: 'EUR', action_type: 'charge' },
      });
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some((e) => e.code === 'TTL_EXPIRED')).toBe(true);
      }
    });

    it('rejects a mandate whose signature does not match its claimed issuer — INVALID_SIGNATURE', async () => {
      // Signed with wrongKeyPair's private key, but CLAIMS keyPair's DID as
      // issuer — the signature verifies against the wrong key.
      const blob = await createTestMandate({
        keyPair: wrongKeyPair, issuerDid: keyPair.did,
        bounds: routineBounds, scope: routineScope, profile: CHARGE_PROFILE_V4,
      });
      const result = await verify({
        bounds: routineBounds, scope: routineScope, mandates: [blob],
        execution: { amount: 5, currency: 'EUR', action_type: 'charge' },
      });
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some((e) => e.code === 'INVALID_SIGNATURE')).toBe(true);
      }
    });

    it('rejects an unknown profile — PROFILE_NOT_FOUND', async () => {
      const result = await verify({
        bounds: { profile: 'unknown@1.0' }, mandates: [], execution: {},
      });
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors[0].code).toBe('PROFILE_NOT_FOUND');
      }
    });

    it('rejects when bounds_hash does not match the mandate — BOUNDS_HASH_MISMATCH', async () => {
      const attestedBounds: AgentBoundsParams = { ...routineBounds, amount_max: 200 };
      const blob = await createTestMandate({ keyPair, bounds: attestedBounds, scope: routineScope, profile: CHARGE_PROFILE_V4 });

      const result = await verify({
        bounds: routineBounds, // amount_max 80 — mismatch with the attested 200
        scope: routineScope, mandates: [blob],
        execution: { amount: 50, currency: 'EUR', action_type: 'charge' },
      });
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some((e) => e.code === 'BOUNDS_HASH_MISMATCH')).toBe(true);
      }
    });

    it('rejects when scope_hash does not match the mandate — SCOPE_HASH_MISMATCH', async () => {
      const attestedScope = { currency: 'USD', action_type: 'charge' };
      const blob = await createTestMandate({ keyPair, bounds: routineBounds, scope: attestedScope, profile: CHARGE_PROFILE_V4 });

      const result = await verify({
        bounds: routineBounds,
        scope: routineScope, // EUR — mismatch with the attested USD
        mandates: [blob],
        execution: { amount: 50, currency: 'EUR', action_type: 'charge' },
      });
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some((e) => e.code === 'SCOPE_HASH_MISMATCH')).toBe(true);
      }
    });

    it('rejects an action_type the profile does not register — INVALID_ACTION_TYPE', async () => {
      const blob = await createTestMandate({ keyPair, bounds: routineBounds, scope: routineScope, profile: CHARGE_PROFILE_V4 });
      const result = await verify({
        bounds: routineBounds, scope: routineScope, mandates: [blob],
        execution: { amount: 5, currency: 'EUR', action_type: 'teleport' },
      });
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors[0].code).toBe('INVALID_ACTION_TYPE');
      }
    });

    it('never locally refuses on a cumulative bound — AS-only (protocol.md Enforcement Authority)', async () => {
      // amount_daily_max is 500; nothing here gives the Gatekeeper any
      // cumulative history to refuse from, and it must not invent one.
      const blob = await createTestMandate({ keyPair, bounds: routineBounds, scope: routineScope, profile: CHARGE_PROFILE_V4 });
      const result = await verify({
        bounds: routineBounds, scope: routineScope, mandates: [blob],
        execution: { amount: 80, currency: 'EUR', action_type: 'charge' },
      });
      expect(result.approved).toBe(true);
    });
  });

  // ─── subset constraint tests ────────────────────────────────────────────────

  describe('scope — subset constraint enforcement (email@0.7)', () => {
    const emailBounds: AgentBoundsParams = {
      profile: EMAIL_PROFILE_V4.id,
      recipient_max: 5,
      send_daily_max: 20,
    };
    const emailScope = {
      allowed_domains: 'gmail.com,acme.com',
      allowed_recipients: 'alice@gmail.com,bob@acme.com',
    };

    it('approves when actual domains are a subset of allowed', async () => {
      const blob = await createTestMandate({ keyPair, bounds: emailBounds, scope: emailScope, profile: EMAIL_PROFILE_V4 });
      const result = await verify({
        bounds: emailBounds, scope: emailScope, mandates: [blob],
        execution: { action_type: 'send', recipient_count: 1, allowed_domains: 'gmail.com', allowed_recipients: 'alice@gmail.com' },
      });
      expect(result.approved).toBe(true);
    });

    it('rejects when actual domain is not in allowed set', async () => {
      const blob = await createTestMandate({ keyPair, bounds: emailBounds, scope: emailScope, profile: EMAIL_PROFILE_V4 });
      const result = await verify({
        bounds: emailBounds, scope: emailScope, mandates: [blob],
        execution: { action_type: 'send', recipient_count: 1, allowed_domains: 'sublin.app', allowed_recipients: 'andreas@sublin.app' },
      });
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some((e) =>
          e.code === 'BOUND_EXCEEDED' && e.field === 'allowed_domains' && e.message.includes('sublin.app'),
        )).toBe(true);
      }
    });

    it('skips the subset check when the scope value is empty', async () => {
      const openScope = { allowed_domains: '', allowed_recipients: '' };
      const blob = await createTestMandate({ keyPair, bounds: emailBounds, scope: openScope, profile: EMAIL_PROFILE_V4 });
      const result = await verify({
        bounds: emailBounds, scope: openScope, mandates: [blob],
        execution: { action_type: 'send', recipient_count: 1, allowed_domains: 'any-domain.com', allowed_recipients: 'anyone@any-domain.com' },
      });
      expect(result.approved).toBe(true);
    });

    it('subset check is case-insensitive', async () => {
      const blob = await createTestMandate({ keyPair, bounds: emailBounds, scope: emailScope, profile: EMAIL_PROFILE_V4 });
      const result = await verify({
        bounds: emailBounds, scope: emailScope, mandates: [blob],
        execution: { action_type: 'send', recipient_count: 1, allowed_domains: 'Gmail.COM', allowed_recipients: 'Alice@Gmail.COM' },
      });
      expect(result.approved).toBe(true);
    });

    it('rejects when one of multiple domains is not allowed', async () => {
      const blob = await createTestMandate({ keyPair, bounds: emailBounds, scope: emailScope, profile: EMAIL_PROFILE_V4 });
      const result = await verify({
        bounds: emailBounds, scope: emailScope, mandates: [blob],
        execution: { action_type: 'send', recipient_count: 2, allowed_domains: 'gmail.com,evil.com', allowed_recipients: 'a@gmail.com,b@evil.com' },
      });
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some((e) =>
          e.code === 'BOUND_EXCEEDED' && e.field === 'allowed_domains' && e.message.includes('evil.com'),
        )).toBe(true);
      }
    });
  });

  // ─── No mandate → fail closed ────────────────────────────────────────────────

  describe('no mandate supplied → fail closed', () => {
    it('an empty array is refused, not approved', async () => {
      const bounds: AgentBoundsParams = { profile: CHARGE_PROFILE_V4.id, amount_max: 80, amount_daily_max: 500, amount_monthly_max: 5000, transaction_count_daily_max: 10 };
      const result = await verify({
        bounds, scope: { currency: 'EUR', action_type: 'charge' }, mandates: [],
        execution: { amount: 5, currency: 'EUR', action_type: 'charge' },
      });
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors).toHaveLength(1);
        expect(result.errors[0].code).toBe('MALFORMED_MANDATE');
        expect(result.errors[0].message).toBe('No mandate supplied — nothing to verify');
      }
    });

    it('a missing mandates field is refused too', async () => {
      const bounds: AgentBoundsParams = { profile: CHARGE_PROFILE_V4.id, amount_max: 80, amount_daily_max: 500, amount_monthly_max: 5000, transaction_count_daily_max: 10 };
      const request = { bounds, execution: { amount: 5, currency: 'EUR', action_type: 'charge' } } as unknown as Parameters<typeof verify>[0];
      const result = await verify(request);
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors[0].code).toBe('MALFORMED_MANDATE');
      }
    });

    it('an unknown profile is still reported first, before the empty-mandates check', async () => {
      const result = await verify({ bounds: { profile: 'unknown@1.0' }, mandates: [], execution: {} });
      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors[0].code).toBe('PROFILE_NOT_FOUND');
      }
    });
  });
});

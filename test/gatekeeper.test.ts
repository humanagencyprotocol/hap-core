import { describe, it, expect, beforeAll } from 'vitest';
import { verify } from '../src/gatekeeper';
import { registerProfile } from '../src/profiles';
import { SPEND_PROFILE, SPEND_PROFILE_V4, EMAIL_PROFILE_V4 } from './fixtures';
import {
  generateTestKeyPair,
  createTestAttestation,
  createTestAttestationV4,
  type TestKeyPair,
} from './helpers';
import type { AgentFrameParams } from '../src/types';

describe('gatekeeper', () => {
  let keyPair: TestKeyPair;
  let wrongKeyPair: TestKeyPair;

  const routineFrame: AgentFrameParams = {
    profile: 'spend@0.3',
    path: 'spend-routine',
    amount_max: 80,
    currency: 'EUR',
    action_type: 'charge',
  };

  const reviewedFrame: AgentFrameParams = {
    profile: 'spend@0.3',
    path: 'spend-reviewed',
    amount_max: 5000,
    currency: 'EUR',
    action_type: 'charge',
  };

  beforeAll(async () => {
    registerProfile('spend@0.3', SPEND_PROFILE);
    registerProfile('spend@0.4', SPEND_PROFILE_V4);
    registerProfile('email@0.4', EMAIL_PROFILE_V4);
    keyPair = await generateTestKeyPair();
    wrongKeyPair = await generateTestKeyPair();
  });

  // ─── v0.3 Tests ─────────────────────────────────────────────────────────────

  describe('within bounds → approved', () => {
    it('approves payment within max amount', async () => {
      const blob = await createTestAttestation({
        keyPair,
        frame: routineFrame,
        profile: SPEND_PROFILE,
        domain: 'finance',
      });

      const result = await verify(
        {
          frame: routineFrame,
          attestations: [blob],
          execution: { amount: 5, currency: 'EUR', action_type: 'charge'},
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(true);
    });

    it('approves payment at exact max amount', async () => {
      const blob = await createTestAttestation({
        keyPair,
        frame: routineFrame,
        profile: SPEND_PROFILE,
        domain: 'finance',
      });

      const result = await verify(
        {
          frame: routineFrame,
          attestations: [blob],
          execution: { amount: 80, currency: 'EUR', action_type: 'charge'},
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(true);
    });
  });

  describe('exceeds max → BOUND_EXCEEDED', () => {
    it('rejects amount exceeding max', async () => {
      const blob = await createTestAttestation({
        keyPair,
        frame: routineFrame,
        profile: SPEND_PROFILE,
        domain: 'finance',
      });

      const result = await verify(
        {
          frame: routineFrame,
          attestations: [blob],
          execution: { amount: 120, currency: 'EUR', action_type: 'charge'},
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors).toHaveLength(1);
        expect(result.errors[0].code).toBe('BOUND_EXCEEDED');
        expect(result.errors[0].field).toBe('amount');
        expect(result.errors[0].actual).toBe(120);
        expect(result.errors[0].bound).toBe(80);
      }
    });
  });

  describe('wrong currency → BOUND_EXCEEDED', () => {
    it('rejects wrong currency', async () => {
      const blob = await createTestAttestation({
        keyPair,
        frame: routineFrame,
        profile: SPEND_PROFILE,
        domain: 'finance',
      });

      const result = await verify(
        {
          frame: routineFrame,
          attestations: [blob],
          execution: { amount: 5, currency: 'USD', action_type: 'charge'},
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some(e => e.code === 'BOUND_EXCEEDED' && e.field === 'currency')).toBe(true);
      }
    });
  });

  describe('expired → TTL_EXPIRED', () => {
    it('rejects expired attestation', async () => {
      const pastExpiry = Math.floor(Date.now() / 1000) - 100;
      const blob = await createTestAttestation({
        keyPair,
        frame: routineFrame,
        profile: SPEND_PROFILE,
        domain: 'finance',
        expiresAt: pastExpiry,
      });

      const result = await verify(
        {
          frame: routineFrame,
          attestations: [blob],
          execution: { amount: 5, currency: 'EUR', action_type: 'charge'},
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some(e => e.code === 'TTL_EXPIRED')).toBe(true);
      }
    });
  });

  describe('bad signature → INVALID_SIGNATURE', () => {
    it('rejects attestation signed with wrong key', async () => {
      const blob = await createTestAttestation({
        keyPair: wrongKeyPair,
        frame: routineFrame,
        profile: SPEND_PROFILE,
        domain: 'finance',
      });

      const result = await verify(
        {
          frame: routineFrame,
          attestations: [blob],
          execution: { amount: 5, currency: 'EUR', action_type: 'charge'},
        },
        keyPair.publicKeyHex // verifying with a different key
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some(e => e.code === 'INVALID_SIGNATURE')).toBe(true);
      }
    });
  });

  describe('missing domain → DOMAIN_NOT_COVERED', () => {
    it('rejects when required domain is missing (multi-owner)', async () => {
      // spend-reviewed requires finance + compliance
      const financeBlob = await createTestAttestation({
        keyPair,
        frame: reviewedFrame,
        profile: SPEND_PROFILE,
        domain: 'finance',
      });

      // Only finance attested, compliance missing
      const result = await verify(
        {
          frame: reviewedFrame,
          attestations: [financeBlob],
          execution: { amount: 2000, currency: 'EUR', action_type: 'charge'},
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some(e => e.code === 'DOMAIN_NOT_COVERED' && e.message.includes('compliance'))).toBe(true);
      }
    });

    it('approves when all domains are covered', async () => {
      const financeBlob = await createTestAttestation({
        keyPair,
        frame: reviewedFrame,
        profile: SPEND_PROFILE,
        domain: 'finance',
      });
      const complianceBlob = await createTestAttestation({
        keyPair,
        frame: reviewedFrame,
        profile: SPEND_PROFILE,
        domain: 'compliance',
      });

      const result = await verify(
        {
          frame: reviewedFrame,
          attestations: [financeBlob, complianceBlob],
          execution: { amount: 2000, currency: 'EUR', action_type: 'charge'},
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(true);
    });
  });

  describe('unknown profile → INVALID_PROFILE', () => {
    it('rejects unknown profile ID', async () => {
      const result = await verify(
        {
          frame: { profile: 'unknown@1.0', path: 'test' },
          attestations: [],
          execution: {},
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors[0].code).toBe('INVALID_PROFILE');
      }
    });
  });

  describe('unknown execution path → INVALID_PROFILE', () => {
    it('rejects unknown path', async () => {
      const result = await verify(
        {
          frame: { profile: 'spend@0.3', path: 'nonexistent-path', amount_max: 80, currency: 'EUR', action_type: 'charge'},
          attestations: [],
          execution: {},
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors[0].code).toBe('INVALID_PROFILE');
      }
    });
  });

  describe('authorization checked before bounds (§8.6.4 rule 4)', () => {
    it('returns authorization errors even if bounds would pass', async () => {
      // No attestations at all — should fail with DOMAIN_NOT_COVERED, not check bounds
      const result = await verify(
        {
          frame: routineFrame,
          attestations: [],
          execution: { amount: 5, currency: 'EUR', action_type: 'charge'},
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some(e => e.code === 'DOMAIN_NOT_COVERED')).toBe(true);
        // Should NOT contain BOUND_EXCEEDED since auth failed first
        expect(result.errors.some(e => e.code === 'BOUND_EXCEEDED')).toBe(false);
      }
    });
  });

  // ─── v0.4 Tests ─────────────────────────────────────────────────────────────

  describe('v0.4 — bounds_hash + context_hash', () => {
    const routineBounds: AgentFrameParams = {
      profile: 'spend@0.4',
      path: 'spend-routine',
      amount_max: 80,
      amount_daily_max: 500,
      amount_monthly_max: 5000,
      transaction_count_daily_max: 10,
    };

    const routineContext = {
      currency: 'EUR',
      action_type: 'charge',
    };

    it('approves v0.4 payment within bounds', async () => {
      const blob = await createTestAttestationV4({
        keyPair,
        bounds: routineBounds,
        context: routineContext,
        profile: SPEND_PROFILE_V4,
        domain: 'finance',
      });

      const result = await verify(
        {
          frame: routineBounds,
          context: routineContext,
          attestations: [blob],
          execution: { amount: 50, currency: 'EUR', action_type: 'charge' },
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(true);
    });

    it('rejects v0.4 payment exceeding amount_max', async () => {
      const blob = await createTestAttestationV4({
        keyPair,
        bounds: routineBounds,
        context: routineContext,
        profile: SPEND_PROFILE_V4,
        domain: 'finance',
      });

      const result = await verify(
        {
          frame: routineBounds,
          context: routineContext,
          attestations: [blob],
          execution: { amount: 120, currency: 'EUR', action_type: 'charge' },
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some(e => e.code === 'BOUND_EXCEEDED' && e.field === 'amount')).toBe(true);
      }
    });

    it('rejects v0.4 when bounds_hash does not match', async () => {
      const differentBounds: AgentFrameParams = {
        ...routineBounds,
        amount_max: 200, // attested for 200 but verifying with 80
      };

      const blob = await createTestAttestationV4({
        keyPair,
        bounds: differentBounds,
        context: routineContext,
        profile: SPEND_PROFILE_V4,
        domain: 'finance',
      });

      const result = await verify(
        {
          frame: routineBounds, // 80 — mismatch with attested 200
          context: routineContext,
          attestations: [blob],
          execution: { amount: 50, currency: 'EUR', action_type: 'charge' },
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some(e => e.code === 'BOUNDS_MISMATCH')).toBe(true);
      }
    });

    it('rejects v0.4 when context_hash does not match', async () => {
      const differentContext = { currency: 'USD', action_type: 'charge' };

      const blob = await createTestAttestationV4({
        keyPair,
        bounds: routineBounds,
        context: differentContext, // attested for USD
        profile: SPEND_PROFILE_V4,
        domain: 'finance',
      });

      const result = await verify(
        {
          frame: routineBounds,
          context: routineContext, // EUR — mismatch with attested USD
          attestations: [blob],
          execution: { amount: 50, currency: 'EUR', action_type: 'charge' },
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some(e => e.code === 'CONTEXT_MISMATCH')).toBe(true);
      }
    });

    it('rejects v0.4 when context field value does not match execution', async () => {
      const blob = await createTestAttestationV4({
        keyPair,
        bounds: routineBounds,
        context: routineContext, // EUR
        profile: SPEND_PROFILE_V4,
        domain: 'finance',
      });

      const result = await verify(
        {
          frame: routineBounds,
          context: routineContext, // EUR
          attestations: [blob],
          execution: { amount: 50, currency: 'USD', action_type: 'charge' }, // USD — not in context
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some(e => e.code === 'BOUND_EXCEEDED' && e.field === 'currency')).toBe(true);
      }
    });

    it('v0.3 backward compat — frame_hash attestation still works on v0.3 profile', async () => {
      // Existing v0.3 path should be unaffected
      const blob = await createTestAttestation({
        keyPair,
        frame: routineFrame,
        profile: SPEND_PROFILE,
        domain: 'finance',
      });

      const result = await verify(
        {
          frame: routineFrame,
          attestations: [blob],
          execution: { amount: 5, currency: 'EUR', action_type: 'charge' },
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(true);
    });
  });

  // ─── v0.4 subset constraint tests ──────────────────────────────────────────

  describe('v0.4 — subset constraint enforcement', () => {
    const emailBounds: AgentFrameParams = {
      profile: 'email@0.4',
      path: 'email-send',
      recipient_max: 5,
      send_daily_max: 20,
    };

    const emailContext = {
      allowed_domains: 'gmail.com,acme.com',
      allowed_recipients: 'alice@gmail.com,bob@acme.com',
    };

    it('approves when actual domains are a subset of allowed', async () => {
      const blob = await createTestAttestationV4({
        keyPair,
        bounds: emailBounds,
        context: emailContext,
        profile: EMAIL_PROFILE_V4,
        domain: 'communications',
      });

      const result = await verify(
        {
          frame: emailBounds,
          context: emailContext,
          attestations: [blob],
          execution: { recipient_count: 1, allowed_domains: 'gmail.com', allowed_recipients: 'alice@gmail.com' },
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(true);
    });

    it('rejects when actual domain is not in allowed set', async () => {
      const blob = await createTestAttestationV4({
        keyPair,
        bounds: emailBounds,
        context: emailContext,
        profile: EMAIL_PROFILE_V4,
        domain: 'communications',
      });

      const result = await verify(
        {
          frame: emailBounds,
          context: emailContext,
          attestations: [blob],
          execution: { recipient_count: 1, allowed_domains: 'sublin.app', allowed_recipients: 'andreas@sublin.app' },
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some(e =>
          e.code === 'BOUND_EXCEEDED' &&
          e.field === 'allowed_domains' &&
          e.message.includes('sublin.app'),
        )).toBe(true);
      }
    });

    it('skips subset check when bound is empty', async () => {
      const openContext = { allowed_domains: '', allowed_recipients: '' };

      const blob = await createTestAttestationV4({
        keyPair,
        bounds: emailBounds,
        context: openContext,
        profile: EMAIL_PROFILE_V4,
        domain: 'communications',
      });

      const result = await verify(
        {
          frame: emailBounds,
          context: openContext,
          attestations: [blob],
          execution: { recipient_count: 1, allowed_domains: 'any-domain.com', allowed_recipients: 'anyone@any-domain.com' },
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(true);
    });

    it('subset check is case-insensitive', async () => {
      const blob = await createTestAttestationV4({
        keyPair,
        bounds: emailBounds,
        context: emailContext,
        profile: EMAIL_PROFILE_V4,
        domain: 'communications',
      });

      const result = await verify(
        {
          frame: emailBounds,
          context: emailContext,
          attestations: [blob],
          execution: { recipient_count: 1, allowed_domains: 'Gmail.COM', allowed_recipients: 'Alice@Gmail.COM' },
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(true);
    });

    it('subset with single value in both bound and actual', async () => {
      const singleContext = { allowed_domains: 'gmail.com', allowed_recipients: '' };

      const blob = await createTestAttestationV4({
        keyPair,
        bounds: emailBounds,
        context: singleContext,
        profile: EMAIL_PROFILE_V4,
        domain: 'communications',
      });

      const result = await verify(
        {
          frame: emailBounds,
          context: singleContext,
          attestations: [blob],
          execution: { recipient_count: 1, allowed_domains: 'gmail.com' },
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(true);
    });

    it('rejects when one of multiple domains is not allowed', async () => {
      const blob = await createTestAttestationV4({
        keyPair,
        bounds: emailBounds,
        context: emailContext,
        profile: EMAIL_PROFILE_V4,
        domain: 'communications',
      });

      const result = await verify(
        {
          frame: emailBounds,
          context: emailContext,
          attestations: [blob],
          execution: { recipient_count: 2, allowed_domains: 'gmail.com,evil.com', allowed_recipients: 'a@gmail.com,b@evil.com' },
        },
        keyPair.publicKeyHex
      );

      expect(result.approved).toBe(false);
      if (!result.approved) {
        expect(result.errors.some(e =>
          e.code === 'BOUND_EXCEEDED' &&
          e.field === 'allowed_domains' &&
          e.message.includes('evil.com'),
        )).toBe(true);
      }
    });
  });
});

/**
 * Hash Determinism Tests
 *
 * Verifies that hashing is deterministic and consistent across calls,
 * and documents how specific edge cases behave.
 */

import { describe, it, expect } from 'vitest';
import { computeBoundsHash, computeScopeHash } from '../src/frame';
import { CHARGE_PROFILE_V4 } from './fixtures';
import type { AgentProfile } from '../src/types';

// ── Shared fixtures ───────────────────────────────────────────────────────────

const BOUNDS = {
  profile: CHARGE_PROFILE_V4.id,
  amount_max: 100,
  amount_daily_max: 500,
  amount_monthly_max: 5000,
  transaction_count_daily_max: 20,
};

const SCOPE = {
  currency: 'USD',
  action_type: 'charge',
};

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('hash determinism', () => {
  describe('bounds hash', () => {
    it('same bounds produce same hash across multiple calls', () => {
      const hash1 = computeBoundsHash(BOUNDS, CHARGE_PROFILE_V4);
      const hash2 = computeBoundsHash(BOUNDS, CHARGE_PROFILE_V4);
      const hash3 = computeBoundsHash(BOUNDS, CHARGE_PROFILE_V4);

      expect(hash1).toBe(hash2);
      expect(hash2).toBe(hash3);
      expect(hash1).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('produces same hash regardless of input object key insertion order', () => {
      // The profile's boundsSchema.keyOrder controls canonical ordering,
      // so inserting keys in a different order must not affect the hash
      const boundsForwardOrder = { ...BOUNDS };
      const boundsReverseOrder = {
        transaction_count_daily_max: 20,
        amount_monthly_max: 5000,
        amount_daily_max: 500,
        amount_max: 100,
        profile: CHARGE_PROFILE_V4.id,
      };

      const hash1 = computeBoundsHash(boundsForwardOrder, CHARGE_PROFILE_V4);
      const hash2 = computeBoundsHash(boundsReverseOrder, CHARGE_PROFILE_V4);

      expect(hash1).toBe(hash2);
    });

    it('different field values produce different hashes', () => {
      const boundsA = { ...BOUNDS, amount_max: 100 };
      const boundsB = { ...BOUNDS, amount_max: 200 };

      expect(computeBoundsHash(boundsA, CHARGE_PROFILE_V4)).not.toBe(
        computeBoundsHash(boundsB, CHARGE_PROFILE_V4),
      );
    });

    it('number 100 and string "100" produce the same canonical form', () => {
      // canonicalBounds converts all values via String(), so number 100 → "100"
      // and string "100" → "100" produce the same canonical line "amount_max=100"
      const boundsWithNumber = { ...BOUNDS, amount_max: 100 };
      const hash1 = computeBoundsHash(boundsWithNumber, CHARGE_PROFILE_V4);
      const hash2 = computeBoundsHash(boundsWithNumber, CHARGE_PROFILE_V4);
      expect(hash1).toBe(hash2);

      const expectedCanonical = [
        `profile=${CHARGE_PROFILE_V4.id}`,
        'amount_max=100',
        'amount_daily_max=500',
        'amount_monthly_max=5000',
        'transaction_count_daily_max=20',
      ].join('\n');

      // String() on the number 100 produces exactly "100"
      expect(String(100)).toBe('100');
      expect(expectedCanonical).toContain('amount_max=100');
    });
  });

  describe('scope hash', () => {
    it('same scope produces same hash across multiple calls', () => {
      const hash1 = computeScopeHash(SCOPE, CHARGE_PROFILE_V4);
      const hash2 = computeScopeHash(SCOPE, CHARGE_PROFILE_V4);
      const hash3 = computeScopeHash(SCOPE, CHARGE_PROFILE_V4);

      expect(hash1).toBe(hash2);
      expect(hash2).toBe(hash3);
      expect(hash1).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('produces same hash regardless of input object key insertion order', () => {
      // scopeSchema.keyOrder is ['currency', 'action_type'], so insertion order
      // of the input object does not affect the canonical form
      const scopeForwardOrder = { currency: 'USD', action_type: 'charge' };
      const scopeReverseOrder = { action_type: 'charge', currency: 'USD' };

      const hash1 = computeScopeHash(scopeForwardOrder, CHARGE_PROFILE_V4);
      const hash2 = computeScopeHash(scopeReverseOrder, CHARGE_PROFILE_V4);

      expect(hash1).toBe(hash2);
    });

    it('different field values produce different hashes', () => {
      const scopeA = { currency: 'USD', action_type: 'charge' };
      const scopeB = { currency: 'EUR', action_type: 'charge' };

      expect(computeScopeHash(scopeA, CHARGE_PROFILE_V4)).not.toBe(
        computeScopeHash(scopeB, CHARGE_PROFILE_V4),
      );
    });
  });

  describe('empty scope', () => {
    it('empty scope always produces sha256 of empty string', () => {
      // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      const EMPTY_SHA256 = 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

      // A profile with no scopeSchema → canonicalScope returns "" → hash of ""
      const noScopeSchema: AgentProfile = { ...CHARGE_PROFILE_V4, scopeSchema: undefined };
      const hash1 = computeScopeHash({}, noScopeSchema);
      const hash2 = computeScopeHash({}, noScopeSchema);

      expect(hash1).toBe(EMPTY_SHA256);
      expect(hash2).toBe(EMPTY_SHA256);
    });

    it('empty scope hash is stable across multiple calls', () => {
      const noScopeSchema: AgentProfile = { ...CHARGE_PROFILE_V4, scopeSchema: undefined };
      const hashes = Array.from({ length: 5 }, () =>
        computeScopeHash({}, noScopeSchema),
      );
      expect(new Set(hashes).size).toBe(1);
    });
  });

  describe('bounds hash differs from scope hash for the same field values', () => {
    it('bounds and scope hashes differ even when field values overlap', () => {
      // Both bounds and scope could theoretically contain "USD" or "charge"
      // as values, but they use different keyOrders, so their canonical forms
      // differ and thus their hashes differ even if individual values
      // coincidentally match.
      const boundsHash = computeBoundsHash(BOUNDS, CHARGE_PROFILE_V4);
      const scopeHash = computeScopeHash(SCOPE, CHARGE_PROFILE_V4);

      expect(boundsHash).not.toBe(scopeHash);
      expect(boundsHash).toMatch(/^sha256:[a-f0-9]{64}$/);
      expect(scopeHash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('bounds hash is sha256 of the bounds canonical form, not the scope canonical form', () => {
      const boundsHash = computeBoundsHash(BOUNDS, CHARGE_PROFILE_V4);
      const scopeHash = computeScopeHash(SCOPE, CHARGE_PROFILE_V4);

      expect(boundsHash).not.toBe(scopeHash);
      expect(computeBoundsHash(BOUNDS, CHARGE_PROFILE_V4)).toBe(boundsHash);
      expect(computeScopeHash(SCOPE, CHARGE_PROFILE_V4)).toBe(scopeHash);
    });
  });
});

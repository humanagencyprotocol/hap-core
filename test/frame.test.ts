import { describe, it, expect } from 'vitest';
import {
  canonicalFrame,
  computeFrameHash,
  validateFrameParams,
  canonicalBounds,
  canonicalContext,
  computeBoundsHash,
  computeContextHash,
  validateBoundsParams,
  validateContextParams,
} from '../src/frame';
import { CHARGE_PROFILE, EMAIL_PROFILE, CHARGE_PROFILE_V4 } from './fixtures';

describe('frame', () => {
  describe('canonicalFrame', () => {
    it('produces canonical string with correct key order', () => {
      const frame = {
        profile: 'charge@0.3',
        path: 'charge-routine',
        amount_max: 80,
        currency: 'EUR',
        action_type: 'charge',
      };

      const result = canonicalFrame(frame, CHARGE_PROFILE);
      expect(result).toBe(
        'profile=charge@0.3\npath=charge-routine\namount_max=80\ncurrency=EUR\naction_type=charge'
      );
    });

    it('converts numbers to strings in canonical form', () => {
      const frame = {
        profile: 'charge@0.3',
        path: 'charge-routine',
        amount_max: 100.5,
        currency: 'USD',
        action_type: 'charge',
      };

      const result = canonicalFrame(frame, CHARGE_PROFILE);
      expect(result).toContain('amount_max=100.5');
    });

    it('works with email profile', () => {
      const frame = {
        profile: 'email@0.3',
        path: 'email-send',
        recipient_max: 5,
        send_daily_max: 20,
        read_max_age_days: 30,
        read_daily_max: 50,
      };

      const result = canonicalFrame(frame, EMAIL_PROFILE);
      expect(result).toBe(
        'profile=email@0.3\npath=email-send\nrecipient_max=5\nsend_daily_max=20\nread_max_age_days=30\nread_daily_max=50'
      );
    });

    it('throws on missing required field', () => {
      const frame = {
        profile: 'charge@0.3',
        path: 'charge-routine',
        // missing amount_max, currency, action_type
      };

      expect(() => canonicalFrame(frame, CHARGE_PROFILE)).toThrow('Missing required field');
    });

    it('throws on unknown field', () => {
      const frame = {
        profile: 'charge@0.3',
        path: 'charge-routine',
        amount_max: 80,
        currency: 'EUR',
        action_type: 'charge',
        unknown_field: 'value',
      };

      expect(() => canonicalFrame(frame, CHARGE_PROFILE)).toThrow('Unknown field');
    });

    it('throws on wrong type (string where number expected)', () => {
      const frame = {
        profile: 'charge@0.3',
        path: 'charge-routine',
        amount_max: 'eighty' as unknown as number,
        currency: 'EUR',
        action_type: 'charge',
      };

      expect(() => canonicalFrame(frame, CHARGE_PROFILE)).toThrow('must be a number');
    });
  });

  describe('computeFrameHash', () => {
    it('returns sha256: prefixed hash', () => {
      const frame = {
        profile: 'charge@0.3',
        path: 'charge-routine',
        amount_max: 80,
        currency: 'EUR',
        action_type: 'charge',
      };

      const hash = computeFrameHash(frame, CHARGE_PROFILE);
      expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('produces same hash for same inputs', () => {
      const frame = {
        profile: 'charge@0.3',
        path: 'charge-routine',
        amount_max: 80,
        currency: 'EUR',
        action_type: 'charge',
      };

      const hash1 = computeFrameHash(frame, CHARGE_PROFILE);
      const hash2 = computeFrameHash(frame, CHARGE_PROFILE);
      expect(hash1).toBe(hash2);
    });

    it('produces different hash for different values', () => {
      const frame1 = {
        profile: 'charge@0.3',
        path: 'charge-routine',
        amount_max: 80,
        currency: 'EUR',
        action_type: 'charge',
      };
      const frame2 = {
        profile: 'charge@0.3',
        path: 'charge-routine',
        amount_max: 100,
        currency: 'EUR',
        action_type: 'charge',
      };

      const hash1 = computeFrameHash(frame1, CHARGE_PROFILE);
      const hash2 = computeFrameHash(frame2, CHARGE_PROFILE);
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('validateFrameParams', () => {
    it('validates correct frame params', () => {
      const frame = {
        profile: 'charge@0.3',
        path: 'charge-routine',
        amount_max: 80,
        currency: 'EUR',
        action_type: 'charge',
      };

      const result = validateFrameParams(frame, CHARGE_PROFILE);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('reports multiple errors at once', () => {
      const frame = {
        profile: 'charge@0.3',
        // missing path, amount_max, currency, action_type
      };

      const result = validateFrameParams(frame, CHARGE_PROFILE);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThanOrEqual(4);
    });
  });
});

// ─── v0.4 Bounds and Context ──────────────────────────────────────────────────

describe('bounds (v0.4)', () => {
  const validBounds = {
    profile: 'charge@0.4',
    path: 'charge-routine',
    amount_max: 80,
    amount_daily_max: 500,
    amount_monthly_max: 5000,
    transaction_count_daily_max: 10,
  };

  describe('canonicalBounds', () => {
    it('produces canonical string with correct key order', () => {
      const result = canonicalBounds(validBounds, CHARGE_PROFILE_V4);
      expect(result).toBe(
        'profile=charge@0.4\npath=charge-routine\namount_max=80\namount_daily_max=500\namount_monthly_max=5000\ntransaction_count_daily_max=10'
      );
    });

    it('throws on missing required field', () => {
      const bounds = { profile: 'charge@0.4', path: 'charge-routine' };
      expect(() => canonicalBounds(bounds, CHARGE_PROFILE_V4)).toThrow('Missing required field');
    });

    it('throws on unknown field', () => {
      const bounds = { ...validBounds, unknown_field: 'value' };
      expect(() => canonicalBounds(bounds, CHARGE_PROFILE_V4)).toThrow('Unknown field');
    });
  });

  describe('computeBoundsHash', () => {
    it('returns sha256: prefixed hash', () => {
      const hash = computeBoundsHash(validBounds, CHARGE_PROFILE_V4);
      expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('produces same hash for same inputs', () => {
      const hash1 = computeBoundsHash(validBounds, CHARGE_PROFILE_V4);
      const hash2 = computeBoundsHash(validBounds, CHARGE_PROFILE_V4);
      expect(hash1).toBe(hash2);
    });

    it('produces different hash for different values', () => {
      const bounds2 = { ...validBounds, amount_max: 100 };
      const hash1 = computeBoundsHash(validBounds, CHARGE_PROFILE_V4);
      const hash2 = computeBoundsHash(bounds2, CHARGE_PROFILE_V4);
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('validateBoundsParams', () => {
    it('validates correct bounds params', () => {
      const result = validateBoundsParams(validBounds, CHARGE_PROFILE_V4);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('returns error when profile has no boundsSchema', () => {
      const result = validateBoundsParams(validBounds, CHARGE_PROFILE);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('boundsSchema');
    });
  });
});

describe('context (v0.4)', () => {
  const validContext = {
    currency: 'EUR',
    action_type: 'charge',
  };

  describe('canonicalContext', () => {
    it('produces canonical string in keyOrder', () => {
      const result = canonicalContext(validContext, CHARGE_PROFILE_V4);
      expect(result).toBe('currency=EUR\naction_type=charge');
    });

    it('returns empty string for profile with no contextSchema', () => {
      const result = canonicalContext({}, CHARGE_PROFILE);
      expect(result).toBe('');
    });

    it('throws on missing required field', () => {
      const ctx = { currency: 'EUR' }; // missing action_type
      expect(() => canonicalContext(ctx, CHARGE_PROFILE_V4)).toThrow('Missing required field');
    });
  });

  describe('computeContextHash', () => {
    it('returns sha256: prefixed hash', () => {
      const hash = computeContextHash(validContext, CHARGE_PROFILE_V4);
      expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('produces same hash for same inputs', () => {
      const hash1 = computeContextHash(validContext, CHARGE_PROFILE_V4);
      const hash2 = computeContextHash(validContext, CHARGE_PROFILE_V4);
      expect(hash1).toBe(hash2);
    });

    it('produces different hash for different values', () => {
      const ctx2 = { currency: 'USD', action_type: 'charge' };
      const hash1 = computeContextHash(validContext, CHARGE_PROFILE_V4);
      const hash2 = computeContextHash(ctx2, CHARGE_PROFILE_V4);
      expect(hash1).not.toBe(hash2);
    });

    it('empty context {} hashes to sha256 of empty string', () => {
      // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      const hash = computeContextHash({}, CHARGE_PROFILE);
      expect(hash).toBe('sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });
  });

  describe('validateContextParams', () => {
    it('validates correct context params', () => {
      const result = validateContextParams(validContext, CHARGE_PROFILE_V4);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('returns valid for empty params when no contextSchema', () => {
      const result = validateContextParams({}, CHARGE_PROFILE);
      expect(result.valid).toBe(true);
    });

    it('returns error for unknown field in context', () => {
      const ctx = { ...validContext, unknown: 'x' };
      const result = validateContextParams(ctx, CHARGE_PROFILE_V4);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('unknown'))).toBe(true);
    });
  });
});

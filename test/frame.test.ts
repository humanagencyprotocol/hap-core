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
import { SPEND_PROFILE, PUBLISH_PROFILE, SPEND_PROFILE_V4 } from './fixtures';

describe('frame', () => {
  describe('canonicalFrame', () => {
    it('produces canonical string with correct key order', () => {
      const frame = {
        profile: 'spend@0.3',
        path: 'spend-routine',
        amount_max: 80,
        currency: 'EUR',
        action_type: 'charge',
      };

      const result = canonicalFrame(frame, SPEND_PROFILE);
      expect(result).toBe(
        'profile=spend@0.3\npath=spend-routine\namount_max=80\ncurrency=EUR\naction_type=charge'
      );
    });

    it('converts numbers to strings in canonical form', () => {
      const frame = {
        profile: 'spend@0.3',
        path: 'spend-routine',
        amount_max: 100.5,
        currency: 'USD',
        action_type: 'charge',
      };

      const result = canonicalFrame(frame, SPEND_PROFILE);
      expect(result).toContain('amount_max=100.5');
    });

    it('works with publish profile', () => {
      const frame = {
        profile: 'publish@0.3',
        path: 'publish-transactional',
        channel: 'email',
        audience: 'individual',
        recipient_max: 5,
        scope: 'external',
      };

      const result = canonicalFrame(frame, PUBLISH_PROFILE);
      expect(result).toBe(
        'profile=publish@0.3\npath=publish-transactional\nchannel=email\naudience=individual\nrecipient_max=5\nscope=external'
      );
    });

    it('throws on missing required field', () => {
      const frame = {
        profile: 'spend@0.3',
        path: 'spend-routine',
        // missing amount_max, currency, action_type
      };

      expect(() => canonicalFrame(frame, SPEND_PROFILE)).toThrow('Missing required field');
    });

    it('throws on unknown field', () => {
      const frame = {
        profile: 'spend@0.3',
        path: 'spend-routine',
        amount_max: 80,
        currency: 'EUR',
        action_type: 'charge',
        unknown_field: 'value',
      };

      expect(() => canonicalFrame(frame, SPEND_PROFILE)).toThrow('Unknown field');
    });

    it('throws on wrong type (string where number expected)', () => {
      const frame = {
        profile: 'spend@0.3',
        path: 'spend-routine',
        amount_max: 'eighty' as unknown as number,
        currency: 'EUR',
        action_type: 'charge',
      };

      expect(() => canonicalFrame(frame, SPEND_PROFILE)).toThrow('must be a number');
    });
  });

  describe('computeFrameHash', () => {
    it('returns sha256: prefixed hash', () => {
      const frame = {
        profile: 'spend@0.3',
        path: 'spend-routine',
        amount_max: 80,
        currency: 'EUR',
        action_type: 'charge',
      };

      const hash = computeFrameHash(frame, SPEND_PROFILE);
      expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('produces same hash for same inputs', () => {
      const frame = {
        profile: 'spend@0.3',
        path: 'spend-routine',
        amount_max: 80,
        currency: 'EUR',
        action_type: 'charge',
      };

      const hash1 = computeFrameHash(frame, SPEND_PROFILE);
      const hash2 = computeFrameHash(frame, SPEND_PROFILE);
      expect(hash1).toBe(hash2);
    });

    it('produces different hash for different values', () => {
      const frame1 = {
        profile: 'spend@0.3',
        path: 'spend-routine',
        amount_max: 80,
        currency: 'EUR',
        action_type: 'charge',
      };
      const frame2 = {
        profile: 'spend@0.3',
        path: 'spend-routine',
        amount_max: 100,
        currency: 'EUR',
        action_type: 'charge',
      };

      const hash1 = computeFrameHash(frame1, SPEND_PROFILE);
      const hash2 = computeFrameHash(frame2, SPEND_PROFILE);
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('validateFrameParams', () => {
    it('validates correct frame params', () => {
      const frame = {
        profile: 'spend@0.3',
        path: 'spend-routine',
        amount_max: 80,
        currency: 'EUR',
        action_type: 'charge',
      };

      const result = validateFrameParams(frame, SPEND_PROFILE);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('reports multiple errors at once', () => {
      const frame = {
        profile: 'spend@0.3',
        // missing path, amount_max, currency, action_type
      };

      const result = validateFrameParams(frame, SPEND_PROFILE);
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThanOrEqual(4);
    });
  });
});

// ─── v0.4 Bounds and Context ──────────────────────────────────────────────────

describe('bounds (v0.4)', () => {
  const validBounds = {
    profile: 'spend@0.4',
    path: 'spend-routine',
    amount_max: 80,
    amount_daily_max: 500,
    amount_monthly_max: 5000,
    transaction_count_daily_max: 10,
  };

  describe('canonicalBounds', () => {
    it('produces canonical string with correct key order', () => {
      const result = canonicalBounds(validBounds, SPEND_PROFILE_V4);
      expect(result).toBe(
        'profile=spend@0.4\npath=spend-routine\namount_max=80\namount_daily_max=500\namount_monthly_max=5000\ntransaction_count_daily_max=10'
      );
    });

    it('throws on missing required field', () => {
      const bounds = { profile: 'spend@0.4', path: 'spend-routine' };
      expect(() => canonicalBounds(bounds, SPEND_PROFILE_V4)).toThrow('Missing required field');
    });

    it('throws on unknown field', () => {
      const bounds = { ...validBounds, unknown_field: 'value' };
      expect(() => canonicalBounds(bounds, SPEND_PROFILE_V4)).toThrow('Unknown field');
    });
  });

  describe('computeBoundsHash', () => {
    it('returns sha256: prefixed hash', () => {
      const hash = computeBoundsHash(validBounds, SPEND_PROFILE_V4);
      expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('produces same hash for same inputs', () => {
      const hash1 = computeBoundsHash(validBounds, SPEND_PROFILE_V4);
      const hash2 = computeBoundsHash(validBounds, SPEND_PROFILE_V4);
      expect(hash1).toBe(hash2);
    });

    it('produces different hash for different values', () => {
      const bounds2 = { ...validBounds, amount_max: 100 };
      const hash1 = computeBoundsHash(validBounds, SPEND_PROFILE_V4);
      const hash2 = computeBoundsHash(bounds2, SPEND_PROFILE_V4);
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('validateBoundsParams', () => {
    it('validates correct bounds params', () => {
      const result = validateBoundsParams(validBounds, SPEND_PROFILE_V4);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('returns error when profile has no boundsSchema', () => {
      const result = validateBoundsParams(validBounds, SPEND_PROFILE);
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
      const result = canonicalContext(validContext, SPEND_PROFILE_V4);
      expect(result).toBe('currency=EUR\naction_type=charge');
    });

    it('returns empty string for profile with no contextSchema', () => {
      const result = canonicalContext({}, SPEND_PROFILE);
      expect(result).toBe('');
    });

    it('throws on missing required field', () => {
      const ctx = { currency: 'EUR' }; // missing action_type
      expect(() => canonicalContext(ctx, SPEND_PROFILE_V4)).toThrow('Missing required field');
    });
  });

  describe('computeContextHash', () => {
    it('returns sha256: prefixed hash', () => {
      const hash = computeContextHash(validContext, SPEND_PROFILE_V4);
      expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('produces same hash for same inputs', () => {
      const hash1 = computeContextHash(validContext, SPEND_PROFILE_V4);
      const hash2 = computeContextHash(validContext, SPEND_PROFILE_V4);
      expect(hash1).toBe(hash2);
    });

    it('produces different hash for different values', () => {
      const ctx2 = { currency: 'USD', action_type: 'charge' };
      const hash1 = computeContextHash(validContext, SPEND_PROFILE_V4);
      const hash2 = computeContextHash(ctx2, SPEND_PROFILE_V4);
      expect(hash1).not.toBe(hash2);
    });

    it('empty context {} hashes to sha256 of empty string', () => {
      // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      const hash = computeContextHash({}, SPEND_PROFILE);
      expect(hash).toBe('sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });
  });

  describe('validateContextParams', () => {
    it('validates correct context params', () => {
      const result = validateContextParams(validContext, SPEND_PROFILE_V4);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('returns valid for empty params when no contextSchema', () => {
      const result = validateContextParams({}, SPEND_PROFILE);
      expect(result.valid).toBe(true);
    });

    it('returns error for unknown field in context', () => {
      const ctx = { ...validContext, unknown: 'x' };
      const result = validateContextParams(ctx, SPEND_PROFILE_V4);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('unknown'))).toBe(true);
    });
  });
});

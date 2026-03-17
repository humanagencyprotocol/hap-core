import { describe, it, expect } from 'vitest';
import { canonicalFrame, computeFrameHash, validateFrameParams } from '../src/frame';
import { SPEND_PROFILE, PUBLISH_PROFILE } from './fixtures';

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

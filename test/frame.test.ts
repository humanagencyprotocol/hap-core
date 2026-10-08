import { describe, it, expect } from 'vitest';
import {
  canonicalBounds,
  canonicalScope,
  computeBoundsHash,
  computeScopeHash,
  validateBoundsParams,
  validateScopeParams,
} from '../src/frame';
import { CHARGE_PROFILE_V4 } from './fixtures';
import type { AgentProfile } from '../src/types';

// v0.3's frameSchema / canonicalFrame / computeFrameHash / validateFrameParams
// are retired with the rest of pre-v0.5 (CLAUDE.md "Decided by the owner" —
// no backward compatibility). This file covers bounds + scope only.

describe('bounds', () => {
  const validBounds = {
    profile: CHARGE_PROFILE_V4.id,
    amount_max: 80,
    amount_daily_max: 500,
    amount_monthly_max: 5000,
    transaction_count_daily_max: 10,
  };

  describe('canonicalBounds', () => {
    it('produces canonical string with correct key order', () => {
      const result = canonicalBounds(validBounds, CHARGE_PROFILE_V4);
      expect(result).toBe(
        `profile=${CHARGE_PROFILE_V4.id}\namount_max=80\namount_daily_max=500\namount_monthly_max=5000\ntransaction_count_daily_max=10`
      );
    });

    it('throws on missing required field', () => {
      const bounds = { profile: CHARGE_PROFILE_V4.id };
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
      const noBoundsSchema: AgentProfile = { ...CHARGE_PROFILE_V4, boundsSchema: undefined };
      const result = validateBoundsParams(validBounds, noBoundsSchema);
      expect(result.valid).toBe(false);
      expect(result.errors[0]).toContain('boundsSchema');
    });
  });
});

describe('scope', () => {
  const validScope = {
    currency: 'EUR',
    action_type: 'charge',
  };

  describe('canonicalScope', () => {
    it('produces canonical string in keyOrder', () => {
      const result = canonicalScope(validScope, CHARGE_PROFILE_V4);
      expect(result).toBe('currency=EUR\naction_type=charge');
    });

    it('returns empty string for profile with no scopeSchema', () => {
      const noScopeSchema: AgentProfile = { ...CHARGE_PROFILE_V4, scopeSchema: undefined };
      const result = canonicalScope({}, noScopeSchema);
      expect(result).toBe('');
    });

    it('throws on missing required field', () => {
      const scope = { currency: 'EUR' }; // missing action_type
      expect(() => canonicalScope(scope, CHARGE_PROFILE_V4)).toThrow('Missing required field');
    });
  });

  describe('computeScopeHash', () => {
    it('returns sha256: prefixed hash', () => {
      const hash = computeScopeHash(validScope, CHARGE_PROFILE_V4);
      expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });

    it('produces same hash for same inputs', () => {
      const hash1 = computeScopeHash(validScope, CHARGE_PROFILE_V4);
      const hash2 = computeScopeHash(validScope, CHARGE_PROFILE_V4);
      expect(hash1).toBe(hash2);
    });

    it('produces different hash for different values', () => {
      const scope2 = { currency: 'USD', action_type: 'charge' };
      const hash1 = computeScopeHash(validScope, CHARGE_PROFILE_V4);
      const hash2 = computeScopeHash(scope2, CHARGE_PROFILE_V4);
      expect(hash1).not.toBe(hash2);
    });

    it('empty scope {} hashes to sha256 of empty string', () => {
      // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      const noScopeSchema: AgentProfile = { ...CHARGE_PROFILE_V4, scopeSchema: undefined };
      const hash = computeScopeHash({}, noScopeSchema);
      expect(hash).toBe('sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });
  });

  describe('validateScopeParams', () => {
    it('validates correct scope params', () => {
      const result = validateScopeParams(validScope, CHARGE_PROFILE_V4);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('returns valid for empty params when no scopeSchema', () => {
      const noScopeSchema: AgentProfile = { ...CHARGE_PROFILE_V4, scopeSchema: undefined };
      const result = validateScopeParams({}, noScopeSchema);
      expect(result.valid).toBe(true);
    });

    it('returns error for unknown field in scope', () => {
      const scope = { ...validScope, unknown: 'x' };
      const result = validateScopeParams(scope, CHARGE_PROFILE_V4);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('unknown'))).toBe(true);
    });
  });
});

// ─── Value Encoding (protocol.md → Bounds & Scope Canonicalization) ──────────

describe('value encoding', () => {
  /** Synthetic profile: one required key + optional string/number keys. */
  const ENCODING_PROFILE: AgentProfile = {
    id: 'encoding@0.7',
    version: '0.7',
    description: 'Synthetic profile for value-encoding tests',
    boundsSchema: {
      keyOrder: ['profile', 'note', 'label', 'amount_max'],
      fields: {
        profile: { type: 'string', required: true },
        note: { type: 'string', required: false, boundType: { kind: 'per_transaction', of: 'note' } },
        label: { type: 'string', required: false, boundType: { kind: 'per_transaction', of: 'label' } },
        amount_max: { type: 'number', required: false, boundType: { kind: 'per_transaction', of: 'amount' } },
      },
    },
    scopeSchema: {
      keyOrder: ['note', 'label'],
      fields: {
        note: { type: 'string', required: false },
        label: { type: 'string', required: false },
      },
    },
    executionContextSchema: { fields: {} },
    requiredGates: [],
    ttl: { default: 3600, max: 86400 },
    retention_minimum: 0,
  };

  describe('percent-encoding', () => {
    it('encodes "=" so it cannot be confused with the separator', () => {
      const result = canonicalBounds({ profile: 'encoding@0.7', note: 'a=b' }, ENCODING_PROFILE);
      expect(result).toBe('profile=encoding@0.7\nnote=a%3Db');
    });

    it('encodes "%" so the encoding is self-inverse', () => {
      const result = canonicalBounds({ profile: 'encoding@0.7', note: '100%' }, ENCODING_PROFILE);
      expect(result).toBe('profile=encoding@0.7\nnote=100%25');
    });

    it('encodes non-ASCII over its UTF-8 bytes, uppercase hex', () => {
      // em dash U+2014 → E2 80 94
      const result = canonicalBounds({ profile: 'encoding@0.7', note: '—' }, ENCODING_PROFILE);
      expect(result).toBe('profile=encoding@0.7\nnote=%E2%80%94');
    });

    it('encodes control bytes below 0x20 (tab) and 0x7F', () => {
      const result = canonicalScope({ note: '\t', label: '\x7f' }, ENCODING_PROFILE);
      expect(result).toBe('note=%09\nlabel=%7F');
    });

    it('leaves printable ASCII, including space, untouched', () => {
      const result = canonicalScope({ note: 'a b~!' }, ENCODING_PROFILE);
      expect(result).toBe('note=a b~!');
    });

    it('is applied to scope too', () => {
      expect(canonicalScope({ note: 'a=b 100% —' }, ENCODING_PROFILE))
        .toBe('note=a%3Db 100%25 %E2%80%94');
    });

    it('does not mutate the stored value — encoding happens at canonicalization time', () => {
      const bounds = { profile: 'encoding@0.7', note: 'a=b 100% —' };
      canonicalBounds(bounds, ENCODING_PROFILE);
      expect(bounds.note).toBe('a=b 100% —');
    });
  });

  describe('raw LF/CR is refused, never normalized', () => {
    it('bounds → BOUNDS_INVALID_VALUE on LF', () => {
      let code: unknown;
      try {
        canonicalBounds({ profile: 'encoding@0.7', note: 'one\ntwo' }, ENCODING_PROFILE);
      } catch (err) {
        code = (err as { code?: string }).code;
      }
      expect(code).toBe('BOUNDS_INVALID_VALUE');
    });

    it('bounds → BOUNDS_INVALID_VALUE on CR', () => {
      expect(() => canonicalBounds({ profile: 'encoding@0.7', note: 'a\rb' }, ENCODING_PROFILE))
        .toThrow(/raw newline or carriage return/);
    });

    it('scope → SCOPE_INVALID_VALUE', () => {
      let code: unknown;
      try {
        canonicalScope({ note: 'a\rb' }, ENCODING_PROFILE);
      } catch (err) {
        code = (err as { code?: string }).code;
      }
      expect(code).toBe('SCOPE_INVALID_VALUE');
    });

    it('names the offending field', () => {
      let field: unknown;
      try {
        canonicalScope({ label: 'a\nb' }, ENCODING_PROFILE);
      } catch (err) {
        field = (err as { field?: string }).field;
      }
      expect(field).toBe('label');
    });

    it('computeBoundsHash surfaces the refusal rather than hashing stripped input', () => {
      expect(() => computeBoundsHash({ profile: 'encoding@0.7', note: 'a\nb' }, ENCODING_PROFILE))
        .toThrow(/Refusing/);
    });
  });

  describe('numbers use the shortest round-trippable form', () => {
    it('20.0 serializes as "20"', () => {
      const result = canonicalBounds(
        { profile: 'encoding@0.7', amount_max: 20.0 },
        ENCODING_PROFILE,
      );
      expect(result).toBe('profile=encoding@0.7\namount_max=20');
    });

    it('12.5 keeps its decimal', () => {
      const result = canonicalBounds(
        { profile: 'encoding@0.7', amount_max: 12.5 },
        ENCODING_PROFILE,
      );
      expect(result).toBe('profile=encoding@0.7\namount_max=12.5');
    });
  });

  describe('absent optional keys are omitted', () => {
    it('emits no record for a key the human never set', () => {
      expect(canonicalBounds({ profile: 'encoding@0.7' }, ENCODING_PROFILE))
        .toBe('profile=encoding@0.7');
    });

    it('never hashes the literal string "undefined"', () => {
      expect(canonicalBounds({ profile: 'encoding@0.7', note: 'x' }, ENCODING_PROFILE))
        .not.toContain('undefined');
    });

    it('keeps "absent" distinguishable from "explicitly empty"', () => {
      const absent = canonicalBounds({ profile: 'encoding@0.7' }, ENCODING_PROFILE);
      const empty = canonicalBounds({ profile: 'encoding@0.7', note: '' }, ENCODING_PROFILE);
      expect(empty).toBe('profile=encoding@0.7\nnote=');
      expect(absent).not.toBe(empty);
    });

    it('a real value of "undefined" is not confusable with an absent key', () => {
      const literal = canonicalBounds(
        { profile: 'encoding@0.7', note: 'undefined' },
        ENCODING_PROFILE,
      );
      expect(literal).toBe('profile=encoding@0.7\nnote=undefined');
      expect(literal).not.toBe(canonicalBounds({ profile: 'encoding@0.7' }, ENCODING_PROFILE));
    });
  });
});

import { describe, it, expect, beforeAll } from 'vitest';
import { getProfile, listProfiles, getAllProfiles, registerProfile, clearProfiles } from '../src/profiles';
import { CHARGE_PROFILE_V4, EMAIL_PROFILE_V4 } from './fixtures';

beforeAll(() => {
  clearProfiles();
  registerProfile(CHARGE_PROFILE_V4.id, CHARGE_PROFILE_V4);
  registerProfile(EMAIL_PROFILE_V4.id, EMAIL_PROFILE_V4);
});

describe('profiles registry', () => {
  describe('getProfile', () => {
    it('returns the charge profile', () => {
      const profile = getProfile(CHARGE_PROFILE_V4.id);
      expect(profile).toBeDefined();
      expect(profile!.id).toBe(CHARGE_PROFILE_V4.id);
    });

    it('returns the email profile', () => {
      const profile = getProfile(EMAIL_PROFILE_V4.id);
      expect(profile).toBeDefined();
      expect(profile!.id).toBe(EMAIL_PROFILE_V4.id);
    });

    it('returns undefined for unknown profile', () => {
      expect(getProfile('unknown@1.0')).toBeUndefined();
    });
  });

  describe('listProfiles', () => {
    it('lists all profile IDs', () => {
      const ids = listProfiles();
      expect(ids).toContain(CHARGE_PROFILE_V4.id);
      expect(ids).toContain(EMAIL_PROFILE_V4.id);
    });
  });

  describe('getAllProfiles', () => {
    it('returns all profiles', () => {
      const profiles = getAllProfiles();
      expect(profiles).toHaveLength(2);
    });
  });
});

describe('charge profile shape (v0.7)', () => {
  it('declares a boundsSchema with an actionTypes registry', () => {
    expect(CHARGE_PROFILE_V4.boundsSchema).toBeDefined();
    expect(CHARGE_PROFILE_V4.boundsSchema!.actionTypes).toEqual(['charge', 'refund', 'subscribe']);
  });

  it('has a boundType on every non-metadata bounds field', () => {
    for (const [name, def] of Object.entries(CHARGE_PROFILE_V4.boundsSchema!.fields)) {
      if (name === 'profile') continue;
      expect(def.boundType, `field "${name}"`).toBeDefined();
    }
  });

  it('declares a scopeSchema (not the retired contextSchema)', () => {
    expect(CHARGE_PROFILE_V4.scopeSchema).toBeDefined();
    expect('contextSchema' in CHARGE_PROFILE_V4).toBe(false);
  });

  it('declares the v0.7 required gates (mandate_owner, not decision_owner)', () => {
    expect(CHARGE_PROFILE_V4.requiredGates).toContain('mandate_owner');
    expect(CHARGE_PROFILE_V4.requiredGates).not.toContain('decision_owner');
    expect(CHARGE_PROFILE_V4.requiredGates).not.toContain('frame');
  });

  it('has no frameSchema or executionPaths — v0.3 is retired', () => {
    expect('frameSchema' in CHARGE_PROFILE_V4).toBe(false);
    expect('executionPaths' in CHARGE_PROFILE_V4).toBe(false);
  });
});

describe('email profile shape (v0.7)', () => {
  it('declares a scopeSchema with subset-constrained recipient/domain fields', () => {
    const fields = EMAIL_PROFILE_V4.scopeSchema!.fields;
    expect(fields.allowed_recipients.constraint?.enforceable).toContain('subset');
    expect(fields.allowed_domains.constraint?.enforceable).toContain('subset');
  });
});

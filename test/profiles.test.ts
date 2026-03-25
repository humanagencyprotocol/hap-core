import { describe, it, expect, beforeAll } from 'vitest';
import { getProfile, listProfiles, getAllProfiles, registerProfile } from '../src/profiles';
import { CHARGE_PROFILE, EMAIL_PROFILE } from './fixtures';

beforeAll(() => {
  registerProfile('charge@0.3', CHARGE_PROFILE);
  registerProfile('email@0.3', EMAIL_PROFILE);
});

describe('profiles', () => {
  describe('getProfile', () => {
    it('returns charge profile', () => {
      const profile = getProfile('charge@0.3');
      expect(profile).toBeDefined();
      expect(profile!.id).toBe('charge@0.3');
    });

    it('returns email profile', () => {
      const profile = getProfile('email@0.3');
      expect(profile).toBeDefined();
      expect(profile!.id).toBe('email@0.3');
    });

    it('returns undefined for unknown profile', () => {
      expect(getProfile('unknown@1.0')).toBeUndefined();
    });
  });

  describe('listProfiles', () => {
    it('lists all profile IDs', () => {
      const ids = listProfiles();
      expect(ids).toContain('charge@0.3');
      expect(ids).toContain('email@0.3');
    });
  });

  describe('getAllProfiles', () => {
    it('returns all profiles', () => {
      const profiles = getAllProfiles();
      expect(profiles).toHaveLength(2);
    });
  });

  describe('charge@0.3', () => {
    it('has correct execution paths', () => {
      expect(CHARGE_PROFILE.executionPaths['charge-routine']).toBeDefined();
      expect(CHARGE_PROFILE.executionPaths['charge-routine'].requiredDomains).toEqual(['finance']);
      expect(CHARGE_PROFILE.executionPaths['charge-reviewed'].requiredDomains).toEqual(['finance', 'compliance']);
    });

    it('has constraint types on amount_max', () => {
      const field = CHARGE_PROFILE.frameSchema.fields['amount_max'];
      expect(field.constraint).toBeDefined();
      expect(field.constraint!.enforceable).toContain('max');
    });

    it('has constraint types on currency', () => {
      const field = CHARGE_PROFILE.frameSchema.fields['currency'];
      expect(field.constraint).toBeDefined();
      expect(field.constraint!.enforceable).toContain('enum');
    });

    it('has all 6 required gates', () => {
      expect(CHARGE_PROFILE.requiredGates).toHaveLength(6);
      expect(CHARGE_PROFILE.requiredGates).toContain('frame');
      expect(CHARGE_PROFILE.requiredGates).toContain('problem');
      expect(CHARGE_PROFILE.requiredGates).toContain('commitment');
      expect(CHARGE_PROFILE.requiredGates).toContain('decision_owner');
    });

    it('has gate questions', () => {
      expect(CHARGE_PROFILE.gateQuestions.problem.question).toBeDefined();
      expect(CHARGE_PROFILE.gateQuestions.objective.question).toBeDefined();
      expect(CHARGE_PROFILE.gateQuestions.tradeoffs.question).toBeDefined();
    });
  });

  describe('email@0.3', () => {
    it('has correct execution paths', () => {
      expect(EMAIL_PROFILE.executionPaths['email-draft']).toBeDefined();
      expect(EMAIL_PROFILE.executionPaths['email-send']).toBeDefined();
      expect(EMAIL_PROFILE.executionPaths['email-read']).toBeDefined();
      expect(EMAIL_PROFILE.executionPaths['email-draft'].requiredDomains).toEqual(['communications']);
    });

    it('has constraint types on recipient_max', () => {
      const field = EMAIL_PROFILE.frameSchema!.fields['recipient_max'];
      expect(field.constraint).toBeDefined();
      expect(field.constraint!.enforceable).toContain('max');
    });

    it('has constraint types on send_daily_max', () => {
      const field = EMAIL_PROFILE.frameSchema!.fields['send_daily_max'];
      expect(field.constraint).toBeDefined();
      expect(field.constraint!.enforceable).toContain('max');
    });
  });
});

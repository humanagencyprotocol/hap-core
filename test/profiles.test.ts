import { describe, it, expect, beforeAll } from 'vitest';
import { getProfile, listProfiles, getAllProfiles, registerProfile } from '../src/profiles';
import { SPEND_PROFILE, PUBLISH_PROFILE } from './fixtures';

beforeAll(() => {
  registerProfile('spend@0.3', SPEND_PROFILE);
  registerProfile('publish@0.3', PUBLISH_PROFILE);
});

describe('profiles', () => {
  describe('getProfile', () => {
    it('returns spend profile', () => {
      const profile = getProfile('spend@0.3');
      expect(profile).toBeDefined();
      expect(profile!.id).toBe('spend@0.3');
    });

    it('returns publish profile', () => {
      const profile = getProfile('publish@0.3');
      expect(profile).toBeDefined();
      expect(profile!.id).toBe('publish@0.3');
    });

    it('returns undefined for unknown profile', () => {
      expect(getProfile('unknown@1.0')).toBeUndefined();
    });
  });

  describe('listProfiles', () => {
    it('lists all profile IDs', () => {
      const ids = listProfiles();
      expect(ids).toContain('spend@0.3');
      expect(ids).toContain('publish@0.3');
    });
  });

  describe('getAllProfiles', () => {
    it('returns all profiles', () => {
      const profiles = getAllProfiles();
      expect(profiles).toHaveLength(2);
    });
  });

  describe('spend@0.3', () => {
    it('has correct execution paths', () => {
      expect(SPEND_PROFILE.executionPaths['spend-routine']).toBeDefined();
      expect(SPEND_PROFILE.executionPaths['spend-routine'].requiredDomains).toEqual(['finance']);
      expect(SPEND_PROFILE.executionPaths['spend-reviewed'].requiredDomains).toEqual(['finance', 'compliance']);
    });

    it('has constraint types on amount_max', () => {
      const field = SPEND_PROFILE.frameSchema.fields['amount_max'];
      expect(field.constraint).toBeDefined();
      expect(field.constraint!.enforceable).toContain('max');
    });

    it('has constraint types on currency', () => {
      const field = SPEND_PROFILE.frameSchema.fields['currency'];
      expect(field.constraint).toBeDefined();
      expect(field.constraint!.enforceable).toContain('enum');
    });

    it('has all 6 required gates', () => {
      expect(SPEND_PROFILE.requiredGates).toHaveLength(6);
      expect(SPEND_PROFILE.requiredGates).toContain('frame');
      expect(SPEND_PROFILE.requiredGates).toContain('problem');
      expect(SPEND_PROFILE.requiredGates).toContain('commitment');
      expect(SPEND_PROFILE.requiredGates).toContain('decision_owner');
    });

    it('has gate questions', () => {
      expect(SPEND_PROFILE.gateQuestions.problem.question).toBeDefined();
      expect(SPEND_PROFILE.gateQuestions.objective.question).toBeDefined();
      expect(SPEND_PROFILE.gateQuestions.tradeoffs.question).toBeDefined();
    });
  });

  describe('publish@0.3', () => {
    it('has correct execution paths', () => {
      expect(PUBLISH_PROFILE.executionPaths['publish-transactional']).toBeDefined();
      expect(PUBLISH_PROFILE.executionPaths['publish-transactional'].requiredDomains).toEqual(['engineering']);
      expect(PUBLISH_PROFILE.executionPaths['publish-marketing'].requiredDomains).toEqual(['marketing', 'product']);
    });

    it('has constraint types on recipient_max', () => {
      const field = PUBLISH_PROFILE.frameSchema.fields['recipient_max'];
      expect(field.constraint).toBeDefined();
      expect(field.constraint!.enforceable).toContain('max');
    });

    it('has constraint types on channel', () => {
      const field = PUBLISH_PROFILE.frameSchema.fields['channel'];
      expect(field.constraint).toBeDefined();
      expect(field.constraint!.enforceable).toContain('enum');
    });
  });
});

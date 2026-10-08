/**
 * A profile can restrict the commitment modes its mandates may be signed with
 * (`commitment_modes`). Profiles without the field keep every mode; a declared
 * list is read fail-closed — a malformed one only ever narrows.
 */
import { describe, it, expect } from 'vitest';
import {
  allowedCommitmentModes, isCommitmentModeAllowed, SIGNABLE_COMMITMENT_MODES,
  validateProfile,
  type AgentProfile,
} from '../src';

const base = {
  id: 'example.com/p@0.1', version: '0.1', description: 'test',
  executionContextSchema: { fields: {} }, requiredGates: ['intent'],
  ttl: { default: 3600, max: 86400 }, retention_minimum: 0,
} as AgentProfile;
const withModes = (commitment_modes: unknown) => ({ ...base, commitment_modes } as AgentProfile);

describe('allowedCommitmentModes', () => {
  it('no declaration → every mode, as before the field existed', () => {
    expect(allowedCommitmentModes(base)).toEqual(['review', 'automatic']);
    expect(allowedCommitmentModes(base)).toEqual(SIGNABLE_COMMITMENT_MODES);
  });

  it('a review-only profile allows review and nothing else', () => {
    const p = withModes(['review']);
    expect(allowedCommitmentModes(p)).toEqual(['review']);
    expect(isCommitmentModeAllowed(p, 'review')).toBe(true);
    expect(isCommitmentModeAllowed(p, 'automatic')).toBe(false);
  });

  it('returns modes in display order whatever order the profile lists them', () => {
    expect(allowedCommitmentModes(withModes(['automatic', 'review']))).toEqual(['review', 'automatic']);
  });

  it.each([
    ['an empty list', []],
    ['a string instead of a list', 'review'],
    ['a misspelled mode', ['reveiw']],
    ['review_above_cap (not chosen by the signer)', ['review_above_cap']],
  ])('fail-closed: %s allows nothing', (_label, declared) => {
    const p = withModes(declared);
    expect(allowedCommitmentModes(p)).toEqual([]);
    expect(isCommitmentModeAllowed(p, 'review')).toBe(false);
    expect(isCommitmentModeAllowed(p, 'automatic')).toBe(false);
  });

  it('never allows a value that is not a signable mode, declared or not', () => {
    expect(isCommitmentModeAllowed(base, 'review_above_cap')).toBe(false);
    expect(isCommitmentModeAllowed(withModes(['review', 'nonsense']), 'nonsense')).toBe(false);
  });
});

describe('validateProfile — commitment_modes', () => {
  const messages = (p: AgentProfile) => validateProfile(p).map((e) => e.message);

  it('accepts no declaration and a valid one', () => {
    expect(messages(base)).toEqual([]);
    expect(messages(withModes(['review']))).toEqual([]);
  });

  it('names each problem', () => {
    expect(messages(withModes('review'))).toEqual(['commitment_modes must be a list of modes.']);
    expect(messages(withModes([]))[0]).toMatch(/empty/);
    expect(messages(withModes(['review', 'reveiw']))[0]).toMatch(/"reveiw" is not a mode/);
    expect(messages(withModes(['review', 'review']))[0]).toMatch(/appears twice/);
    for (const e of validateProfile(withModes('review'))) expect(e.code).toBe('PROFILE_INVALID');
  });
});

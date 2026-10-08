/**
 * The shipped email profile, not a fixture — status check.
 *
 * `requiredFor` is only worth anything if the profile people actually use
 * declares it. A fixture proving the engine works would pass happily while the
 * real profile left the hole open — which is exactly how the empty-content
 * binding survived review.
 *
 * FINDING (v0.7 wire-switch Phase 0, hap-core): as of this change, no file
 * under hap-profiles/ has been migrated to v0.7 field names — every version,
 * including email/0.7.profile.json, still declares `contextSchema` (not
 * `scopeSchema`) and `requiredGates: [..., "decision_owner"]` (not
 * `"mandate_owner"`), and several bounds fields still carry the retired
 * `paths` array. hap-profiles migration is a separate repo and explicitly out
 * of scope for this change (CLAUDE.md: "Do not touch other repos"). This test
 * documents the gap rather than silently dropping coverage: it pins that
 * `validateProfile` correctly flags the shipped file as non-conformant today,
 * so the moment hap-profiles ships a v0.7-vocabulary version this test's
 * first assertion starts failing — which is the signal to swap in the real
 * gatekeeper.verify() exercise that used to live here.
 *
 * Reads hap-profiles from the sibling checkout the gateway loads by default.
 * Skips if absent so a standalone hap-core clone still tests green.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { validateProfile } from '../src/profile';
import type { AgentProfile } from '../src/types';

const PROFILE_PATH = join(__dirname, '..', '..', 'hap-profiles', 'email', '0.7.profile.json');
const available = existsSync(PROFILE_PATH);

describe.skipIf(!available)('email@0.7 as shipped by hap-profiles (pre-migration)', () => {
  const profile: AgentProfile = available
    ? (JSON.parse(readFileSync(PROFILE_PATH, 'utf8')) as AgentProfile)
    : (null as unknown as AgentProfile);

  it('still declares the retired v0.6 field contextSchema — hap-profiles v0.7 vocabulary migration is pending', () => {
    expect('contextSchema' in profile).toBe(true);
    expect(profile.scopeSchema).toBeUndefined();
    const errors = validateProfile(profile);
    expect(errors.some((e) => e.field === 'contextSchema')).toBe(true);
  });

  it('still requires the retired gate name "decision_owner", not "mandate_owner"', () => {
    expect(profile.requiredGates).toContain('decision_owner');
    const errors = validateProfile(profile);
    expect(errors.some((e) => e.field === 'requiredGates')).toBe(true);
  });

  it('declares requiredFor on the recipient dimensions, under the old key (contextSchema.fields)', () => {
    // Read via the retired field name directly (not scopeSchema) — the
    // point of this test is what the file ON DISK says today.
    const fields = (profile as unknown as { contextSchema: AgentProfile['scopeSchema'] }).contextSchema!.fields;
    expect(fields.allowed_recipients.constraint?.requiredFor).toContain('send');
    expect(fields.allowed_domains.constraint?.requiredFor).toContain('send');
  });
});

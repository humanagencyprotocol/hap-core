/**
 * The shipped email profile, not a fixture.
 *
 * `requiredFor` is only worth anything if the profile people actually use
 * declares it. A fixture proving the engine works would pass happily while the
 * real profile left the hole open — which is exactly how the empty-content
 * binding survived review.
 *
 * email@0.8 is the first email version in v0.7 vocabulary (scopeSchema,
 * mandate_owner, no `paths`). During the hap-core v0.7 port this test briefly
 * pinned the pre-migration email@0.7 as non-conformant; with 0.8 published it
 * exercises the real profile through the Gatekeeper again.
 *
 * Reads hap-profiles from $HAP_PROFILES_DIR or the sibling checkout the gateway
 * loads by default. Skips if absent so a standalone hap-core clone still tests
 * green; CI checks hap-profiles out.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verify } from '../src/gatekeeper';
import { registerProfile } from '../src/profiles';
import { validateProfile } from '../src/profile';
import { generateTestKeyPair, createTestMandate, type TestKeyPair } from './helpers';
import { HAP_PROFILES_DIR } from './vectors/_spec-dir';
import type { AgentProfile } from '../src/types';

const PROFILE_PATH = join(HAP_PROFILES_DIR, 'email', '0.8.profile.json');
const available = existsSync(PROFILE_PATH);

describe.skipIf(!available)('email@0.8 as shipped', () => {
  let keyPair: TestKeyPair;
  let profile: AgentProfile;

  // Exactly the fields the shipped boundsSchema declares.
  const bounds = { profile: '', recipient_max: 5, send_daily_max: 20, read_max_age_days: 30, read_access: 'none', setup_daily_max: 5 };
  const scope = { allowed_recipients: 'andreas@example.com', allowed_domains: 'example.com' };

  beforeAll(async () => {
    profile = JSON.parse(readFileSync(PROFILE_PATH, 'utf8')) as AgentProfile;
    bounds.profile = profile.id;
    registerProfile(profile.id, profile);
    keyPair = await generateTestKeyPair();
  });

  async function check(execution: Record<string, string | number>) {
    const blob = await createTestMandate({ keyPair, bounds, scope, profile });
    return verify({ bounds, scope, mandates: [blob], execution });
  }

  it('is a conformant v0.7 profile', () => {
    expect(validateProfile(profile)).toEqual([]);
  });

  it('declares requiredFor on the recipient dimensions', () => {
    const fields = profile.scopeSchema!.fields;
    expect(fields.allowed_recipients.constraint?.requiredFor).toContain('send');
    expect(fields.allowed_domains.constraint?.requiredFor).toContain('send');
  });

  it('approves an ordinary send to an authorized recipient', async () => {
    const r = await check({
      action_type: 'send',
      recipient_count: 1,
      allowed_recipients: 'andreas@example.com',
      allowed_domains: 'example.com',
    });
    expect(r.approved, JSON.stringify(r.errors)).toBe(true);
  });

  it('REFUSES a send that exposes no recipients — the send_draft shape', async () => {
    // gmail's send_draft declares staticExecution action_type "send" and an
    // empty executionMapping: it transmits, and the Gatekeeper never learns to
    // whom. Refusing it is the intended consequence, not collateral damage.
    const r = await check({ action_type: 'send', recipient_count: 1 });
    expect(r.approved).toBe(false);
  });

  it('still allows a delete, which engages no recipients', async () => {
    const r = await check({ action_type: 'delete', recipient_count: 0 });
    expect(r.approved, JSON.stringify(r.errors)).toBe(true);
  });

  it('still refuses a recipient outside the authorized set', async () => {
    const r = await check({
      action_type: 'send',
      recipient_count: 1,
      allowed_recipients: 'stranger@elsewhere.com',
      allowed_domains: 'elsewhere.com',
    });
    expect(r.approved).toBe(false);
  });
});

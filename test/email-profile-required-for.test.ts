/**
 * The shipped email profile, not a fixture.
 *
 * `requiredFor` is only worth anything if the profile people actually use
 * declares it. A fixture proving the engine works would pass happily while the
 * real profile left the hole open — which is exactly how the empty-content
 * binding survived review.
 *
 * Reads hap-profiles from the sibling checkout the gateway loads by default.
 * Skips if absent so a standalone hap-core clone still tests green.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verify } from '../src/gatekeeper';
import { registerProfile } from '../src/profiles';
import { generateTestKeyPair, createTestAttestationV4, type TestKeyPair } from './helpers';
import type { AgentProfile } from '../src/types';

const PROFILE_PATH = join(__dirname, '..', '..', 'hap-profiles', 'email', '0.4.profile.json');
const available = existsSync(PROFILE_PATH);

describe.skipIf(!available)('email@0.4 as shipped', () => {
  let keyPair: TestKeyPair;
  let profile: AgentProfile;

  // Exactly the fields the shipped boundsSchema declares — no 'path', which
  // the real profile rejects even though the test fixtures carry it.
  const bounds = { profile: 'email@0.4', recipient_max: 5, send_daily_max: 20 };
  const context = { allowed_recipients: 'andreas@example.com', allowed_domains: 'example.com' };

  beforeAll(async () => {
    profile = JSON.parse(readFileSync(PROFILE_PATH, 'utf8')) as AgentProfile;
    registerProfile('email@0.4', profile);
    keyPair = await generateTestKeyPair();
  });

  async function check(execution: Record<string, string | number>) {
    const blob = await createTestAttestationV4({ keyPair, bounds, context, profile, domain: 'email' });
    return verify({ frame: bounds, context, attestations: [blob], execution }, keyPair.publicKeyHex);
  }

  it('declares requiredFor on the recipient dimensions', () => {
    const fields = profile.contextSchema!.fields;
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
    expect(r.approved).toBe(true);
  });

  it('REFUSES a send that exposes no recipients — the send_draft shape', async () => {
    // gmail's send_draft declares staticExecution action_type "send" and an
    // empty executionMapping: it transmits, and the Gatekeeper never learns to
    // whom. Refusing it is the intended consequence of this change, not
    // collateral damage.
    const r = await check({ action_type: 'send', recipient_count: 1 });
    expect(r.approved).toBe(false);
  });

  it('still allows a delete, which engages no recipients', async () => {
    // delete_draft: action_type "delete", recipient_count 0. Must keep working.
    const r = await check({ action_type: 'delete', recipient_count: 0 });
    expect(r.approved).toBe(true);
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

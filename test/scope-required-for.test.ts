/**
 * A constrained dimension the call does not expose.
 *
 * `allowed_recipients` was only ever compared when the call happened to carry
 * recipients. Gmail's `send_message` accepts `raw` — a whole pre-formatted
 * message — and its schema states that raw causes to/cc/subject/body to be
 * ignored, so `to` is never populated and the subset check had nothing to
 * compare. It skipped, and the send passed as authorized. `send_draft` is the
 * same shape: it transmits, and the Gatekeeper never sees to whom.
 *
 * Silence must not read as compliance. But it must still be allowed to mean
 * "not applicable" — deleting a draft has no recipients, and denying that would
 * break every non-transmitting action. `requiredFor` draws that line on the
 * ACTION, which is where it belongs.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { verify } from '../src/gatekeeper';
import { registerProfile } from '../src/profiles';
import { EMAIL_PROFILE_V4 } from './fixtures';
import { generateTestKeyPair, createTestMandate, type TestKeyPair } from './helpers';
import type { AgentBoundsParams, AgentProfile } from '../src/types';

const GUARDED = 'email-guarded@0.7';
const LEGACY = 'email-legacy@0.7';

/** EMAIL_PROFILE_V4 with recipients required for sends. */
function withRequiredFor(id: string, requiredFor?: string[]): AgentProfile {
  const base = JSON.parse(JSON.stringify(EMAIL_PROFILE_V4)) as AgentProfile;
  base.id = id;
  const field = base.scopeSchema!.fields.allowed_recipients;
  if (requiredFor) field.constraint!.requiredFor = requiredFor;
  return base;
}

describe('a constrained dimension the call does not expose', () => {
  let keyPair: TestKeyPair;

  const bounds: AgentBoundsParams = {
    profile: GUARDED,
    recipient_max: 5,
    send_daily_max: 20,
  };
  const scope = { allowed_recipients: 'andreas@example.com', allowed_domains: 'example.com' };

  beforeAll(async () => {
    registerProfile(GUARDED, withRequiredFor(GUARDED, ['send']));
    registerProfile(LEGACY, withRequiredFor(LEGACY));
    keyPair = await generateTestKeyPair();
  });

  async function check(profileId: string, execution: Record<string, string | number>) {
    const requestBounds = { ...bounds, profile: profileId };
    const profile = profileId === GUARDED ? withRequiredFor(GUARDED, ['send']) : withRequiredFor(LEGACY);
    const blob = await createTestMandate({ keyPair, bounds: requestBounds, scope, profile });
    return verify({ bounds: requestBounds, scope, mandates: [blob], execution });
  }

  it('approves a send whose recipients are visible and in scope', async () => {
    const r = await check(GUARDED, {
      action_type: 'send',
      recipient_count: 1,
      allowed_recipients: 'andreas@example.com',
      allowed_domains: 'example.com',
    });
    expect(r.approved).toBe(true);
  });

  it('REFUSES a send that exposes no recipients at all', async () => {
    // The `raw` case. Previously this passed: nothing to compare, so no error.
    const r = await check(GUARDED, { action_type: 'send', recipient_count: 1 });
    expect(r.approved).toBe(false);
    if (!r.approved) {
      expect(r.errors[0].field).toBe('allowed_recipients');
      expect(r.errors[0].message).toMatch(/no allowed_recipients to check/i);
    }
  });

  it('REFUSES a send whose recipients are present but empty', async () => {
    // Refusing only on ABSENT values would be bypassable by sending "".
    const r = await check(GUARDED, {
      action_type: 'send',
      recipient_count: 1,
      allowed_recipients: '',
    });
    expect(r.approved).toBe(false);
  });

  it('still allows an action that does not engage recipients', async () => {
    // Deleting a draft transmits nothing. Denying it would break every
    // non-transmitting tool under this profile — the reason the rule keys on
    // the action rather than simply demanding the field always be present.
    const r = await check(GUARDED, { action_type: 'delete', recipient_count: 0 });
    expect(r.approved).toBe(true);
  });

  it('a send to a recipient outside the authorized set is still refused', async () => {
    // The pre-existing check must keep working alongside the new one.
    const r = await check(GUARDED, {
      action_type: 'send',
      recipient_count: 1,
      allowed_recipients: 'stranger@elsewhere.com',
    });
    expect(r.approved).toBe(false);
  });

  it('a profile without requiredFor keeps its previous behaviour', async () => {
    // Backwards compatibility: existing profiles must not start refusing calls
    // the moment this ships. Closing the hole is a per-profile decision.
    const r = await check(LEGACY, { action_type: 'send', recipient_count: 1 });
    expect(r.approved).toBe(true);
  });
});

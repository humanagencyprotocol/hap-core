/**
 * A `subset` scope field with NO `enum` in the profile.
 *
 * delegation@0.6 drops the fixed list of profile names from `allowed_profiles`:
 * the signer picks any area available in their workspace, so the profile can
 * no longer enumerate the values. The Gatekeeper must still enforce the field
 * purely from the mandate's OWN signed list — the enum was never part of the
 * check, and this pins that down: a value the mandate lists passes even though
 * no enum names it, and a value it does not list is refused.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { verify } from '../src/gatekeeper';
import { registerProfile } from '../src/profiles';
import { generateTestKeyPair, createTestMandate, type TestKeyPair } from './helpers';
import type { AgentBoundsParams, AgentProfile } from '../src/types';

const ID = 'example.com/profiles/delegating@0.6';

/** A minimal delegating profile: `allowed_profiles` is a free list (no enum). */
const PROFILE = {
  id: ID,
  version: '0.6',
  commitment_modes: ['review'],
  boundsSchema: {
    actionTypes: ['mandate'],
    keyOrder: ['profile', 'mandate_daily_max'],
    fields: {
      profile: { type: 'string', required: true },
      mandate_daily_max: {
        type: 'number', required: true, unit: 'count',
        boundType: { kind: 'cumulative_count', window: 'daily' }, appliesTo: ['mandate'],
      },
    },
  },
  executionContextSchema: {
    fields: {
      allowed_profiles: {
        source: 'declared', description: 'Profile a proposal is for', required: false,
        constraint: { type: 'string', enforceable: ['subset'] },
      },
    },
  },
  requiredGates: ['bounds', 'intent', 'commitment', 'mandate_owner'],
  ttl: { default: 86400, max: 2592000 },
  scopeSchema: {
    keyOrder: ['allowed_profiles'],
    fields: {
      allowed_profiles: {
        type: 'string', required: true, valuesFrom: 'profiles',
        constraint: { type: 'string', enforceable: ['subset'], requiredFor: ['mandate'] },
      },
    },
  },
} as unknown as AgentProfile;

describe('subset scope field without an enum', () => {
  let keyPair: TestKeyPair;
  const bounds: AgentBoundsParams = { profile: ID, mandate_daily_max: 5 };
  const scope = { allowed_profiles: 'sales,invoicing' };

  beforeAll(async () => {
    registerProfile(ID, PROFILE);
    keyPair = await generateTestKeyPair();
  });

  async function check(execution: Record<string, string | number>) {
    const blob = await createTestMandate({ keyPair, bounds, scope, profile: PROFILE, commitmentMode: 'review' });
    return verify({ bounds, scope, mandates: [blob], execution });
  }

  it('approves a value the mandate lists, with no enum naming it', async () => {
    const r = await check({ action_type: 'mandate', allowed_profiles: 'invoicing' });
    expect(r.approved).toBe(true);
  });

  it('compares case-insensitively and trims, like every subset field', async () => {
    const r = await check({ action_type: 'mandate', allowed_profiles: ' Sales ' });
    expect(r.approved).toBe(true);
  });

  it('REFUSES a value the mandate does not list', async () => {
    const r = await check({ action_type: 'mandate', allowed_profiles: 'charge' });
    expect(r.approved).toBe(false);
    if (!r.approved) {
      expect(r.errors[0].field).toBe('allowed_profiles');
      expect(r.errors[0].code).toBe('BOUND_EXCEEDED');
    }
  });

  it('REFUSES a mandate action that exposes no value (requiredFor)', async () => {
    const r = await check({ action_type: 'mandate' });
    expect(r.approved).toBe(false);
  });
});

/**
 * Cumulative bounds must apply only to the actions they govern.
 *
 * The local gate counts by (profileId, path) and nothing else. Every
 * cumulative_count bound on a profile therefore sees the SAME running total —
 * so on a profile like customers, which declares both write_daily_max and
 * delete_daily_max, the small delete limit counts writes too and blocks them.
 *
 * This never surfaced because the local gate could not fire at all (the path
 * always resolved to "", see cumulative-path.test.ts). Fixing that turns this
 * latent bug live, which is why it has to be fixed in the same change rather
 * than after publishing.
 *
 * The Authority Server already solves this by selecting bounds per action type.
 * These tests pin the same behaviour locally, driven by the profile's declared
 * `appliesTo` and falling back to the name convention.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { verify } from '../src/gatekeeper';
import { registerProfile } from '../src/profiles';
import { generateTestKeyPair, createTestAttestationV4, type TestKeyPair } from './helpers';
import type { AgentProfile, AgentBoundsParams, ExecutionLogQuery, CumulativeWindow } from '../src/types';

/** Mirrors hap-profiles/customers@0.5: two count bounds, one path, no `path` bound. */
function customersProfile(withAppliesTo: boolean): AgentProfile {
  const write: Record<string, unknown> = {
    type: 'number', required: true,
    boundType: { kind: 'cumulative_count', window: 'daily' },
  };
  const del: Record<string, unknown> = {
    type: 'number', required: true,
    boundType: { kind: 'cumulative_count', window: 'daily' },
  };
  if (withAppliesTo) {
    write.appliesTo = ['write'];
    del.appliesTo = ['delete'];
  }
  return {
    id: withAppliesTo ? 'customers-declared@0.5' : 'customers-inferred@0.5',
    version: '0.4',
    boundsSchema: {
      keyOrder: ['profile', 'write_daily_max', 'delete_daily_max'],
      fields: {
        profile: { type: 'string', required: true },
        write_daily_max: write,
        delete_daily_max: del,
      },
    },
    contextSchema: { keyOrder: [], fields: {} },
  } as unknown as AgentProfile;
}

/** Mirrors hap-profiles/calendar@0.4: a bound named for the domain, not the action. */
function calendarProfile(): AgentProfile {
  return {
    id: 'calendar-shape@0.4',
    version: '0.4',
    boundsSchema: {
      keyOrder: ['profile', 'booking_daily_max'],
      fields: {
        profile: { type: 'string', required: true },
        booking_daily_max: {
          type: 'number', required: true,
          boundType: { kind: 'cumulative_count', window: 'daily' },
        },
      },
    },
    contextSchema: { keyOrder: [], fields: {} },
  } as unknown as AgentProfile;
}

const PATH = 'customers-path';

/** All prior actions share one path, exactly as ExecutionLog records them. */
function logWith(count: number): ExecutionLogQuery {
  return {
    sumByWindow(_p: string, path: string, field: string, _w: CumulativeWindow, _n?: number) {
      if (path !== PATH) return 0;
      return field === '_count' ? count : 0;
    },
  } as ExecutionLogQuery;
}

describe('cumulative bounds are selected by action type', () => {
  let keyPair: TestKeyPair;

  beforeAll(async () => {
    registerProfile('customers-declared@0.5', customersProfile(true));
    registerProfile('customers-inferred@0.5', customersProfile(false));
    keyPair = await generateTestKeyPair();
  });

  async function attempt(profileId: string, actionType: string, priorCount: number) {
    const profile = profileId === 'customers-declared@0.5' ? customersProfile(true) : customersProfile(false);
    const bounds = { profile: profileId, write_daily_max: 10, delete_daily_max: 2 } as AgentBoundsParams;
    const blob = await createTestAttestationV4({
      keyPair, bounds, context: {}, profile, domain: 'owner',
    });
    return verify(
      { frame: bounds, context: {}, attestations: [blob], execution: { action_type: actionType }, path: PATH },
      keyPair.publicKeyHex,
      undefined,
      logWith(priorCount),
    );
  }

  it('declared appliesTo: a small delete limit does NOT block writes', async () => {
    // 3 prior actions. delete_daily_max is 2 — but this is a write, and the
    // profile says that bound governs deletes only.
    const result = await attempt('customers-declared@0.5', 'write', 3);
    expect(result.approved).toBe(true);
  });

  it('declared appliesTo: the write limit still blocks writes when exceeded', async () => {
    const result = await attempt('customers-declared@0.5', 'write', 10);
    expect(result.approved).toBe(false);
    expect(result.errors?.some(e => e.code === 'CUMULATIVE_LIMIT_EXCEEDED')).toBe(true);
  });

  it('declared appliesTo: the delete limit still blocks deletes when exceeded', async () => {
    const result = await attempt('customers-declared@0.5', 'delete', 2);
    expect(result.approved).toBe(false);
  });

  it('no appliesTo: falls back to the name convention and still separates them', async () => {
    // write_daily_max -> "write", delete_daily_max -> "delete".
    const result = await attempt('customers-inferred@0.5', 'write', 3);
    expect(result.approved).toBe(true);
  });

  it('calendar: a domain-named bound is skipped under a mismatched action type', async () => {
    // booking_daily_max vs action_type "write" — the shipped calendar bug. The
    // manifest now labels calendar writes "booking" so the two line up; this
    // pins the behaviour that made the limit unenforceable in the first place.
    registerProfile('calendar-shape@0.4', calendarProfile());
    const bounds = { profile: 'calendar-shape@0.4', booking_daily_max: 2 } as AgentBoundsParams;
    const blob = await createTestAttestationV4({
      keyPair, bounds, context: {}, profile: calendarProfile(), domain: 'owner',
    });
    const run = (actionType: string) => verify(
      { frame: bounds, context: {}, attestations: [blob], execution: { action_type: actionType }, path: PATH },
      keyPair.publicKeyHex,
      undefined,
      logWith(5), // well past the limit of 2
    );

    // "write" does not match the "booking" prefix → bound skipped → allowed.
    expect((await run('write')).approved).toBe(true);
    // "booking" matches → bound applies → blocked.
    expect((await run('booking')).approved).toBe(false);
  });

  it('no action type available: enforces every bound (fail closed)', async () => {
    const profile = customersProfile(false);
    const bounds = { profile: 'customers-inferred@0.5', write_daily_max: 10, delete_daily_max: 2 } as AgentBoundsParams;
    const blob = await createTestAttestationV4({ keyPair, bounds, context: {}, profile, domain: 'owner' });
    const result = await verify(
      { frame: bounds, context: {}, attestations: [blob], execution: {}, path: PATH },
      keyPair.publicKeyHex,
      undefined,
      logWith(3),
    );
    // Cannot tell which action this is, so the strictest bound applies.
    expect(result.approved).toBe(false);
  });
});

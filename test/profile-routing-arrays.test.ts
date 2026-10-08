/**
 * Bounds Schema rule 6: a bounds field MUST NOT declare `path` or `paths`.
 *
 * Found while migrating hap-profiles to v0.7: customers@0.8 and email@0.7 still
 * carry `paths` on their bounds, and validateProfile did not say so.
 */

import { describe, it, expect } from 'vitest';
import { validateProfile } from '../src/profile';
import type { AgentProfile } from '../src/types';

function profileWithBound(extra: Record<string, unknown>): AgentProfile {
  return {
    id: 'test/routing@0.1',
    version: '0.1',
    description: 'routing-array check',
    boundsSchema: {
      keyOrder: ['profile', 'send_daily_max'],
      actionTypes: ['send'],
      fields: {
        profile: { type: 'string', required: true },
        send_daily_max: {
          type: 'number',
          required: false,
          boundType: { kind: 'cumulative_count', window: 'daily' },
          appliesTo: ['send'],
          ...extra,
        },
      },
    },
    executionContextSchema: { fields: {} },
    requiredGates: [],
    ttl: { default: 3600, max: 86400 },
    retention_minimum: 0,
  } as unknown as AgentProfile;
}

describe('validateProfile — action-routing arrays (rule 6)', () => {
  it('refuses `paths` on a bounds field', () => {
    const errs = validateProfile(profileWithBound({ paths: ['email-send'] }));
    expect(errs.some((e) => e.code === 'PROFILE_INVALID' && e.field === 'send_daily_max' && /paths/.test(e.message))).toBe(true);
  });

  it('refuses `path` on a bounds field', () => {
    const errs = validateProfile(profileWithBound({ path: 'email-send' }));
    expect(errs.some((e) => e.field === 'send_daily_max' && /"path"/.test(e.message))).toBe(true);
  });

  it('accepts the same field without routing arrays', () => {
    expect(validateProfile(profileWithBound({})).filter((e) => e.field === 'send_daily_max')).toEqual([]);
  });
});

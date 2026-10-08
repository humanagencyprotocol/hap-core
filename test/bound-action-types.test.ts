/**
 * `boundActionTypes` — which action types' tickets count toward a cumulative
 * bound's running total, for a gateway's own usage DISPLAY only.
 *
 * Cumulative enforcement itself moved to the Authority Server exclusively in
 * v0.7 (protocol.md → *Enforcement Authority*; *Migration from v0.6* semantic
 * change 9: "Local cumulative enforcement is removed, not merely
 * deprecated"). `boundActionTypes` survives as a pure, exported helper
 * because a gateway still needs to partition totals for DISPLAY the same way
 * the Authority Server partitions them for enforcement — the two must not
 * disagree about what a number means, even though only the AS decides
 * whether it refuses.
 *
 * (Previously pinned alongside the now-removed local cumulative-enforcement
 * tests in cumulative-partition.test.ts / cumulative-action-type.test.ts /
 * cumulative-path.test.ts — those exercised `gatekeeper.verify()` refusing on
 * a cumulative bound from its own records, which is no longer something this
 * package does.)
 */
import { describe, it, expect } from 'vitest';
import { boundActionTypes } from '../src/gatekeeper';
import type { ProfileBoundsField } from '../src/types';

describe('boundActionTypes', () => {
  const f = (def: Partial<ProfileBoundsField>) => def as ProfileBoundsField;

  it('declared appliesTo wins', () => {
    expect(boundActionTypes('anything', f({ appliesTo: ['order'], boundType: { kind: 'cumulative_sum', of: 'value', window: 'daily' } })))
      .toEqual(['order']);
  });

  it('an undeclared count bound named for an action counts that action', () => {
    expect(boundActionTypes('delete_daily_max', f({ boundType: { kind: 'cumulative_count', window: 'daily' } }))).toEqual(['delete']);
  });

  it('transaction_* and undeclared sums govern every action type', () => {
    expect(boundActionTypes('transaction_count_daily_max', f({ boundType: { kind: 'cumulative_count', window: 'daily' } }))).toBeUndefined();
    expect(boundActionTypes('amount_daily_max', f({ boundType: { kind: 'cumulative_sum', of: 'amount', window: 'daily' } }))).toBeUndefined();
  });
});

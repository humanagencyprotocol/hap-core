/**
 * A cumulative bound's running total is made of the action types it governs —
 * not of every execution under the profile.
 *
 * Found 2026-09-30 driving the shipped sales@0.1 profile through a real gateway:
 * after one quote, one send and one order, every counter read 3 and the daily
 * order value summed the quote and send values too. `appliesTo` already picked
 * the right bound for each call (cumulative-action-type.test.ts); the total fed
 * into that bound was still the profile's combined one. The Authority Server
 * partitions by action type (*Cumulative Tracking* rule 4); any caller that
 * passes an execution log to verify() got the combined total and refused early.
 * (Suveren's gateway passes none — its log only feeds the usage display, which
 * had the same bug and is fixed there.)
 *
 * The log below filters for real, the way the gateway's ExecutionLog must: a
 * mock that ignores the filter would pass whether or not the gate passes it.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verify, boundActionTypes } from '../src/gatekeeper';
import { registerProfile } from '../src/profiles';
import { generateTestKeyPair, createTestAttestationV4, type TestKeyPair } from './helpers';
import type {
  AgentProfile, AgentBoundsParams, ExecutionLogEntry, ExecutionLogQuery, CumulativeWindow, ProfileBoundsField,
} from '../src/types';

const PROFILE_PATH = join(__dirname, '..', '..', 'hap-profiles', 'sales', '0.1.profile.json');
const PATH = 'sales-path';

/**
 * The shape of sales@0.1 that matters here, inline so CI (which checks out
 * hap-core alone) still runs the partition tests. The shipped file runs the
 * same suite when the sibling checkout is present.
 */
const INLINE_SALES = {
  id: 'sales-inline@0.1',
  version: '0.1',
  boundsSchema: {
    actionTypes: ['quote', 'send', 'order'],
    keyOrder: ['profile', 'read_access', 'value_max', 'discount_max', 'order_value_daily_max',
      'quote_daily_max', 'send_daily_max', 'order_daily_max'],
    fields: {
      profile: { type: 'string', required: true },
      read_access: { type: 'string', required: true, boundType: { kind: 'enum', values: ['unlimited', 'none'] } },
      value_max: { type: 'number', required: true, boundType: { kind: 'per_transaction', of: 'value' } },
      discount_max: { type: 'number', required: true, boundType: { kind: 'per_transaction', of: 'discount_pct' } },
      order_value_daily_max: { type: 'number', required: true,
        boundType: { kind: 'cumulative_sum', of: 'value', window: 'daily' }, appliesTo: ['order'] },
      quote_daily_max: { type: 'number', required: true,
        boundType: { kind: 'cumulative_count', window: 'daily' }, appliesTo: ['quote'] },
      send_daily_max: { type: 'number', required: true,
        boundType: { kind: 'cumulative_count', window: 'daily' }, appliesTo: ['send'] },
      order_daily_max: { type: 'number', required: true,
        boundType: { kind: 'cumulative_count', window: 'daily' }, appliesTo: ['order'] },
    },
  },
  contextSchema: {
    keyOrder: ['currency'],
    fields: { currency: { type: 'string', required: true, constraint: { type: 'string', enforceable: ['enum'] }, enum: ['EUR'] } },
  },
} as unknown as AgentProfile;

const variants: Array<{ name: string; available: boolean; load: () => AgentProfile }> = [
  { name: 'inline sales@0.1 shape', available: true, load: () => INLINE_SALES },
  {
    name: 'shipped sales@0.1',
    available: existsSync(PROFILE_PATH),
    load: () => JSON.parse(readFileSync(PROFILE_PATH, 'utf8')) as AgentProfile,
  },
];

for (const variant of variants) {
describe.skipIf(!variant.available)(`cumulative totals are partitioned by action type (${variant.name})`, () => {
  let profile: AgentProfile;
  /** In-memory log with the filtering contract of ExecutionLogQuery. */
  class Log implements ExecutionLogQuery {
    constructor(private profileId: string) {}
    entries: ExecutionLogEntry[] = [];
    add(action_type: string, value: number) {
      this.entries.push({ profileId: this.profileId, path: PATH, execution: { action_type, value }, timestamp: 1_000 });
    }
    sumByWindow(profileId: string, path: string, field: string, _w: CumulativeWindow, _now?: number, actionTypes?: readonly string[]) {
      let total = 0;
      for (const e of this.entries) {
        if (e.profileId !== profileId || e.path !== path) continue;
        const at = e.execution.action_type;
        if (actionTypes && typeof at === 'string' && !actionTypes.includes(at)) continue;
        total += field === '_count' ? 1 : Number(e.execution[field] ?? 0);
      }
      return total;
    }
  }

  const boundsFor = (profile: AgentProfile) => ({
    profile: profile.id, read_access: 'unlimited', value_max: 50, discount_max: 25,
    order_value_daily_max: 100, quote_daily_max: 2, send_daily_max: 6, order_daily_max: 7,
  }) as unknown as AgentBoundsParams;
  const context = { currency: 'EUR' };

  let kp: TestKeyPair;
  let blob: string;
  let bounds: AgentBoundsParams;

  beforeAll(async () => {
    profile = variant.load();
    bounds = boundsFor(profile);
    registerProfile(profile.id, profile);
    kp = await generateTestKeyPair();
    blob = await createTestAttestationV4({ keyPair: kp, bounds, context, profile, domain: 'owner' });
  });

  const attempt = (log: Log, action_type: string, value: number) =>
    verify(
      { frame: bounds, context, attestations: [blob], execution: { action_type, value, discount_pct: 0, currency: 'EUR' }, path: PATH },
      kp.publicKeyHex, 1_000, log,
    );

  it('sends and orders do not use up the quote count', async () => {
    const log = new Log(profile.id);
    log.add('quote', 10);
    for (let i = 0; i < 5; i++) { log.add('send', 10); log.add('order', 10); }
    // quote_daily_max is 2 and one quote exists. The 10 sends and orders must not count.
    const r = await attempt(log, 'quote', 10);
    expect(r.errors).toBeUndefined();
    expect(r.approved).toBe(true);
  });

  it('the quote count still refuses the quote over its limit', async () => {
    const log = new Log(profile.id);
    log.add('quote', 10); log.add('quote', 10);
    const r = await attempt(log, 'quote', 10);
    expect(r.approved).toBe(false);
    expect(r.errors?.some(e => e.code === 'CUMULATIVE_LIMIT_EXCEEDED')).toBe(true);
  });

  it('quote and send values do not count toward the daily order value', async () => {
    const log = new Log(profile.id);
    for (let i = 0; i < 4; i++) { log.add('quote', 40); log.add('send', 40); }
    log.add('order', 40);
    // Orders so far: 40. This order: 40. 80 <= 100, whatever quotes and sends sum to.
    const r = await attempt(log, 'order', 40);
    expect(r.errors).toBeUndefined();
    expect(r.approved).toBe(true);
  });

  it('the daily order value still refuses when orders alone exceed it', async () => {
    const log = new Log(profile.id);
    log.add('order', 40); log.add('order', 40);
    const r = await attempt(log, 'order', 40);
    expect(r.approved).toBe(false);
    expect(r.errors?.find(e => e.code === 'CUMULATIVE_LIMIT_EXCEEDED')?.message).toMatch(/order_value_daily_max/);
  });

  it('an execution with no recorded action type counts against every bound (fail closed)', async () => {
    const log = new Log(profile.id);
    log.add('quote', 10);
    log.entries.push({ profileId: profile.id, path: PATH, execution: { value: 10 }, timestamp: 1_000 });
    const r = await attempt(log, 'quote', 10);
    expect(r.approved).toBe(false);
  });
});
}

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

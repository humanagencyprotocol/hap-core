/**
 * A per_transaction bound the call does not expose a value for.
 *
 * `amount_max` (per_transaction, of: amount) only ever compared when the call
 * happened to carry `amount`. A connector whose amount argument is optional, a
 * tool-gating mapping with a mistyped field name, or a third-party connector
 * that never maps the amount at all each turn a monetary cap into a limit
 * nothing can exceed — a 5,000 cap refuses a declared 6,000 but says nothing
 * about a call that declares no value at all. `requiredFor` closes this the
 * same way `FieldConstraint.requiredFor` closed it for scope constraints in
 * v0.6: silence must not read as compliance, but it must still mean "not
 * applicable" for action types that legitimately carry no such value (a
 * deletion has no amount).
 *
 * content/0.7/review.md → "Per-transaction bounds must be able to require
 * their value"; suveren-as/docs/work-plan.md → "Missing value passes a
 * per-transaction bound".
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { verify } from '../src/gatekeeper';
import { registerProfile } from '../src/profiles';
import { validateBoundsRequiredFor, computeBoundsHash } from '../src/frame';
import { CHARGE_PROFILE_V4 } from './fixtures';
import { generateTestKeyPair, createTestAttestationV4, type TestKeyPair } from './helpers';
import type { AgentBoundsParams, AgentProfile } from '../src/types';

const GUARDED = 'charge-guarded@0.4';
const LEGACY = 'charge-legacy@0.4';

/** CHARGE_PROFILE_V4 with amount_max requiring its value for the given action types. */
function withRequiredFor(id: string, requiredFor?: string[]): AgentProfile {
  const base = JSON.parse(JSON.stringify(CHARGE_PROFILE_V4)) as AgentProfile;
  base.id = id;
  base.boundsSchema!.actionTypes = ['charge', 'refund', 'subscribe'];
  const amountMax = base.boundsSchema!.fields.amount_max;
  if (requiredFor) {
    amountMax.boundType = { kind: 'per_transaction', of: 'amount', requiredFor };
  }
  return base;
}

describe('per_transaction bound requiredFor', () => {
  let keyPair: TestKeyPair;

  const bounds: AgentBoundsParams = {
    profile: GUARDED,
    path: 'charge-routine',
    amount_max: 5000,
    amount_daily_max: 50000,
    amount_monthly_max: 500000,
    transaction_count_daily_max: 100,
  };
  // action_type is itself an enum-constrained context field (allowed execution
  // values); list every action type this suite exercises so the unrelated
  // context check doesn't mask the per_transaction behaviour under test.
  const context = { currency: 'EUR', action_type: 'charge,refund,subscribe' };

  beforeAll(async () => {
    registerProfile(GUARDED, withRequiredFor(GUARDED, ['charge', 'refund']));
    registerProfile(LEGACY, withRequiredFor(LEGACY));
    keyPair = await generateTestKeyPair();
  });

  async function check(profileId: string, execution: Record<string, string | number>) {
    const profile = profileId === GUARDED ? withRequiredFor(GUARDED, ['charge', 'refund']) : withRequiredFor(LEGACY);
    const frame = { ...bounds, profile: profileId };
    const blob = await createTestAttestationV4({ keyPair, bounds: frame, context, profile, domain: 'finance' });
    return verify({ frame, context, attestations: [blob], execution }, keyPair.publicKeyHex);
  }

  it('approves a charge within the bound', async () => {
    const r = await check(GUARDED, { amount: 4000, currency: 'EUR', action_type: 'charge' });
    expect(r.approved).toBe(true);
  });

  it('REFUSES a charge over the bound (control: enforcement still works)', async () => {
    const r = await check(GUARDED, { amount: 6000, currency: 'EUR', action_type: 'charge' });
    expect(r.approved).toBe(false);
  });

  it('REFUSES a charge that exposes no amount at all', async () => {
    // Previously this passed: nothing to compare against the bound, so no error
    // — a cap of 5,000 permitted a call declaring no value whatsoever.
    const r = await check(GUARDED, { currency: 'EUR', action_type: 'charge' });
    expect(r.approved).toBe(false);
    if (!r.approved) {
      expect(r.errors[0].field).toBe('amount');
      expect(r.errors[0].message).toMatch(/exposes no amount/i);
    }
  });

  it('REFUSES a charge whose amount is not a number (string)', async () => {
    const r = await check(GUARDED, { amount: 'a lot', currency: 'EUR', action_type: 'charge' } as unknown as Record<string, string | number>);
    expect(r.approved).toBe(false);
  });

  it('REFUSES a charge whose amount is NaN', async () => {
    const r = await check(GUARDED, { amount: NaN, currency: 'EUR', action_type: 'charge' });
    expect(r.approved).toBe(false);
  });

  it('REFUSES a charge whose amount is null — null is "missing", not zero', async () => {
    // Number(null) === 0: a value lost in transit (an unmapped connector
    // field, or JSON.stringify(NaN) === 'null' on the wire) must not silently
    // read as "amount 0, within bound".
    const r = await check(GUARDED, { amount: null as unknown as number, currency: 'EUR', action_type: 'charge' });
    expect(r.approved).toBe(false);
    if (!r.approved) {
      // Must be classified as MISSING (requiredFor's own message), not just
      // caught by the generic non-numeric fallback that happened to exist
      // already — that distinction is the whole point of the null !== 0 fix.
      expect(r.errors[0].message).toMatch(/exposes no amount/i);
    }
  });

  it('an unlisted action type with no value keeps passing (today\'s behaviour)', async () => {
    // amount_max's requiredFor is ['charge', 'refund'] — 'subscribe' is not
    // listed, so a subscribe call with no amount must keep behaving exactly
    // as it did before this change.
    const r = await check(GUARDED, { action_type: 'subscribe' });
    expect(r.approved).toBe(true);
  });

  it('a profile without requiredFor keeps its previous (skip-on-absence) behaviour', async () => {
    const r = await check(LEGACY, { currency: 'EUR', action_type: 'charge' });
    expect(r.approved).toBe(true);
  });

  it('a profile without requiredFor is byte-identical in its approval for a normal in-bounds call', async () => {
    const r = await check(LEGACY, { amount: 4000, currency: 'EUR', action_type: 'charge' });
    expect(r.approved).toBe(true);
  });
});

describe('requiredFor has no effect on bounds_hash', () => {
  it('a profile declaring requiredFor hashes the same attested values as one without it', () => {
    // bounds_hash is computed from keyOrder + the attested VALUES
    // (canonicalBounds), never from boundType/schema metadata — adding
    // requiredFor to a profile's schema must not change the hash of any
    // existing mandate signed under a profile version that didn't have it.
    const withIt = withRequiredFor('hash-check-a@0.4', ['charge']);
    const withoutIt = withRequiredFor('hash-check-b@0.4');
    const sameBounds: AgentBoundsParams = {
      profile: 'x',
      path: 'charge-routine',
      amount_max: 5000,
      amount_daily_max: 50000,
      amount_monthly_max: 500000,
      transaction_count_daily_max: 100,
    };
    expect(computeBoundsHash(sameBounds, withIt)).toBe(computeBoundsHash(sameBounds, withoutIt));
  });
});

describe('validateBoundsRequiredFor (authoring-time check)', () => {
  it('accepts a requiredFor entry that is a real action type', () => {
    const profile = withRequiredFor('v@0.4', ['charge']);
    expect(validateBoundsRequiredFor(profile)).toEqual([]);
  });

  it('flags a requiredFor entry naming an action type outside the registry', () => {
    const profile = withRequiredFor('v@0.4', ['teleport']);
    const errors = validateBoundsRequiredFor(profile);
    expect(errors.some((e) => e.includes('teleport'))).toBe(true);
  });

  it('flags requiredFor attached to a non-per_transaction bound', () => {
    const profile = withRequiredFor('v@0.4', ['charge']);
    // amount_daily_max is cumulative_sum — requiredFor there is meaningless.
    (profile.boundsSchema!.fields.amount_daily_max.boundType as { requiredFor?: string[] }).requiredFor = ['charge'];
    const errors = validateBoundsRequiredFor(profile);
    expect(errors.some((e) => e.includes('amount_daily_max'))).toBe(true);
  });

  it('a profile with no requiredFor anywhere validates clean', () => {
    expect(validateBoundsRequiredFor(CHARGE_PROFILE_V4)).toEqual([]);
  });
});

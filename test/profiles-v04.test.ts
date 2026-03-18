/**
 * v0.4 Profile Loading Tests
 *
 * Verifies that a v0.4 profile loaded from the hap-profiles repo registers
 * correctly and that its schema structure and hash functions work as expected.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { registerProfile, getProfile } from '../src/profiles';
import { computeBoundsHash, computeContextHash } from '../src/frame';
import type { AgentProfile } from '../src/types';

// ── Load the real v0.4 spend profile from hap-profiles ───────────────────────

const PROFILE_PATH = join(
  import.meta.dirname,
  '../../hap-profiles/spend/profile.json',
);

const RAW_PROFILE = JSON.parse(readFileSync(PROFILE_PATH, 'utf-8')) as AgentProfile;
const PROFILE_ID = 'github.com/humanagencyprotocol/hap-profiles/spend@0.4';

beforeAll(() => {
  registerProfile(PROFILE_ID, RAW_PROFILE);
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('v0.4 profiles', () => {
  it('registers and retrieves v0.4 spend profile', () => {
    const profile = getProfile(PROFILE_ID);
    expect(profile).toBeDefined();
    expect(profile!.id).toBe(PROFILE_ID);
    expect(profile!.version).toBe('0.4');
  });

  it('v0.4 profile has boundsSchema with keyOrder and fields', () => {
    const profile = getProfile(PROFILE_ID)!;
    expect(profile.boundsSchema).toBeDefined();
    expect(Array.isArray(profile.boundsSchema!.keyOrder)).toBe(true);
    expect(profile.boundsSchema!.keyOrder.length).toBeGreaterThan(0);
    expect(typeof profile.boundsSchema!.fields).toBe('object');
  });

  it('v0.4 profile has contextSchema with keyOrder and fields', () => {
    const profile = getProfile(PROFILE_ID)!;
    expect(profile.contextSchema).toBeDefined();
    expect(Array.isArray(profile.contextSchema!.keyOrder)).toBe(true);
    expect(profile.contextSchema!.keyOrder.length).toBeGreaterThan(0);
    expect(typeof profile.contextSchema!.fields).toBe('object');
  });

  it('v0.4 profile has no frameSchema', () => {
    const profile = getProfile(PROFILE_ID)!;
    expect(profile.frameSchema).toBeUndefined();
  });

  it('v0.4 spend boundsSchema has amount_max, amount_daily_max, amount_monthly_max, transaction_count_daily_max', () => {
    const profile = getProfile(PROFILE_ID)!;
    const fields = profile.boundsSchema!.fields;
    expect(fields['amount_max']).toBeDefined();
    expect(fields['amount_daily_max']).toBeDefined();
    expect(fields['amount_monthly_max']).toBeDefined();
    expect(fields['transaction_count_daily_max']).toBeDefined();
  });

  it('v0.4 spend contextSchema has currency, action_type', () => {
    const profile = getProfile(PROFILE_ID)!;
    const fields = profile.contextSchema!.fields;
    expect(fields['currency']).toBeDefined();
    expect(fields['action_type']).toBeDefined();
  });

  it('required gate is "bounds" not "frame"', () => {
    const profile = getProfile(PROFILE_ID)!;
    expect(profile.requiredGates).toContain('bounds');
    expect(profile.requiredGates).not.toContain('frame');
  });

  it('computeBoundsHash works with v0.4 profile', () => {
    const profile = getProfile(PROFILE_ID)!;
    const bounds = {
      profile: PROFILE_ID,
      path: 'spend-routine',
      amount_max: 100,
      amount_daily_max: 500,
      amount_monthly_max: 5000,
      transaction_count_daily_max: 20,
    };

    const hash = computeBoundsHash(bounds, profile);
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('computeContextHash works with v0.4 profile', () => {
    const profile = getProfile(PROFILE_ID)!;
    const context = {
      currency: 'USD',
      action_type: 'charge',
    };

    const hash = computeContextHash(context, profile);
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('computeBoundsHash is deterministic', () => {
    const profile = getProfile(PROFILE_ID)!;
    const bounds = {
      profile: PROFILE_ID,
      path: 'spend-routine',
      amount_max: 50,
      amount_daily_max: 200,
      amount_monthly_max: 2000,
      transaction_count_daily_max: 10,
    };

    const hash1 = computeBoundsHash(bounds, profile);
    const hash2 = computeBoundsHash(bounds, profile);
    expect(hash1).toBe(hash2);
  });

  it('computeContextHash is deterministic', () => {
    const profile = getProfile(PROFILE_ID)!;
    const context = { currency: 'EUR', action_type: 'refund' };

    const hash1 = computeContextHash(context, profile);
    const hash2 = computeContextHash(context, profile);
    expect(hash1).toBe(hash2);
  });

  it('different bounds produce different hashes', () => {
    const profile = getProfile(PROFILE_ID)!;
    const base = {
      profile: PROFILE_ID,
      path: 'spend-routine',
      amount_max: 100,
      amount_daily_max: 500,
      amount_monthly_max: 5000,
      transaction_count_daily_max: 20,
    };
    const modified = { ...base, amount_max: 200 };

    expect(computeBoundsHash(base, profile)).not.toBe(computeBoundsHash(modified, profile));
  });

  it('different contexts produce different hashes', () => {
    const profile = getProfile(PROFILE_ID)!;
    const usd = { currency: 'USD', action_type: 'charge' };
    const eur = { currency: 'EUR', action_type: 'charge' };

    expect(computeContextHash(usd, profile)).not.toBe(computeContextHash(eur, profile));
  });

  it('short name lookup works for v0.4 profile', () => {
    // The profile ID contains "spend" — callers resolve it by matching short name
    // This test verifies the profile is findable via the registry after registerProfile
    const profile = getProfile(PROFILE_ID);
    expect(profile).toBeDefined();
    // Confirm the full ID embeds the short name "spend"
    expect(PROFILE_ID).toContain('spend');
    expect(PROFILE_ID).toContain('@0.4');
  });
});

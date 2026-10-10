/**
 * The shipped customers profile, not a fixture: customers@0.10 makes the CRM's
 * scope field `contact_type` required for every write and delete.
 *
 * Why: the gatekeeper skips a subset-constrained scope field the call does not
 * expose unless `requiredFor` covers the action type. customers@0.9 had none,
 * so a call that stayed silent about the contact type passed a "customers only"
 * mandate unchecked. The CRM connector (crm-mcp 1.4.1) also requires the value
 * in its tool schema, which fires first in the gateway — this test proves the
 * profile layer on its own, for any connector that does not.
 *
 * Reads hap-profiles from $HAP_PROFILES_DIR or the sibling checkout; skips if
 * customers/0.10 is absent.
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

const PROFILE_PATH = join(HAP_PROFILES_DIR, 'customers', '0.10.profile.json');
const available = existsSync(PROFILE_PATH);

describe.skipIf(!available)('customers@0.10 as shipped', () => {
  let keyPair: TestKeyPair;
  let profile: AgentProfile;

  const bounds: Record<string, string | number> = { profile: '', read_access: 'unlimited', export_access: 'none', write_daily_max: 10, delete_daily_max: 5, setup_daily_max: 0 };
  const scope = { contact_type: 'customer' };

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

  it('is a conformant v0.7 profile that declares requiredFor on contact_type', () => {
    expect(validateProfile(profile)).toEqual([]);
    const c = profile.scopeSchema!.fields.contact_type.constraint;
    expect(c?.requiredFor).toEqual(expect.arrayContaining(['write', 'delete']));
  });

  it('approves a write on a customer under a customers-only mandate', async () => {
    const r = await check({ action_type: 'write', contact_type: 'customer' });
    expect(r.approved, JSON.stringify(r.errors)).toBe(true);
  });

  it('REFUSES a write that exposes no contact_type', async () => {
    const r = await check({ action_type: 'write' });
    expect(r.approved).toBe(false);
    expect((r.errors ?? []).map((e) => e.message).join(' ')).toMatch(/exposes no contact_type/);
  });

  it('REFUSES a delete that exposes no contact_type', async () => {
    const r = await check({ action_type: 'delete' });
    expect(r.approved).toBe(false);
    expect((r.errors ?? []).map((e) => e.message).join(' ')).toMatch(/exposes no contact_type/);
  });

  it('REFUSES a write on a lead under a customers-only mandate', async () => {
    const r = await check({ action_type: 'write', contact_type: 'lead' });
    expect(r.approved).toBe(false);
  });

  it('REFUSES a conversion customer → lead (both types declared) under a customers-only mandate', async () => {
    const r = await check({ action_type: 'write', contact_type: 'customer,lead' });
    expect(r.approved).toBe(false);
  });

  it('still allows setup, which does not engage contact_type', async () => {
    const r = await check({ action_type: 'setup' });
    expect(r.approved, JSON.stringify(r.errors)).toBe(true);
  });
});

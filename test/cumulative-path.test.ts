/**
 * Local cumulative enforcement — the execution-log path must match.
 *
 * The gatekeeper enforces cumulative bounds locally, before the Authority
 * Server is asked for a receipt. It scopes the running total by
 * (profileId, path), reading the path from the request.
 *
 * That path used to be read from `frame.path` — which no shipped profile
 * declares. `canonicalBounds` walks `boundsSchema.keyOrder`, and
 * `validateBoundsParams` REJECTS any key not in the schema, so a caller
 * physically cannot put `path` in the frame without breaking attestation
 * verification. It therefore always resolved to "", while the execution log
 * stored real paths. No entry ever matched, every running total read zero, and
 * the local gate silently never fired.
 *
 * It went unnoticed because hap-core's own EMAIL_PROFILE_V4 fixture DOES list
 * `path` in its keyOrder — a shape none of the ten shipped profiles use. The
 * tests were green against a profile that does not exist in production.
 *
 * These tests therefore use a PRODUCTION-SHAPED profile (no `path` bound) and
 * pass the path where it belongs: alongside the frame, not inside it.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { verify } from '../src/gatekeeper';
import { registerProfile } from '../src/profiles';
import { generateTestKeyPair, createTestAttestationV4, type TestKeyPair } from './helpers';
import type { AgentProfile, AgentBoundsParams, ExecutionLogQuery, CumulativeWindow } from '../src/types';

/** Mirrors hap-profiles/email/0.4 — note: NO `path` in keyOrder. */
const EMAIL_PROD_SHAPED: AgentProfile = {
  id: 'email-prodshape@0.4',
  version: '0.4',
  boundsSchema: {
    keyOrder: ['profile', 'send_daily_max'],
    fields: {
      profile: { type: 'string', required: true },
      send_daily_max: {
        type: 'number',
        required: true,
        displayName: 'Daily send limit',
        boundType: { kind: 'cumulative_count', window: 'daily' },
      },
    },
  },
  contextSchema: { keyOrder: [], fields: {} },
} as unknown as AgentProfile;

/** Execution log holding N prior sends, all recorded under `storedPath`. */
function logWith(storedPath: string, count: number): ExecutionLogQuery {
  return {
    sumByWindow(profileId: string, path: string, field: string, _w: CumulativeWindow, _now?: number) {
      if (path !== storedPath) return 0; // the real log skips non-matching paths
      return field === '_count' ? count : 0;
    },
  } as ExecutionLogQuery;
}

const BOUNDS: AgentBoundsParams = {
  profile: 'email-prodshape@0.4',
  send_daily_max: 3,
} as AgentBoundsParams;

const STORED_PATH = 'email-send';

describe('local cumulative enforcement scopes by the request path', () => {
  let keyPair: TestKeyPair;
  let blob: string;

  beforeAll(async () => {
    registerProfile('email-prodshape@0.4', EMAIL_PROD_SHAPED);
    keyPair = await generateTestKeyPair();
    blob = await createTestAttestationV4({
      keyPair,
      bounds: BOUNDS,
      context: {},
      profile: EMAIL_PROD_SHAPED,
      domain: 'owner',
    });
  });

  it('BLOCKS once the running count reaches the bound', async () => {
    // 3 prior sends + this one = 4 > send_daily_max 3.
    const result = await verify(
      { frame: BOUNDS, context: {}, attestations: [blob], execution: {}, path: STORED_PATH },
      keyPair.publicKeyHex,
      undefined,
      logWith(STORED_PATH, 3),
    );

    expect(result.approved).toBe(false);
    expect(result.errors?.some(e => e.code === 'CUMULATIVE_LIMIT_EXCEEDED')).toBe(true);
  });

  it('ALLOWS while under the bound', async () => {
    const result = await verify(
      { frame: BOUNDS, context: {}, attestations: [blob], execution: {}, path: STORED_PATH },
      keyPair.publicKeyHex,
      undefined,
      logWith(STORED_PATH, 1),
    );

    expect(result.approved).toBe(true);
  });

  it('the regression itself: omitting the path reads zero and never blocks', async () => {
    // This is exactly what production did. The bound is exceeded three times
    // over, yet the call is approved, because the lookup path ("") matches no
    // stored entry. Kept as a test so the failure mode is documented rather
    // than merely fixed — if someone drops `path` again, this pins the cost.
    const result = await verify(
      { frame: BOUNDS, context: {}, attestations: [blob], execution: {} },
      keyPair.publicKeyHex,
      undefined,
      logWith(STORED_PATH, 99),
    );

    expect(result.approved).toBe(true);
  });

  it('a path that matches nothing in the log does not block either', async () => {
    const result = await verify(
      { frame: BOUNDS, context: {}, attestations: [blob], execution: {}, path: 'some-other-path' },
      keyPair.publicKeyHex,
      undefined,
      logWith(STORED_PATH, 99),
    );

    expect(result.approved).toBe(true);
  });
});

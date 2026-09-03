/**
 * Conformance vectors — canonical bounds & scope.
 *
 * Reads the spec's answer key (content/0.7/vectors/canonical-bounds-and-scope.json)
 * and checks this implementation byte-for-byte against it. What this proves is
 * cross-implementation agreement: a one-character disagreement about
 * canonicalization means nothing either party signs will ever verify against
 * the other, and it is invisible until two implementations meet.
 *
 * Vocabulary note: the vector file is v0.7, which renamed "context" to "scope".
 * This package is still on the v0.6 wire vocabulary, so `kind: "scope"` cases
 * run through canonicalContext/computeContextHash, and the refusal code
 * SCOPE_INVALID_VALUE is asserted as its v0.6 name CONTEXT_INVALID_VALUE.
 * The BYTES and HASHES are unaffected by the rename — those are what the
 * vectors pin.
 */

import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import {
  canonicalBounds,
  canonicalContext,
  computeBoundsHash,
  computeContextHash,
} from '../src/frame';
import type { AgentProfile, AgentBoundsParams, AgentContextParams } from '../src/types';

const VECTORS_PATH = fileURLToPath(
  new URL('../../content/0.7/vectors/canonical-bounds-and-scope.json', import.meta.url),
);
const EMAIL_PROFILE_PATH = fileURLToPath(
  new URL('../../hap-profiles/email/0.6.profile.json', import.meta.url),
);

interface VectorCase {
  id: string;
  note?: string;
  kind: 'bounds' | 'scope';
  key_order: string[];
  values: Record<string, string | number>;
  canonical?: string;
  hash?: string;
  expected_error?: string;
}

interface VectorFile {
  spec_version: string;
  cases: VectorCase[];
  must_refuse: VectorCase[];
}

/** Minimal profile whose schema is exactly the vector's key_order, all fields optional. */
function profileFromCase(vc: VectorCase): AgentProfile {
  const fields: Record<string, { type: 'string' | 'number'; required: false }> = {};
  for (const key of vc.key_order) {
    const value = vc.values[key];
    fields[key] = { type: typeof value === 'number' ? 'number' : 'string', required: false };
  }

  const base: AgentProfile = {
    id: `vector/${vc.id}`,
    version: '0.7',
    description: `Synthetic profile for conformance vector ${vc.id}`,
    executionContextSchema: { fields: {} },
    requiredGates: [],
    ttl: { default: 3600, max: 86400 },
    retention_minimum: 0,
  };

  if (vc.kind === 'bounds') {
    return { ...base, boundsSchema: { keyOrder: vc.key_order, fields } };
  }
  return { ...base, contextSchema: { keyOrder: vc.key_order, fields } };
}

/** v0.7 vector code → the code this (v0.6-vocabulary) package throws. */
function expectedCode(vc: VectorCase): string {
  return vc.expected_error === 'SCOPE_INVALID_VALUE'
    ? 'CONTEXT_INVALID_VALUE'
    : String(vc.expected_error);
}

const haveVectors = existsSync(VECTORS_PATH);

if (!haveVectors) {
  // eslint-disable-next-line no-console
  console.warn(
    '\n' +
      '='.repeat(78) +
      '\n!! CONFORMANCE VECTORS NOT FOUND — canonicalization is UNVERIFIED in this run.\n' +
      `!! Expected: ${VECTORS_PATH}\n` +
      '!! These vectors are the only check that this implementation hashes bounds and\n' +
      '!! scope the same way as any other. Restore the spec checkout before trusting a\n' +
      '!! green suite.\n' +
      '='.repeat(78) +
      '\n',
  );
}

describe.skipIf(!haveVectors)('conformance vectors — canonical bounds & scope', () => {
  const vectors: VectorFile = haveVectors
    ? JSON.parse(readFileSync(VECTORS_PATH, 'utf8'))
    : { spec_version: '', cases: [], must_refuse: [] };

  it('loaded a vector set with cases', () => {
    expect(vectors.cases.length).toBeGreaterThan(0);
    expect(vectors.must_refuse.length).toBeGreaterThan(0);
  });

  describe('canonical string + hash', () => {
    for (const vc of vectors.cases) {
      it(`${vc.id} (${vc.kind})`, () => {
        const profile = profileFromCase(vc);

        if (vc.kind === 'bounds') {
          const params = vc.values as AgentBoundsParams;
          expect(canonicalBounds(params, profile)).toBe(vc.canonical);
          expect(computeBoundsHash(params, profile)).toBe(vc.hash);
        } else {
          const params = vc.values as AgentContextParams;
          expect(canonicalContext(params, profile)).toBe(vc.canonical);
          expect(computeContextHash(params, profile)).toBe(vc.hash);
        }
      });
    }
  });

  describe('must_refuse', () => {
    for (const vc of vectors.must_refuse) {
      it(`${vc.id} → ${vc.expected_error}`, () => {
        const profile = profileFromCase(vc);
        let thrown: unknown;

        try {
          if (vc.kind === 'bounds') {
            canonicalBounds(vc.values as AgentBoundsParams, profile);
          } else {
            canonicalContext(vc.values as AgentContextParams, profile);
          }
        } catch (err) {
          thrown = err;
        }

        expect(thrown, 'canonicalization should have refused this value').toBeDefined();
        expect((thrown as { code?: string }).code).toBe(expectedCode(vc));
      });
    }
  });
});

// ─── Shipped profile: absent optional keys ───────────────────────────────────

const haveEmailProfile = existsSync(EMAIL_PROFILE_PATH);

if (!haveEmailProfile) {
  // eslint-disable-next-line no-console
  console.warn(
    `\n!! hap-profiles email@0.6 not found at ${EMAIL_PROFILE_PATH} — ` +
      'the absent-optional-key rule is UNVERIFIED against a shipped profile in this run.\n',
  );
}

describe.skipIf(!haveEmailProfile)('shipped profile email@0.6 — absent optional keys', () => {
  const profile: AgentProfile = JSON.parse(readFileSync(EMAIL_PROFILE_PATH, 'utf8'));

  it('every bound except `profile` is optional (premise of this test)', () => {
    const fields = Object.entries(profile.boundsSchema!.fields);
    const required = fields.filter(([, def]) => (def as { required?: boolean }).required);
    expect(required.map(([n]) => n)).toEqual(['profile']);
  });

  it('omits keys the human never set instead of hashing the string "undefined"', () => {
    // What the gateway UI actually sends: it hides bounds marked
    // enforcedBy=gatekeeper / enforced=false, so read_max_age_days and
    // read_daily_max are simply absent from the bounds object.
    const bounds: AgentBoundsParams = {
      profile: profile.id,
      recipient_max: 5,
      send_daily_max: 20,
    };

    expect(profile.id).not.toContain('='); // id needs no encoding, keeps this assertion readable
    const canonical = canonicalBounds(bounds, profile);

    expect(canonical).toBe(`profile=${profile.id}\nrecipient_max=5\nsend_daily_max=20`);
    expect(canonical).not.toContain('undefined');
    expect(canonical).not.toContain('read_max_age_days');
    expect(canonical).not.toContain('read_daily_max');
  });

  it('a fully-populated grant is unaffected by the omission rule', () => {
    const bounds: AgentBoundsParams = {
      profile: profile.id,
      recipient_max: 5,
      send_daily_max: 20,
      read_max_age_days: 30,
      read_daily_max: 50,
    };

    expect(canonicalBounds(bounds, profile)).toBe(
      `profile=${profile.id}\nrecipient_max=5\nsend_daily_max=20\n` +
        'read_max_age_days=30\nread_daily_max=50',
    );
  });
});

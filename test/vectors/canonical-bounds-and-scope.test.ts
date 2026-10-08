/**
 * Conformance vectors — canonical-bounds-and-scope.json.
 *
 * "That two implementations turn the same authorization into the same
 * bytes, and therefore the same hash." No code translation: the vector's
 * `kind: "scope"` cases run through the v0.7 scope functions directly
 * (`canonicalScope` / `computeScopeHash`), and `SCOPE_INVALID_VALUE` is
 * asserted as itself — this package is v0.7 vocabulary now, so there is
 * nothing to translate.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalBounds, canonicalScope, computeBoundsHash, computeScopeHash } from '../../src/frame';
import { VECTORS_DIR, haveVectors, requireVectors } from './_spec-dir';
import type { AgentProfile, AgentBoundsParams, AgentScopeParams } from '../../src/types';

interface VectorCase {
  id: string;
  note?: string;
  kind: 'bounds' | 'scope';
  key_order: string[];
  values: Record<string, string | number>;
  canonical: string;
  hash: string;
}

requireVectors();

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
  return { ...base, scopeSchema: { keyOrder: vc.key_order, fields } };
}

describe.skipIf(!haveVectors)('conformance vectors — canonical bounds & scope', () => {
  const file = JSON.parse(readFileSync(join(VECTORS_DIR, 'canonical-bounds-and-scope.json'), 'utf8')) as {
    cases: VectorCase[];
  };

  it('loaded a vector set with cases of both kinds', () => {
    expect(file.cases.some((c) => c.kind === 'bounds')).toBe(true);
    expect(file.cases.some((c) => c.kind === 'scope')).toBe(true);
  });

  for (const vc of file.cases) {
    it(`${vc.id} (${vc.kind}): canonical string, byte for byte`, () => {
      const profile = profileFromCase(vc);
      const canonical = vc.kind === 'bounds'
        ? canonicalBounds(vc.values as AgentBoundsParams, profile)
        : canonicalScope(vc.values as AgentScopeParams, profile);
      expect(canonical).toBe(vc.canonical);
    });

    it(`${vc.id} (${vc.kind}): hash`, () => {
      const profile = profileFromCase(vc);
      const hash = vc.kind === 'bounds'
        ? computeBoundsHash(vc.values as AgentBoundsParams, profile)
        : computeScopeHash(vc.values as AgentScopeParams, profile);
      expect(hash).toBe(vc.hash);
    });
  }
});

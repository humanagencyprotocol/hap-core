/**
 * Conformance vectors — profile-hash.json (content/0.7/vectors/README.md).
 *
 * "That two parties who provisioned the same profile through different
 * channels compute the same profile_hash." Reads the published profile bytes
 * from the hap-profiles sibling checkout and the answer key from the spec
 * sibling checkout — no copy of either lives in this package.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { computeProfileHash } from '../../src/profile';
import { VECTORS_DIR, HAP_PROFILES_DIR, haveVectors, requireVectors } from './_spec-dir';
import { existsSync } from 'node:fs';

interface ProfileHashCase {
  id: string;
  profile_id: string;
  source: string;
  profile_hash: string;
}

requireVectors();

describe.skipIf(!haveVectors)('conformance vectors — profile-hash', () => {
  const file = JSON.parse(readFileSync(join(VECTORS_DIR, 'profile-hash.json'), 'utf8')) as {
    cases: ProfileHashCase[];
  };

  it('loaded a vector set with at least one case', () => {
    expect(file.cases.length).toBeGreaterThan(0);
  });

  for (const vc of file.cases) {
    // `source` names the published file relative to hap-profiles, e.g.
    // "hap-profiles/charge/0.5.profile.json as published (commit 0646a98)".
    const match = vc.source.match(/hap-profiles\/(\S+\.json)/);
    const relPath = match?.[1];

    it(`${vc.id}: ${vc.profile_id}`, () => {
      expect(relPath, `could not parse a profile path out of source "${vc.source}"`).toBeDefined();
      const absPath = join(HAP_PROFILES_DIR, relPath!);
      if (!existsSync(absPath)) {
        if (process.env.CI) throw new Error(`hap-profiles file not found: ${absPath}`);
        // eslint-disable-next-line no-console
        console.warn(`!! Skipping ${vc.id} — ${absPath} not found (hap-profiles sibling checkout missing).`);
        return;
      }
      const raw = readFileSync(absPath, 'utf8');
      const parsed = JSON.parse(raw);
      expect(computeProfileHash(parsed)).toBe(vc.profile_hash);
    });

    it(`${vc.id}: is invariant to re-indentation, key order, and a trailing newline`, () => {
      if (!relPath) return;
      const absPath = join(HAP_PROFILES_DIR, relPath);
      if (!existsSync(absPath)) return; // already warned above
      const parsed = JSON.parse(readFileSync(absPath, 'utf8'));

      // Re-indented + trailing-newline variant: same structure, different bytes.
      const reindented = JSON.parse(JSON.stringify(parsed, null, 4) + '\n\n');
      expect(computeProfileHash(reindented)).toBe(vc.profile_hash);

      // Key-reordered variant: every object's keys reversed, recursively.
      // (JSON.stringify's replacer-array form filters EVERY level of nesting
      // to the given key list, so it cannot be used to just reorder — it
      // would silently drop nested keys with different names. Reorder by
      // hand instead.)
      const reorder = (v: unknown): unknown => {
        if (Array.isArray(v)) return v.map(reorder);
        if (v !== null && typeof v === 'object') {
          const out: Record<string, unknown> = {};
          for (const k of Object.keys(v as Record<string, unknown>).reverse()) {
            out[k] = reorder((v as Record<string, unknown>)[k]);
          }
          return out;
        }
        return v;
      };
      expect(computeProfileHash(reorder(parsed))).toBe(vc.profile_hash);
    });
  }
});

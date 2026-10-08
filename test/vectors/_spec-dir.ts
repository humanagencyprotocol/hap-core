/**
 * Locates the HAP spec checkout the conformance vectors live in.
 *
 * hap-core publishes standalone (github.com/humanagencyprotocol/hap-core); the
 * spec and its vectors live in a sibling repo (hap-protocol, checked out
 * locally at `../content`, or at `$HAP_SPEC_DIR` when set). A developer's
 * local checkout — this one — has both as sibling directories, so the
 * relative path resolves with no configuration. `ci.yml` checks out the spec
 * repo into that same sibling path so CI resolves it identically.
 *
 * protocol.md's own normative text requires this: "The reference core
 * library is required to consume these files in its tests rather than carry
 * its own copies" (vectors/README.md → *Provenance*). Vectors are normative
 * data — this package must never hold a second copy of their values.
 */
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

/** `../content` relative to the hap-core package root, or `$HAP_SPEC_DIR`. */
export const SPEC_DIR = process.env.HAP_SPEC_DIR ?? fileURLToPath(new URL('../../../content', import.meta.url));

export const VECTORS_DIR = join(SPEC_DIR, '0.7', 'vectors');

export const HAP_PROFILES_DIR =
  process.env.HAP_PROFILES_DIR ?? fileURLToPath(new URL('../../../hap-profiles', import.meta.url));

export const haveVectors = existsSync(VECTORS_DIR);

/**
 * In CI, a missing spec checkout is a setup bug, not "nothing to test here" —
 * silently skipping is exactly how these vectors went unconsumed before
 * (vectors/README.md → *Provenance*; CLAUDE.md "Phase 0 plan" step 1: "vector
 * tests FAIL (not skip) when process.env.CI is set"). Locally, a standalone
 * hap-core clone without the sibling spec checkout still runs (skipped, with
 * a loud warning) so contributors aren't blocked on a checkout they may not
 * have.
 */
export function requireVectors(): void {
  if (haveVectors) return;
  if (process.env.CI) {
    throw new Error(
      `CONFORMANCE VECTORS NOT FOUND at ${VECTORS_DIR} — in CI this is a setup failure, not a skip. ` +
        'ci.yml must check out humanagencyprotocol/hap-protocol into ../content.',
    );
  }
  // eslint-disable-next-line no-console
  console.warn(
    `\n${'='.repeat(78)}\n!! CONFORMANCE VECTORS NOT FOUND at ${VECTORS_DIR} — these tests are SKIPPED.\n` +
      '!! Restore the sibling hap-protocol checkout (../content) before trusting a green suite.\n' +
      `${'='.repeat(78)}\n`,
  );
}

/**
 * Version negotiation — protocol.md → *Version negotiation (v0.7)* and the
 * v0.7 → v0.8 exception (*Migration from v0.7*).
 *
 * Two sets, because v0.8 is a re-grant release:
 *
 * - {@link PROTOCOL_VERSION} — the one version this package ISSUES. A v0.8
 *   Authority Server issues `version: "0.8"` only, and refuses a mandate
 *   request that does not support it (rule 3, exception).
 * - {@link SUPPORTED_VERSIONS} — the versions this package can VERIFY and
 *   ENFORCE, each under its own rules (rule 4). A Gatekeeper sends this list
 *   as `supported_versions`; a verifier accepts an artifact of any of them.
 *   v0.7 is kept so that a Gatekeeper upgraded before its Authority Server
 *   keeps working, and so that v0.7 artifacts remain verifiable as evidence.
 *
 * `negotiateVersion` picks what an Authority Server issues. Its default is
 * the strict v0.8 set; an AS that bridges the transition passes the wider
 * set explicitly, behind its own switch.
 */
import { HapError } from './errors';

/** The protocol version this package issues. */
export const PROTOCOL_VERSION = '0.8';

/** Every version this package verifies and enforces, newest first. */
export const SUPPORTED_VERSIONS: readonly string[] = ['0.8', '0.7'];

/** The versions an Authority Server built on this package issues. */
export const ISSUABLE_VERSIONS: readonly string[] = [PROTOCOL_VERSION];

/** A protocol version this package knows the rules of. */
export type SupportedVersion = '0.8' | '0.7';

export function isSupportedVersion(v: unknown): v is SupportedVersion {
  return typeof v === 'string' && SUPPORTED_VERSIONS.includes(v);
}

/**
 * The highest version both the requester and the issuer support.
 *
 * @param requested `supported_versions` from the mandate request. Absent →
 * read as `["0.6"]` (protocol.md rule 1), which no issuer here supports, so
 * the refusal is honest rather than a silent assumption.
 * @param supported What the issuer is willing to issue. Default: v0.8 only.
 * @throws HapError `VERSION_UNSUPPORTED` when no version is common to both.
 */
export function negotiateVersion(
  requested: readonly string[] | undefined,
  supported: readonly string[] = ISSUABLE_VERSIONS,
): string {
  const requestedVersions = requested ?? ['0.6'];
  // Highest-first so a requester offering several supported versions gets the
  // newest one both sides agree on, not merely the first common element.
  const common = supported.filter((v) => requestedVersions.includes(v)).sort().reverse();
  if (common.length === 0) {
    throw new HapError(
      'VERSION_UNSUPPORTED',
      `no protocol version in [${requestedVersions.join(', ')}] is supported by this implementation ` +
        `(supports [${supported.join(', ')}])`,
    );
  }
  return common[0];
}

/**
 * Refuse an artifact of a version this package cannot verify (rule 4: an
 * artifact is read under its own version, never re-interpreted).
 * @throws HapError `VERSION_UNSUPPORTED`
 */
export function assertSupportedVersion(version: unknown, what: string): asserts version is SupportedVersion {
  if (!isSupportedVersion(version)) {
    throw new HapError(
      'VERSION_UNSUPPORTED',
      `${what} version ${JSON.stringify(version)} is not verifiable by this implementation ` +
        `(verifies [${SUPPORTED_VERSIONS.join(', ')}])`,
    );
  }
}

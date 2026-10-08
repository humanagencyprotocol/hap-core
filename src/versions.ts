/**
 * Version negotiation — protocol.md → *Version negotiation (v0.7)*.
 *
 * "Gatekeepers and Authority Servers MUST reject unknown or untrusted
 * versions" is a safety rule, not a transition plan; this module is the
 * transition plan. A mandate request carries `supported_versions`; the AS
 * issues at the highest version both sides support, or refuses with
 * `VERSION_UNSUPPORTED` where there is none. A request without the field is
 * read as `["0.6"]` (rule 1) — but this package issues and verifies `0.7`
 * only (CLAUDE.md "Decided by the owner": no backward verify path), so that
 * default exists to make the refusal message honest, not to accept the
 * mandate.
 */
import { HapError } from './errors';

/** The protocol version this package issues and verifies. */
export const PROTOCOL_VERSION = '0.7';

/** The protocol versions this package can verify and enforce. */
export const SUPPORTED_VERSIONS: readonly string[] = ['0.7'];

/**
 * The highest version both the requester and this implementation support.
 *
 * @param requested `supported_versions` from the mandate request. Absent →
 * read as `["0.6"]` (protocol.md rule 1) — which, against this package's
 * `SUPPORTED_VERSIONS`, has no overlap and refuses honestly rather than
 * silently assuming `0.7`.
 * @throws HapError `VERSION_UNSUPPORTED` when no version is common to both.
 */
export function negotiateVersion(
  requested: readonly string[] | undefined,
  supported: readonly string[] = SUPPORTED_VERSIONS,
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

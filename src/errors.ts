/**
 * Canonical v0.7 error codes — protocol.md → *Error Codes*.
 *
 * "Error codes are canonical across the protocol. Implementations MUST emit
 * exactly these codes and MUST NOT alias them under different names." This
 * module is the single list both the Gatekeeper (local checks) and any AS
 * client built on this library read from, so the two cannot drift.
 *
 * v0.7 renamed every code that carried a retired word (attestation → mandate,
 * context → scope, receipt → ticket) — see protocol.md → *Migration from
 * v0.6* → "Error-code renames" for the old→new map. There is no alias: a v0.6
 * code name is simply gone from this list, by design (no backward
 * compatibility — CLAUDE.md "Decided by the owner").
 */

/** Codes an Authority Server (or a local Gatekeeper check) emits refusing a mandate request. */
export const MANDATE_ERROR_CODES = [
  'BOUNDS_HASH_MISMATCH',
  'SCOPE_HASH_MISMATCH',
  'INVALID_SIGNATURE',
  'OWNER_NOT_COVERED',
  'TTL_EXPIRED',
  'PROFILE_NOT_FOUND',
  'PROFILE_INVALID',
  'PROFILE_HASH_MISMATCH',
  'COVERAGE_INSUFFICIENT',
  'MALFORMED_MANDATE',
  'VERSION_UNSUPPORTED',
  'OWNER_NOT_APPROVER',
  'BOUNDS_INVALID_VALUE',
  'SCOPE_INVALID_VALUE',
  'ABOVE_CAP_CONFIG_INVALID',
  'OWNER_SIGNATURE_REQUIRED',
  'OWNER_SIGNATURE_INVALID',
] as const;

/** Codes an Authority Server emits refusing a ticket request. */
export const TICKET_ERROR_CODES = [
  'MANDATE_NOT_FOUND',
  'MANDATE_EXPIRED',
  'MANDATE_REVOKED',
  'BOUND_EXCEEDED',
  'CUMULATIVE_LIMIT_EXCEEDED',
  'COVERAGE_INSUFFICIENT',
  'PROFILE_NOT_FOUND',
  'INVALID_ACTION_TYPE',
  'APPROVAL_REQUIRED',
  'PROPOSAL_REQUIRED',
  'PROPOSAL_NOT_FOUND',
  'PROPOSAL_NOT_APPROVED',
  'PROPOSAL_EXPIRED',
  'PROPOSAL_REJECTED',
  'PROPOSAL_MISMATCH',
  'PROPOSAL_MANDATE_MISMATCH',
  'PROPOSAL_ALREADY_EXECUTED',
  'MALFORMED_TICKET_REQUEST',
  'IDEMPOTENCY_KEY_REQUIRED',
  'IDEMPOTENCY_MISMATCH',
  'APPROVAL_SIGNATURE_REQUIRED',
  'APPROVAL_SIGNATURE_INVALID',
] as const;

/** The full canonical surface — every code a conformant implementation may emit. */
export type HapErrorCode = (typeof MANDATE_ERROR_CODES)[number] | (typeof TICKET_ERROR_CODES)[number];

/**
 * A refusal carrying one of the canonical codes above. Thrown by local
 * (Gatekeeper-side, no-wire-round-trip) checks in this library; an AS client
 * built on hap-core maps a wire `{ code, message }` error onto the same type.
 */
export class HapError extends Error {
  constructor(public readonly code: HapErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = 'HapError';
  }
}

/**
 * Gatekeeper — local (Phase 1) verification for bounded execution (v0.7).
 *
 * protocol.md → *Validation Steps* (Phase 1, never reaches the wire):
 *   1. Resolve profile from bounds.profile
 *   2. Recompute bounds_hash and scope_hash
 *   3. For each mandate: decode, verify AS signature, verify version,
 *      verify bounds_hash / scope_hash / profile_hash, verify expiry
 *   4. Check actionType registry membership
 *   5. Check per_transaction bounds and enum capability flags locally
 *      (Enforcement Authority: this is what makes per_transaction
 *      compromise-resistant — *Enforcement classes*)
 *   6. Check scope constraints (enum, subset, requiredFor) locally — the AS
 *      never sees scope plaintext, so the Gatekeeper is the sole enforcer
 *   7. Return { approved } or { approved: false, errors: [...] }
 *
 * What this module deliberately does NOT do (protocol.md → *Enforcement
 * Authority*, *Migration from v0.6* semantic change 9): enforce
 * `cumulative_sum` / `cumulative_count` bounds. "Local cumulative
 * enforcement is removed, not merely deprecated: a Gatekeeper MUST NOT
 * refuse an execution on a cumulative bound from its own records" — only
 * the Authority Server's ticket history is authoritative for a running
 * total across every Gatekeeper exercising the bucket. v0.3/v0.4's
 * frame-based path is retired entirely (CLAUDE.md "Decided by the owner").
 */

import { decodeMandateBlob, verifyMandateSignature, checkMandateExpiry, validateMandateOwners } from './mandate';
import { canonicalBounds, canonicalScope, computeBoundsHash, computeScopeHash, CanonicalValueError } from './frame';
import { computeProfileHash } from './profile';
import { getProfile } from './profiles';
import { HapError, type HapErrorCode } from './errors';
import { PROTOCOL_VERSION } from './versions';
import type {
  GatekeeperRequest,
  GatekeeperResult,
  GatekeeperError,
  AgentProfile,
  AgentBoundsParams,
  AgentScopeParams,
  MandatePayload,
  Mandate,
  ProfileBoundsField,
} from './types';

/** Options for {@link verify}. */
export interface VerifyOptions {
  /** Restricts mandate-signature verification to these Authority Server
   * DIDs — protocol.md → *Ticket Verification* step 1 applies identically
   * to mandates: "a verifier MUST reject a [...] whose issuer it does not
   * trust." Omitted → any issuer that resolves a valid did:key is accepted
   * (appropriate for a Gatekeeper that has not yet pinned an AS). */
  trustedIssuers?: readonly string[];
  now?: number;
}

/**
 * Verify an execution request against the mandates supplied.
 *
 * @param request bounds, mandate blobs, execution values, and optional scope
 */
export async function verify(request: GatekeeperRequest, opts: VerifyOptions = {}): Promise<GatekeeperResult> {
  const now = opts.now ?? Math.floor(Date.now() / 1000);

  // 1. Resolve profile from bounds.profile.
  const profileId = request.bounds.profile;
  if (typeof profileId !== 'string') {
    return { approved: false, errors: [{ code: 'PROFILE_NOT_FOUND', message: 'Missing profile in bounds' }] };
  }
  const profile = getProfile(profileId);
  if (!profile) {
    return { approved: false, errors: [{ code: 'PROFILE_NOT_FOUND', message: `Unknown profile: ${profileId}` }] };
  }

  // Fail closed when there is nothing to verify. A `for` loop over an empty
  // (or missing) mandates array runs zero times and collects zero errors —
  // "no errors" is not the same as "verified".
  if (!Array.isArray(request.mandates) || request.mandates.length === 0) {
    return { approved: false, errors: [{ code: 'MALFORMED_MANDATE', message: 'No mandate supplied — nothing to verify' }] };
  }

  // 2. Recompute bounds_hash and scope_hash from what the caller holds.
  const bounds = request.bounds as AgentBoundsParams;
  const scope: AgentScopeParams | undefined = request.scope;

  let expectedBoundsHash: string;
  try {
    expectedBoundsHash = computeBoundsHash(bounds, profile);
  } catch (err) {
    if (err instanceof CanonicalValueError) {
      return { approved: false, errors: [{ code: err.code, field: err.field, message: err.message }] };
    }
    return { approved: false, errors: [{ code: 'BOUNDS_HASH_MISMATCH', message: `Bounds hash computation failed: ${err}` }] };
  }

  // Scope hash is only recomputed when scope is explicitly provided. Scope
  // CONSTRAINTS (enum/subset/requiredFor) are always enforced below against
  // whatever scope and execution values the caller supplies; this is a
  // separate, stricter hash-identity check against the held mandate.
  let expectedScopeHash: string | undefined;
  if (scope && Object.keys(scope).length > 0) {
    try {
      expectedScopeHash = computeScopeHash(scope, profile);
    } catch (err) {
      if (err instanceof CanonicalValueError) {
        return { approved: false, errors: [{ code: err.code, field: err.field, message: err.message }] };
      }
      return { approved: false, errors: [{ code: 'SCOPE_HASH_MISMATCH', message: `Scope hash computation failed: ${err}` }] };
    }
  }

  const expectedProfileHash = computeProfileHash(profile);

  // 3. Verify every mandate blob.
  const errors: GatekeeperError[] = [];
  for (const blob of request.mandates) {
    const mandateErrors = await verifyOneMandate(blob, {
      expectedBoundsHash,
      expectedScopeHash,
      expectedProfileHash,
      trustedIssuers: opts.trustedIssuers,
      now,
    });
    errors.push(...mandateErrors);
  }
  if (errors.length > 0) {
    return { approved: false, errors };
  }

  // 4. actionType registry membership — checked before any bound is read
  // (protocol.md → required-refusals vector "no-action-type": "Checked
  // before any bound is read").
  const actionType = typeof request.execution.action_type === 'string' ? request.execution.action_type : undefined;
  const registry = profile.boundsSchema?.actionTypes;
  if (registry && registry.length > 0) {
    if (actionType === undefined || !registry.includes(actionType)) {
      return {
        approved: false,
        errors: [{
          code: 'INVALID_ACTION_TYPE',
          field: 'action_type',
          message: `action_type ${JSON.stringify(actionType)} is not in profile ${profile.id}'s actionTypes registry [${registry.join(', ')}]`,
        }],
      };
    }
  }

  // 5. per_transaction bounds and enum capability flags, locally.
  const boundsErrors = checkBounds(request, profile, actionType);
  if (boundsErrors.length > 0) {
    return { approved: false, errors: boundsErrors };
  }

  // 6. Scope constraints — the sole enforcer, since the AS only ever holds scope_hash.
  if (profile.scopeSchema && Object.keys(profile.scopeSchema.fields).length > 0) {
    const enforceableFields = Object.entries(profile.scopeSchema.fields)
      .filter(([, def]) => def.constraint?.enforceable?.length);

    if (enforceableFields.length > 0 && !scope) {
      return {
        approved: false,
        errors: [{
          code: 'BOUND_EXCEEDED',
          message: `Declared scope required for constraint enforcement but not provided. Fields: ${enforceableFields.map(([n]) => n).join(', ')}`,
        }],
      };
    }

    if (scope) {
      const scopeErrors = checkScopeConstraints(scope, request.execution, profile);
      if (scopeErrors.length > 0) {
        return { approved: false, errors: scopeErrors };
      }
    }
  }

  return { approved: true };
}

// ─── Mandate Verification ────────────────────────────────────────────────────

interface MandateCheckOptions {
  expectedBoundsHash: string;
  expectedScopeHash: string | undefined;
  expectedProfileHash: string;
  trustedIssuers: readonly string[] | undefined;
  now: number;
}

/** The canonical code a thrown value names, from a {@link HapError} or from
 * this package's `"CODE: message"` convention (mandate.ts, ticket.ts). */
function codeFromThrown(err: unknown): HapErrorCode {
  if (err instanceof HapError) return err.code;
  if (err instanceof Error) {
    const [prefix] = err.message.split(':');
    return prefix as HapErrorCode;
  }
  return 'MALFORMED_MANDATE';
}

async function verifyOneMandate(blob: string, opts: MandateCheckOptions): Promise<GatekeeperError[]> {
  let mandate: Mandate;
  try {
    mandate = decodeMandateBlob(blob);
  } catch (err) {
    return [{ code: 'MALFORMED_MANDATE', message: (err as Error).message }];
  }

  if (mandate.payload.version !== PROTOCOL_VERSION) {
    return [{
      code: 'VERSION_UNSUPPORTED',
      message: `mandate version ${JSON.stringify(mandate.payload.version)} is not verifiable by this Gatekeeper (verifies ${PROTOCOL_VERSION} only)`,
    }];
  }

  try {
    await verifyMandateSignature(mandate, { trustedIssuers: opts.trustedIssuers });
  } catch (err) {
    return [{ code: codeFromThrown(err), message: (err as Error).message }];
  }

  try {
    checkMandateExpiry(mandate.payload, opts.now);
  } catch (err) {
    return [{ code: codeFromThrown(err), message: (err as Error).message }];
  }

  try {
    validateMandateOwners(mandate.payload);
  } catch (err) {
    return [{ code: codeFromThrown(err), message: (err as Error).message }];
  }

  const errors: GatekeeperError[] = [];
  const payload: MandatePayload = mandate.payload;

  if (payload.bounds_hash !== opts.expectedBoundsHash) {
    errors.push({ code: 'BOUNDS_HASH_MISMATCH', message: 'Mandate bounds_hash does not match the recomputed bounds_hash' });
  }
  if (opts.expectedScopeHash !== undefined && payload.scope_hash !== opts.expectedScopeHash) {
    errors.push({ code: 'SCOPE_HASH_MISMATCH', message: 'Mandate scope_hash does not match the recomputed scope_hash' });
  }
  if (payload.profile_hash !== opts.expectedProfileHash) {
    errors.push({ code: 'PROFILE_HASH_MISMATCH', message: 'Mandate profile_hash does not match the Gatekeeper\'s provisioned profile bytes' });
  }

  return errors;
}

// ─── Bounds Checking (per_transaction, enum) ─────────────────────────────────

/**
 * Which action types' executions count toward this cumulative bound's
 * running total — `undefined` means all of them. Display-only now that
 * local cumulative enforcement is removed (protocol.md → *Enforcement
 * Authority*: cumulative bounds are AS-only). Exported so a gateway's own
 * usage display partitions totals the same way the Authority Server does.
 */
export function boundActionTypes(
  fieldName: string,
  fieldDef: ProfileBoundsField,
): readonly string[] | undefined {
  if (fieldDef.appliesTo) return fieldDef.appliesTo;

  const bt = fieldDef.boundType;
  if (!bt || bt.kind !== 'cumulative_count') return undefined;

  const prefix = fieldName.replace(/_(?:daily|monthly|weekly)_max$/, '');
  if (prefix === fieldName || prefix.startsWith('transaction')) return undefined;
  return [prefix];
}

/**
 * Local bounds enforcement — `per_transaction` and `enum` only.
 * `cumulative_sum` / `cumulative_count` fields are skipped entirely: they
 * are AS-only (*Enforcement Authority*), and the Gatekeeper's own
 * (incomplete, single-Gatekeeper) history is not authoritative for them.
 */
function checkBounds(
  request: GatekeeperRequest,
  profile: AgentProfile,
  actionType: string | undefined,
): GatekeeperError[] {
  const errors: GatekeeperError[] = [];
  if (!profile.boundsSchema) return errors;

  const bounds = request.bounds as AgentBoundsParams;

  for (const [fieldName, fieldDef] of Object.entries(profile.boundsSchema.fields)) {
    if (fieldName === 'profile') continue;

    const boundValue = bounds[fieldName];
    if (boundValue === undefined) continue;

    const bt = fieldDef.boundType;
    if (!bt) {
      // A missing boundType is a profile authoring bug — fail closed on
      // enforcement rather than silently skipping.
      errors.push({
        code: 'PROFILE_INVALID',
        field: fieldName,
        message: `Profile ${profile.id} bound "${fieldName}" has no boundType — enforcement semantics undefined.`,
        bound: boundValue,
        actual: boundValue,
      });
      continue;
    }

    switch (bt.kind) {
      case 'per_transaction': {
        const actual = request.execution[bt.of];

        // `requiredFor`: for a listed action_type, absence (or a non-numeric
        // value) is a denial, not a skip. Unlisted action types, or no
        // `requiredFor` at all, keep skip-on-absence behaviour below.
        const engaged = !!bt.requiredFor?.length
          && actionType !== undefined
          && bt.requiredFor.includes(actionType);

        if (engaged) {
          // `null` is "missing", not the number 0 — a value lost upstream
          // must not silently read as "amount 0, within bound".
          const missing = actual === undefined || actual === null;
          const numericActual = missing ? NaN : (typeof actual === 'number' ? actual : Number(actual));
          const missingOrNonNumeric = missing || Number.isNaN(numericActual);
          if (missingOrNonNumeric) {
            errors.push({
              code: 'BOUND_EXCEEDED',
              field: bt.of,
              message: missing
                ? `Bound "${fieldName}" requires "${bt.of}" for "${actionType}" calls, but this ` +
                  `call exposes no ${bt.of} to check against it. Refusing: the call cannot be ` +
                  `shown to stay within ${fieldName}.`
                : `Bound "${fieldName}" requires a numeric "${bt.of}" for "${actionType}" calls, ` +
                  `but this call's value (${String(actual)}) is not a number. Refusing: the call ` +
                  `cannot be shown to stay within ${fieldName}.`,
              bound: boundValue,
              actual,
            });
            continue;
          }
        }

        if (actual === undefined) continue;
        if (typeof boundValue !== 'number' || typeof actual !== 'number') {
          errors.push({
            code: 'BOUND_EXCEEDED',
            field: bt.of,
            message: `Bound "${fieldName}" requires numeric values (bound=${boundValue}, actual=${actual})`,
            bound: boundValue,
            actual,
          });
          break;
        }
        if (actual > boundValue) {
          errors.push({
            code: 'BOUND_EXCEEDED',
            field: bt.of,
            message: `Value ${actual} exceeds authorized maximum of ${boundValue} for ${fieldName}`,
            bound: boundValue,
            actual,
          });
        }
        break;
      }

      case 'enum': {
        // Enum bounds are capability flags, validated at mandate time. They
        // are NOT compared against runtime execution here — tool-proxy gates
        // tool calls against the manifest's required value before they
        // reach the Gatekeeper.
        if (typeof boundValue === 'string' && !bt.values.includes(boundValue)) {
          errors.push({
            code: 'BOUND_EXCEEDED',
            field: fieldName,
            message: `Bound "${fieldName}"="${boundValue}" is not in allowed values [${bt.values.join(', ')}]`,
            bound: boundValue,
            actual: boundValue,
          });
        }
        break;
      }

      case 'cumulative_sum':
      case 'cumulative_count':
        // AS-only (protocol.md → *Enforcement Authority*). A Gatekeeper
        // MUST NOT refuse on these from its own records.
        break;
    }
  }

  return errors;
}

// ─── Scope Constraints ───────────────────────────────────────────────────────

/**
 * Check scope param values against scopeSchema enum/subset constraints.
 * Scope enum fields constrain the allowed values in execution.
 */
function checkScopeConstraints(
  scope: AgentScopeParams,
  execution: Record<string, string | number>,
  profile: AgentProfile,
): GatekeeperError[] {
  const errors: GatekeeperError[] = [];

  if (!profile.scopeSchema) return errors;

  for (const [fieldName, fieldDef] of Object.entries(profile.scopeSchema.fields)) {
    if (!fieldDef.constraint) continue;

    // A constrained dimension that the call does not expose cannot be
    // checked. Skipping is only safe when the action does not engage that
    // dimension — deleting a draft has no recipients. When it DOES engage
    // it, silence must not read as compliance.
    const requiredFor = fieldDef.constraint.requiredFor;
    if (requiredFor?.length) {
      const boundValue = scope[fieldName];
      const actualValue = execution[fieldName];
      const actionType = execution['action_type'];
      const constrained = boundValue !== undefined && boundValue !== '';
      const engaged = actionType !== undefined && requiredFor.includes(String(actionType));

      if (constrained && engaged && (actualValue === undefined || actualValue === '')) {
        errors.push({
          code: 'BOUND_EXCEEDED',
          field: fieldName,
          message:
            `Authorization limits "${fieldName}" to [${boundValue}], but this ` +
            `"${String(actionType)}" call exposes no ${fieldName} to check against it. ` +
            `Refusing: the call cannot be shown to stay in scope.`,
          bound: boundValue,
        });
        continue; // nothing further to compare for this field
      }
    }

    for (const enforceType of fieldDef.constraint.enforceable) {
      if (enforceType === 'enum') {
        const boundValue = scope[fieldName];
        const actualValue = execution[fieldName];

        if (actualValue === undefined) continue;

        const allowed = typeof boundValue === 'string'
          ? boundValue.split(',').map(s => s.trim())
          : [String(boundValue)];

        const actualStr = String(actualValue);

        if (!allowed.includes(actualStr)) {
          errors.push({
            code: 'BOUND_EXCEEDED',
            field: fieldName,
            message: `Value "${actualStr}" not in authorized scope values [${allowed.join(', ')}]`,
            bound: boundValue,
            actual: actualValue,
          });
        }
      }

      if (enforceType === 'subset') {
        const boundValue = scope[fieldName];
        const actualValue = execution[fieldName];

        if (boundValue === undefined || boundValue === '') continue;
        if (actualValue === undefined || actualValue === '') continue;

        const allowed = String(boundValue).split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
        const actuals = String(actualValue).split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

        const disallowed = actuals.filter(v => !allowed.includes(v));
        if (disallowed.length > 0) {
          errors.push({
            code: 'BOUND_EXCEEDED',
            field: fieldName,
            message: `Values [${disallowed.join(', ')}] not in authorized set [${allowed.join(', ')}]`,
            bound: boundValue,
            actual: actualValue,
          });
        }
      }
    }
  }

  return errors;
}

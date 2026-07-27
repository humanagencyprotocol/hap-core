/**
 * Gatekeeper — Stateless Verification for Bounded Execution
 *
 * Supports both v0.3 (frameSchema / frame_hash) and v0.4 (boundsSchema + contextSchema /
 * bounds_hash + context_hash).
 *
 * v0.3 flow (§8.6):
 *   1. Resolve profile from frame
 *   2. Recompute frame_hash
 *   3. For each required domain: find attestation, verify signature, verify frame_hash, verify TTL
 *   4. Check bounds: max → actual <= bound, enum → actual in allowed
 *   5. Return { approved } or { approved: false, errors: [...] }
 *
 * v0.4 flow:
 *   1. Resolve profile from bounds.profile
 *   2. Recompute bounds_hash and context_hash
 *   3. For each required domain: find attestation, verify signature, verify bounds_hash + context_hash, verify TTL
 *   4. Check bounds (from boundsSchema), check context constraints (from contextSchema)
 *   5. Resolve cumulative fields, check cumulative limits
 *   6. Return { approved } or { approved: false, errors: [...] }
 */

import {
  decodeAttestationBlob,
  verifyAttestationSignature,
  checkAttestationExpiry,
  verifyFrameHash,
  verifyBoundsHash,
  verifyContextHash,
  isV4Attestation,
} from './attestation';
import { computeFrameHash, computeBoundsHash, computeContextHash } from './frame';
import { getProfile } from './profiles';
import type {
  GatekeeperRequest,
  GatekeeperResult,
  GatekeeperError,
  AgentProfile,
  AgentBoundsParams,
  AgentContextParams,
  ExecutionLogQuery,
  CumulativeFieldDef,
  ProfileBoundsField,
  BoundType,
} from './types';

/**
 * Verify an execution request against attested authorization.
 *
 * For v0.4 profiles (have boundsSchema), the `frame` param is interpreted as `bounds`,
 * and the optional `context` param is used for the context hash check.
 *
 * For v0.3 profiles (have frameSchema only), existing logic is used unchanged.
 *
 * @param request - The frame/bounds, attestations, execution values, and optional context
 * @param publicKeyHex - The SP's public key in hex (cached locally by MCP server)
 * @param now - Current timestamp in seconds (for testing)
 * @param executionLog - Optional execution log for resolving cumulative fields
 */
export async function verify(
  request: GatekeeperRequest,
  publicKeyHex: string,
  now: number = Math.floor(Date.now() / 1000),
  executionLog?: ExecutionLogQuery,
): Promise<GatekeeperResult> {
  const errors: GatekeeperError[] = [];

  // 1. Resolve profile from frame/bounds
  const profileId = request.frame.profile;
  if (typeof profileId !== 'string') {
    return { approved: false, errors: [{ code: 'INVALID_PROFILE', message: 'Missing profile in frame' }] };
  }

  const profile = getProfile(profileId);
  if (!profile) {
    return { approved: false, errors: [{ code: 'INVALID_PROFILE', message: `Unknown profile: ${profileId}` }] };
  }

  // Detect v0.4 vs v0.3 based on profile schema
  const isV4Profile = !!profile.boundsSchema;

  if (isV4Profile) {
    return verifyV4(request, profile, publicKeyHex, now, executionLog);
  } else {
    return verifyV3(request, profile, publicKeyHex, now, executionLog, errors);
  }
}

// ─── v0.3 Verification ────────────────────────────────────────────────────────

async function verifyV3(
  request: GatekeeperRequest,
  profile: AgentProfile,
  publicKeyHex: string,
  now: number,
  executionLog: ExecutionLogQuery | undefined,
  errors: GatekeeperError[],
): Promise<GatekeeperResult> {
  let expectedFrameHash: string;
  try {
    expectedFrameHash = computeFrameHash(request.frame, profile);
  } catch (err) {
    return { approved: false, errors: [{ code: 'FRAME_MISMATCH', message: `Frame hash computation failed: ${err}` }] };
  }

  // Verify attestations (domains come from SP group config in v0.4, not from profile)
  const requiredDomains: string[] = [];
  const coveredDomains = new Set<string>();

  for (const blob of request.attestations) {
    let attestation;
    try {
      attestation = decodeAttestationBlob(blob);
    } catch {
      errors.push({ code: 'MALFORMED_ATTESTATION', message: 'Failed to decode attestation blob' });
      continue;
    }

    try {
      await verifyAttestationSignature(attestation, publicKeyHex);
    } catch {
      errors.push({ code: 'INVALID_SIGNATURE', message: 'Attestation signature verification failed' });
      continue;
    }

    try {
      verifyFrameHash(attestation, expectedFrameHash);
    } catch {
      errors.push({ code: 'FRAME_MISMATCH', message: 'Attestation frame_hash does not match computed frame_hash' });
      continue;
    }

    try {
      checkAttestationExpiry(attestation.payload, now);
    } catch {
      const domainNames = (attestation.payload.resolved_domains ?? []).map(d => d.domain).join(', ');
      errors.push({ code: 'TTL_EXPIRED', message: `Attestation for domain "${domainNames}" has expired` });
      continue;
    }

    for (const rd of attestation.payload.resolved_domains ?? []) {
      coveredDomains.add(rd.domain);
    }
  }

  for (const domain of requiredDomains) {
    if (!coveredDomains.has(domain)) {
      errors.push({ code: 'DOMAIN_NOT_COVERED', message: `Required domain "${domain}" not covered by any valid attestation` });
    }
  }

  if (errors.length > 0) {
    return { approved: false, errors };
  }

  // Resolve cumulative fields
  if (executionLog && profile.executionContextSchema?.fields) {
    const cumulativeErrors = resolveCumulativeFields(request, profile, executionLog, now);
    if (cumulativeErrors.length > 0) {
      return { approved: false, errors: cumulativeErrors };
    }
  }

  // Check bounds using frameSchema
  const boundsErrors = checkBoundsFromFrameSchema(request, profile);
  if (boundsErrors.length > 0) {
    return { approved: false, errors: boundsErrors };
  }

  return { approved: true };
}

// ─── v0.4 Verification ────────────────────────────────────────────────────────

async function verifyV4(
  request: GatekeeperRequest,
  profile: AgentProfile,
  publicKeyHex: string,
  now: number,
  executionLog: ExecutionLogQuery | undefined,
): Promise<GatekeeperResult> {
  const errors: GatekeeperError[] = [];

  // In v0.4 the `frame` param carries bounds; `context` carries context params
  const bounds = request.frame as AgentBoundsParams;
  const context: AgentContextParams | undefined = request.context;

  // Compute expected hashes
  let expectedBoundsHash: string;
  let expectedContextHash: string | undefined;

  try {
    expectedBoundsHash = computeBoundsHash(bounds, profile);
  } catch (err) {
    return { approved: false, errors: [{ code: 'BOUNDS_MISMATCH', message: `Bounds hash computation failed: ${err}` }] };
  }

  // Context hash is only computed when context is explicitly provided.
  // At execution time, context is not re-verified — it was checked at authorization time.
  if (context && Object.keys(context).length > 0) {
    try {
      expectedContextHash = computeContextHash(context, profile);
    } catch (err) {
      return { approved: false, errors: [{ code: 'CONTEXT_MISMATCH', message: `Context hash computation failed: ${err}` }] };
    }
  }

  // Verify attestations (domains come from SP group config, not profile)
  const requiredDomains: string[] = [];
  const coveredDomains = new Set<string>();

  for (const blob of request.attestations) {
    let attestation;
    try {
      attestation = decodeAttestationBlob(blob);
    } catch {
      errors.push({ code: 'MALFORMED_ATTESTATION', message: 'Failed to decode attestation blob' });
      continue;
    }

    try {
      await verifyAttestationSignature(attestation, publicKeyHex);
    } catch {
      errors.push({ code: 'INVALID_SIGNATURE', message: 'Attestation signature verification failed' });
      continue;
    }

    // Verify bounds hash
    try {
      verifyBoundsHash(attestation, expectedBoundsHash);
    } catch {
      errors.push({ code: 'BOUNDS_MISMATCH', message: 'Attestation bounds_hash does not match computed bounds_hash' });
      continue;
    }

    // Verify context hash (only when context was provided and hash was computed)
    if (isV4Attestation(attestation) && expectedContextHash) {
      try {
        verifyContextHash(attestation, expectedContextHash);
      } catch {
        errors.push({ code: 'CONTEXT_MISMATCH', message: 'Attestation context_hash does not match computed context_hash' });
        continue;
      }
    }

    try {
      checkAttestationExpiry(attestation.payload, now);
    } catch {
      const domainNames = (attestation.payload.resolved_domains ?? []).map(d => d.domain).join(', ');
      errors.push({ code: 'TTL_EXPIRED', message: `Attestation for domain "${domainNames}" has expired` });
      continue;
    }

    for (const rd of attestation.payload.resolved_domains ?? []) {
      coveredDomains.add(rd.domain);
    }
  }

  for (const domain of requiredDomains) {
    if (!coveredDomains.has(domain)) {
      errors.push({ code: 'DOMAIN_NOT_COVERED', message: `Required domain "${domain}" not covered by any valid attestation` });
    }
  }

  if (errors.length > 0) {
    return { approved: false, errors };
  }

  // v0.4 bounds check — single pass that dispatches on each field's
  // boundType.kind. Replaces the two-pass (resolveCumulativeFields +
  // checkBoundsFromBoundsSchema) approach, which used name-pattern
  // heuristics and silently failed when ctx field names didn't round-trip
  // through `${fieldName}_max`.
  const v4BoundsErrors = checkBoundsV4(request, profile, executionLog, now);
  if (v4BoundsErrors.length > 0) {
    return { approved: false, errors: v4BoundsErrors };
  }

  // Check context constraints using contextSchema.
  // Fail closed: if the profile declares enforceable context constraints but
  // no declared context was supplied, reject — the SP cannot enforce these
  // (it only holds context_hash), so skipping the check would silently
  // bypass scope restrictions like allowed_recipients / allowed_domains.
  if (profile.contextSchema && Object.keys(profile.contextSchema.fields).length > 0) {
    const enforceableFields = Object.entries(profile.contextSchema.fields)
      .filter(([, def]) => def.constraint?.enforceable?.length);

    if (enforceableFields.length > 0 && !context) {
      return {
        approved: false,
        errors: [{
          code: 'BOUND_EXCEEDED',
          message: `Declared context required for constraint enforcement but not provided. Fields: ${enforceableFields.map(([n]) => n).join(', ')}`,
        }],
      };
    }

    if (context) {
      const contextErrors = checkContextConstraints(context, request.execution, profile);
      if (contextErrors.length > 0) {
        return { approved: false, errors: contextErrors };
      }
    }
  }

  return { approved: true };
}

// ─── Bounds Checking ─────────────────────────────────────────────────────────

/**
 * Check execution values against authorization frame bounds (v0.3).
 * Uses the profile's frameSchema constraint definitions.
 */
function checkBoundsFromFrameSchema(request: GatekeeperRequest, profile: AgentProfile): GatekeeperError[] {
  const errors: GatekeeperError[] = [];

  if (!profile.frameSchema) return errors;

  for (const [fieldName, fieldDef] of Object.entries(profile.frameSchema.fields)) {
    if (!fieldDef.constraint) continue;

    const constraint = fieldDef.constraint;

    for (const enforceType of constraint.enforceable) {
      if (enforceType === 'max') {
        const execField = fieldName.replace(/_max$/, '');
        const boundValue = request.frame[fieldName];
        const actualValue = request.execution[execField];

        if (actualValue === undefined) continue;

        if (typeof boundValue !== 'number' || typeof actualValue !== 'number') {
          errors.push({
            code: 'BOUND_EXCEEDED',
            field: execField,
            message: `Bound check requires numeric values for "${execField}"`,
            bound: boundValue,
            actual: actualValue,
          });
          continue;
        }

        if (actualValue > boundValue) {
          errors.push({
            code: 'BOUND_EXCEEDED',
            field: execField,
            message: `Value ${actualValue} exceeds authorized maximum of ${boundValue}`,
            bound: boundValue,
            actual: actualValue,
          });
        }
      }

      if (enforceType === 'enum') {
        const boundValue = request.frame[fieldName];
        const actualValue = request.execution[fieldName];

        if (actualValue === undefined) continue;

        const allowed = typeof boundValue === 'string'
          ? boundValue.split(',').map(s => s.trim())
          : [String(boundValue)];

        const actualStr = String(actualValue);

        if (!allowed.includes(actualStr)) {
          errors.push({
            code: 'BOUND_EXCEEDED',
            field: fieldName,
            message: `Value "${actualStr}" not in authorized values [${allowed.join(', ')}]`,
            bound: boundValue,
            actual: actualValue,
          });
        }
      }
    }
  }

  return errors;
}

/**
 * v0.4 bounds enforcement — dispatches on each bound field's declared
 * `boundType.kind` with no name-pattern heuristics. This is the single
 * source of truth for client-side bounds checking in v0.4.
 *
 * Why this replaces the old two-function approach:
 *
 *   checkBoundsFromBoundsSchema (old) stripped "_max" from the bound name
 *   to guess the execution context field, which required a fixed naming
 *   convention (e.g., "amount_max" → "amount"). Profiles that used other
 *   conventions silently failed to enforce.
 *
 *   resolveCumulativeFields (old) appended "_max" to the cumulative
 *   execution context field name to find its corresponding bound, which
 *   required ANOTHER fixed naming convention (e.g., "amount_daily" →
 *   "amount_daily_max"). Profiles where the ctx field added a "_count_"
 *   infix (write_count_daily → write_daily_max, not
 *   write_count_daily_max) silently failed too.
 *
 * The new function ignores ctx field names entirely and reads
 * enforcement semantics from `fieldDef.boundType`:
 *
 *   per_transaction  — compares `execution[of] <= bound`
 *   cumulative_sum   — sumByWindow(of, window) + execution[of] <= bound
 *   cumulative_count — sumByWindow('_count', window) + 1 <= bound
 *   enum             — bound value must be in the allowed set (attest-time
 *                      validation; not an execution-time check)
 */
/**
 * Does this bound govern the action being attempted?
 *
 * Cumulative totals are scoped by (profileId, path) only, so without this every
 * cumulative_count bound on a profile sees the same running count. On customers
 * — which declares both write_daily_max and delete_daily_max — the smaller
 * delete limit would count writes and block them.
 *
 * Preferred answer is the profile's declared `appliesTo`. Absent that, fall back
 * to the field-name convention (`delete_daily_max` → `delete`), matching how the
 * Authority Server selects bounds so the two enforcement points cannot disagree.
 *
 * Fails CLOSED: when the action type is unknown, or the bound's name implies no
 * particular action, the bound is enforced.
 */
function boundGovernsAction(
  fieldName: string,
  fieldDef: ProfileBoundsField,
  bt: BoundType,
  actionType: string | undefined,
): boolean {
  if (fieldDef.appliesTo) {
    return actionType ? fieldDef.appliesTo.includes(actionType) : true;
  }

  // The name convention only ever disambiguated count bounds; sums are governed
  // by their `of` field and stay unfiltered, as at the Authority Server.
  if (bt.kind !== 'cumulative_count' || !actionType) return true;

  const prefix = fieldName.replace(/_(?:daily|monthly|weekly)_max$/, '');
  const namedForAnAction = prefix !== fieldName;
  const matches = prefix === actionType || prefix.startsWith('transaction');
  return !namedForAnAction || matches;
}

function checkBoundsV4(
  request: GatekeeperRequest,
  profile: AgentProfile,
  executionLog: ExecutionLogQuery | undefined,
  now: number,
): GatekeeperError[] {
  const errors: GatekeeperError[] = [];
  if (!profile.boundsSchema) return errors;

  const bounds = request.frame as AgentBoundsParams;
  const profileId = String(bounds.profile ?? profile.id);
  const actionType = typeof request.execution.action_type === 'string'
    ? request.execution.action_type
    : undefined;
  // Prefer the explicit request path. `frame.path` is retained only as a
  // fallback for callers that legitimately declare `path` in their profile's
  // boundsSchema; for every shipped profile it is absent, which is exactly why
  // this silently resolved to "" and disabled the cumulative gate entirely.
  const path = request.path ?? (bounds.path ? String(bounds.path) : '');

  for (const [fieldName, fieldDef] of Object.entries(profile.boundsSchema.fields)) {
    if (fieldName === 'profile' || fieldName === 'path') continue;

    const boundValue = bounds[fieldName];
    if (boundValue === undefined) continue;

    const bt = fieldDef.boundType;
    if (!bt) {
      // v0.4 requires boundType on every non-metadata bound field. A
      // missing boundType is a profile authoring bug — fail closed on
      // enforcement rather than silently skipping (which is what caused
      // the write_daily_max display bug in the first place).
      errors.push({
        code: 'BOUND_EXCEEDED',
        field: fieldName,
        message: `Profile ${profile.id} bound "${fieldName}" has no boundType — enforcement semantics undefined. Add boundType to the profile's boundsSchema.`,
        bound: boundValue,
        actual: boundValue,
      });
      continue;
    }

    if (!boundGovernsAction(fieldName, fieldDef, bt, actionType)) continue;

    switch (bt.kind) {
      case 'per_transaction': {
        const actual = request.execution[bt.of];
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

      case 'cumulative_sum': {
        if (typeof boundValue !== 'number') {
          errors.push({
            code: 'CUMULATIVE_LIMIT_EXCEEDED',
            field: bt.of,
            message: `Cumulative bound "${fieldName}" must be numeric`,
            bound: boundValue,
            actual: 0,
          });
          break;
        }
        if (!executionLog) break;

        const runningTotal = executionLog.sumByWindow(profileId, path, bt.of, bt.window, now);
        const currentRaw = request.execution[bt.of];
        const current = typeof currentRaw === 'number'
          ? currentRaw
          : (currentRaw !== undefined ? Number(currentRaw) : 0);
        const total = runningTotal + current;

        if (total > boundValue) {
          errors.push({
            code: 'CUMULATIVE_LIMIT_EXCEEDED',
            field: bt.of,
            message: `Cumulative ${bt.window} sum of ${bt.of} (${total}) exceeds limit of ${boundValue} for ${fieldName}`,
            bound: boundValue,
            actual: total,
          });
        }
        break;
      }

      case 'cumulative_count': {
        if (typeof boundValue !== 'number') {
          errors.push({
            code: 'CUMULATIVE_LIMIT_EXCEEDED',
            field: fieldName,
            message: `Cumulative count bound "${fieldName}" must be numeric`,
            bound: boundValue,
            actual: 0,
          });
          break;
        }
        if (!executionLog) break;

        const runningCount = executionLog.sumByWindow(profileId, path, '_count', bt.window, now);
        const total = runningCount + 1;

        if (total > boundValue) {
          errors.push({
            code: 'CUMULATIVE_LIMIT_EXCEEDED',
            field: fieldName,
            message: `Cumulative ${bt.window} count (${total}) exceeds limit of ${boundValue} for ${fieldName}`,
            bound: boundValue,
            actual: total,
          });
        }
        break;
      }

      case 'enum': {
        // Enum bounds are capability flags. The stored bound value must
        // be in the allowed set (a profile authoring check, really
        // belongs at attestation time). They are NOT compared against
        // runtime execution here — tool-proxy gates tool calls against
        // the manifest's required value before they reach the gatekeeper.
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
    }
  }

  return errors;
}

/**
 * Check context param values against contextSchema enum constraints (v0.4).
 * Context enum fields constrain the allowed values in execution.
 */
function checkContextConstraints(
  context: AgentContextParams,
  execution: Record<string, string | number>,
  profile: AgentProfile,
): GatekeeperError[] {
  const errors: GatekeeperError[] = [];

  if (!profile.contextSchema) return errors;

  for (const [fieldName, fieldDef] of Object.entries(profile.contextSchema.fields)) {
    if (!fieldDef.constraint) continue;

    for (const enforceType of fieldDef.constraint.enforceable) {
      if (enforceType === 'enum') {
        // The context field value is the allowed value; execution must match
        const boundValue = context[fieldName];
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
            message: `Value "${actualStr}" not in authorized context values [${allowed.join(', ')}]`,
            bound: boundValue,
            actual: actualValue,
          });
        }
      }

      if (enforceType === 'subset') {
        const boundValue = context[fieldName];
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

// ─── Cumulative Fields ────────────────────────────────────────────────────────

/**
 * Resolve cumulative fields by querying the execution log, then check their bounds.
 *
 * For each cumulative field in the execution context schema:
 * 1. Query the execution log for the running total within the window
 * 2. Add the current call's contribution (field value or +1 for _count)
 * 3. Inject the resolved value into request.execution
 * 4. Check against the corresponding bounds field (fieldName + "_max")
 */
function resolveCumulativeFields(
  request: GatekeeperRequest,
  profile: AgentProfile,
  executionLog: ExecutionLogQuery,
  now: number,
): GatekeeperError[] {
  const errors: GatekeeperError[] = [];

  // Profile ID comes from bounds (v0.4) or frame (v0.3)
  const profileId = String(request.frame.profile);

  // For v0.4, the bounds source (request.frame) holds the cumulative max fields
  const boundsOrFrame = request.frame;

  for (const [fieldName, fieldDef] of Object.entries(profile.executionContextSchema.fields)) {
    if (fieldDef.source !== 'cumulative') continue;

    const cumDef = fieldDef as CumulativeFieldDef;
    const { cumulativeField, window: windowType } = cumDef;

    const path = request.frame.path ? String(request.frame.path) : '';
    const runningTotal = executionLog.sumByWindow(profileId, path, cumulativeField, windowType, now);

    let currentContribution: number;
    if (cumulativeField === '_count') {
      currentContribution = 1;
    } else {
      const val = request.execution[cumulativeField];
      currentContribution = typeof val === 'number' ? val : (val !== undefined ? Number(val) : 0);
    }

    const cumulativeValue = runningTotal + currentContribution;

    // Inject resolved value into execution for downstream inspection
    request.execution[fieldName] = cumulativeValue;

    // Check against bound — convention: cumulative field "X_daily" → bound "X_daily_max"
    const boundFieldName = fieldName + '_max';
    const boundValue = boundsOrFrame[boundFieldName];

    if (boundValue === undefined) continue;

    if (typeof boundValue !== 'number') {
      errors.push({
        code: 'CUMULATIVE_LIMIT_EXCEEDED',
        field: fieldName,
        message: `Cumulative bound requires numeric value for "${boundFieldName}"`,
        bound: boundValue,
        actual: cumulativeValue,
      });
      continue;
    }

    if (cumulativeValue > boundValue) {
      errors.push({
        code: 'CUMULATIVE_LIMIT_EXCEEDED',
        field: fieldName,
        message: `Cumulative ${windowType} value ${cumulativeValue} exceeds limit of ${boundValue}`,
        bound: boundValue,
        actual: cumulativeValue,
      });
    }
  }

  return errors;
}

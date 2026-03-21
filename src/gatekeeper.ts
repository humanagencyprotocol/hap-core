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
  const pathId = request.frame.path;
  if (typeof pathId !== 'string') {
    return { approved: false, errors: [{ code: 'INVALID_PROFILE', message: 'Missing path in frame' }] };
  }

  const executionPath = profile.executionPaths[pathId];
  if (!executionPath) {
    return { approved: false, errors: [{ code: 'INVALID_PROFILE', message: `Unknown execution path: ${pathId}` }] };
  }

  let expectedFrameHash: string;
  try {
    expectedFrameHash = computeFrameHash(request.frame, profile);
  } catch (err) {
    return { approved: false, errors: [{ code: 'FRAME_MISMATCH', message: `Frame hash computation failed: ${err}` }] };
  }

  // Verify attestations
  const requiredDomains = executionPath.requiredDomains ?? [];
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
      const domainNames = attestation.payload.resolved_domains.map(d => d.domain).join(', ');
      errors.push({ code: 'TTL_EXPIRED', message: `Attestation for domain "${domainNames}" has expired` });
      continue;
    }

    for (const rd of attestation.payload.resolved_domains) {
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
  const context: AgentContextParams = request.context ?? {};

  const pathId = bounds.path;
  if (typeof pathId !== 'string') {
    return { approved: false, errors: [{ code: 'INVALID_PROFILE', message: 'Missing path in bounds' }] };
  }

  const executionPath = profile.executionPaths[pathId];
  if (!executionPath) {
    return { approved: false, errors: [{ code: 'INVALID_PROFILE', message: `Unknown execution path: ${pathId}` }] };
  }

  // Compute expected hashes
  let expectedBoundsHash: string;
  let expectedContextHash: string;

  try {
    expectedBoundsHash = computeBoundsHash(bounds, profile);
  } catch (err) {
    return { approved: false, errors: [{ code: 'BOUNDS_MISMATCH', message: `Bounds hash computation failed: ${err}` }] };
  }

  try {
    expectedContextHash = computeContextHash(context, profile);
  } catch (err) {
    return { approved: false, errors: [{ code: 'CONTEXT_MISMATCH', message: `Context hash computation failed: ${err}` }] };
  }

  // Verify attestations (requiredDomains may be undefined in v0.4 — domains come from SP group config)
  const requiredDomains = executionPath.requiredDomains ?? [];
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

    // Verify context hash (only for v0.4 attestations that have context_hash)
    if (isV4Attestation(attestation)) {
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
      const domainNames = attestation.payload.resolved_domains.map(d => d.domain).join(', ');
      errors.push({ code: 'TTL_EXPIRED', message: `Attestation for domain "${domainNames}" has expired` });
      continue;
    }

    for (const rd of attestation.payload.resolved_domains) {
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

  // Resolve cumulative fields from execution log
  if (executionLog && profile.executionContextSchema?.fields) {
    const cumulativeErrors = resolveCumulativeFields(request, profile, executionLog, now);
    if (cumulativeErrors.length > 0) {
      return { approved: false, errors: cumulativeErrors };
    }
  }

  // Check bounds using boundsSchema
  const boundsErrors = checkBoundsFromBoundsSchema(request, profile);
  if (boundsErrors.length > 0) {
    return { approved: false, errors: boundsErrors };
  }

  // Check context constraints using contextSchema
  if (profile.contextSchema && Object.keys(profile.contextSchema.fields).length > 0) {
    const contextErrors = checkContextConstraints(context, request.execution, profile);
    if (contextErrors.length > 0) {
      return { approved: false, errors: contextErrors };
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
 * Check execution values against boundsSchema constraints (v0.4).
 * Convention: bounds field "X_max" → checks execution field "X".
 */
function checkBoundsFromBoundsSchema(request: GatekeeperRequest, profile: AgentProfile): GatekeeperError[] {
  const errors: GatekeeperError[] = [];
  const bounds = request.frame as AgentBoundsParams;

  if (!profile.boundsSchema) return errors;

  for (const [fieldName, fieldDef] of Object.entries(profile.boundsSchema.fields)) {
    if (!fieldDef.constraint) continue;

    const constraint = fieldDef.constraint;

    for (const enforceType of constraint.enforceable) {
      if (enforceType === 'max') {
        // Convention: bounds field "X_max" maps to execution field "X"
        const execField = fieldName.replace(/_max$/, '');
        const boundValue = bounds[fieldName];
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

  // Profile ID and path come from bounds (v0.4) or frame (v0.3)
  const profileId = String(request.frame.profile);
  const path = String(request.frame.path);

  // For v0.4, the bounds source (request.frame) holds the cumulative max fields
  const boundsOrFrame = request.frame;

  for (const [fieldName, fieldDef] of Object.entries(profile.executionContextSchema.fields)) {
    if (fieldDef.source !== 'cumulative') continue;

    const cumDef = fieldDef as CumulativeFieldDef;
    const { cumulativeField, window: windowType } = cumDef;

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

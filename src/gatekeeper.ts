/**
 * Gatekeeper — Stateless Verification for Bounded Execution
 *
 * Implements §8.6 of the HAP v0.3 spec:
 * 1. Resolve profile from frame
 * 2. Recompute frame_hash
 * 3. For each required domain: find attestation, verify signature, verify frame_hash, verify TTL
 * 4. Check bounds: max → actual <= bound, enum → actual in allowed
 * 5. Return { approved } or { approved: false, errors: [...] }
 */

import { decodeAttestationBlob, verifyAttestationSignature, checkAttestationExpiry, verifyFrameHash } from './attestation';
import { computeFrameHash } from './frame';
import { getProfile } from './profiles';
import type {
  GatekeeperRequest,
  GatekeeperResult,
  GatekeeperError,
  AgentProfile,
  AttestationPayload,
  ExecutionLogQuery,
  CumulativeFieldDef,
} from './types';

/**
 * Verify an execution request against attested authorization.
 *
 * @param request - The frame, attestations, and execution values
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

  // 1. Resolve profile from frame
  const profileId = request.frame.profile;
  if (typeof profileId !== 'string') {
    return { approved: false, errors: [{ code: 'INVALID_PROFILE', message: 'Missing profile in frame' }] };
  }

  const profile = getProfile(profileId);
  if (!profile) {
    return { approved: false, errors: [{ code: 'INVALID_PROFILE', message: `Unknown profile: ${profileId}` }] };
  }

  // 2. Recompute frame_hash
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

  // 3. For each required domain: find attestation, verify
  const requiredDomains = executionPath.requiredDomains;
  const coveredDomains = new Set<string>();

  for (const blob of request.attestations) {
    let attestation;
    try {
      attestation = decodeAttestationBlob(blob);
    } catch {
      errors.push({ code: 'MALFORMED_ATTESTATION', message: 'Failed to decode attestation blob' });
      continue;
    }

    // Verify signature
    try {
      await verifyAttestationSignature(attestation, publicKeyHex);
    } catch {
      errors.push({ code: 'INVALID_SIGNATURE', message: 'Attestation signature verification failed' });
      continue;
    }

    // Verify frame_hash match
    try {
      verifyFrameHash(attestation, expectedFrameHash);
    } catch {
      errors.push({ code: 'FRAME_MISMATCH', message: 'Attestation frame_hash does not match computed frame_hash' });
      continue;
    }

    // Verify TTL
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

  // Check domain coverage
  for (const domain of requiredDomains) {
    if (!coveredDomains.has(domain)) {
      errors.push({ code: 'DOMAIN_NOT_COVERED', message: `Required domain "${domain}" not covered by any valid attestation` });
    }
  }

  // If authorization verification failed, return immediately (§8.6.4 rule 4)
  if (errors.length > 0) {
    return { approved: false, errors };
  }

  // 4. Resolve cumulative fields from execution log (if present)
  if (executionLog && profile.executionContextSchema?.fields) {
    const cumulativeErrors = resolveCumulativeFields(request, profile, executionLog, now);
    if (cumulativeErrors.length > 0) {
      return { approved: false, errors: cumulativeErrors };
    }
  }

  // 5. Check bounds — for each constrained field in the frame schema
  const boundsErrors = checkBounds(request, profile);
  if (boundsErrors.length > 0) {
    return { approved: false, errors: boundsErrors };
  }

  return { approved: true };
}

/**
 * Check execution values against authorization frame bounds.
 * Uses the profile's constraint definitions to determine how to check each field.
 */
function checkBounds(request: GatekeeperRequest, profile: AgentProfile): GatekeeperError[] {
  const errors: GatekeeperError[] = [];

  for (const [fieldName, fieldDef] of Object.entries(profile.frameSchema.fields)) {
    if (!fieldDef.constraint) continue;

    const constraint = fieldDef.constraint;

    for (const enforceType of constraint.enforceable) {
      if (enforceType === 'max') {
        // The frame field is the bound (e.g., amount_max: 80)
        // We need to find the corresponding execution field
        // Convention: frame field "X_max" maps to execution field "X"
        const execField = fieldName.replace(/_max$/, '');
        const boundValue = request.frame[fieldName];
        const actualValue = request.execution[execField];

        if (actualValue === undefined) continue; // Field not in execution request

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
        // The frame field value is the allowed value (or comma-separated set)
        const boundValue = request.frame[fieldName];
        const actualValue = request.execution[fieldName];

        if (actualValue === undefined) continue;

        // Allowed values: the frame value itself (single value for now)
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
 * Resolve cumulative fields by querying the execution log, then check their bounds.
 *
 * For each cumulative field in the execution context schema:
 * 1. Query the execution log for the running total within the window
 * 2. Add the current call's contribution (field value or +1 for _count)
 * 3. Inject the resolved value into request.execution
 * 4. Check against the corresponding frame bound (fieldName + "_max")
 */
function resolveCumulativeFields(
  request: GatekeeperRequest,
  profile: AgentProfile,
  executionLog: ExecutionLogQuery,
  now: number,
): GatekeeperError[] {
  const errors: GatekeeperError[] = [];
  const profileId = String(request.frame.profile);
  const path = String(request.frame.path);

  for (const [fieldName, fieldDef] of Object.entries(profile.executionContextSchema.fields)) {
    if (fieldDef.source !== 'cumulative') continue;

    const cumDef = fieldDef as CumulativeFieldDef;
    const { cumulativeField, window: windowType } = cumDef;

    // Query running total from execution log
    const runningTotal = executionLog.sumByWindow(profileId, path, cumulativeField, windowType, now);

    // Add current call's contribution
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

    // Check against frame bound — convention: cumulative field "X_daily" maps to frame "X_daily_max"
    const boundFieldName = fieldName + '_max';
    const boundValue = request.frame[boundFieldName];

    if (boundValue === undefined) continue; // No bound defined for this cumulative field

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

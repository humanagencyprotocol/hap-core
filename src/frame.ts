/**
 * Frame Canonicalization for Agent Profiles
 *
 * Agent profiles support mixed-type fields (strings and numbers).
 * Canonical form: all values are converted to strings via String(value).
 * Keys are ordered according to the profile's keyOrder.
 */

import { createHash } from 'crypto';
import type { AgentFrameParams, AgentProfile } from './types';

/**
 * Validates frame parameters against the profile's frame schema.
 */
export function validateFrameParams(
  params: AgentFrameParams,
  profile: AgentProfile
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Check all required fields are present
  for (const [fieldName, fieldDef] of Object.entries(profile.frameSchema.fields)) {
    if (fieldDef.required && !(fieldName in params)) {
      errors.push(`Missing required field: ${fieldName}`);
    }
  }

  // Validate each provided field
  for (const [field, value] of Object.entries(params)) {
    const fieldDef = profile.frameSchema.fields[field];
    if (!fieldDef) {
      errors.push(`Unknown field "${field}" not defined in profile ${profile.id}`);
      continue;
    }

    // Type check
    if (fieldDef.type === 'number' && typeof value !== 'number') {
      errors.push(`Field "${field}" must be a number, got ${typeof value}`);
    }
    if (fieldDef.type === 'string' && typeof value !== 'string') {
      errors.push(`Field "${field}" must be a string, got ${typeof value}`);
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Builds the canonical frame string from parameters.
 * All values are converted to strings. Keys are ordered per profile's keyOrder.
 *
 * @throws Error if any field fails validation
 */
export function canonicalFrame(params: AgentFrameParams, profile: AgentProfile): string {
  const validation = validateFrameParams(params, profile);
  if (!validation.valid) {
    throw new Error(`Invalid frame parameters: ${validation.errors.join('; ')}`);
  }

  const lines = profile.frameSchema.keyOrder.map(
    (key) => `${key}=${String(params[key])}`
  );

  return lines.join('\n');
}

/**
 * Computes the frame hash from a canonical frame string.
 *
 * @returns Hash in format "sha256:<64 hex chars>"
 */
export function frameHash(canonicalFrameString: string): string {
  const hash = createHash('sha256').update(canonicalFrameString, 'utf8').digest('hex');
  return `sha256:${hash}`;
}

/**
 * Convenience: builds canonical frame and computes hash in one step.
 */
export function computeFrameHash(params: AgentFrameParams, profile: AgentProfile): string {
  return frameHash(canonicalFrame(params, profile));
}

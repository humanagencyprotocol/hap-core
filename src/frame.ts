/**
 * Frame Canonicalization for Agent Profiles
 *
 * Agent profiles support mixed-type fields (strings and numbers).
 * Canonical form: all values are converted to strings via String(value).
 * Keys are ordered according to the profile's keyOrder.
 *
 * v0.3: frameSchema
 * v0.4: boundsSchema + contextSchema (separate hashes)
 */

import { createHash } from 'crypto';
import type { AgentFrameParams, AgentBoundsParams, AgentContextParams, AgentProfile } from './types';

// ─── v0.3 Frame Functions ─────────────────────────────────────────────────────

/**
 * Validates frame parameters against the profile's frame schema.
 */
export function validateFrameParams(
  params: AgentFrameParams,
  profile: AgentProfile
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!profile.frameSchema) {
    return { valid: false, errors: ['Profile does not have a frameSchema'] };
  }

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

  const lines = profile.frameSchema!.keyOrder.map(
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

// ─── v0.4 Bounds Functions ────────────────────────────────────────────────────

/**
 * Validates bounds parameters against the profile's boundsSchema (v0.4).
 */
export function validateBoundsParams(
  params: AgentBoundsParams,
  profile: AgentProfile
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!profile.boundsSchema) {
    return { valid: false, errors: ['Profile does not have a boundsSchema'] };
  }

  // Check all required fields are present
  for (const [fieldName, fieldDef] of Object.entries(profile.boundsSchema.fields)) {
    if (fieldDef.required && !(fieldName in params)) {
      errors.push(`Missing required field: ${fieldName}`);
    }
  }

  // Validate each provided field
  for (const [field, value] of Object.entries(params)) {
    const fieldDef = profile.boundsSchema.fields[field];
    if (!fieldDef) {
      errors.push(`Unknown field "${field}" not defined in boundsSchema of profile ${profile.id}`);
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
 * Validates context parameters against the profile's contextSchema (v0.4).
 */
export function validateContextParams(
  params: AgentContextParams,
  profile: AgentProfile
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!profile.contextSchema) {
    // No contextSchema is valid — empty context
    if (Object.keys(params).length > 0) {
      errors.push('Profile does not have a contextSchema but context params were provided');
    }
    return { valid: errors.length === 0, errors };
  }

  // Check all required fields are present
  for (const [fieldName, fieldDef] of Object.entries(profile.contextSchema.fields)) {
    if (fieldDef.required && !(fieldName in params)) {
      errors.push(`Missing required field: ${fieldName}`);
    }
  }

  // Validate each provided field
  for (const [field, value] of Object.entries(params)) {
    const fieldDef = profile.contextSchema.fields[field];
    if (!fieldDef) {
      errors.push(`Unknown field "${field}" not defined in contextSchema of profile ${profile.id}`);
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
 * Builds the canonical bounds string from parameters.
 * All values are converted to strings. Keys are ordered per profile's boundsSchema.keyOrder.
 *
 * @throws Error if any field fails validation
 */
export function canonicalBounds(params: AgentBoundsParams, profile: AgentProfile): string {
  const validation = validateBoundsParams(params, profile);
  if (!validation.valid) {
    throw new Error(`Invalid bounds parameters: ${validation.errors.join('; ')}`);
  }

  const lines = profile.boundsSchema!.keyOrder.map(
    (key) => `${key}=${String(params[key])}`
  );

  return lines.join('\n');
}

/**
 * Builds the canonical context string from parameters.
 * All values are converted to strings. Keys are ordered per profile's contextSchema.keyOrder.
 * For empty context (no contextSchema or no fields), returns "".
 *
 * @throws Error if any field fails validation
 */
export function canonicalContext(params: AgentContextParams, profile: AgentProfile): string {
  // No contextSchema or no fields → empty context
  if (!profile.contextSchema || Object.keys(profile.contextSchema.fields).length === 0) {
    return '';
  }

  const validation = validateContextParams(params, profile);
  if (!validation.valid) {
    throw new Error(`Invalid context parameters: ${validation.errors.join('; ')}`);
  }

  const lines = profile.contextSchema.keyOrder.map(
    (key) => `${key}=${String(params[key])}`
  );

  return lines.join('\n');
}

/**
 * Computes the bounds hash from bounds parameters (v0.4).
 *
 * @returns Hash in format "sha256:<64 hex chars>"
 */
export function computeBoundsHash(params: AgentBoundsParams, profile: AgentProfile): string {
  const canonical = canonicalBounds(params, profile);
  const hash = createHash('sha256').update(canonical, 'utf8').digest('hex');
  return `sha256:${hash}`;
}

/**
 * Computes the context hash from context parameters (v0.4).
 * For empty context {}, returns the sha256 of "":
 *   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
 *
 * @returns Hash in format "sha256:<64 hex chars>"
 */
export function computeContextHash(params: AgentContextParams, profile: AgentProfile): string {
  const canonical = canonicalContext(params, profile);
  const hash = createHash('sha256').update(canonical, 'utf8').digest('hex');
  return `sha256:${hash}`;
}

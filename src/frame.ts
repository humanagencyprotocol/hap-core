/**
 * Frame Canonicalization for Agent Profiles
 *
 * Agent profiles support mixed-type fields (strings and numbers).
 * Canonical form: `key=value` records joined with LF, keys in the profile's
 * keyOrder. Values are stringified with String(value) — the shortest
 * round-trippable form for numbers — then percent-encoded per protocol.md
 * (`=`, `%`, and every byte outside printable ASCII); a value carrying a raw
 * LF/CR is refused, never normalized. See `canonicalRecords` below.
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

// ─── Value Encoding (normative, v0.5+) ───────────────────────────────────────

/**
 * Thrown when a value cannot be canonicalized at all — currently only for raw
 * LF/CR inside a value. Carries the protocol error code so callers can map it
 * straight onto the wire without string-matching a message.
 *
 * protocol.md → *Bounds & Scope Canonicalization* → Value encoding:
 *   "Values MUST NOT contain raw newline (\n) or carriage-return (\r)
 *    characters. Implementations MUST reject input containing them; silent
 *    stripping or normalization is a violation because it produces a hash that
 *    does not faithfully represent the input."
 */
export class CanonicalValueError extends Error {
  readonly code: 'BOUNDS_INVALID_VALUE' | 'CONTEXT_INVALID_VALUE';
  readonly field: string;

  constructor(code: 'BOUNDS_INVALID_VALUE' | 'CONTEXT_INVALID_VALUE', field: string, message: string) {
    super(message);
    this.name = 'CanonicalValueError';
    this.code = code;
    this.field = field;
  }
}

/**
 * Percent-encode a value per protocol.md → *Value encoding*.
 *
 * Encoded, over the value's UTF-8 bytes, as `%` + two UPPERCASE hex digits:
 *   - `=` (0x3D) — otherwise it would be read as the key/value separator
 *   - `%` (0x25) — so the encoding is self-inverse
 *   - every byte outside printable ASCII 0x20–0x7E
 *
 * LF and CR are deliberately NOT in this list: they are refused upstream, so
 * encoding them is unreachable (v0.7 removed the spec's contradiction here).
 *
 * This runs at canonicalization time only. Stored values keep the human's
 * original bytes.
 */
function percentEncodeCanonicalValue(raw: string): string {
  const bytes = new TextEncoder().encode(raw);
  let out = '';
  for (const b of bytes) {
    if (b === 0x3d || b === 0x25 || b < 0x20 || b > 0x7e) {
      out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
    } else {
      out += String.fromCharCode(b);
    }
  }
  return out;
}

/**
 * The one place `key=value` records are built for bounds and context.
 *
 * Rules applied here (all normative, protocol.md → *Bounds & Scope
 * Canonicalization*):
 *   - keys in the schema's keyOrder, never alphabetical
 *   - a value carrying a raw LF/CR is REFUSED (never stripped or encoded)
 *   - `=`, `%`, and any byte outside 0x20–0x7E are percent-encoded (UPPERCASE)
 *   - numbers use JS `String()`, which is the shortest round-trippable form
 *     (`String(20.0)` === "20")
 *   - a key with no value is OMITTED entirely — it emits no record
 *
 * On the omission rule: required keys are guaranteed present by the caller's
 * validation (`validateBoundsParams` / `validateContextParams` reject a missing
 * required field), so "explicit inclusion of all required keys" still holds.
 * What remains are *optional* keys the human never set. Rendering those as the
 * literal string "undefined" — the pre-fix behaviour — hashed a JavaScript
 * artifact that no other language would produce and that collides with a real
 * value of "undefined". Omitting them (rather than emitting `key=`) also keeps
 * "the human set no limit" distinct from "the human set an empty value", and
 * matches this package's JSON canonicalization, which drops undefined-valued
 * properties.
 */
function canonicalRecords(
  params: Record<string, string | number | undefined>,
  keyOrder: string[],
  code: 'BOUNDS_INVALID_VALUE' | 'CONTEXT_INVALID_VALUE',
): string {
  const lines: string[] = [];

  for (const key of keyOrder) {
    const value = params[key];
    if (value === undefined || value === null) continue;

    const raw = String(value);
    if (raw.includes('\n') || raw.includes('\r')) {
      throw new CanonicalValueError(
        code,
        key,
        `Value for "${key}" contains a raw newline or carriage return. ` +
          'Refusing: a hash over stripped or normalized input would not represent what was authorized.',
      );
    }

    lines.push(`${key}=${percentEncodeCanonicalValue(raw)}`);
  }

  return lines.join('\n');
}

/**
 * Builds the canonical bounds string from parameters.
 * Keys are ordered per profile's boundsSchema.keyOrder; values are encoded per
 * protocol.md → *Value encoding* (see `canonicalRecords`).
 *
 * @throws Error if any field fails validation
 * @throws CanonicalValueError (code BOUNDS_INVALID_VALUE) if a value carries a raw LF/CR
 */
export function canonicalBounds(params: AgentBoundsParams, profile: AgentProfile): string {
  const validation = validateBoundsParams(params, profile);
  if (!validation.valid) {
    throw new Error(`Invalid bounds parameters: ${validation.errors.join('; ')}`);
  }

  return canonicalRecords(params, profile.boundsSchema!.keyOrder, 'BOUNDS_INVALID_VALUE');
}

/**
 * Builds the canonical context string from parameters.
 * Keys are ordered per profile's contextSchema.keyOrder; values are encoded per
 * protocol.md → *Value encoding* (see `canonicalRecords`).
 * For empty context (no contextSchema or no fields), returns "".
 *
 * @throws Error if any field fails validation
 * @throws CanonicalValueError (code CONTEXT_INVALID_VALUE) if a value carries a raw LF/CR
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

  return canonicalRecords(params, profile.contextSchema.keyOrder, 'CONTEXT_INVALID_VALUE');
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

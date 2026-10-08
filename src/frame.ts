/**
 * Bounds & Scope Canonicalization (protocol.md → *Bounds & Scope
 * Canonicalization*).
 *
 * Canonical form: `key=value` records joined with LF, keys in the profile's
 * keyOrder. Values are stringified with String(value) — the shortest
 * round-trippable form for numbers — then percent-encoded per protocol.md
 * (`=`, `%`, and every byte outside printable ASCII); a value carrying a raw
 * LF/CR is refused, never normalized. See `canonicalRecords` below.
 *
 * v0.3's `frameSchema` / `canonicalFrame` / `computeFrameHash` are retired
 * with the rest of v0.3 (CLAUDE.md "Decided by the owner": no backward
 * compatibility). v0.7 renames `contextSchema` → `scopeSchema` and
 * `AgentContextParams` → `AgentScopeParams` (protocol.md → *Migration from
 * v0.6*); the functions below follow suit (`canonicalContext` →
 * `canonicalScope`, `computeContextHash` → `computeScopeHash`,
 * `validateContextParams` → `validateScopeParams`).
 */

import { createHash } from 'crypto';
import type { AgentBoundsParams, AgentScopeParams, AgentProfile } from './types';

// ─── Bounds Validation ────────────────────────────────────────────────────────

/**
 * Validates bounds parameters against the profile's boundsSchema.
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

// ─── Scope Validation ─────────────────────────────────────────────────────────

/**
 * Validates scope parameters against the profile's scopeSchema.
 */
export function validateScopeParams(
  params: AgentScopeParams,
  profile: AgentProfile
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!profile.scopeSchema) {
    // No scopeSchema is valid — empty scope
    if (Object.keys(params).length > 0) {
      errors.push('Profile does not have a scopeSchema but scope params were provided');
    }
    return { valid: errors.length === 0, errors };
  }

  // Check all required fields are present
  for (const [fieldName, fieldDef] of Object.entries(profile.scopeSchema.fields)) {
    if (fieldDef.required && !(fieldName in params)) {
      errors.push(`Missing required field: ${fieldName}`);
    }
  }

  // Validate each provided field
  for (const [field, value] of Object.entries(params)) {
    const fieldDef = profile.scopeSchema.fields[field];
    if (!fieldDef) {
      errors.push(`Unknown field "${field}" not defined in scopeSchema of profile ${profile.id}`);
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

// ─── Value Encoding (normative, protocol.md → *Bounds & Scope Canonicalization*) ─

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
  readonly code: 'BOUNDS_INVALID_VALUE' | 'SCOPE_INVALID_VALUE';
  readonly field: string;

  constructor(code: 'BOUNDS_INVALID_VALUE' | 'SCOPE_INVALID_VALUE', field: string, message: string) {
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
 * encoding them is unreachable (v0.7 removed the spec's own contradiction here
 * — earlier versions listed them in the percent-encode rule too, which read
 * as permission to encode what the line above already refuses).
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
 * The one place `key=value` records are built for bounds and scope.
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
 * validation (`validateBoundsParams` / `validateScopeParams` reject a missing
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
  code: 'BOUNDS_INVALID_VALUE' | 'SCOPE_INVALID_VALUE',
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
 * Builds the canonical scope string from parameters.
 * Keys are ordered per profile's scopeSchema.keyOrder; values are encoded per
 * protocol.md → *Value encoding* (see `canonicalRecords`).
 * For empty scope (no scopeSchema or no fields), returns "".
 *
 * @throws Error if any field fails validation
 * @throws CanonicalValueError (code SCOPE_INVALID_VALUE) if a value carries a raw LF/CR
 */
export function canonicalScope(params: AgentScopeParams, profile: AgentProfile): string {
  // No scopeSchema or no fields → empty scope
  if (!profile.scopeSchema || Object.keys(profile.scopeSchema.fields).length === 0) {
    return '';
  }

  const validation = validateScopeParams(params, profile);
  if (!validation.valid) {
    throw new Error(`Invalid scope parameters: ${validation.errors.join('; ')}`);
  }

  return canonicalRecords(params, profile.scopeSchema.keyOrder, 'SCOPE_INVALID_VALUE');
}

/**
 * Computes the bounds hash from bounds parameters.
 *
 * @returns Hash in format "sha256:<64 hex chars>"
 */
export function computeBoundsHash(params: AgentBoundsParams, profile: AgentProfile): string {
  const canonical = canonicalBounds(params, profile);
  const hash = createHash('sha256').update(canonical, 'utf8').digest('hex');
  return `sha256:${hash}`;
}

/**
 * Computes the scope hash from scope parameters.
 * For empty scope {}, returns the sha256 of "":
 *   "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
 *
 * @returns Hash in format "sha256:<64 hex chars>"
 */
export function computeScopeHash(params: AgentScopeParams, profile: AgentProfile): string {
  const canonical = canonicalScope(params, profile);
  const hash = createHash('sha256').update(canonical, 'utf8').digest('hex');
  return `sha256:${hash}`;
}

/**
 * Content binding — Level 2 content proof (HAP v0.5 Content Provenance).
 *
 * A receipt normally proves who/why/bounds/when but NOT the action's content.
 * Content binding closes that gap: the gateway computes a `content_hash` over
 * the action's content per the profile's {@link ContentBinding} and hands the
 * SP only the hash. The SP signs it into the receipt verbatim — it never sees
 * the content, so HAP's privacy-minimal design is preserved. Anyone holding
 * the content can recompute the hash and check it against the signed receipt.
 *
 * The hash only verifies if the verifier reproduces the EXACT bytes we hashed,
 * so canonicalization is normative and versioned (pin via `ContentBinding.version`):
 *
 *  - kind:"jcs"  → RFC 8785 JCS of the record payload (see {@link canonicalize}).
 *  - kind:"text" → UTF-8 of the string after {@link canonicalizeText}
 *    (Unicode NFC, LF line endings, trailing per-line whitespace stripped,
 *    trailing blank lines removed), taken pre-footer when `pre_footer` is set.
 *
 * At `version:"2"` the profile also declares WHICH tool arguments are bound
 * ({@link selectBoundFields}), so a receipt can commit to an email's recipients
 * and not only its prose — while still omitting what the intended verifier
 * cannot see. Every string entering the hashed object is canonicalized by the
 * same `text` rule, so a delivered copy with CRLF endings still reproduces it.
 *
 * Both Node and the browser produce byte-identical output: JCS relies only on
 * environment-independent primitives, and the text rule uses String.normalize +
 * plain string ops. The SHA-256 is computed with Node `crypto` here (the same
 * pattern as frame.ts); browser callers that need to recompute use their own
 * SubtleCrypto digest over the identical canonical bytes.
 */

import { createHash } from 'crypto';
import { canonicalize } from './canonicalize';
import type { ContentBinding } from './types';

/**
 * Canonicalize free text per the v0.5 'text' rule. Idempotent.
 *
 *   1. Unicode NFC normalization.
 *   2. CRLF / CR → LF.
 *   3. Strip trailing spaces/tabs from every line.
 *   4. Remove trailing blank lines.
 */
export function canonicalizeText(input: string): string {
  const nfc = input.normalize('NFC');
  const lf = nfc.replace(/\r\n?/g, '\n');
  const lines = lf.split('\n').map((line) => line.replace(/[ \t]+$/, ''));
  return lines.join('\n').replace(/\n+$/, '');
}

/** sha256 of a UTF-8 string → 64 hex chars. */
function sha256Hex(bytes: string): string {
  return createHash('sha256').update(bytes, 'utf8').digest('hex');
}

/**
 * Compute the canonical bytes that a content hash is taken over, WITHOUT
 * hashing — exposed so verifiers can debug a mismatch by inspecting the exact
 * serialization both sides should agree on.
 */
export function contentCanonicalBytes(
  kind: ContentBinding['kind'],
  content: Record<string, unknown> | string,
): string {
  if (kind === 'jcs') {
    if (typeof content === 'string') {
      throw new Error('content_binding kind="jcs" expects a record payload (object), got a string');
    }
    return canonicalize(content);
  }
  if (typeof content !== 'string') {
    throw new Error('content_binding kind="text" expects a string, got an object');
  }
  return canonicalizeText(content);
}

/**
 * Compute a profile-bound content hash, formatted `sha256:<hex>` (matching the
 * frame/bounds/context hash format used elsewhere in HAP).
 *
 * @param binding the profile's content_binding declaration
 * @param content the record payload (jcs) or the resolved text field (text)
 */
export function computeContentHash(
  binding: ContentBinding,
  content: Record<string, unknown> | string,
): string {
  return `sha256:${sha256Hex(contentCanonicalBytes(binding.kind, content))}`;
}

// ─── v2: binding over a declared field subset ────────────────────────────────

/** Why a field binding refused. Every case is fail-closed by design. */
export type ContentBindingErrorCode =
  /** The profile declares version:"2" with no usable `fields` list. */
  | 'NO_FIELDS_DECLARED'
  /** `required_fields` names something absent from `fields`. */
  | 'REQUIRED_FIELD_NOT_DECLARED'
  /** A required field was absent or empty at call time. */
  | 'MISSING_REQUIRED_FIELD'
  /** No declared field carried a value — the hash would commit to nothing. */
  | 'EMPTY_BINDING';

/**
 * A field binding could not be computed. ALWAYS a refusal, never a downgrade:
 * the alternative is a receipt that verifies while proving less than it appears
 * to, which is the failure content binding exists to prevent.
 */
export class ContentBindingError extends Error {
  readonly code: ContentBindingErrorCode;
  /** The offending field, when the code names one. */
  readonly field?: string;

  constructor(code: ContentBindingErrorCode, message: string, field?: string) {
    super(message);
    this.name = 'ContentBindingError';
    this.code = code;
    this.field = field;
  }
}

/** True when this binding selects a declared subset (v2) rather than v1's implicit scope. */
export function isFieldBinding(binding: ContentBinding): boolean {
  return binding.version === '2' && Array.isArray(binding.fields) && binding.fields.length > 0;
}

/**
 * Whether a field binding covers this action type, per the profile's `appliesTo`.
 *
 * Read STRICTLY — an undeclared action type is NOT covered. This differs from
 * how bounds read the same key (there, an unknown action type enforces the
 * bound, because an extra limit is safe). Here the two directions are not
 * symmetric: applying a field binding to a call that carries no content refuses
 * a legitimate action, so an unknown action type must fall outside rather than
 * inside. Callers are expected to warn on the undeclared case — it is a
 * manifest bug either way.
 */
export function bindingAppliesTo(
  binding: ContentBinding,
  actionType: string | undefined,
): boolean {
  if (!binding.appliesTo) return true;
  return actionType !== undefined && binding.appliesTo.includes(actionType);
}

/**
 * Canonicalize one value on its way into the bound object, or `undefined` when
 * it carries nothing (absent / null / empty after canonicalization).
 *
 * Strings are run through {@link canonicalizeText} — the SAME rule `kind:"text"`
 * uses, applied per string rather than to one field. This is not decoration:
 * the verifier of an email holds the DELIVERED copy, whose body has CRLF line
 * endings and transport-added trailing whitespace. JCS embeds strings verbatim,
 * so without this the recipient could never reproduce the hash.
 *
 * Deliberately NOT normalized: array order (the To: header preserves what was
 * sent, and reordering recipients is a change worth catching) and address case
 * (the local part is case-sensitive per RFC 5321, so lowercasing would be a
 * semantic claim this layer has no business making).
 */
function canonicalizeValue(value: unknown): unknown {
  if (value === null || value === undefined) return undefined;
  if (typeof value === 'string') {
    const text = canonicalizeText(value);
    return text === '' ? undefined : text;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) {
    const items = value.map(canonicalizeValue).filter((v) => v !== undefined);
    return items.length > 0 ? items : undefined;
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      const c = canonicalizeValue(v);
      if (c !== undefined) out[key] = c;
    }
    return Object.keys(out).length > 0 ? out : undefined;
  }
  return undefined; // functions/symbols — not JSON, nothing to bind
}

/**
 * Build the object a v2 binding hashes: exactly the declared `fields` that
 * carry a value, canonicalized. Exported so a verifier can construct the same
 * object from what they hold and see it before hashing.
 *
 * Throws {@link ContentBindingError} rather than returning a partial result —
 * see that class for why refusing is the only safe outcome.
 */
export function selectBoundFields(
  binding: ContentBinding,
  args: Record<string, unknown>,
): Record<string, unknown> {
  const fields = binding.fields;
  if (!fields || fields.length === 0) {
    throw new ContentBindingError(
      'NO_FIELDS_DECLARED',
      'content_binding version "2" requires a non-empty `fields` list.',
    );
  }

  const required = new Set(binding.required_fields ?? []);
  for (const field of required) {
    if (!fields.includes(field)) {
      throw new ContentBindingError(
        'REQUIRED_FIELD_NOT_DECLARED',
        `content_binding requires "${field}" but does not bind it — required_fields must be a subset of fields.`,
        field,
      );
    }
  }

  const bound: Record<string, unknown> = {};
  for (const field of fields) {
    const value = canonicalizeValue(args[field]);
    if (value === undefined) {
      if (required.has(field)) {
        throw new ContentBindingError(
          'MISSING_REQUIRED_FIELD',
          `content_binding requires "${field}", which is absent or empty in this call. ` +
            `Refusing rather than hashing a partial object.`,
          field,
        );
      }
      continue; // legitimately absent (an email with no cc)
    }
    bound[field] = value;
  }

  if (Object.keys(bound).length === 0) {
    throw new ContentBindingError(
      'EMPTY_BINDING',
      `No declared field (${fields.join(', ')}) carried a value — the hash would commit to nothing.`,
    );
  }

  return bound;
}

/**
 * Compute a v2 field-binding hash from raw tool arguments: select the declared
 * subset, then hash it by the declared `kind`. Convenience over
 * {@link selectBoundFields} + {@link computeContentHash} for the common path.
 */
export function computeFieldsContentHash(
  binding: ContentBinding,
  args: Record<string, unknown>,
): string {
  return computeContentHash(binding, selectBoundFields(binding, args));
}

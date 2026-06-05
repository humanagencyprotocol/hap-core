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

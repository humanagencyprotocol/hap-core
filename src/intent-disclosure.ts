/**
 * Intent hashing + intent-disclosure binding (HAP v0.5).
 *
 * Two shared, environment-independent hashes that the attester (gateway), the
 * Authority Server, and any approver MUST compute identically:
 *
 *  1. {@link computeIntentHash} — `gate_content_hashes.intent`. The intent text
 *     is canonicalized (Unicode NFC, LF line endings, trailing-whitespace strip
 *     — the same rule as content-binding's `canonicalizeText`) before hashing,
 *     so independent multi-owner approvers reproduce an identical hash from the
 *     same logical statement. See protocol.md → "Intent canonicalization".
 *
 *  2. {@link computeIntentDisclosureHash} — `intent_disclosure_hash`, the C2
 *     binding from companion spec `intent-disclosure@0.1`. It commits the
 *     encrypted disclosure object (`intent_ciphertext` + `approvers_frozen`)
 *     into the SIGNED attestation payload, so a compromised AS cannot swap the
 *     ciphertext/wrapped keys or widen/shrink the approver set without breaking
 *     the attestation signature.
 *
 * Both produce `sha256:<hex>` to match the frame/bounds/context hash format.
 */

import { createHash } from 'crypto';
import { canonicalize } from './canonicalize';
import { canonicalizeText } from './content-binding';

function sha256Hex(bytes: string): string {
  return createHash('sha256').update(bytes, 'utf8').digest('hex');
}

/**
 * `gate_content_hashes.intent` for an intent statement.
 * Canonicalizes the text (NFC / LF / trailing-whitespace strip) before hashing.
 */
export function computeIntentHash(intentText: string): string {
  return `sha256:${sha256Hex(canonicalizeText(intentText))}`;
}

/**
 * The exact bytes `intent_disclosure_hash` is taken over, WITHOUT hashing —
 * exposed so an implementer debugging a mismatch can inspect the serialization
 * both sides must agree on:
 *
 *   intent_ciphertext ‖ "\n" ‖ JCS(sort(approvers_frozen))
 *
 * where `intent_ciphertext` is the exact base64url string of the disclosure
 * object, `sort` orders the approver DIDs by Unicode code point, and `JCS` is
 * RFC 8785 canonicalization of the sorted array (via {@link canonicalize}).
 */
export function intentDisclosureCanonicalBytes(
  intentCiphertext: string,
  approversFrozen: string[],
): string {
  const sorted = [...approversFrozen].sort();
  return `${intentCiphertext}\n${canonicalize(sorted)}`;
}

/**
 * `intent_disclosure_hash` — `sha256:<hex>` over
 * {@link intentDisclosureCanonicalBytes}. Computed by the attester after
 * encryption and signed into the attestation; recomputed by the AS (at
 * issuance) and by each approver (on receipt) and compared, fail-closed.
 */
export function computeIntentDisclosureHash(
  intentCiphertext: string,
  approversFrozen: string[],
): string {
  return `sha256:${sha256Hex(intentDisclosureCanonicalBytes(intentCiphertext, approversFrozen))}`;
}

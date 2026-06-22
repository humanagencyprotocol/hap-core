/**
 * Intent hashing + intent-disclosure binding (HAP v0.5) — conformance.
 *
 * Pins the byte-level contract for `gate_content_hashes.intent` and the
 * `intent_disclosure_hash` C2 binding, so the gateway (attester), the AS, and
 * any approver — in any language — reproduce identical hashes.
 */
import { describe, it, expect } from 'vitest';
import {
  computeIntentHash,
  computeIntentDisclosureHash,
  intentDisclosureCanonicalBytes,
} from '../src/intent-disclosure';

describe('computeIntentHash — canonicalization', () => {
  it('is stable across line endings and trailing whitespace (NFC/LF/trim)', () => {
    const a = computeIntentHash('Refund the customer.\nKeep it under €50.');
    const b = computeIntentHash('Refund the customer.  \r\nKeep it under €50.\n\n');
    expect(a).toBe(b);
  });

  it('normalizes Unicode to NFC (composed === decomposed)', () => {
    // "é" composed (U+00E9) vs decomposed (e + U+0301) must hash identically.
    const composed = computeIntentHash('café');
    const decomposed = computeIntentHash('café');
    expect(composed).toBe(decomposed);
  });

  it('distinguishes genuinely different intent', () => {
    expect(computeIntentHash('Pay invoice 1')).not.toBe(computeIntentHash('Pay invoice 2'));
  });

  it('is sha256:<64 hex>', () => {
    expect(computeIntentHash('x')).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

describe('computeIntentDisclosureHash — C2 binding', () => {
  const ct = 'YmFzZTY0dXJsLWNpcGhlcnRleHQ'; // stand-in base64url ciphertext
  const approvers = ['did:key:bob', 'did:key:alice'];

  it('is order-independent in the approver set (sorted before hashing)', () => {
    expect(computeIntentDisclosureHash(ct, ['did:key:alice', 'did:key:bob'])).toBe(
      computeIntentDisclosureHash(ct, ['did:key:bob', 'did:key:alice']),
    );
  });

  it('changes when the ciphertext changes (tamper detection)', () => {
    expect(computeIntentDisclosureHash(ct, approvers)).not.toBe(
      computeIntentDisclosureHash(ct + 'X', approvers),
    );
  });

  it('changes when an approver is added or removed (tamper detection)', () => {
    const base = computeIntentDisclosureHash(ct, approvers);
    expect(base).not.toBe(computeIntentDisclosureHash(ct, [...approvers, 'did:key:carol']));
    expect(base).not.toBe(computeIntentDisclosureHash(ct, ['did:key:alice']));
  });

  it('canonical bytes are ciphertext ‖ "\\n" ‖ JCS(sorted approvers)', () => {
    expect(intentDisclosureCanonicalBytes(ct, approvers)).toBe(
      `${ct}\n["did:key:alice","did:key:bob"]`,
    );
  });

  it('is sha256:<64 hex>', () => {
    expect(computeIntentDisclosureHash(ct, approvers)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

/**
 * Execution receipts (HAP v0.5/v0.6) — the wire type and holder-side
 * verification. Until v0.6 this library had no receipt surface at all; every
 * verifier hand-assembled the strip→canonicalize→verify dance. This module is
 * that dance, once.
 *
 * Receipt payloads are camelCase on the wire (unlike the snake_case
 * attestation payload) — a shipped inconsistency v0.6 chose to document
 * rather than break (changelog.md → "Renames and terminology").
 */

import * as ed from '@noble/ed25519';
import type { ContentBinding, Subject } from './types';
import { canonicalize } from './canonicalize';

/** Signed execution receipt — protocol.md → "Receipt Payload Schema". */
export interface ReceiptPayload {
  id: string;
  groupId?: string | null;
  userId?: string;
  boundsHash: string;
  profileId: string;
  /** Downstream tool name. Audit metadata only — never a dispatch key. */
  action: string;
  /** Semantic category — drives cumulative bucketing and bounds dispatch. */
  actionType: string;
  executionContext: Record<string, unknown>;
  cumulativeState?: Record<string, unknown>;
  limits?: Record<string, unknown>;
  timestamp: number;
  /** v0.6 — hash of the bound content, computed by the Gatekeeper, copied
   * verbatim by the AS. The AS never sees the content. */
  contentHash?: string;
  /** v0.6 — the binding declaration echoed into the signed receipt, so a
   * verifier knows exactly what `contentHash` covers. */
  contentBinding?: Pick<ContentBinding, 'version' | 'kind' | 'fields' | 'required_fields' | 'appliesTo'>;
  /** v0.6 — disclosed subset of the attestation's identity overlay. */
  subjects?: Subject[];
  /** v0.6 — review path: the proposal this receipt executed. */
  proposalId?: string;
  /** v0.6 — review path: the owner's HAP-approval signature (or its sha256)
   * for the executed proposal. */
  approvalSignature?: string;
  /** Ed25519 over the JCS-canonical payload (this field excluded), base64url. */
  signature: string;
}

/**
 * Verify a receipt's AS signature: strip `signature`, JCS-canonicalize the
 * rest, Ed25519-verify against the AS public key (hex). This is holder-side
 * verification — it needs the COMPLETE receipt; a redacted public view cannot
 * be re-verified this way (protocol.md → "Receipt Verification").
 *
 * Content is checked separately: where `contentHash` is present, recompute it
 * from the held artifact via the content-binding module and compare.
 *
 * @throws Error prefixed `INVALID_SIGNATURE:` when verification fails.
 */
export async function verifyReceiptSignature(receipt: ReceiptPayload, publicKeyHex: string): Promise<void> {
  const { signature, ...unsigned } = receipt;
  if (!signature) {
    throw new Error('INVALID_SIGNATURE: receipt carries no signature');
  }
  const bytes = new TextEncoder().encode(canonicalize(unsigned));
  const base64 = signature.replace(/-/g, '+').replace(/_/g, '/');
  const padding = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
  const sigBytes = new Uint8Array(Buffer.from(base64 + padding, 'base64'));
  const publicKeyBytes = new Uint8Array(Buffer.from(publicKeyHex, 'hex'));

  const ok = await ed.verifyAsync(sigBytes, bytes, publicKeyBytes).catch(() => false);
  if (!ok) {
    throw new Error('INVALID_SIGNATURE: receipt signature verification failed');
  }
}

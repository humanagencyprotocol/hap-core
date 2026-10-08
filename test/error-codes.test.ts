/**
 * Every refusal carries its protocol code as a field, not only in the text.
 *
 * The gateway branches on `err.code` (work-plan V6: no matching on error
 * text). Two faults found in review of the v0.7 port: the base64url decoder
 * named every failure MALFORMED_MANDATE — even inside a ticket or an owner
 * signature — and in owner-signature.ts the decode ran outside the verify
 * call's `.catch`, so a malformed owner or approval signature escaped with no
 * code at all.
 */

import { describe, it, expect } from 'vitest';
import { decodeMandateBlob } from '../src/mandate';
import { verifyApproval } from '../src/owner-signature';
import { checkDiscloseSubset } from '../src/profile';
import { encodeDidKey } from '../src/did-key';
import type { ApprovalObject } from '../src/owner-signature';

async function codeOf(fn: () => unknown): Promise<string | undefined> {
  try {
    await fn();
  } catch (err) {
    return (err as { code?: string }).code;
  }
  return 'did not throw';
}

const someDid = encodeDidKey(new Uint8Array(32).fill(7));

describe('refusal codes are fields', () => {
  it('a non-base64url mandate blob is MALFORMED_MANDATE, as a field', async () => {
    expect(await codeOf(() => decodeMandateBlob('not+base64url='))).toBe('MALFORMED_MANDATE');
  });

  it('a standard-base64 approval signature is APPROVAL_SIGNATURE_INVALID, not a mandate error', async () => {
    const approval = { mandate_id: 'm', version: '0.7' } as unknown as ApprovalObject;
    expect(await codeOf(() => verifyApproval(approval, 'abc+/=', someDid))).toBe('APPROVAL_SIGNATURE_INVALID');
  });

  it('a widened disclose_fields is MALFORMED_MANDATE, as a field', async () => {
    expect(await codeOf(() => checkDiscloseSubset(['recipient'], []))).toBe('MALFORMED_MANDATE');
  });
});

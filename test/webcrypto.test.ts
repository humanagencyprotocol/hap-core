/**
 * Without WebCrypto (`globalThis.crypto.subtle` missing), a GENUINE signature is never reported as
 * forged: every verifier throws CryptoUnavailableError (code CRYPTO_UNAVAILABLE), and verifies
 * again once WebCrypto is back.
 */
import { describe, it, expect, afterEach } from 'vitest';
import * as ed from '@noble/ed25519';
import {
  encodeDidKey, signMandate, encodeMandateBlob, decodeMandateBlob, verifyMandate, verifyMandateSignature,
  buildMandateProjection, signMandateProjection, verifyOwnerSignature, signApproval, verifyApproval,
  CryptoUnavailableError, type MandatePayload, type ApprovalObject,
} from '../src/index';

const real = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!;
const hideSubtle = () => Object.defineProperty(globalThis, 'crypto', { value: { getRandomValues: (a: Uint8Array) => a }, configurable: true, writable: true });
afterEach(() => { Object.defineProperty(globalThis, 'crypto', real); });

async function world() {
  const as = new Uint8Array(32).fill(7);
  const owner = new Uint8Array(32).fill(11);
  const asDid = encodeDidKey(await ed.getPublicKeyAsync(as));
  const ownerDid = encodeDidKey(await ed.getPublicKeyAsync(owner));
  const H = (c: string) => `sha256:${c.repeat(64)}`;
  const entry = { did: ownerDid, nonce: 'bm9uY2Utbm9uY2Utbm9uY2U', binding: 'raw', signing_surface: 'gateway' } as const;
  const base = {
    mandate_id: 'mnd_webcrypto_1', version: '0.8', profile_id: 'p@0.1', profile_hash: H('0'), bounds_hash: H('1'), scope_hash: H('2'),
    execution_context_hash: H('3'), gate_content_hashes: {}, issuer: asDid, mandate_owners: [{ did: ownerDid }], commitment_mode: 'review',
    issued_at: 1_800_000_000, expires_at: 1_800_003_600,
  } as unknown as MandatePayload;
  const sig = await signMandateProjection(buildMandateProjection(base, entry), owner);
  const signedEntry = { ...entry, alg: 'EdDSA', signature: sig, signed_at: 1_800_000_000 };
  const payload = { ...base, mandate_owners: [signedEntry] } as unknown as MandatePayload;
  const blob = encodeMandateBlob(await signMandate(payload, as));
  const approval = { typ: 'HAP-approval', version: '0.8', approver_did: ownerDid } as unknown as ApprovalObject;
  const approvalSig = await signApproval(approval, owner);
  return { blob, asDid, ownerDid, signedEntry, approval, approvalSig };
}

describe('without WebCrypto', () => {
  it('a genuine mandate is "cannot check", never INVALID_SIGNATURE', async () => {
    const w = await world();
    hideSubtle();
    const e = await verifyMandate(w.blob, { trustedIssuers: [w.asDid], now: 1_800_000_010 }).catch((x) => x);
    expect(e).toBeInstanceOf(CryptoUnavailableError);
    expect(e.code).toBe('CRYPTO_UNAVAILABLE');
    await expect(verifyMandateSignature(decodeMandateBlob(w.blob))).rejects.toBeInstanceOf(CryptoUnavailableError);
  });
  it('a genuine owner signature and approval are "cannot check" too', async () => {
    const w = await world();
    const m = decodeMandateBlob(w.blob);
    hideSubtle();
    await expect(verifyOwnerSignature(m, w.signedEntry as never)).rejects.toBeInstanceOf(CryptoUnavailableError);
    await expect(verifyApproval(w.approval, w.approvalSig, w.ownerDid)).rejects.toBeInstanceOf(CryptoUnavailableError);
  });
  it('with WebCrypto back, the same objects verify', async () => {
    const w = await world();
    await expect(verifyMandate(w.blob, { trustedIssuers: [w.asDid], now: 1_800_000_010 })).resolves.toBeTruthy();
    await expect(verifyOwnerSignature(decodeMandateBlob(w.blob), w.signedEntry as never)).resolves.toBeUndefined();
    await expect(verifyApproval(w.approval, w.approvalSig, w.ownerDid)).resolves.toBeUndefined();
  });
});

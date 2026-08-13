/**
 * Receipt verification — the holder-side check this library never had:
 * strip signature → JCS → Ed25519. Key-order independence matters (a receipt
 * that traveled through JSON round-trips must still verify), and a redacted
 * receipt must FAIL, because that is the documented public-view limitation.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as ed from '@noble/ed25519';
import { canonicalize } from '../src/canonicalize';
import { verifyReceiptSignature, type ReceiptPayload } from '../src/receipt';

let pubHex: string;
let receipt: ReceiptPayload;

beforeAll(async () => {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  pubHex = Buffer.from(pub).toString('hex');

  const unsigned = {
    id: 'r-1',
    groupId: null,
    userId: 'alice',
    boundsHash: 'sha256:' + 'a'.repeat(64),
    profileId: 'charge@0.4',
    action: 'create_payment_link',
    actionType: 'charge',
    executionContext: { amount: 48, currency: 'EUR' },
    cumulativeState: { daily: { amount: 391, count: 12 } },
    timestamp: 1_767_139_300,
    contentHash: 'sha256:' + 'b'.repeat(64),
    contentBinding: { version: '2', kind: 'jcs', fields: ['to', 'subject', 'body'] },
    proposalId: 'prop-1',
  };
  const sig = await ed.signAsync(new TextEncoder().encode(canonicalize(unsigned)), priv);
  receipt = {
    ...(unsigned as Omit<ReceiptPayload, 'signature'>),
    signature: Buffer.from(sig).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  };
});

describe('verifyReceiptSignature', () => {
  it('verifies a complete signed receipt', async () => {
    await expect(verifyReceiptSignature(receipt, pubHex)).resolves.toBeUndefined();
  });

  it('is key-order independent (JCS): different insertion order still verifies', async () => {
    const reordered = Object.fromEntries(Object.entries(receipt).reverse()) as unknown as ReceiptPayload;
    expect(Object.keys(reordered)).not.toEqual(Object.keys(receipt)); // genuinely reordered
    await expect(verifyReceiptSignature(reordered, pubHex)).resolves.toBeUndefined();
  });

  it('TAMPER: changing the amount breaks it', async () => {
    const t = { ...receipt, executionContext: { ...receipt.executionContext, amount: 4800 } };
    await expect(verifyReceiptSignature(t, pubHex)).rejects.toThrow(/INVALID_SIGNATURE/);
  });

  it('REDACTION: a receipt with signed fields removed fails — the public-view limitation, demonstrated', async () => {
    const { userId: _u, cumulativeState: _c, ...redacted } = receipt;
    await expect(verifyReceiptSignature(redacted as ReceiptPayload, pubHex)).rejects.toThrow(/INVALID_SIGNATURE/);
  });

  it('rejects a receipt with no signature at all', async () => {
    const { signature: _s, ...bare } = receipt;
    await expect(verifyReceiptSignature({ ...bare, signature: '' } as ReceiptPayload, pubHex)).rejects.toThrow(/INVALID_SIGNATURE/);
  });
});

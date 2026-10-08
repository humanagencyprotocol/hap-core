/**
 * Ticket verification — the holder-side check this library never had:
 * strip signature → JCS → Ed25519, with the verification key resolved from
 * the ticket's own `issuer` (protocol.md → *Ticket Verification* step 1).
 * Key-order independence matters (a ticket that traveled through JSON
 * round-trips must still verify), and a redacted ticket must FAIL, because
 * that is the documented public-view limitation.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as ed from '@noble/ed25519';
import { canonicalize } from '../src/canonicalize';
import { encodeDidKey } from '../src/did-key';
import { signTicket, verifyTicketSignature, publicTicketView, type TicketPayload } from '../src/ticket';

let issuerDid: string;
let privateKey: Uint8Array;
let ticket: TicketPayload;

beforeAll(async () => {
  privateKey = ed.utils.randomPrivateKey();
  issuerDid = encodeDidKey(await ed.getPublicKeyAsync(privateKey));

  const unsigned: Omit<TicketPayload, 'signature'> = {
    id: 't-1',
    mandateId: 'mandate-1',
    groupId: null,
    userId: 'alice',
    boundsHash: 'sha256:' + 'a'.repeat(64),
    profileId: 'charge@0.7',
    action: 'create_payment_link',
    actionType: 'charge',
    executionContext: { amount: 48, currency: 'EUR' },
    cumulativeState: { daily: { amount: 391, count: 12 } },
    limits: { profile: 'charge@0.7', amount_max: 100, amount_daily_max: 500 },
    version: '0.7',
    issuer: issuerDid,
    timestamp: 1_767_139_300,
    contentHash: 'sha256:' + 'b'.repeat(64),
    contentBinding: { version: '2', kind: 'jcs', fields: ['to', 'subject', 'body'] },
    proposalId: 'prop-1',
  };
  ticket = await signTicket(unsigned, privateKey);
});

describe('signTicket / verifyTicketSignature', () => {
  it('verifies a complete signed ticket, resolving the key from issuer', async () => {
    await expect(verifyTicketSignature(ticket)).resolves.toBeUndefined();
  });

  it('is key-order independent (JCS): different insertion order still verifies', async () => {
    const reordered = Object.fromEntries(Object.entries(ticket).reverse()) as unknown as TicketPayload;
    expect(Object.keys(reordered)).not.toEqual(Object.keys(ticket)); // genuinely reordered
    await expect(verifyTicketSignature(reordered)).resolves.toBeUndefined();
  });

  it('TAMPER: changing the amount breaks it', async () => {
    const t = { ...ticket, executionContext: { ...ticket.executionContext, amount: 4800 } };
    await expect(verifyTicketSignature(t)).rejects.toThrow(/INVALID_SIGNATURE/);
  });

  it('REDACTION: a ticket with signed fields removed fails — the public-view limitation, demonstrated', async () => {
    const { userId: _u, cumulativeState: _c, ...redacted } = ticket;
    await expect(verifyTicketSignature(redacted as TicketPayload)).rejects.toThrow(/INVALID_SIGNATURE/);
  });

  it('rejects a ticket with no signature at all', async () => {
    const { signature: _s, ...bare } = ticket;
    await expect(verifyTicketSignature({ ...bare, signature: '' } as TicketPayload)).rejects.toThrow(/INVALID_SIGNATURE/);
  });

  it('rejects a trusted-issuer allowlist that does not include this issuer', async () => {
    await expect(verifyTicketSignature(ticket, { trustedIssuers: ['did:key:z6MkSomeoneElse'] })).rejects.toThrow(/INVALID_SIGNATURE/);
  });

  it('accepts when the trusted-issuer allowlist includes this issuer', async () => {
    await expect(verifyTicketSignature(ticket, { trustedIssuers: [issuerDid] })).resolves.toBeUndefined();
  });

  it('groupId: null is signed as null, not omitted', () => {
    const { signature: _s, ...unsigned } = ticket;
    expect(canonicalize(unsigned)).toContain('"groupId":null');
  });
});

describe('publicTicketView', () => {
  it('discloses nothing by default — executionContext stripped entirely', () => {
    const view = publicTicketView(ticket);
    expect(view.executionContext).toEqual({});
    expect('userId' in view).toBe(false);
    expect('cumulativeState' in view).toBe(false);
    expect('limits' in view).toBe(false);
  });

  it('discloses exactly the governing fields named, nothing else', () => {
    const view = publicTicketView(ticket, ['currency']);
    expect(view.executionContext).toEqual({ currency: 'EUR' });
  });

  it('is not independently re-verifiable — it is missing signed fields', async () => {
    const view = publicTicketView(ticket, ['currency']);
    await expect(verifyTicketSignature(view as TicketPayload)).rejects.toThrow();
  });
});

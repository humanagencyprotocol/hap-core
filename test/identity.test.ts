/**
 * Identity Assurance (HAP v0.6) — conformance.
 *
 * Pins the level/method/trust-root invariants and the footer wording, so the
 * gateway footer and the AS verify page stay byte-identical to the spec.
 */
import { describe, it, expect } from 'vitest';
import { validateSubject, deriveIdentityLine } from '../src/identity';
import type { Subject } from '../src/types';

const selfDeclared: Subject = {
  did: 'did:key:alice', assurance: 'low', method: 'self_declared', trust_root: 'self',
};
const asVouched: Subject = {
  did: 'did:key:alice', assurance: 'high', method: 'as_vouched', trust_root: 'as',
  verifier: 'did:web:suveren.ai', disclose: { name: 'Andreas Schadauer' }, verified_at: 1,
};
const eudi: Subject = {
  did: 'did:key:alice', assurance: 'high', method: 'eudi', trust_root: 'external',
  verifier: 'eudi:de', disclose: { name: 'Andreas Schadauer' }, owner_signature: 'sig', verified_at: 1,
};

describe('validateSubject', () => {
  it('accepts a valid self_declared / as_vouched / eudi subject', () => {
    expect(validateSubject(selfDeclared).valid).toBe(true);
    expect(validateSubject(asVouched).valid).toBe(true);
    expect(validateSubject(eudi).valid).toBe(true);
  });

  it('rejects a name disclosed at low assurance', () => {
    const bad = { ...selfDeclared, disclose: { name: 'Andreas' } } as Subject;
    expect(validateSubject(bad).valid).toBe(false);
  });

  it('rejects as_vouched without a verifier', () => {
    const bad = { ...asVouched, verifier: undefined } as Subject;
    const r = validateSubject(bad);
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toContain('verifier');
  });

  it('rejects as_vouched with the wrong trust_root', () => {
    expect(validateSubject({ ...asVouched, trust_root: 'self' } as Subject).valid).toBe(false);
  });

  it('rejects eudi without an owner_signature', () => {
    const r = validateSubject({ ...eudi, owner_signature: null } as Subject);
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toContain('owner_signature');
  });

  it('rejects high assurance with a low-only method', () => {
    expect(validateSubject({ ...selfDeclared, assurance: 'high' } as Subject).valid).toBe(false);
  });
});

describe('deriveIdentityLine — footer wording (name only at high)', () => {
  const op = { operatorName: 'Suveren' };

  it('low / self-declared shows NO name', () => {
    expect(deriveIdentityLine(selfDeclared, op)).toBe('Sent by an AI agent via Suveren');
  });

  it('absent subject shows no name', () => {
    expect(deriveIdentityLine(undefined, op)).toBe('Sent by an AI agent via Suveren');
  });

  it('high / as_vouched shows "«name»\'s AI agent, verified by «operator»" (v1.1)', () => {
    expect(deriveIdentityLine(asVouched, op)).toBe(
      "Sent by Andreas Schadauer's AI agent, verified by Suveren",
    );
  });

  it('renders the actual operator, not a hardcoded brand', () => {
    expect(deriveIdentityLine(asVouched, { operatorName: 'Acme' })).toBe(
      "Sent by Andreas Schadauer's AI agent, verified by Acme",
    );
  });

  it('high / eudi shows "identity verified (EUDI)" without naming the operator', () => {
    expect(deriveIdentityLine(eudi, op)).toBe(
      "Sent by Andreas Schadauer's AI agent, identity verified (EUDI)",
    );
  });

  it('uses ASCII punctuation only (no em-dash) so encoding stays intact', () => {
    expect(deriveIdentityLine(asVouched, op)).not.toContain('—');
    expect(deriveIdentityLine(eudi, op)).not.toContain('—');
  });

  it('high but disclosure off (no name) falls back to no name', () => {
    const noName = { ...asVouched, disclose: undefined } as Subject;
    expect(deriveIdentityLine(noName, op)).toBe('Sent by an AI agent via Suveren');
  });
});

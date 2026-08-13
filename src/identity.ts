/**
 * Identity Assurance (HAP v0.6) — validation + footer derivation for the signed
 * {@link Subject} overlay. See review.md → "Identity Assurance".
 *
 * Two pure helpers, the single source of truth for both the gateway footer and
 * the AS verify page:
 *  - {@link validateSubject} — enforces the level/method/trust-root invariants.
 *  - {@link deriveIdentityLine} — the human-readable footer line for a subject.
 */

import type { OwnerMandate, Subject } from './types';

export interface SubjectValidation {
  valid: boolean;
  errors: string[];
}

/**
 * Enforce the Identity-Assurance invariants on a single subject:
 *  - `self_declared` ⇒ `low` / `self`, no disclosed name.
 *  - `as_vouched`    ⇒ `high` / `as`,  `verifier` required.
 *  - `eudi`          ⇒ `high` / `external`, `verifier` required — and, when the
 *    carrying attestation's `owner_mandates` are supplied, a corresponding
 *    entry with `binding:"eudi"` for this subject's DID.
 *  - `disclose.name` only at `assurance:"high"`.
 *
 * v0.6: `Subject.owner_signature` is deprecated and IGNORED here — it signed
 * the identity claim, not the mandate (see the field's deprecation note). The
 * signature-bearing object is the attestation's `owner_mandates` entry, which
 * is payload-level context this per-subject check cannot see on its own; pass
 * `opts.ownerMandates` to enforce the eudi ⇒ mandate-entry rule, omit it to
 * validate subject shape alone (pre-0.6 callers keep their behaviour minus
 * the retired owner_signature requirement).
 */
export function validateSubject(
  subject: Subject,
  opts?: { ownerMandates?: OwnerMandate[] },
): SubjectValidation {
  const errors: string[] = [];
  const { did, assurance, method, trust_root, verifier, disclose } = subject;

  if (!did) errors.push('subject.did is required');

  if (assurance === 'low') {
    if (method !== 'self_declared') errors.push(`low assurance requires method "self_declared", got "${method}"`);
    if (trust_root !== 'self') errors.push(`low assurance requires trust_root "self", got "${trust_root}"`);
    if (disclose) errors.push('low assurance MUST NOT disclose a name');
  } else if (assurance === 'high') {
    if (method === 'as_vouched') {
      if (trust_root !== 'as') errors.push('as_vouched requires trust_root "as"');
      if (!verifier) errors.push('as_vouched requires a verifier');
    } else if (method === 'eudi') {
      if (trust_root !== 'external') errors.push('eudi requires trust_root "external"');
      if (!verifier) errors.push('eudi requires a verifier');
      if (opts?.ownerMandates !== undefined) {
        const entry = opts.ownerMandates.find(m => m.did === did && m.binding === 'eudi');
        if (!entry) errors.push('eudi requires an owner_mandates entry with binding "eudi" for this DID');
      }
    } else {
      errors.push(`high assurance requires method "as_vouched" or "eudi", got "${method}"`);
    }
    if (disclose && typeof disclose.name !== 'string') errors.push('disclose.name must be a string');
  } else {
    errors.push(`assurance must be "low" or "high", got "${assurance as string}"`);
  }

  return { valid: errors.length === 0, errors };
}

/**
 * The footer line for a subject — the ONE place this wording lives.
 * The name appears only at `high` with a disclosed name; otherwise no name.
 *
 *  - low / no disclosure → "Sent by an AI agent via «operator»"
 *  - high / as_vouched   → "Sent by «name»'s AI agent, verified by «operator»"
 *  - high / eudi         → "Sent by «name»'s AI agent, identity verified (EUDI)"
 *
 * Footer wording v1.1 (July 2026): the named forms read "«name»'s AI agent"
 * (more natural than the v1 "an AI agent of «name»"). The v1 wording is frozen
 * for already-sent content; verifiers strip BOTH forms (see the gateway's
 * FOOTER_RE and the AS ContentVerifier).
 *
 * Punctuation is ASCII (comma, not em-dash) so the line survives header and
 * plain-text encoding intact across email, calendar, and publishing channels.
 * The leading verb ("Sent") is the default; presentation layers may swap it
 * (e.g. the gateway uses "Published" for the publish profile).
 *
 * `operatorName` is the rendered AS operator (e.g. "Suveren") — never hardcode it
 * upstream; a different operator self-vouches under its own name.
 */
export function deriveIdentityLine(
  subject: Subject | undefined | null,
  { operatorName }: { operatorName: string },
): string {
  const name = subject?.assurance === 'high' ? subject.disclose?.name : undefined;
  if (!name) {
    return `Sent by an AI agent via ${operatorName}`;
  }
  if (subject!.method === 'eudi') {
    return `Sent by ${name}'s AI agent, identity verified (EUDI)`;
  }
  return `Sent by ${name}'s AI agent, verified by ${operatorName}`;
}

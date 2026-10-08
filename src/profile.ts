/**
 * Profile hashing and authoring-time validation (new in v0.7).
 *
 * `computeProfileHash` is the AS-side and Gatekeeper-side half of
 * `profile_hash` (protocol.md → *Profile hash*): "sha256 of the RFC 8785
 * (JCS) serialization of the profile JSON" — over the PARSED document, never
 * file bytes, so two parties who provisioned the same profile through
 * different channels (a git checkout, an npm tarball, a copy with a
 * trailing newline) always agree.
 *
 * `validateProfile` folds together the authoring-time checks that used to
 * live in three places (`frame.ts`'s `validateBoundsRequiredFor`,
 * `commitment-modes.ts`'s `validateCommitmentModes`, and nothing at all for
 * the v0.7 structural rules) into one function returning the canonical
 * `PROFILE_INVALID` shape an AS can emit directly. Like its predecessors,
 * it is NOT wired into `registerProfile` — nothing in hap-core validates
 * profile JSON at load time; call it explicitly from an authoring tool, a
 * hap-profiles CI check, or a test.
 */
import { createHash } from 'crypto';
import { canonicalize } from './canonicalize';
import { allowedCommitmentModes, SIGNABLE_COMMITMENT_MODES } from './commitment-modes';
import type { AgentProfile, BoundType } from './types';
import { HapError, type HapErrorCode } from './errors';

/** One authoring-time finding. `code` is always a canonical v0.7 code — in
 * practice always `PROFILE_INVALID`, since that is the only mandate-request
 * refusal the protocol attributes to "the profile fails validation"
 * (protocol.md → Error Codes). */
export interface ProfileValidationError {
  code: HapErrorCode;
  field?: string;
  message: string;
}

/**
 * `profile_hash` — `"sha256:" + sha256(JCS(parsed))`, over the PARSED
 * profile document. Formatting, key order, and a trailing newline on disk
 * never change it (protocol.md → *Profile hash*; conformance vector set
 * `profile-hash.json`).
 */
export function computeProfileHash(parsed: unknown): string {
  const hash = createHash('sha256').update(canonicalize(parsed), 'utf8').digest('hex');
  return `sha256:${hash}`;
}

/** Keys retired by earlier versions. A profile authored against an old
 * vocabulary fails loudly here instead of silently losing the field's
 * effect (protocol.md → *Migration from v0.6*, "Signed-payload, profile, and
 * wire renames"). */
const RETIRED_PROFILE_KEYS: Record<string, string> = {
  contextSchema: 'scopeSchema',
  ownerMandate: 'ownerSignature',
  receipt_lookup: 'ticket_lookup',
  frameSchema: '(removed — v0.3 execution frames are retired)',
};

/**
 * Authoring-time structural validation (protocol.md → *Bounds Schema*,
 * *Owner Signatures* → "Where the requirement lives", *Migration from
 * v0.6*). Returns `[]` for a clean profile; never throws.
 */
export function validateProfile(profile: AgentProfile): ProfileValidationError[] {
  const errors: ProfileValidationError[] = [];
  const p = profile as AgentProfile & Record<string, unknown>;

  // ── Retired keys (v0.7 rename table) ────────────────────────────────────
  for (const [retired, current] of Object.entries(RETIRED_PROFILE_KEYS)) {
    if (retired in p) {
      errors.push({
        code: 'PROFILE_INVALID',
        field: retired,
        message: `"${retired}" is retired in v0.7 — use "${current}" instead.`,
      });
    }
  }
  if (Array.isArray(p.requiredGates) && (p.requiredGates as unknown[]).includes('decision_owner')) {
    errors.push({
      code: 'PROFILE_INVALID',
      field: 'requiredGates',
      message: '"decision_owner" is retired in v0.7 — the required gate is "mandate_owner".',
    });
  }

  // ── Bounds schema ────────────────────────────────────────────────────────
  const boundsSchema = profile.boundsSchema;
  if (boundsSchema) {
    const actionTypes = boundsSchema.actionTypes ? [...boundsSchema.actionTypes] : undefined;

    for (const [fieldName, fieldDef] of Object.entries(boundsSchema.fields)) {
      if (fieldName === 'profile') continue;

      // Bounds Schema rule 6: no action-routing arrays. v0.4 retired execution
      // paths; routing is the job of actionType + the tool-gating manifest.
      const routing = ['path', 'paths'].filter((k) => k in (fieldDef as object));
      if (routing.length > 0) {
        errors.push({
          code: 'PROFILE_INVALID',
          field: fieldName,
          message: `Bounds field "${fieldName}" declares ${routing.map((k) => `"${k}"`).join(' and ')} — action-routing arrays are forbidden (Bounds Schema rule 6); use actionType and appliesTo.`,
        });
      }

      if (!fieldDef.boundType) {
        errors.push({
          code: 'PROFILE_INVALID',
          field: fieldName,
          message: `Bounds field "${fieldName}" has no boundType — enforcement semantics undefined (Bounds Schema rule 2).`,
        });
        continue;
      }
      const bt = fieldDef.boundType as BoundType & { requiredFor?: unknown };

      // appliesTo on a per_transaction or enum bound (new in v0.7).
      if (fieldDef.appliesTo && (bt.kind === 'per_transaction' || bt.kind === 'enum')) {
        errors.push({
          code: 'PROFILE_INVALID',
          field: fieldName,
          message: `Bounds field "${fieldName}": appliesTo MUST NOT be declared on a ${bt.kind} bound (Bounds Schema rule 7).`,
        });
      }

      // cumulative_count on a v0.7+ profile MUST declare appliesTo.
      if (bt.kind === 'cumulative_count' && !fieldDef.appliesTo?.length) {
        errors.push({
          code: 'PROFILE_INVALID',
          field: fieldName,
          message: `Bounds field "${fieldName}": a cumulative_count bound on a v0.7+ profile MUST declare appliesTo (Bounds Schema rule 7) — absence would silently throttle every action type.`,
        });
      }

      // appliesTo members MUST be drawn from the actionTypes registry.
      if (fieldDef.appliesTo && actionTypes) {
        for (const at of fieldDef.appliesTo) {
          if (!actionTypes.includes(at)) {
            errors.push({
              code: 'PROFILE_INVALID',
              field: fieldName,
              message: `Bounds field "${fieldName}": appliesTo names "${at}", which is not in boundsSchema.actionTypes [${actionTypes.join(', ')}].`,
            });
          }
        }
      }

      // requiredFor is only meaningful on a per_transaction bound — every
      // enforcement point ignores it on any other kind.
      if (bt.kind !== 'per_transaction' && (bt as { requiredFor?: unknown }).requiredFor !== undefined) {
        errors.push({
          code: 'PROFILE_INVALID',
          field: fieldName,
          message: `Bounds field "${fieldName}": requiredFor is only meaningful on a per_transaction bound (found on kind "${bt.kind}") — every enforcement point ignores it there. Remove it.`,
        });
      }

      // per_transaction.requiredFor members MUST also be registered.
      if (bt.kind === 'per_transaction' && Array.isArray(bt.requiredFor) && actionTypes) {
        for (const at of bt.requiredFor as string[]) {
          if (!actionTypes.includes(at)) {
            errors.push({
              code: 'PROFILE_INVALID',
              field: fieldName,
              message: `Bounds field "${fieldName}": requiredFor names "${at}", which is not in boundsSchema.actionTypes [${actionTypes.join(', ')}].`,
            });
          }
        }
      }
    }
  }

  // ── Commitment modes ─────────────────────────────────────────────────────
  const declaredModes = (p as { commitment_modes?: unknown }).commitment_modes;
  if (declaredModes !== undefined) {
    if (!Array.isArray(declaredModes)) {
      errors.push({ code: 'PROFILE_INVALID', field: 'commitment_modes', message: 'commitment_modes must be a list of modes.' });
    } else {
      if (declaredModes.length === 0) {
        errors.push({
          code: 'PROFILE_INVALID',
          field: 'commitment_modes',
          message: 'commitment_modes is empty — no mandate could ever be signed under this profile.',
        });
      }
      const seen = new Set<unknown>();
      for (const m of declaredModes) {
        if (!(SIGNABLE_COMMITMENT_MODES as readonly string[]).includes(m as string)) {
          errors.push({
            code: 'PROFILE_INVALID',
            field: 'commitment_modes',
            message: `commitment_modes: "${String(m)}" is not a mode a signer can choose (${SIGNABLE_COMMITMENT_MODES.join(', ')}).`,
          });
        }
        if (seen.has(m)) {
          errors.push({ code: 'PROFILE_INVALID', field: 'commitment_modes', message: `commitment_modes: "${String(m)}" appears twice.` });
        }
        seen.add(m);
      }
    }
  }
  // allowedCommitmentModes is the fail-closed reader; an always-empty result
  // for a profile that DID declare modes means the declaration is unusable.
  if (Array.isArray(declaredModes) && declaredModes.length > 0 && allowedCommitmentModes(profile).length === 0) {
    errors.push({
      code: 'PROFILE_INVALID',
      field: 'commitment_modes',
      message: 'commitment_modes declares no mode this profile can actually use.',
    });
  }

  return errors;
}

/**
 * A mandate's `disclose_fields` MUST be a subset of the profile's own list
 * (protocol.md → *Mandate Payload*, conditional field `disclose_fields`: "a
 * subset of the profile's `disclose_fields` list"). A mandate may narrow
 * disclosure, never widen it.
 *
 * @throws Error prefixed `MALFORMED_MANDATE:` when it is not a subset.
 */
export function checkDiscloseSubset(
  mandateDiscloseFields: readonly string[] | undefined,
  profileDiscloseFields: readonly string[] | undefined,
): void {
  if (!mandateDiscloseFields || mandateDiscloseFields.length === 0) return;
  const allowed = new Set(profileDiscloseFields ?? []);
  const widened = mandateDiscloseFields.filter((f) => !allowed.has(f));
  if (widened.length > 0) {
    throw new HapError(
      'MALFORMED_MANDATE',
      `disclose_fields [${widened.join(', ')}] is not a subset of the profile's ` +
        `disclose_fields [${[...allowed].join(', ')}] — a mandate may narrow disclosure, never widen it.`,
    );
  }
}

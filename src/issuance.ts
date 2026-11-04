/**
 * Pure checks both enforcement points apply around issuance and execution
 * (v0.8). An Authority Server composes them into its stage order
 * (protocol.md → *Mandate Issuance & Validation*, *Ticket Issuance*); a
 * Gatekeeper applies the execution-side ones locally (*Validation Steps*).
 * They live here so the two cannot disagree about what a value means.
 */

import { createHash } from 'crypto';
import { canonicalize } from './canonicalize';
import { HapError } from './errors';
import { isKeyBearingDid } from './did-key';
import type { AgentProfile, AgentBoundsParams, MandatePayload, ProfileBoundsField } from './types';

/**
 * `execution_context_hash` — sha256 over the JCS of the profile's
 * `executionContextSchema`, or of `{}` when the profile has none (protocol.md
 * → *Execution Context Schema*, stated in v0.8).
 */
export function computeExecutionContextHash(profile: Pick<AgentProfile, 'executionContextSchema'>): string {
  const schema = profile.executionContextSchema ?? {};
  return `sha256:${createHash('sha256').update(canonicalize(schema), 'utf8').digest('hex')}`;
}

/** The execution-context fields some bound of the profile reads
 * (`boundType.of` of every `per_transaction` and `cumulative_sum` bound). */
export function boundReadFields(profile: AgentProfile): Set<string> {
  const fields = new Set<string>();
  for (const def of Object.values(profile.boundsSchema?.fields ?? {})) {
    const bt = def.boundType;
    if (bt && (bt.kind === 'per_transaction' || bt.kind === 'cumulative_sum')) fields.add(bt.of);
  }
  return fields;
}

/**
 * Build the wire execution context (*Validation Steps*, step 11; *Ticket
 * Request Schema*, rules 7–8): only what a bound reads travels. `action_type`
 * travels as the request's own `actionType`, scope values never travel,
 * `_`-prefixed keys are advisory metadata. A `null` value is no value.
 */
export function wireExecutionContext(
  execution: Record<string, unknown>,
  profile: AgentProfile,
): Record<string, unknown> {
  const allowed = boundReadFields(profile);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(execution)) {
    if (!allowed.has(k) || k.startsWith('_') || v === undefined || v === null) continue;
    out[k] = v;
  }
  return out;
}

/**
 * Every value present for a field some bound reads MUST be a finite,
 * non-negative number (*Ticket Issuance*, stage 7; *Validation Steps*, step
 * 8). `null` counts as absent. A `_`-prefixed key is refused.
 * @throws HapError `MALFORMED_TICKET_REQUEST`
 */
export function checkExecutionValues(execution: Record<string, unknown>, profile: AgentProfile): void {
  for (const k of Object.keys(execution)) {
    if (k.startsWith('_')) {
      throw new HapError('MALFORMED_TICKET_REQUEST', `executionContext key "${k}" is reserved and MUST NOT travel`);
    }
  }
  for (const field of boundReadFields(profile)) {
    const v = execution[field];
    if (v === undefined || v === null) continue;
    if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) {
      throw new HapError(
        'MALFORMED_TICKET_REQUEST',
        `executionContext.${field} MUST be a finite, non-negative number, got ${JSON.stringify(v)}`,
      );
    }
  }
}

/** Whether a cumulative bound governs this action type: its `appliesTo`
 * names it, or it has none (Bounds Schema rule 7). */
export function boundGoverns(def: ProfileBoundsField, actionType: string): boolean {
  return !def.appliesTo || def.appliesTo.includes(actionType);
}

/**
 * The `cumulative_sum` bounds that govern this action type and whose field is
 * absent from the execution context (*Ticket Issuance*, stage 7): each is a
 * `BOUND_EXCEEDED`, unless a committed above-cap approval covers the action.
 */
export function missingSumFields(
  execution: Record<string, unknown>,
  profile: AgentProfile,
  actionType: string,
): Array<{ bound: string; field: string }> {
  const missing: Array<{ bound: string; field: string }> = [];
  for (const [name, def] of Object.entries(profile.boundsSchema?.fields ?? {})) {
    const bt = def.boundType;
    if (!bt || bt.kind !== 'cumulative_sum' || !boundGoverns(def, actionType)) continue;
    const v = execution[bt.of];
    if (v === undefined || v === null) missing.push({ bound: name, field: bt.of });
  }
  return missing;
}

/**
 * Bounds values against the profile at issuance (*Mandate Issuance*, stage
 * 4): a number where the field is numeric (`"100"` is refused), no higher
 * than a declared `maximum`, and an `enum` value in its `values`.
 * @throws HapError `BOUNDS_INVALID_VALUE`
 */
export function checkBoundsValues(bounds: AgentBoundsParams, profile: AgentProfile): void {
  for (const [name, def] of Object.entries(profile.boundsSchema?.fields ?? {})) {
    if (name === 'profile') continue;
    const v = bounds[name];
    if (v === undefined || v === null) continue;
    if (def.type === 'number' || def.maximum !== undefined) {
      if (typeof v !== 'number' || !Number.isFinite(v)) {
        throw new HapError('BOUNDS_INVALID_VALUE', `bound "${name}" MUST be a number, got ${JSON.stringify(v)}`);
      }
      if (def.maximum !== undefined && v > def.maximum) {
        throw new HapError('BOUNDS_INVALID_VALUE', `bound "${name}" = ${v} exceeds the profile's maximum ${def.maximum}`);
      }
    }
    const bt = def.boundType;
    if (bt?.kind === 'enum' && !bt.values.includes(String(v))) {
      throw new HapError('BOUNDS_INVALID_VALUE', `bound "${name}" = ${JSON.stringify(v)} is not in [${bt.values.join(', ')}]`);
    }
  }
}

/** A group's caps for one profile, as the AS holds them. */
export interface GroupCaps {
  /** Caps a proposal may lift (`approval` kind) — numeric per_transaction fields only. */
  approval?: Record<string, number>;
  /** Hard caps: refused at signing, never routed. Numeric or enum values. */
  hard?: Record<string, number | string>;
}

/**
 * Whether a bound value exceeds a cap. For an `enum` bound the cap is one of
 * its values, and a value that comes EARLIER in the profile's `values` order
 * (more permissive) exceeds it (Bounds Schema rule 10; *Group ceilings*).
 */
export function exceedsCap(value: string | number, cap: string | number, def: ProfileBoundsField): boolean {
  const bt = def.boundType;
  if (bt?.kind === 'enum') {
    const order = bt.values;
    const vi = order.indexOf(String(value));
    const ci = order.indexOf(String(cap));
    if (vi < 0 || ci < 0) return true; // an unknown value or cap fails closed
    return vi < ci;
  }
  return typeof value !== 'number' || typeof cap !== 'number' || value > cap;
}

/**
 * Hard group ceilings at signing (*Group ceilings*; *Group roles*, rule 5):
 * a cap on a bound the Gatekeeper alone enforces (`enforcedBy: "gatekeeper"`)
 * or on an `enum` bound is always hard, as is every cap in `hard`; a bound
 * above one, or an optional bound omitted where a cap exists, is refused.
 * Caps in `approval` on a cumulative bound are hard too (Commitment Modes,
 * rule 7). An omitted REQUIRED bound is `MALFORMED_MANDATE`, checked
 * elsewhere.
 * @throws HapError `GROUP_CAP_EXCEEDED`
 */
export function checkGroupCeilings(bounds: AgentBoundsParams, profile: AgentProfile, caps: GroupCaps): void {
  const fields = profile.boundsSchema?.fields ?? {};
  const hard: Record<string, number | string> = { ...(caps.hard ?? {}) };
  for (const [name, cap] of Object.entries(caps.approval ?? {})) {
    const def = fields[name];
    const bt = def?.boundType;
    if (!def || !bt) continue;
    if (bt.kind !== 'per_transaction' || def.enforcedBy === 'gatekeeper') hard[name] = cap;
  }
  for (const [name, def] of Object.entries(fields)) {
    if (name === 'profile') continue;
    const cap = hard[name];
    if (cap === undefined) continue;
    const v = bounds[name];
    if (v === undefined || v === null) {
      if (!def.required) {
        throw new HapError('GROUP_CAP_EXCEEDED', `bound "${name}" is omitted under a group ceiling of ${JSON.stringify(cap)} — an omitted bound is unlimited`);
      }
      continue;
    }
    if (exceedsCap(v, cap, def)) {
      throw new HapError('GROUP_CAP_EXCEEDED', `bound "${name}" = ${JSON.stringify(v)} exceeds the group's hard cap ${JSON.stringify(cap)}`);
    }
  }
}

/**
 * The above-cap configuration a mandate request or a group supplies
 * (*Commitment Modes*, rule 7; *Group roles*, rules 2 and 4; Mandate rule
 * 10): caps name numeric `per_transaction` bounds of the profile and never
 * `profile`; approvers are key-bearing DIDs; outside a group the count is an
 * integer ≥ 1 and no greater than the approvers other than the owner.
 * @throws HapError `ABOVE_CAP_CONFIG_INVALID`
 */
export function validateAboveCapConfig(
  config: { caps?: Record<string, number>; approvers?: readonly string[]; approvals?: number },
  profile: AgentProfile,
  opts: { ownerDid: string; inGroup: boolean },
): void {
  const fields = profile.boundsSchema?.fields ?? {};
  for (const name of Object.keys(config.caps ?? {})) {
    if (name === 'profile') throw new HapError('ABOVE_CAP_CONFIG_INVALID', 'above_cap_caps MUST NOT name profile');
    const def = fields[name];
    if (!def || def.boundType?.kind !== 'per_transaction' || def.type !== 'number') {
      throw new HapError('ABOVE_CAP_CONFIG_INVALID', `above_cap_caps names "${name}", which is not a numeric per_transaction bound of ${profile.id}`);
    }
  }
  for (const did of config.approvers ?? []) {
    if (!isKeyBearingDid(did)) {
      throw new HapError('ABOVE_CAP_CONFIG_INVALID', `above-cap approver ${did} is not a key-bearing DID`);
    }
  }
  if (config.approvers !== undefined && !opts.inGroup) {
    const others = config.approvers.filter((d) => d !== opts.ownerDid).length;
    const n = config.approvals;
    if (n === undefined || !Number.isInteger(n) || n < 1 || n > others) {
      throw new HapError(
        'ABOVE_CAP_CONFIG_INVALID',
        `above_cap_approvals MUST be an integer between 1 and the ${others} approver(s) other than the owner, got ${JSON.stringify(n)}`,
      );
    }
  }
}

/**
 * Whether a request exceeds an approval-kind cap of the mandate, or — v0.8 —
 * the field the cap reads is absent (an action of unknown amount is above
 * the cap). Returns the offending caps.
 */
export function capsExceeded(
  execution: Record<string, unknown>,
  mandate: Pick<MandatePayload, 'above_cap_caps'>,
  profile: AgentProfile,
): Array<{ bound: string; field: string; cap: number; value: unknown }> {
  const out: Array<{ bound: string; field: string; cap: number; value: unknown }> = [];
  for (const [name, cap] of Object.entries(mandate.above_cap_caps ?? {})) {
    const bt = profile.boundsSchema?.fields[name]?.boundType;
    if (!bt || bt.kind !== 'per_transaction') continue;
    const v = execution[bt.of];
    if (v === undefined || v === null || typeof v !== 'number' || v > cap) {
      out.push({ bound: name, field: bt.of, cap, value: v });
    }
  }
  return out;
}

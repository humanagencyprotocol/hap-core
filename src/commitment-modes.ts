/**
 * Which commitment modes a profile allows its mandates to be signed with
 * (`AgentProfile.commitment_modes`; protocol.md → *Commitment Modes*, rule
 * 8). One source for the Authority Server's refusal and the mandate screen's
 * choice, so the two cannot disagree.
 */
import type { AgentProfile, CommitmentMode, SignableCommitmentMode } from './types';

/** Every mode a signer can choose, in the order a mandate screen shows them. */
export const SIGNABLE_COMMITMENT_MODES: readonly SignableCommitmentMode[] = ['review', 'automatic'];

/** Every mode a signed mandate can carry. */
export const COMMITMENT_MODES: readonly CommitmentMode[] = ['automatic', 'review', 'review_above_cap'];

const isSignable = (v: unknown): v is SignableCommitmentMode =>
  typeof v === 'string' && (SIGNABLE_COMMITMENT_MODES as readonly string[]).includes(v);

/**
 * The signable modes a mandate under this profile may carry, in display
 * order. No declaration → all of them. A declaration is read fail-closed:
 * entries that are not a signable mode are dropped (`review_above_cap` is
 * ignored by rule 8 — it follows from `automatic`), so a malformed list can
 * only narrow — `[]`, `"review"` (not a list) or `["reveiw"]` allow nothing.
 */
export function allowedCommitmentModes(profile: AgentProfile): readonly SignableCommitmentMode[] {
  const declared = (profile as { commitment_modes?: unknown }).commitment_modes;
  if (declared === undefined) return SIGNABLE_COMMITMENT_MODES;
  if (!Array.isArray(declared)) return [];
  return SIGNABLE_COMMITMENT_MODES.filter((m) => declared.includes(m));
}

/**
 * Whether a mandate under this profile may be SIGNED with `mode` (rule 8):
 * `automatic` and `review` where listed; `review_above_cap` if and only if
 * `automatic` is admitted. The Authority Server refuses any other with
 * `COMMITMENT_MODE_NOT_ALLOWED`.
 */
export function isCommitmentModeAllowed(profile: AgentProfile, mode: string): boolean {
  const allowed = allowedCommitmentModes(profile);
  if (mode === 'review_above_cap') return allowed.includes('automatic');
  return isSignable(mode) && allowed.includes(mode);
}

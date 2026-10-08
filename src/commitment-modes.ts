/**
 * Which commitment modes a profile allows its mandates to be signed with
 * (`AgentProfile.commitment_modes`). One source for the Authority Server's
 * refusal and the mandate screen's choice, so the two cannot disagree.
 */
import type { AgentProfile, SignableCommitmentMode } from './types';

/** Every mode a signer can choose, in the order a mandate screen shows them. */
export const SIGNABLE_COMMITMENT_MODES: readonly SignableCommitmentMode[] = ['review', 'automatic'];

const isSignable = (v: unknown): v is SignableCommitmentMode =>
  typeof v === 'string' && (SIGNABLE_COMMITMENT_MODES as readonly string[]).includes(v);

/**
 * The modes a mandate under this profile may carry, in display order.
 * No declaration → all of them. A declaration is read fail-closed: entries
 * that are not a signable mode are dropped, so a malformed list can only
 * narrow — `[]`, `"review"` (not a list) or `["reveiw"]` allow nothing.
 */
export function allowedCommitmentModes(profile: AgentProfile): readonly SignableCommitmentMode[] {
  const declared = (profile as { commitment_modes?: unknown }).commitment_modes;
  if (declared === undefined) return SIGNABLE_COMMITMENT_MODES;
  if (!Array.isArray(declared)) return [];
  return SIGNABLE_COMMITMENT_MODES.filter((m) => declared.includes(m));
}

/** Whether a mandate under this profile may be signed with `mode`. */
export function isCommitmentModeAllowed(profile: AgentProfile, mode: string): boolean {
  return isSignable(mode) && allowedCommitmentModes(profile).includes(mode);
}

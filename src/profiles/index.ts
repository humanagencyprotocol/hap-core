/**
 * Profile Registry — dynamically populated from git-hosted profile sources.
 */

import type { AgentProfile } from '../types';

const PROFILES: Record<string, AgentProfile> = {};

export function registerProfile(profileId: string, profile: AgentProfile): void {
  PROFILES[profileId] = profile;
}

export function getProfile(profileId: string): AgentProfile | undefined {
  return PROFILES[profileId];
}

export function listProfiles(): string[] {
  return Object.keys(PROFILES);
}

export function getAllProfiles(): AgentProfile[] {
  return Object.values(PROFILES);
}

/**
 * HAP Core Types — Agent Demo
 *
 * Types for agent-oriented profiles with bounded execution.
 */

// ─── Attestation Types ───────────────────────────────────────────────────────

export interface AttestationHeader {
  typ: 'HAP-attestation';
  alg: 'EdDSA';
  kid?: string;
}

export interface ResolvedDomain {
  domain: string;
  did: string;
}

export interface AttestationPayload {
  attestation_id: string;
  version: '0.3';
  profile_id: string;
  frame_hash: string;
  execution_context_hash: string;
  resolved_domains: ResolvedDomain[];
  gate_content_hashes: Record<string, string>;
  issued_at: number;
  expires_at: number;
}

export interface Attestation {
  header: AttestationHeader;
  payload: AttestationPayload;
  signature: string;
}

// ─── Profile Types ───────────────────────────────────────────────────────────

/**
 * Field constraint type — what kind of bound a field supports.
 * - max: numeric upper bound (actual <= bound)
 * - enum: value must be in the allowed set
 */
export interface FieldConstraint {
  type: 'number' | 'string';
  enforceable: Array<'max' | 'enum'>;
}

/**
 * Frame field definition within a profile.
 */
export interface ProfileFrameField {
  type: 'string' | 'number';
  required: boolean;
  description?: string;
  constraint?: FieldConstraint;
}

/**
 * Execution context field definition — declared source (value comes from the agent's tool call).
 */
export interface DeclaredFieldDef {
  source: 'declared';
  description: string;
  required: boolean;
  constraint?: FieldConstraint;
}

/**
 * Cumulative window types for stateful limit tracking.
 */
export type CumulativeWindow = 'daily' | 'weekly' | 'monthly';

/**
 * Execution context field definition — cumulative source (resolved from execution log).
 *
 * The gatekeeper resolves these by querying the execution log:
 * - `cumulativeField`: which declared field to sum (use "_count" for plain counting)
 * - `window`: time window for aggregation (daily, weekly, monthly)
 *
 * The resolved value = running total within window + current call value.
 */
export interface CumulativeFieldDef {
  source: 'cumulative';
  cumulativeField: string;
  window: CumulativeWindow;
  description: string;
  required: boolean;
  constraint?: FieldConstraint;
}

/**
 * Execution context field definition — either declared or cumulative.
 */
export type ExecutionContextFieldDef = DeclaredFieldDef | CumulativeFieldDef;

/**
 * Gate question definition.
 */
export interface GateQuestion {
  question: string;
  required: boolean;
}

/**
 * Execution path definition within a profile.
 */
export interface ExecutionPath {
  description: string;
  requiredDomains: string[];
  ttl?: { default: number; max: number };
}

/**
 * Agent Profile — defines constraint types, execution paths, gate questions,
 * and the frame schema for bounded execution.
 */
export interface AgentProfile {
  id: string;
  version: string;
  description: string;

  frameSchema: {
    keyOrder: string[];
    fields: Record<string, ProfileFrameField>;
  };

  executionContextSchema: {
    fields: Record<string, ExecutionContextFieldDef>;
  };

  executionPaths: Record<string, ExecutionPath>;

  requiredGates: string[];

  gateQuestions: {
    problem: GateQuestion;
    objective: GateQuestion;
    tradeoffs: GateQuestion;
  };

  ttl: { default: number; max: number };
  retention_minimum: number;

  /** Tool gating configuration — how MCP tools map to execution context. */
  toolGating?: ProfileToolGating;
}

// ─── Tool Gating Types ───────────────────────────────────────────────────

/**
 * Execution mapping value — either a direct field name or a field with a divisor
 * for unit conversion (e.g., Stripe cents → EUR units).
 */
export type ExecutionMappingValue = string | { field: string; divisor: number };

/**
 * Tool gating entry — how a tool's calls map to execution context fields.
 */
export interface ProfileToolGatingEntry {
  executionMapping: Record<string, ExecutionMappingValue>;
  staticExecution?: Record<string, string | number>;
}

/**
 * Profile-level tool gating configuration.
 * - default: applied to all tools not listed in overrides
 * - overrides: per-tool configs keyed by original MCP tool name (null = exempt)
 */
export interface ProfileToolGating {
  default: ProfileToolGatingEntry;
  overrides?: Record<string, ProfileToolGatingEntry | null>;
}

// ─── Execution Log Types ─────────────────────────────────────────────────────

/**
 * A recorded execution — stored after gatekeeper approval for cumulative tracking.
 */
export interface ExecutionLogEntry {
  profileId: string;
  path: string;
  execution: Record<string, string | number>;
  timestamp: number; // Unix seconds
}

/**
 * Interface for querying cumulative execution data.
 * Implementations live in the MCP server layer (not hap-core).
 */
export interface ExecutionLogQuery {
  /**
   * Sum a field's values within a time window for a given profile.
   * Use field="_count" to count executions instead of summing a field.
   */
  sumByWindow(profileId: string, path: string, field: string, window: CumulativeWindow, now?: number): number;
}

// ─── Frame Types ─────────────────────────────────────────────────────────────

/**
 * Agent frame parameters — mixed types (strings and numbers).
 * Keys and values come from the profile's frameSchema.
 */
export type AgentFrameParams = Record<string, string | number>;

// ─── Gatekeeper Types ────────────────────────────────────────────────────────

/**
 * Request to the Gatekeeper for bounded execution verification.
 */
export interface GatekeeperRequest {
  /** The authorization frame (what was attested to) */
  frame: AgentFrameParams;
  /** Attestation blobs (base64url) for each domain */
  attestations: string[];
  /** The agent's execution values for this specific action */
  execution: Record<string, string | number>;
}

/**
 * Structured error from Gatekeeper verification.
 */
export interface GatekeeperError {
  code: 'BOUND_EXCEEDED' | 'CUMULATIVE_LIMIT_EXCEEDED' | 'INVALID_SIGNATURE' | 'TTL_EXPIRED' | 'FRAME_MISMATCH' | 'DOMAIN_NOT_COVERED' | 'INVALID_PROFILE' | 'MALFORMED_ATTESTATION';
  field?: string;
  message: string;
  bound?: string | number;
  actual?: string | number;
}

/**
 * Gatekeeper verification result.
 */
export type GatekeeperResult =
  | { approved: true }
  | { approved: false; errors: GatekeeperError[] };

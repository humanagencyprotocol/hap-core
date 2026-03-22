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
  version: '0.3' | '0.4';
  profile_id: string;
  /** v0.3 (deprecated) — hash of the authorization frame */
  frame_hash?: string;
  /** v0.4 — hash of the bounds parameters */
  bounds_hash?: string;
  /** v0.4 — hash of the context parameters */
  context_hash?: string;
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
 * - subset: every item in actual must appear in bound (comma-separated, case-insensitive)
 */
export interface FieldConstraint {
  type: 'number' | 'string';
  enforceable: Array<'max' | 'enum' | 'subset'>;
}

/**
 * Frame field definition within a profile.
 */
export interface ProfileFrameField {
  type: 'string' | 'number';
  required: boolean;
  description?: string;
  constraint?: FieldConstraint;
  enum?: string[];
}

/**
 * Bounds field definition within a v0.4 profile.
 */
export interface ProfileBoundsField {
  type: 'string' | 'number';
  required: boolean;
  description?: string;
  displayName?: string;
  format?: 'email' | 'domain' | 'url' | 'currency';
  constraint?: FieldConstraint;
  enum?: string[];
}

/**
 * Context field definition within a v0.4 profile.
 */
export interface ProfileContextField {
  type: 'string' | 'number';
  required: boolean;
  description?: string;
  displayName?: string;
  format?: 'email' | 'domain' | 'url' | 'currency';
  constraint?: FieldConstraint;
  enum?: string[];
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
  requiredDomains?: string[];  // v0.3: defined in profile. v0.4: moved to SP group config.
  ttl?: { default: number; max: number };
}

/**
 * Agent Profile — defines constraint types, execution paths, gate questions,
 * and the frame/bounds/context schemas for bounded execution.
 *
 * Supports both v0.3 (frameSchema) and v0.4 (boundsSchema + contextSchema).
 */
export interface AgentProfile {
  id: string;
  name?: string;
  version: string;
  description: string;

  /**
   * v0.3 frame schema (deprecated, kept for backward compat).
   * Used when boundsSchema is not present.
   */
  frameSchema?: {
    keyOrder: string[];
    fields: Record<string, ProfileFrameField>;
  };

  /**
   * v0.4 bounds schema — defines the authorization bounds parameters.
   */
  boundsSchema?: {
    keyOrder: string[];
    fields: Record<string, ProfileBoundsField>;
  };

  /**
   * v0.4 context schema — defines the execution context parameters (e.g., currency, action_type).
   * May be absent or empty for profiles with no static context.
   */
  contextSchema?: {
    keyOrder: string[];
    fields: Record<string, ProfileContextField>;
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

  /**
   * Tool gating configuration — how MCP tools map to execution context.
   * @deprecated Tool gating now lives in integration manifests (content/integrations/*.json).
   * Kept for backward compatibility with profiles that still include it.
   */
  toolGating?: ProfileToolGating;
}

// ─── Tool Gating Types ───────────────────────────────────────────────────

/**
 * Available transforms for array-aware execution mappings.
 * - length: array length → number
 * - join: array items joined by comma → string
 * - join_domains: extract email domains, deduplicate, sort, join → string
 */
export type ExecutionMappingTransform = 'join' | 'join_domains' | 'length';

/**
 * Execution mapping value — how a tool argument maps to execution context field(s).
 * - string: direct copy (argName → fieldName)
 * - { field, divisor }: numeric division (e.g., cents ÷ 100 → EUR)
 * - { field, transform }: array transform (e.g., join_domains)
 * - Array form: one argument maps to multiple execution fields
 */
export type ExecutionMappingValue =
  | string
  | { field: string; divisor: number }
  | { field: string; transform: ExecutionMappingTransform }
  | Array<{ field: string; divisor?: number; transform?: ExecutionMappingTransform }>;

/**
 * Tool gating entry — how a tool's calls map to execution context fields.
 * Read-only tools use { category: "read" } — they require authorization
 * but skip execution context verification.
 */
export interface ProfileToolGatingEntry {
  executionMapping: Record<string, ExecutionMappingValue>;
  staticExecution?: Record<string, string | number>;
  /** Read-only tools: require authorization but no execution context checks */
  category?: 'read';
}

/**
 * Profile-level tool gating configuration.
 * - default: applied to all tools not listed in overrides
 * - overrides: per-tool configs keyed by original MCP tool name
 *   Use { category: "read" } for read-only tools (null is deprecated)
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

/**
 * Agent bounds parameters — mixed types (strings and numbers).
 * Keys and values come from the profile's boundsSchema (v0.4).
 */
export type AgentBoundsParams = Record<string, string | number>;

/**
 * Agent context parameters — mixed types (strings and numbers).
 * Keys and values come from the profile's contextSchema (v0.4).
 */
export type AgentContextParams = Record<string, string | number>;

// ─── Gatekeeper Types ────────────────────────────────────────────────────────

/**
 * Request to the Gatekeeper for bounded execution verification.
 */
export interface GatekeeperRequest {
  /** The authorization frame (what was attested to) — v0.3 */
  frame: AgentFrameParams;
  /** Attestation blobs (base64url) for each domain */
  attestations: string[];
  /** The agent's execution values for this specific action */
  execution: Record<string, string | number>;
  /** v0.4: context parameters (currency, action_type, etc.) */
  context?: AgentContextParams;
}

/**
 * Structured error from Gatekeeper verification.
 */
export interface GatekeeperError {
  code: 'BOUND_EXCEEDED' | 'CUMULATIVE_LIMIT_EXCEEDED' | 'INVALID_SIGNATURE' | 'TTL_EXPIRED' | 'FRAME_MISMATCH' | 'BOUNDS_MISMATCH' | 'CONTEXT_MISMATCH' | 'DOMAIN_NOT_COVERED' | 'INVALID_PROFILE' | 'MALFORMED_ATTESTATION';
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

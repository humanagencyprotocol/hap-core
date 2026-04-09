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
  /**
   * v0.4 — commitment mode chosen by the decision owner at attestation time.
   * - 'automatic': agent may invoke bounded tools without per-action review.
   * - 'review': every tool call requires an approved proposal before the
   *   receipt route will sign a receipt.
   *
   * Cryptographically bound in the signed payload so a compromised SP cannot
   * silently flip 'review' → 'automatic'. Absent on v0.3 attestations.
   */
  commitment_mode?: 'automatic' | 'review';
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
 * Bound enforcement semantics — how a v0.4 bound is checked.
 *
 * Every bounds field in a v0.4 profile declares a `boundType` so the SP
 * receipt route and hap-core gatekeeper can dispatch on it directly,
 * without parsing field names or guessing conventions. This is the
 * single source of truth for "what does this bound mean at enforcement
 * time" — if a new kind is needed, add a variant here and update the
 * dispatch sites.
 *
 * See `ProfileBoundsField.boundType`.
 */
export type BoundType =
  /**
   * Per-transaction cap. The execution context field named in `of` must
   * satisfy `execution[of] <= bound` for the current call. No cumulative
   * tracking. Used by: amount_max, recipient_max, booking_duration_max, etc.
   */
  | { kind: 'per_transaction'; of: string }
  /**
   * Cumulative sum within a time window. The SP maintains a running sum
   * of `execution[of]` across all prior executions in the window; the
   * current call is approved iff `running_sum + execution[of] <= bound`.
   * Used by: amount_daily_max, spend_monthly_max, etc.
   */
  | { kind: 'cumulative_sum'; of: string; window: CumulativeWindow }
  /**
   * Cumulative count within a time window. Every qualifying execution
   * counts as +1; the current call is approved iff
   * `running_count + 1 <= bound`. No execution context field is read.
   * Used by: write_daily_max, post_monthly_max, booking_daily_max, etc.
   */
  | { kind: 'cumulative_count'; window: CumulativeWindow }
  /**
   * String bound restricted to a fixed set of allowed values. The bound's
   * value must be one of `values` at attestation time. The gateway
   * tool-proxy gates tool calls based on the stored bound (via the
   * integration manifest's `boundField` + `requiredValue`). Not cumulated,
   * not checked by the SP receipt route — it's a capability flag.
   * Used by: read_access, delete_access, archive_access.
   */
  | { kind: 'enum'; values: readonly string[] };

/**
 * Bounds field definition within a v0.4 profile.
 *
 * v0.4 adds the required `boundType` — an explicit declaration of how
 * the bound is enforced. The older `constraint.enforceable` pattern is
 * deprecated and superseded by `boundType`.
 */
export interface ProfileBoundsField {
  type: 'string' | 'number';
  required: boolean;
  description?: string;
  displayName?: string;
  format?: 'email' | 'domain' | 'url' | 'currency';
  /**
   * v0.4 enforcement semantics. Required for all new profiles.
   * Optional here only so the type stays backward compatible with v0.3
   * profiles that predate the boundType convention — consumers must
   * treat a missing boundType as an error when running in v0.4 mode.
   */
  boundType?: BoundType;
  /** @deprecated v0.4: use boundType instead. */
  constraint?: FieldConstraint;
  /** @deprecated v0.4: use boundType: { kind: 'enum', values: [...] }. */
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
 * @deprecated v0.4 uses a single intent gate with no profile-specific questions.
 */
export interface GateQuestion {
  question: string;
  required: boolean;
}

/**
 * @deprecated Execution paths removed in v0.4. Kept for backward compatibility.
 */
export interface ExecutionPath {
  description: string;
  requiredDomains?: string[];
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

  /** @deprecated Execution paths removed in v0.4. Kept for backward compatibility. */
  executionPaths?: Record<string, ExecutionPath>;

  requiredGates: string[];

  /**
   * v0.4: no gateQuestions — intent prompt is universal, defined in the gateway UI.
   * v0.3: profile-specific gate questions (deprecated).
   */
  gateQuestions?: {
    problem?: GateQuestion;
    objective?: GateQuestion;
    tradeoffs?: GateQuestion;
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

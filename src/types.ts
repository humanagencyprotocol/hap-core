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
  version: '0.3' | '0.4' | '0.5';
  profile_id: string;
  /** v0.3 (deprecated) — hash of the authorization frame */
  frame_hash?: string;
  /** v0.4 — hash of the bounds parameters */
  bounds_hash?: string;
  /** v0.4 — hash of the context parameters */
  context_hash?: string;
  execution_context_hash: string;
  /**
   * v0.4 (deprecated in v0.5) — domain-scoped owners. Optional so v0.5
   * attestations that carry only `resolved_owners` remain valid. During the
   * transition the AS emits BOTH `resolved_domains` (internal coverage) and
   * `resolved_owners` (the v0.5 signed wire field).
   */
  resolved_domains?: ResolvedDomain[];
  /**
   * v0.5 — the Decision Owner DIDs this attestation covers (person-centric
   * model; replaces the abstract domain in `resolved_domains`). Carried in the
   * signed payload so verifiers bind the action to the human(s) who authorized it.
   */
  resolved_owners?: string[];
  gate_content_hashes: Record<string, string>;
  /**
   * v0.5 (companion spec `intent-disclosure@0.1`) — present iff the attestation
   * carries an encrypted-intent disclosure object. `sha256:`-prefixed hash that
   * binds the disclosure's `intent_ciphertext` + `approvers_frozen` into the
   * signed payload (see {@link computeIntentDisclosureHash}), so a compromised
   * AS cannot swap the ciphertext/wrapped keys or alter the approver set
   * without invalidating the attestation signature (companion invariant C2).
   */
  intent_disclosure_hash?: string;
  /**
   * v0.6 (Identity Assurance) — optional signed overlay carrying the verified
   * real-world identity of the Decision Owner(s), one entry per owner. Present
   * only when identity is disclosed; an attestation with no `subjects` renders
   * as `low` (pseudonymous, no name). See {@link Subject} and
   * {@link deriveIdentityLine}.
   */
  subjects?: Subject[];
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

/**
 * v0.6 Identity Assurance — a signed overlay binding a Decision Owner's verified
 * real-world identity to the attestation, gated by HOW the identity was verified.
 *
 * Two display levels (`assurance`): `low` discloses no name; `high` MAY disclose a
 * name. At `high`, two trust roots: `as` (the AS operator vouches — valid only
 * within its own domain) and `external` (an external eID such as EUDI — carries the
 * owner's own signature, AS-independent). See review.md → "Identity Assurance".
 */
export interface Subject {
  /** The Decision Owner DID this subject describes (matches an entry in resolved_owners). */
  did: string;
  /** `low` → no name shown; `high` → the name MAY be shown. */
  assurance: 'low' | 'high';
  /** How identity was established. */
  method: 'self_declared' | 'as_vouched' | 'eudi';
  /** Who vouches: `self` (owner's claim), `as` (operator), `external` (eID scheme). */
  trust_root: 'self' | 'as' | 'external';
  /** Verifier id — the AS operator (as_vouched) or the eID scheme (eudi). Required at `high`. */
  verifier?: string;
  /** Disclosed attributes. `name` present ONLY at `assurance:"high"` and when disclosure is on. */
  disclose?: { name: string };
  /** When the underlying verification was performed (unix seconds). */
  verified_at?: number;
  /**
   * eudi only (Phase 2) — the owner's per-event wallet signature, making the
   * identity claim non-repudiable independent of the AS. Null/absent otherwise.
   */
  owner_signature?: string | null;
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
  /**
   * Action types for which this dimension MUST be present in the execution
   * context. When the grant constrains this field and the action is one of
   * these, an absent value is a denial rather than a skipped check.
   *
   * Without it, a constraint is only enforced against calls that happen to
   * expose the value. Gmail's `send_message` is the live case: pass `raw` and
   * `to` is never populated, so `allowed_recipients` had nothing to compare and
   * the check passed — a send to an unverified recipient looked authorized.
   * `send_draft` has the same shape: it transmits, and the Gatekeeper cannot
   * see to whom.
   *
   * Keyed on `action_type` because "does this action engage recipients?" is a
   * property of the action, not of the field name — deleting a draft has no
   * recipients and must keep passing, while sending one must not. This keeps
   * the engine profile-agnostic: it compares declared strings and knows nothing
   * about email, calendars or payments.
   *
   * Omitted → previous behaviour: absence skips the check.
   */
  requiredFor?: string[];
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
 * The measurement dimension of a numeric bound's value.
 *
 * Orthogonal to `BoundType` (which describes how the bound is *enforced*).
 * `unit` describes what the *value* means — 4 minutes vs 4 hours vs 4 EUR.
 *
 * UI uses this to render the unit next to the input. Future gatekeeper
 * versions can use it to enforce unit alignment between profile bounds
 * and tool payloads.
 */
export type FieldUnit =
  | 'count'                 // dimensionless integer (no unit suffix in UI)
  | 'minutes' | 'hours' | 'days'
  | `currency:${string}`    // ISO 4217 code, e.g. 'currency:EUR'
  | 'percent';

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
  /**
   * Which execution action types this bound governs, e.g. `["write"]`.
   *
   * When present, this is authoritative. When absent, enforcement falls back to
   * inferring the action type from the FIELD NAME (`send_daily_max` → `send`),
   * which is a convention rather than a contract: a profile that names a bound
   * after the domain concept instead of the action — calendar's
   * `booking_daily_max` against an action type of `write` — matches nothing and
   * is skipped, so a limit the user set is never applied and nothing says so.
   *
   * Declaring it removes the guess. Deliberately additive: profiles migrate one
   * at a time, and every remaining fallback is logged, so the cases still
   * relying on the naming convention become visible instead of staying silent.
   */
  appliesTo?: string[];
  /**
   * The measurement dimension of the bound's value. UI renders the unit
   * inline next to the input (e.g. `4 min`, `100 EUR`). Independent from
   * `boundType` — the same unit can appear under different enforcement
   * kinds, and the same boundType can carry different units.
   */
  unit?: FieldUnit;
  /** @deprecated v0.4: use boundType instead. */
  constraint?: FieldConstraint;
  /** @deprecated v0.4: use boundType: { kind: 'enum', values: [...] }. */
  enum?: string[];
}

/**
 * v0.5 Content Provenance — how a profile's action content is hashed into a
 * signed receipt (`contentHash`). The ephemeral-content analog of Output
 * Provenance: it binds the *bytes* of the action rather than a location.
 *
 * Profile-bound and OPTIONAL. Absent → no content hash is produced (full
 * backward compatibility). The gateway computes the hash; the SP only ever
 * receives the hash, never the content, so HAP's privacy-minimal design holds.
 *
 * At `version:"1"` the profile declares only the *policy* — whether to bind and
 * how to canonicalize. It does NOT name the tool field: that is tool-specific
 * and is resolved at runtime (the same content-field resolver the footer uses
 * for `kind:"text"`; the whole record payload for `kind:"jcs"`).
 *
 * At `version:"2"` the profile additionally declares WHICH fields are bound (see
 * {@link ContentBinding.fields}). Neither v1 mode is the general case: `text`
 * binds one field and leaves everything beside it unbound, while `jcs` over the
 * whole payload is checkable only by a party that already knows the whole
 * payload — an email recipient holds the body, the subject and their own
 * address, but not `bcc`. The general case is a declared subset, chosen so the
 * intended verifier can reproduce it.
 */
export interface ContentBinding {
  /** Canonicalization version. A verifier MUST pin the version named here. */
  version: string;
  /**
   * - 'jcs'  → structured writes: RFC 8785 JCS over the record payload
   *   (v1) or over the object built from {@link fields} (v2).
   * - 'text' → free text: NFC + LF + trailing-whitespace strip (see
   *   canonicalizeText), auto-detected content field.
   */
  kind: 'jcs' | 'text';
  /** text only: hash the content BEFORE any appended Suveren footer. */
  pre_footer?: boolean;

  /**
   * v2 only — the tool-argument keys this binding covers, and the complete
   * statement of what a verifier must reproduce. The Gatekeeper builds an
   * object from exactly these keys and canonicalizes it by `kind`.
   *
   * Adding or removing an entry changes every resulting hash, so it is a
   * BREAKING profile change requiring a version bump, never a silent edit.
   *
   * Choose the subset by one rule: bind everything the approving human is
   * shown, and nothing the intended verifier cannot see.
   */
  fields?: string[];
  /**
   * v2 only — the subset of {@link fields} whose absence is a fault rather than
   * a fact. An absent OPTIONAL field is omitted from the hashed object (an
   * email legitimately has no `cc`); an absent REQUIRED field means the call is
   * not the call this profile thinks it is, and MUST refuse rather than hash a
   * partial object that reads exactly like a complete one.
   *
   * MUST be a subset of `fields`. Absent → every field is optional, and only a
   * wholly empty selection refuses.
   */
  required_fields?: string[];
  /**
   * v2 only — the action types this binding covers, using the same vocabulary
   * as {@link ProfileBoundsField.appliesTo}. A profile gates more than its
   * content-bearing calls: `email` also gates deletes, which carry an id and no
   * content, and applying a field binding to those would refuse them.
   *
   * Absent → the binding applies to every gated action under the profile.
   */
  appliesTo?: string[];
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
   * One line on what this version changed and why it matters to the person
   * granting authority — written for them, not for a changelog.
   *
   * A grant pins the profile version it was signed against, so authorities
   * issued before a newer version keep their old terms indefinitely and
   * nothing prompts an upgrade. A version number alone does not motivate one:
   * "email@0.4 → 0.5" says nothing, while "binds recipients, not only the
   * message body" says what the older grant is not protecting.
   *
   * Belongs on the profile because the profile is what changed; a UI cannot
   * know why 0.5 exists. Absent → surfaces show the version alone.
   */
  whatsNew?: string;

  /**
   * Whether receipts under this profile may be looked up BY THEIR CONTENT — a
   * verifier holding the content supplies its hash and learns which receipts
   * bind it, without needing a receipt id.
   *
   * OFF unless declared, and that default is the point. The lookup is a
   * confirmation oracle: given a guess at the content it says whether that
   * content was authorized. Where the bound content has low entropy this is
   * disclosure, not verification — guessing a message body is hopeless,
   * guessing `production` takes a second. It is the same enumeration hazard
   * recorded for per-field commitments, arriving from the other direction.
   *
   * Enable only when the bound content is unguessable enough that producing it
   * is equivalent to already having it: prose, an artifact URL, a whole record
   * payload. Never for a binding over a short value drawn from a small set.
   *
   * Why it must exist at all: most consequential actions cannot carry their
   * receipt id. A released build was built before the receipt existed, a
   * content-addressed artifact would change identity if the id were added, and
   * a forwarded message has usually lost the footer that carried it.
   */
  receipt_lookup?: boolean;

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
   * v0.5 Content Provenance (OPTIONAL, profile-bound). When present, the
   * gateway computes a `contentHash` for gated writes under this profile and
   * passes it (hash only) to the SP, which signs it into the receipt. Absent
   * → no content hash. See {@link ContentBinding}.
   */
  content_binding?: ContentBinding;

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
  /**
   * Authorization path used to scope cumulative lookups in the execution log.
   *
   * Deliberately OUTSIDE `frame`: the frame is hashed and validated against the
   * profile's boundsSchema, so an extra key there is rejected as an unknown
   * field and breaks attestation verification outright. Cumulative checks
   * previously read the path from the frame, where callers cannot legally put
   * it — so it resolved to "" while the log stored real paths, no entry ever
   * matched, and every running total read zero. The local gate existed but
   * could never fire.
   */
  path?: string;
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

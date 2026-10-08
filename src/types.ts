/**
 * HAP Core Types — v0.7 ("mandate" / "ticket" / "scope" / "Mandate Owner")
 *
 * v0.7 is a vocabulary release (protocol.md → *Migration from v0.6*): the
 * wire renames *attestation* → *mandate*, *context* → *scope*, *execution
 * receipt* → *mandate ticket*, and *Decision Owner* → *Mandate Owner*. There
 * is no backward-compat alias here — v0.6 and earlier artifacts are
 * verification-only history outside this package (CLAUDE.md "Decided by the
 * owner": no verify path for 0.5/0.6, no old→new code map).
 */

// ─── Mandate Types ────────────────────────────────────────────────────────────

export interface MandateHeader {
  typ: 'HAP-mandate';
  alg: 'EdDSA';
  /**
   * When present MUST identify the same key as `issuer` (for a `did:key`
   * issuer, the multibase key fingerprint) — Mandate rule 8. The field a
   * party writes (`kid`) loses to the field a party cannot forge (`issuer`).
   */
  kid?: string;
}

/** Signature-assurance axis — what custody signed the mandate projection or
 * approval. Independent of identity assurance ({@link Subject.method}). */
export type OwnerSignatureBinding = 'raw' | 'webauthn' | 'eudi';

/** Which surface showed the owner what they signed. A DECLARATION, not a proof
 * — no verifier can check it; see protocol.md → *Owner Signatures*. */
export type SigningSurface = 'gatekeeper_local' | 'as_web' | 'wallet_display';

/**
 * v0.7 `mandate_owners` entry (protocol.md → *Mandate field: mandate_owners*).
 * `did` is required; the remaining fields are present together when the
 * owner co-signed and absent together when they did not (Mandate rule 7).
 *
 * There is deliberately NO `public_key` field, and it MUST NOT be added: the
 * verification key is carried in the DID itself (key-bearing `did:key`), so a
 * non-key-bearing DID fails STRUCTURALLY instead of validating against a key
 * the AS could have substituted.
 */
export interface MandateOwnerEntry {
  /** The Mandate Owner's DID. For a co-signing entry, MUST be key-bearing. */
  did: string;
  /** Signature algorithm hint. The DID's multicodec wins on any disagreement. */
  alg?: 'EdDSA' | 'ES256';
  /** base64url (no padding) signature over the JCS bytes of the mandate projection. */
  signature?: string;
  /** When the owner signed (unix seconds). */
  signed_at?: number;
  /** Defence-in-depth against duplicate issuance by an HONEST AS only —
   * AS-side nonce enforcement is no defence against the AS itself. */
  nonce?: string;
  /** Required-present, value-open when a signature is carried: an AS MUST
   * NOT reject an entry for a `binding` value it does not recognize. */
  binding?: OwnerSignatureBinding;
  signing_surface?: SigningSurface;
}

/**
 * v0.6 Identity Assurance — a signed overlay binding a Mandate Owner's verified
 * real-world identity to the mandate, gated by HOW the identity was verified.
 *
 * Two display levels (`assurance`): `low` discloses no name; `high` MAY disclose a
 * name. At `high`, two trust roots: `as` (the AS operator vouches — valid only
 * within its own domain) and `external` (an external eID such as EUDI — carries the
 * owner's own signature, AS-independent).
 */
export interface Subject {
  /** The Mandate Owner DID this subject describes (matches the `mandate_owners` entry). */
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
}

/** protocol.md → *Mandate Payload (v0.7)*. */
export interface MandatePayload {
  mandate_id: string;
  version: '0.7';
  profile_id: string;
  /** Hash of the canonical bounds string. */
  bounds_hash: string;
  /** Hash of the canonical scope string (sha256 of "" when scope is empty). */
  scope_hash: string;
  execution_context_hash: string;
  /** `sha256` over the JCS serialization of the profile the Gatekeeper
   * provisioned for `profile_id` — the content address of the rulebook this
   * mandate was issued under (new in v0.7). */
  profile_hash: string;
  /** The Authority Server's DID — SHOULD be the `did:key` of the signing key
   * itself (new in v0.7). */
  issuer: string;
  /** Exactly one entry in v0.7 (Mandate rule 7). */
  mandate_owners: MandateOwnerEntry[];
  gate_content_hashes: Record<string, string>;
  commitment_mode: 'automatic' | 'review' | 'review_above_cap';
  /** Required, together with `above_cap_approvers`, iff `commitment_mode === "review_above_cap"`. */
  above_cap_caps?: Record<string, number>;
  above_cap_approvers?: string[];
  /**
   * Present iff the mandate carries an encrypted-intent disclosure object
   * (companion spec `intent-disclosure@0.1`) — `sha256:`-prefixed hash
   * binding `intent_ciphertext` + `approvers_frozen` into the signed payload.
   */
  intent_disclosure_hash?: string;
  /** Signed identity-assurance block, one entry per owner — present iff the
   * Mandate Owner disclosed identity. */
  subjects?: Subject[];
  /**
   * The owner's narrowing of the profile's `disclose_fields` list (new in
   * v0.7) — a subset of the profile's own list. See *Ticket Disclosure Is
   * Declared*.
   */
  disclose_fields?: string[];
  issued_at: number;
  expires_at: number;
}

export interface Mandate {
  header: MandateHeader;
  payload: MandatePayload;
  /** base64url (no padding) Ed25519 signature over the JCS-canonical payload. */
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
 * Bound enforcement semantics — how a bound is checked.
 *
 * Every bounds field in a profile declares a `boundType` so the AS and
 * hap-core gatekeeper can dispatch on it directly, without parsing field
 * names or guessing conventions. This is the single source of truth for
 * "what does this bound mean at enforcement time" — if a new kind is needed,
 * add a variant here and update the dispatch sites.
 *
 * See `ProfileBoundsField.boundType`.
 */
export type BoundType =
  /**
   * Per-transaction cap. The execution context field named in `of` must
   * satisfy `execution[of] <= bound` for the current call. No cumulative
   * tracking. Used by: amount_max, recipient_max, booking_duration_max, etc.
   *
   * `requiredFor` closes the converse: without it, a call that does not
   * carry `of` at all is simply skipped — a 5,000 cap refuses 6,000 but
   * permits a call that declares no value whatsoever, which is indistinguishable
   * from an unenforced bound. Values are drawn from the profile's
   * `boundsSchema.actionTypes` registry. For a listed `action_type`, an
   * execution whose context lacks `of` — or whose value is not a finite
   * number — MUST be refused rather than skipped. `appliesTo` MUST NOT be
   * declared on a `per_transaction` bound (protocol.md → Bounds Schema rule 7)
   * — it applies wherever `of` is present in the execution context.
   */
  | { kind: 'per_transaction'; of: string; requiredFor?: string[] }
  /**
   * Cumulative sum within a time window. The AS maintains a running sum
   * of `execution[of]` across all prior tickets in the window; the
   * current call is approved iff `running_sum + execution[of] <= bound`.
   * AS-only enforcement (protocol.md → *Enforcement Authority*); the
   * Gatekeeper MUST NOT enforce this locally. Used by: amount_daily_max,
   * spend_monthly_max, etc.
   */
  | { kind: 'cumulative_sum'; of: string; window: CumulativeWindow }
  /**
   * Cumulative count within a time window. Every qualifying ticket
   * counts as +1; the current call is approved iff
   * `running_count + 1 <= bound`. No execution context field is read.
   * AS-only enforcement. `appliesTo` is REQUIRED on a profile published
   * under v0.7 or later (Bounds Schema rule 7) — absence would mean
   * "governs every action type", so a forgotten declaration silently
   * throttles every action. Used by: write_daily_max, post_monthly_max,
   * booking_daily_max, etc.
   */
  | { kind: 'cumulative_count'; window: CumulativeWindow }
  /**
   * String bound restricted to a fixed set of allowed values. The bound's
   * value must be one of `values` at mandate time. The gateway
   * tool-proxy gates tool calls based on the stored bound (via the
   * integration manifest's `boundField` + `requiredValue`). Not cumulated,
   * not checked by the AS ticket route — it's a capability flag.
   * `appliesTo` MUST NOT be declared here (it is a capability flag, not an
   * action-scoped limit). Used by: read_access, delete_access, archive_access.
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
 * Bounds field definition within a profile.
 *
 * Every non-metadata bounds field MUST declare `boundType` — an explicit
 * declaration of how the bound is enforced. Implementations MUST fail
 * closed on any bounds field that omits it (Bounds Schema rule 2).
 */
export interface ProfileBoundsField {
  type: 'string' | 'number';
  required: boolean;
  description?: string;
  displayName?: string;
  format?: 'email' | 'domain' | 'url' | 'currency';
  /** Enforcement semantics. REQUIRED on every bounds field except `profile`. */
  boundType?: BoundType;
  /**
   * Which execution action types this bound governs, e.g. `["write"]`.
   *
   * When present, this is authoritative. When absent, a `cumulative_sum` bound
   * (or any bound on a profile published before v0.7) governs every action
   * type in the profile's `actionTypes` registry; a `cumulative_count` bound
   * on a v0.7+ profile MUST declare it (Bounds Schema rule 7). MUST NOT be
   * declared on a `per_transaction` bound (it applies wherever its `of`
   * field is present in the execution context) or on an `enum` bound (a
   * capability flag, not an action-scoped limit).
   */
  appliesTo?: string[];
  /**
   * The measurement dimension of the bound's value. UI renders the unit
   * inline next to the input (e.g. `4 min`, `100 EUR`). Independent from
   * `boundType` — the same unit can appear under different enforcement
   * kinds, and the same boundType can carry different units.
   */
  unit?: FieldUnit;
  /**
   * The largest value a mandate may set for this (numeric) bound — a ceiling
   * on what the owner can grant, declared by the profile. E.g. reporting@0.2
   * `read_max_age_days: { maximum: 366 }`: no reporting mandate may read back
   * further than a year.
   *
   * Distinct from the bound itself: the bound limits each ACTION; `maximum`
   * limits the MANDATE. A value above it is not a valid mandate for this
   * profile — the mandate editor caps its input, the issuing Authority Server
   * should refuse it, and an enforcement point that reads the bound applies
   * min(value, maximum). Absent → no ceiling.
   */
  maximum?: number;
}

/**
 * v0.5 Content Provenance — how a profile's action content is hashed into a
 * signed ticket (`contentHash`). The ephemeral-content analog of Output
 * Provenance: it binds the *bytes* of the action rather than a location.
 *
 * Profile-bound and OPTIONAL. Absent → no content hash is produced (full
 * backward compatibility). The gateway computes the hash; the AS only ever
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
 * Scope field definition within a profile (renamed from `ProfileContextField`
 * in v0.7 — protocol.md → *Migration from v0.6*, `contextSchema` → `scopeSchema`).
 */
export interface ProfileScopeField {
  type: 'string' | 'number';
  required: boolean;
  description?: string;
  displayName?: string;
  format?: 'email' | 'domain' | 'url' | 'currency';
  /**
   * What this field NAMES on the read path. `counterparty` = the other
   * party to a communication (matched against an item's participants);
   * `resource` = the container an item belongs to (a direct attribute match —
   * and a resource scope enforced on writes MUST also bind reads). Absent →
   * implementations MAY infer `counterparty` from `format: email|domain`
   * (transitional; the explicit declaration is normative).
   */
  scopeKind?: 'counterparty' | 'resource';
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
 * Execution context field definition — cumulative source (resolved from the
 * AS's ticket history; see protocol.md → *Cumulative State*).
 *
 * - `cumulativeField`: which declared field to sum (use "_count" for plain counting)
 * - `window`: time window for aggregation (daily, weekly, monthly)
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
 * Agent Profile — defines the bounds/scope/execution-context schemas, gates,
 * TTL policy, and retention for a bounded authority (protocol.md → *Profiles*).
 */
/**
 * A commitment mode a person can choose when signing a mandate. (`review_above_cap`
 * is not chosen by the signer — it follows from team caps.)
 */
export type SignableCommitmentMode = 'automatic' | 'review';

/** protocol.md → *Owner Signatures* → "Where the requirement lives" — the
 * profile-floor tier: `minBinding` names the weakest `OwnerSignatureBinding`
 * this profile accepts for a co-signing owner. */
export interface ProfileOwnerSignatureFloor {
  required: boolean;
  minBinding?: OwnerSignatureBinding;
}

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
   * Whether tickets under this profile may be looked up BY THEIR CONTENT — a
   * verifier holding the content supplies its hash and learns which tickets
   * bind it, without needing a ticket id. (Renamed from `receipt_lookup` in
   * v0.7.)
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
   */
  ticket_lookup?: boolean;

  /**
   * The commitment modes a mandate under this profile may be signed with.
   * Absent → every mode (`automatic`, `review`), as before this field existed.
   *
   * Lets a profile be review-only: every action it governs then needs a
   * person's approval, whatever the signer would have picked. The Authority
   * Server refuses to sign a mandate whose `commitment_mode` is not listed;
   * a mandate screen offers only the listed modes. Fail-closed: a declared
   * list with no valid entry allows nothing — a malformed declaration never
   * widens what a profile allows. See {@link allowedCommitmentModes}.
   */
  commitment_modes?: readonly SignableCommitmentMode[];

  /**
   * The bounds schema — the enforceable parameters (protocol.md → *Bounds
   * Schema*).
   */
  boundsSchema?: {
    keyOrder: string[];
    fields: Record<string, ProfileBoundsField>;
    /**
     * Registry of the action types this profile recognizes (e.g.
     * `["send", "delete", "setup"]`). Every `execution.action_type` the
     * Authority Server and gateway accept for this profile MUST be a member
     * when the registry is declared (protocol.md → Bounds Schema, rule 2);
     * it is also what a `per_transaction` bound's `requiredFor` draws from.
     * Absent on profiles published before the registry existed — membership
     * is then uncheckable, not a violation.
     */
    actionTypes?: readonly string[];
  };

  /**
   * The scope schema — operational scoping fields that stay local (renamed
   * from `contextSchema` in v0.7). May be absent or empty for profiles with
   * no static scope.
   */
  scopeSchema?: {
    keyOrder: string[];
    fields: Record<string, ProfileScopeField>;
  };

  executionContextSchema: {
    fields: Record<string, ExecutionContextFieldDef>;
  };

  requiredGates: string[];

  ttl: { default: number; max: number };
  retention_minimum: number;

  /**
   * Content Provenance (OPTIONAL, profile-bound). When present, the
   * gateway computes a `contentHash` for gated writes under this profile and
   * passes it (hash only) to the AS, which signs it into the ticket. Absent
   * → no content hash. See {@link ContentBinding}.
   */
  content_binding?: ContentBinding;

  /**
   * The execution-context fields a ticket under this profile MAY disclose
   * (new in v0.7 — protocol.md → *Ticket Disclosure Is Declared*). Absent →
   * nothing is disclosed by default. A mandate's own `disclose_fields` (when
   * present) MUST be a subset of this list — a mandate may narrow disclosure,
   * never widen it.
   */
  disclose_fields?: string[];

  /**
   * Profile-floor requirement for an owner signature on a mandate under this
   * profile (protocol.md → *Owner Signatures* → "Where the requirement
   * lives"). Reserved for domains that cannot mean anything without a
   * signature — used more freely it forks `charge` from `charge-with-cosign`.
   */
  ownerSignature?: ProfileOwnerSignatureFloor;
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
  sumByWindow(
    profileId: string,
    path: string,
    field: string,
    window: CumulativeWindow,
    now?: number,
    /**
     * Only count executions whose `execution.action_type` is one of these.
     * Omitted → every execution counts (a bound that governs all action types).
     *
     * Consumption is partitioned by action type (*Cumulative Tracking* rule 4):
     * a bound counts only the action types it governs. Without the filter a
     * profile with several action types feeds every bound the combined total —
     * sales' "orders per day" counted quotes and sends too, and its daily order
     * value summed quote values. Use {@link boundActionTypes} to derive it.
     *
     * Implementations SHOULD count an entry that carries no `action_type`
     * against every filter: an unknown action is not evidence of headroom.
     */
    actionTypes?: readonly string[],
  ): number;
}

// ─── Bounds / Scope param types ──────────────────────────────────────────────

/**
 * Agent bounds parameters — mixed types (strings and numbers).
 * Keys and values come from the profile's boundsSchema.
 */
export type AgentBoundsParams = Record<string, string | number>;

/**
 * Agent scope parameters — mixed types (strings and numbers). Keys and
 * values come from the profile's scopeSchema (renamed from
 * `AgentContextParams` in v0.7).
 */
export type AgentScopeParams = Record<string, string | number>;

// ─── Gatekeeper Types ────────────────────────────────────────────────────────

/**
 * Request to the Gatekeeper for bounded execution verification.
 */
export interface GatekeeperRequest {
  /** The bounds the mandate(s) committed to. */
  bounds: AgentBoundsParams;
  /** Mandate blobs (base64url) to verify against. */
  mandates: string[];
  /** The agent's execution values for this specific action. */
  execution: Record<string, string | number>;
  /** Scope parameters (currency, action_type, allowed recipients, etc.) —
   * enforced locally only; never sent to the Authority Server. */
  scope?: AgentScopeParams;
  /**
   * Authorization path used to scope cumulative lookups in the execution log
   * (display only — see {@link ExecutionLogQuery}; the Gatekeeper MUST NOT
   * enforce cumulative bounds locally, protocol.md → *Enforcement Authority*).
   */
  path?: string;
}

/**
 * Structured error from Gatekeeper verification. Codes are the canonical
 * v0.7 surface ({@link HapErrorCode}, `src/errors.ts`) plus the two
 * Gatekeeper-local-only codes that never reach the wire (`FRAME_MISMATCH`
 * is retired with v0.3; a Gatekeeper reports `BOUNDS_HASH_MISMATCH` /
 * `SCOPE_HASH_MISMATCH` for both its own local mismatch and the AS's wire
 * refusal, per protocol.md → *Error Codes*, "Gatekeeper · local").
 */
export interface GatekeeperError {
  code: import('./errors').HapErrorCode;
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

# Changelog

## 0.13.0 — unreleased (v0.8 wire)

HAP v0.8 — a **re-grant release** (protocol.md → *Migration from v0.7*). No
field is renamed or retired; every new signed field is optional or
conditional. This package now **issues `version: "0.8"`** and **verifies
`"0.8"` and `"0.7"`**, each under its own rules (*Version negotiation*, rule
4): a v0.7 artifact stays verifiable as evidence, a v0.8 Authority Server
issues no tickets against it.

### Versions

- `PROTOCOL_VERSION` is `"0.8"`; `SUPPORTED_VERSIONS` is `["0.8", "0.7"]`
  (what a Gatekeeper sends as `supported_versions`); new `ISSUABLE_VERSIONS`
  (`["0.8"]`) is the default of `negotiateVersion`, so a v0.8 issuer refuses a
  request that does not support 0.8. An AS that bridges the transition passes
  the wider set explicitly. New `assertSupportedVersion`, `isSupportedVersion`.

### Signed objects

- Mandate payload: `above_cap_approvals` (present exactly with
  `above_cap_approvers`; Mandate rule 10) — `validateAboveCapFields`.
- Owner-signed projection: `binding`, `signing_surface`, `subjects_disclosed`
  (always present under 0.8), `above_cap_approvals` with the other two;
  `buildMandateProjection` reconstructs per the mandate's version.
- `HAP-approval`: `approver_did`, `action`, `action_type`,
  `proposal_content_hash` (0.8). `verifyApproval` checks `approver_did`.
- Ticket: `idempotencyKey`, `proposalContentHash`, `approvalSignatures`.
  `verifyTicketSignature` enforces the shape rules (no `typ`, no
  `mandate_id`/`issued_at`, required fields). New `verifyTicketAgainstRequest`
  (`TICKET_REQUEST_MISMATCH`), `reconstructApproval`, `verifyTicketApprovals`,
  `approvalsSufficient`.
- New `ticket-projection.ts`: `HAP-ticket-projection` — build, sign, verify,
  and `verifyProjectionOwner` against the mandate.
- New `verifier-policy.ts`: `HAP-verifier-policy` evaluation with the codes
  the specification's table assigns (`PolicyError`).

### Proposals

- New `proposal-content.ts`: `computeProposalContentHash` (JCS → sha256),
  `encryptProposalContent` / `decryptProposalContent` with the pinned
  construction (AES-256-GCM, IV ‖ ct ‖ tag; HPKE base mode DHKEM-X25519 /
  HKDF-SHA256 / AES-256-GCM, empty info and AAD) on `@hpke/core`;
  `checkProposalReaders`. New dependency `@hpke/core`.

### Issuance and execution checks (`issuance.ts`)

- `computeExecutionContextHash`, `boundReadFields`, `wireExecutionContext`,
  `checkExecutionValues` (finite, non-negative; `_` keys refused),
  `missingSumFields`, `checkBoundsValues` (`maximum`, numeric type, enum),
  `checkGroupCeilings` (`GROUP_CAP_EXCEEDED`, enum order), `validateAboveCapConfig`,
  `capsExceeded`.
- Gatekeeper `verify`: accepts 0.7 and 0.8 mandates; refuses a non-numeric or
  negative value a bound reads (`MALFORMED_TICKET_REQUEST`); refuses an
  absent amount under a governing `cumulative_sum` bound (`BOUND_EXCEEDED`,
  v0.8 "a missing amount fails safe") unless an above-cap cap reads the field.

### Profiles

- `validateProfile`: `maximum` must be a number, `enforcedBy` must be
  `"gatekeeper"`, `disclose_fields` only names fields a bound reads, a
  version-2 `content_binding` with `kind: "text"` is invalid; an entry
  `review_above_cap` in `commitment_modes` is ignored (alone it is malformed).
- `isCommitmentModeAllowed(profile, "review_above_cap")` is true iff
  `automatic` is admitted (Commitment Modes, rule 8).
- Types: `enforcedBy` on a bounds field; `CommitmentMode`, `ProtocolVersion`.

### Canonicalization

- A string with a lone surrogate is refused, never signed (RFC 8785 / I-JSON).

### Error codes

Added: `COMMITMENT_MODE_NOT_ALLOWED`, `GROUP_CAP_EXCEEDED`,
`APPROVAL_IMPOSSIBLE`, `PROPOSAL_CONTENT_MISMATCH`, `PROPOSAL_WITHDRAWN`,
`CONTENT_BINDING_INCOMPLETE`, `TICKET_REQUEST_MISMATCH`, `POLICY_UNMET`,
`PROPOSAL_NOT_ENCRYPTED`, `DECIDER_INVALID`, `PROPOSAL_ALREADY_DECIDED`,
`PROPOSAL_APPROVERS_INVALID`. None retired.

### Conformance

Every `content/0.8/vectors/*` reproduces byte for byte (payload signatures
incl. the review-path ticket, the public projection and the JCS edge cases;
proposal encryption; profile hashes; canonical bounds and scope), and every
`required-refusals.json` row is decided here or named AS-only in the test.
The v0.7 signature vectors still pass through the same functions.

## 0.12.0 — 2026-10-08

**BREAKING.** HAP v0.7 wire — the vocabulary rename (protocol.md →
*Migration from v0.6*) plus the structural changes it requires. No backward
compatibility: v0.5/v0.6 artifacts are not verifiable by this package; such
mandates fail with `VERSION_UNSUPPORTED` and are re-issued (decided
2026-10-08). Consumers on `^0.11` are unaffected until they upgrade.

### Renamed (mechanical, 1:1 — see README.md for the full table)

- Files: `attestation.ts` → `mandate.ts`; the former `mandate.ts` (owner-signed
  projection) → `owner-signature.ts`; `receipt.ts` → `ticket.ts`.
- Types: `Attestation`/`AttestationPayload`/`AttestationHeader` →
  `Mandate`/`MandatePayload`/`MandateHeader`; `OwnerMandate` →
  `MandateOwnerEntry`; `MandateBinding` → `OwnerSignatureBinding`;
  `ProfileContextField`/`AgentContextParams` →
  `ProfileScopeField`/`AgentScopeParams`; `AgentProfile.contextSchema` →
  `scopeSchema`; `AgentProfile.receipt_lookup` → `ticket_lookup`.
- Functions: `encode/decodeAttestationBlob` → `encode/decodeMandateBlob`;
  `attestationId` → `mandateBlobId`; `verifyAttestationSignature` →
  `verifyMandateSignature`; `checkAttestationExpiry` → `checkMandateExpiry`;
  `verifyAttestationV4` → `verifyMandate`; `verifyContextHash`/
  `canonicalContext`/`computeContextHash`/`validateContextParams` →
  `verifyScopeHash`/`canonicalScope`/`computeScopeHash`/`validateScopeParams`;
  `ReceiptPayload`/`verifyReceiptSignature` → `TicketPayload`/
  `verifyTicketSignature`; `verifyOwnerMandate(s)` → `verifyOwnerSignature(s)`;
  `MandateError` → `OwnerSignatureError`; `mandateSigningBytes` →
  `projectionSigningBytes`.
- `GatekeeperRequest`: `attestations` → `mandates`, `context` → `scope`,
  `frame` → `bounds` (v0.3's dual frame/bounds field is gone — bounds is the
  only shape now). `GatekeeperError.code` is now `HapErrorCode`
  (`src/errors.ts`) — the canonical v0.7 code list, not a package-local union.
- Error codes, to their canonical v0.7 names (protocol.md → *Error Codes*):
  `MALFORMED_ATTESTATION` → `MALFORMED_MANDATE`; `ATTESTATION_REVOKED` →
  `MANDATE_REVOKED`; `MANDATE_SIGNATURE_REQUIRED`/`_INVALID` →
  `OWNER_SIGNATURE_REQUIRED`/`_INVALID`; `NOT_KEY_BEARING`/`OWNER_NOT_RESOLVED`
  → `OWNER_SIGNATURE_INVALID`; `INVALID_PROFILE` → `PROFILE_NOT_FOUND` /
  `PROFILE_INVALID`; `BOUNDS_MISMATCH` → `BOUNDS_HASH_MISMATCH`;
  `CONTEXT_MISMATCH` → `SCOPE_HASH_MISMATCH`; `CONTEXT_INVALID_VALUE` →
  `SCOPE_INVALID_VALUE`.

### Removed (no alias)

v0.3's frame-based path and the dual-version (v0.3/v0.4) Gatekeeper:
`verifyAttestation` (v0.3), `verifyFrameHash`, `isV4Attestation`,
`verifyV3`/`checkBoundsFromFrameSchema`, `frameSchema`,
`canonicalFrame`/`computeFrameHash`/`validateFrameParams`,
`AgentFrameParams`, `GateQuestion`, `ExecutionPath`/`executionPaths`,
`ProfileFrameField`, `DOMAIN_NOT_COVERED`, `ResolvedDomain`/
`resolved_domains`/`resolved_owners`/`owner_mandates`, `frame_hash`,
`Subject.owner_signature`.

**Local cumulative enforcement is removed, not merely deprecated**
(protocol.md → *Migration from v0.6*, semantic change 9): the Gatekeeper no
longer tracks or refuses on `cumulative_sum`/`cumulative_count` bounds from
its own records — that is Authority-Server-only. `boundActionTypes` and
`ExecutionLogQuery` are kept (a gateway's own usage display still needs to
partition totals the same way).

### Added

- `src/base64url.ts` — strict base64url encode/decode (`toBase64Url`,
  `fromBase64Url`); rejects standard base64 (`+`/`/`/padding) rather than
  silently repairing it (protocol.md → *Mandate Payload* rule 3).
- `src/errors.ts` — `MANDATE_ERROR_CODES`, `TICKET_ERROR_CODES`,
  `HapErrorCode`, `HapError`.
- `src/versions.ts` — `PROTOCOL_VERSION`, `SUPPORTED_VERSIONS`,
  `negotiateVersion` (protocol.md → *Version negotiation*).
- `src/profile.ts` — `computeProfileHash` (the `profile_hash` content
  address — protocol.md → *Profile hash*); `validateProfile` (folds in the
  authoring-time checks formerly split across `validateBoundsRequiredFor`
  and `validateCommitmentModes`, plus the new v0.7 structural rules:
  `appliesTo` registry membership, `cumulative_count` requiring `appliesTo`,
  missing `boundType`, `appliesTo` on `per_transaction`/`enum`, retired
  profile keys); `checkDiscloseSubset`.
- `types.ts`: `AgentProfile.ownerSignature` (the profile-floor tier of Owner
  Signatures) and `AgentProfile.disclose_fields`; `MandatePayload.profile_hash`
  and `.issuer`; `MandateOwnerEntry` signature fields now explicitly
  all-or-none; `TicketPayload.mandateId`/`.version`/`.issuer`/`.limits`
  (required).
- `src/owner-signature.ts`: `checkOwnerSignatureRequirement` — the
  "Verifier policy" / "profile floor" tier of Owner Signatures (protocol.md →
  *Owner Signatures* → "Where the requirement lives"), checkable without
  trusting the AS.
- `src/ticket.ts`: `publicTicketView` — a redacted public projection of a
  ticket (new in v0.7 — *Ticket Disclosure Is Declared*), explicitly NOT
  independently re-verifiable (*Ticket Verification*: "the holder is the
  verifier").
- `src/mandate.ts`: `signMandate`, `verifyMandateSignature` (resolves the
  verification key from the mandate's own `issuer` DID — never from a key
  supplied alongside the artifact), `validateMandateOwners`, `verifyMandate`.
- Conformance vectors: `test/vectors/*.test.ts` reads
  `content/0.7/vectors/*.json` directly (profile-hash,
  canonical-bounds-and-scope, payload-signatures, required-refusals) — no
  copy of their values lives in this repo. `ci.yml` checks out the spec repo
  as a sibling so these run for real in CI instead of skipping.

### Fixed

- `gatekeeper.verify()`'s AS-key resolution no longer takes a `publicKeyHex`
  parameter from the caller — the key is resolved from each mandate's own
  `issuer` DID (protocol.md → *Ticket Verification* step 1, applied
  identically to mandates), so a caller cannot verify a mandate against a
  key the mandate does not itself claim.

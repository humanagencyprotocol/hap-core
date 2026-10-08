# @humanagencyp/hap-core

Core types, cryptographic primitives, and verification logic for the [Human Agency Protocol](https://humanagencyprotocol.org).

**v0.7 vocabulary** — the wire renames *attestation* → **mandate**, *execution
receipt* → **mandate ticket**, *context* → **scope**, and *Decision Owner* →
**Mandate Owner** (protocol.md → *Migration from v0.6*). This package issues
and verifies `version: "0.7"` artifacts only — there is no backward-compat
verify path for v0.5/v0.6; a v0.6 mandate fails verification with
`VERSION_UNSUPPORTED` and must be re-issued. See the rename table below.

## Install

```bash
npm install @humanagencyp/hap-core
```

## What's included

- **Types** — `AgentProfile`, `AgentBoundsParams`, `AgentScopeParams`, `Mandate`/`MandatePayload`, execution context schemas
- **Frame** — Canonical hashing of bounds and scope (`computeBoundsHash`, `computeScopeHash`)
- **Mandate** — Ed25519 signing and verification of mandate blobs (`signMandate`, `verifyMandate`, `verifyMandateSignature`)
- **Owner Signature** — the `HAP-mandate-projection` and `HAP-approval` objects and their verification (`buildMandateProjection`, `verifyOwnerSignature(s)`, `signApproval`/`verifyApproval`)
- **Ticket** — the signed mandate-ticket wire type and holder-side verification (`signTicket`, `verifyTicketSignature`, `publicTicketView`)
- **Gatekeeper** — local (Phase 1) execution verification: mandate signature/expiry/hash checks, `per_transaction` bounds, `enum` capability flags, scope constraints. **Does not** enforce `cumulative_sum`/`cumulative_count` bounds — those are Authority-Server-only (protocol.md → *Enforcement Authority*)
- **Profile** — `computeProfileHash` (content address of a provisioned profile) and `validateProfile` (authoring-time checks)
- **Versions** — `negotiateVersion`, `PROTOCOL_VERSION`, `SUPPORTED_VERSIONS`
- **Errors** — the canonical v0.7 error-code list (`HapErrorCode`, `HapError`)
- **base64url** — strict (no padding, no standard-base64 characters) encode/decode
- **Profiles registry** — `registerProfile`, `getProfile`, `getAllProfiles`, `clearProfiles`

## Usage

```typescript
import {
  type AgentProfile,
  computeBoundsHash,
  computeScopeHash,
  verify,
  registerProfile,
  getProfile,
} from '@humanagencyp/hap-core';

// Register a profile
registerProfile(profile.id, profile);

// Compute deterministic hashes for bounds and scope
const boundsHash = computeBoundsHash(bounds, profile);
const scopeHash = computeScopeHash(scope, profile);

// Verify an execution against bounds and mandates (Gatekeeper, Phase 1 — never
// reaches the wire). The AS public key is resolved from each mandate's own
// `issuer` DID, never supplied by the caller.
const result = await verify({ bounds, mandates, execution, scope });

if (result.approved) {
  // Execution is within bounds — request a ticket from the Authority Server next.
}
```

## Constraint types

The Gatekeeper enforces two kinds of constraints locally, from the profile's
bounds and scope schemas:

| Type | Enforced by | Example |
|---|---|---|
| `per_transaction` bound | Gatekeeper (and the AS at ticket time) | `amount_max: 1000` |
| `enum` bound (capability flag) | Gatekeeper and AS at mandate time | `read_access: ["unlimited", "none"]` |
| scope `enum` | Gatekeeper only (the AS only ever holds `scope_hash`) | `currency: ["USD", "EUR"]` |
| scope `subset` | Gatekeeper only | `allowed_domains: "acme.com,partner.org"` |

`cumulative_sum` and `cumulative_count` bounds are **Authority-Server-only**
(protocol.md → *Enforcement Authority*; *Migration from v0.6* semantic change
9: "Local cumulative enforcement is removed, not merely deprecated"). The
Gatekeeper MUST NOT refuse an execution on a cumulative bound from its own
records — only the AS's ticket history is authoritative for a running total
across every Gatekeeper exercising the bucket.

## v0.6 → v0.7 rename table

Mechanical, 1:1 (full list: protocol.md → *Migration from v0.6*):

| v0.6 | v0.7 |
|---|---|
| `attestation.ts` | `mandate.ts` |
| `mandate.ts` (owner-signed projection) | `owner-signature.ts` |
| `receipt.ts` | `ticket.ts` |
| `Attestation` / `AttestationPayload` / `AttestationHeader` | `Mandate` / `MandatePayload` / `MandateHeader` |
| `OwnerMandate` | `MandateOwnerEntry` |
| `MandateBinding` | `OwnerSignatureBinding` |
| `ProfileContextField` / `AgentContextParams` | `ProfileScopeField` / `AgentScopeParams` |
| `AgentProfile.contextSchema` | `AgentProfile.scopeSchema` |
| `AgentProfile.receipt_lookup` | `AgentProfile.ticket_lookup` |
| `encode/decodeAttestationBlob` | `encode/decodeMandateBlob` |
| `attestationId` | `mandateBlobId` |
| `verifyAttestationSignature` | `verifyMandateSignature` |
| `checkAttestationExpiry` | `checkMandateExpiry` |
| `verifyAttestationV4` | `verifyMandate` |
| `verifyContextHash` / `canonicalContext` / `computeContextHash` / `validateContextParams` | `verifyScopeHash` / `canonicalScope` / `computeScopeHash` / `validateScopeParams` |
| `ReceiptPayload` / `verifyReceiptSignature` | `TicketPayload` / `verifyTicketSignature` |
| `verifyOwnerMandate(s)` | `verifyOwnerSignature(s)` |
| `MandateError` | `OwnerSignatureError` |
| `mandateSigningBytes` | `projectionSigningBytes` |

Removed (v0.3 and the dual-version Gatekeeper path are retired, no alias):
`verifyAttestation`, `verifyFrameHash`, `isV4Attestation`, `frameSchema`,
`canonicalFrame`/`computeFrameHash`/`validateFrameParams`, `AgentFrameParams`,
`DOMAIN_NOT_COVERED`, local cumulative bounds enforcement.

Error codes renamed to their canonical v0.7 names (protocol.md → *Error
Codes*): `MALFORMED_ATTESTATION` → `MALFORMED_MANDATE`, `ATTESTATION_REVOKED`
→ `MANDATE_REVOKED`, `MANDATE_SIGNATURE_*` → `OWNER_SIGNATURE_*`,
`BOUNDS_MISMATCH` → `BOUNDS_HASH_MISMATCH`, `CONTEXT_MISMATCH` →
`SCOPE_HASH_MISMATCH`, `CONTEXT_INVALID_VALUE` → `SCOPE_INVALID_VALUE`, and
others — see `src/errors.ts` for the full canonical list.

**v0.7 only, in brief:** 0.5/0.6 mandates fail verification with
`VERSION_UNSUPPORTED` and must be re-issued; signatures are strict
base64url (standard base64 is rejected, not silently repaired); the
Gatekeeper no longer enforces cumulative bounds locally.

## Conformance vectors

`npm test` consumes the spec's published conformance vectors directly from
`content/0.7/vectors/*.json` (a sibling checkout of
[hap-protocol](https://github.com/humanagencyprotocol/hap-protocol) — see
`test/vectors/_spec-dir.ts`), rather than keeping a copy of their values in
this repo. If that sibling checkout is absent, the vector tests skip locally
with a warning but **fail** in CI (`CI=true`).

## License

MIT

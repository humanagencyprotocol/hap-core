# @humanagencyp/hap-core

Core types, cryptographic primitives, and verification logic for the [Human Agency Protocol](https://humanagencyprotocol.org).

## Install

```bash
npm install @humanagencyp/hap-core
```

## What's included

- **Types** — `AgentProfile`, `AgentBoundsParams`, `AgentContextParams`, execution context schemas, gate questions
- **Frame** — Canonical hashing of bounds and context (`computeBoundsHash`, `computeContextHash`)
- **Attestation** — Ed25519 signing and verification of attestation blobs
- **Gatekeeper** — Execution verification against bounds, context constraints, and cumulative tracking
- **Profiles** — Runtime profile registry (`registerProfile`, `getProfile`, `getAllProfiles`, `clearProfiles`)

## Usage

```typescript
import {
  type AgentProfile,
  computeBoundsHash,
  computeContextHash,
  verify,
  registerProfile,
  getProfile,
} from '@humanagencyp/hap-core';

// Register a profile
registerProfile(profile.id, profile);

// Compute deterministic hashes for bounds and context
const boundsHash = computeBoundsHash(bounds, profile);
const contextHash = computeContextHash(context, profile);

// Verify an execution against bounds and attestations
const result = await verify(
  { frame, attestations, execution, context },
  publicKeyHex,
);

if (result.approved) {
  // Execution is within bounds
}
```

## Constraint types

The gatekeeper enforces three types of constraints from the profile's bounds and context schemas:

| Type | Description | Example |
|---|---|---|
| `max` | Numeric upper bound | `amount_max: 1000` |
| `enum` | Value must be in allowed set | `currency: ["USD", "EUR"]` |
| `subset` | Every item must appear in bound | `allowed_domains: "acme.com,partner.org"` |

## Cumulative tracking

Bounds fields ending in `_daily_max` or `_monthly_max` are checked against cumulative execution logs. The gatekeeper resolves running totals from an `ExecutionLog` interface:

```typescript
interface ExecutionLog {
  sumByWindow(profileId: string, path: string, field: string, window: 'daily' | 'monthly'): Promise<number>;
}
```

## License

MIT

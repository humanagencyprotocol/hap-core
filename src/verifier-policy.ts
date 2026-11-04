/**
 * Verifier policy — `HAP-verifier-policy` (protocol.md → *Owner Signatures*
 * → *Verifier policy*, new in v0.8, specification-led).
 *
 * The relying party's own, declarative statement of what it demands of a
 * ticket (or projection) before acting on or trusting it. Every present
 * line is a conjunct; an unmet line is a refusal naming the line and its
 * code; absent lines impose nothing. The policy is never sent to the
 * Authority Server.
 */

import { HapError, type HapErrorCode } from './errors';
import type { Mandate, OwnerSignatureBinding } from './types';
import type { TicketPayload } from './ticket';
import { verifyTicketSignature, verifyTicketApprovals, approvalsSufficient } from './ticket';
import { verifyTicketProjection, verifyProjectionOwner, type TicketProjection } from './ticket-projection';
import { verifyMandateSignature } from './mandate';
import { verifyOwnerSignatures, bindingRank, BINDING_RANK } from './owner-signature';

export interface VerifierPolicy {
  typ: 'HAP-verifier-policy';
  version: string;
  trusted_issuers?: string[];
  min_binding?: OwnerSignatureBinding | string;
  required_owners?: string[];
  profile_hashes?: Record<string, string>;
  action_types?: string[];
  freshness_seconds?: number;
  required_fields?: string[];
  require_approval_signature?: boolean;
}

/** A refusal naming the policy line that failed. */
export class PolicyError extends HapError {
  constructor(public readonly line: keyof VerifierPolicy, code: HapErrorCode, message: string) {
    super(code, `${line}: ${message}`);
    this.name = 'PolicyError';
  }
}

export interface PolicyInput {
  /** The complete ticket, where the relying party holds it. */
  ticket?: TicketPayload;
  /** Or the projection, where only the public view was served. */
  projection?: TicketProjection;
  /** The mandate the artifact chains to, where the policy needs it
   * (`min_binding`, `required_owners`, `profile_hashes`, `require_approval_signature`). */
  mandate?: Mandate;
  now?: number;
  /** The relying party acts on the artifact (freshness applies to `valid_until`). */
  asAuthorization?: boolean;
  /** Whether the ticket's action exceeded an approval-kind cap — known to a
   * party that holds the mandate's caps and the execution context. */
  aboveCap?: boolean;
}

/**
 * Evaluate a policy (protocol.md → *Verifier policy*, "Evaluation"). The
 * artifact's own signature is verified first under `trusted_issuers` where
 * present, else under any resolvable issuer.
 * @throws PolicyError with the line and the code the table assigns.
 */
export async function evaluateVerifierPolicy(policy: VerifierPolicy, input: PolicyInput): Promise<void> {
  if (policy.typ !== 'HAP-verifier-policy') {
    throw new HapError('POLICY_UNMET', 'policy document must carry typ "HAP-verifier-policy"');
  }
  const artifact = input.ticket ?? input.projection;
  if (!artifact) throw new HapError('POLICY_UNMET', 'no ticket or projection to evaluate');
  const now = input.now ?? Math.floor(Date.now() / 1000);

  // trusted_issuers — an unlisted issuer, or a signature that does not verify
  // under the listed key, is reported as INVALID_SIGNATURE on purpose.
  try {
    if (input.ticket) {
      await verifyTicketSignature(input.ticket, { trustedIssuers: policy.trusted_issuers });
    } else if (input.projection) {
      await verifyTicketProjection(input.projection, { trustedIssuers: policy.trusted_issuers, now, asAuthorization: input.asAuthorization });
    }
    if (input.mandate) {
      await verifyMandateSignature(input.mandate, { trustedIssuers: policy.trusted_issuers });
    }
  } catch (err) {
    const code = err instanceof HapError ? err.code : 'INVALID_SIGNATURE';
    throw new PolicyError(code === 'POLICY_UNMET' ? 'freshness_seconds' : 'trusted_issuers', code, (err as Error).message);
  }

  // Owner signatures on the mandate — verified once, used by two lines.
  let verifiedOwnerDids: Map<string, string> | undefined; // did → binding
  const needOwners = policy.min_binding !== undefined || policy.required_owners !== undefined;
  if (needOwners) {
    verifiedOwnerDids = new Map();
    if (input.mandate) {
      try {
        const entries = await verifyOwnerSignatures(input.mandate);
        for (const e of entries) verifiedOwnerDids.set(e.did, e.binding ?? 'raw');
        if (input.projection?.owner) await verifyProjectionOwner(input.projection, input.mandate);
      } catch (err) {
        throw new PolicyError('min_binding', 'OWNER_SIGNATURE_REQUIRED', `no verifiable owner signature: ${(err as Error).message}`);
      }
    }
  }

  if (policy.min_binding !== undefined) {
    const minRank = BINDING_RANK[policy.min_binding as OwnerSignatureBinding];
    if (minRank === undefined) {
      throw new PolicyError('min_binding', 'OWNER_SIGNATURE_REQUIRED', `unknown binding "${policy.min_binding}" — satisfies no minimum`);
    }
    const best = Math.max(-1, ...[...verifiedOwnerDids!.values()].map(bindingRank));
    if (best < minRank) {
      throw new PolicyError('min_binding', 'OWNER_SIGNATURE_REQUIRED', `no verified owner signature at binding >= "${policy.min_binding}"`);
    }
  }

  if (policy.required_owners !== undefined) {
    for (const did of policy.required_owners) {
      if (!verifiedOwnerDids!.has(did)) {
        throw new PolicyError('required_owners', 'OWNER_SIGNATURE_REQUIRED', `no verified owner signature by ${did}`);
      }
    }
  }

  if (policy.profile_hashes !== undefined) {
    const mandate = input.mandate;
    if (!mandate) throw new PolicyError('profile_hashes', 'PROFILE_HASH_MISMATCH', 'the mandate is needed to check profile_hashes');
    const expected = policy.profile_hashes[mandate.payload.profile_id];
    if (expected === undefined) {
      throw new PolicyError('profile_hashes', 'PROFILE_HASH_MISMATCH', `profile ${mandate.payload.profile_id} is not listed`);
    }
    if (expected !== mandate.payload.profile_hash) {
      throw new PolicyError('profile_hashes', 'PROFILE_HASH_MISMATCH', `profile_hash differs from the listed one for ${mandate.payload.profile_id}`);
    }
    if (mandate.payload.mandate_id !== artifact.mandateId) {
      throw new PolicyError('profile_hashes', 'PROFILE_HASH_MISMATCH', 'the mandate supplied is not the one the artifact names');
    }
  }

  if (policy.action_types !== undefined && !policy.action_types.includes(artifact.actionType)) {
    throw new PolicyError('action_types', 'POLICY_UNMET', `actionType ${artifact.actionType} is not in the listed set`);
  }

  if (policy.freshness_seconds !== undefined) {
    if (now - artifact.timestamp > policy.freshness_seconds) {
      throw new PolicyError('freshness_seconds', 'POLICY_UNMET', `ticket is ${now - artifact.timestamp}s old, policy allows ${policy.freshness_seconds}s`);
    }
    if (input.projection && input.asAuthorization && now > input.projection.valid_until) {
      throw new PolicyError('freshness_seconds', 'POLICY_UNMET', 'projection presented after valid_until');
    }
  }

  if (policy.required_fields !== undefined) {
    const ctx = input.ticket?.executionContext ?? input.projection?.executionContext ?? {};
    for (const f of policy.required_fields) {
      if (ctx[f] === undefined) {
        throw new PolicyError('required_fields', 'POLICY_UNMET', `execution-context field ${f} is not ${input.ticket ? 'present' : 'disclosed'}`);
      }
    }
  }

  if (policy.require_approval_signature) {
    const ticket = input.ticket;
    const mandate = input.mandate;
    if (!ticket || !mandate) {
      throw new PolicyError('require_approval_signature', 'APPROVAL_SIGNATURE_REQUIRED', 'the complete ticket and its mandate are needed to verify approvals');
    }
    if (ticket.proposalId !== undefined) {
      let verified;
      try {
        verified = await verifyTicketApprovals(ticket, mandate);
      } catch (err) {
        throw new PolicyError('require_approval_signature', 'APPROVAL_SIGNATURE_REQUIRED', (err as Error).message);
      }
      const aboveCap = input.aboveCap ?? (ticket.approvalSignatures !== undefined && ticket.approvalSignatures.length > 0);
      if (!approvalsSufficient(mandate, verified, aboveCap)) {
        throw new PolicyError('require_approval_signature', 'APPROVAL_SIGNATURE_REQUIRED', 'the ticket lacks a verifiable signature for each decision it rests on');
      }
    }
  }
}

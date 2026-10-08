/**
 * Test fixtures — profile data for unit tests (v0.7 shape).
 *
 * These mirror the profiles in hap-profiles/ but are kept as test fixtures
 * so tests don't depend on git fetching.
 *
 * Names keep their historical "_V4" suffix (from when hap-core carried both
 * v0.3 frameSchema and v0.4 boundsSchema profiles side by side) even though
 * v0.3 is retired and these are now the only shape — renaming every
 * reference across the suite was out of scope for this change.
 */

import type { AgentProfile } from '../src/types';

/**
 * v0.7 email profile fixture — boundsSchema + scopeSchema with subset
 * constraints. No `path` field (protocol.md → *Bounds Derivation*: "There
 * is no path field in v0.5").
 */
export const EMAIL_PROFILE_V4: AgentProfile = {
  id: 'email@0.7',
  version: '0.7',
  name: 'Email',
  description: 'Email authority — governs sending, drafting, and reading email via Gmail',

  boundsSchema: {
    actionTypes: ['send', 'delete'],
    keyOrder: ['profile', 'recipient_max', 'send_daily_max'],
    fields: {
      profile: { type: 'string', required: true },
      recipient_max: {
        type: 'number',
        required: false,
        description: 'Maximum recipients per email',
        boundType: { kind: 'per_transaction', of: 'recipient_count' },
      },
      send_daily_max: {
        type: 'number',
        required: false,
        description: 'Maximum emails sent or drafted per day',
        boundType: { kind: 'cumulative_count', window: 'daily' },
        appliesTo: ['send'],
      },
    },
  },

  scopeSchema: {
    keyOrder: ['allowed_recipients', 'allowed_domains'],
    fields: {
      allowed_recipients: {
        type: 'string',
        required: false,
        description: 'Comma-separated list of allowed email addresses',
        constraint: { type: 'string', enforceable: ['subset'] },
      },
      allowed_domains: {
        type: 'string',
        required: false,
        description: 'Comma-separated list of allowed recipient domains',
        constraint: { type: 'string', enforceable: ['subset'] },
      },
    },
  },

  executionContextSchema: {
    fields: {
      recipient_count: {
        source: 'declared',
        description: 'Number of recipients in this email',
        required: true,
        constraint: { type: 'number', enforceable: ['max'] },
      },
      allowed_recipients: {
        source: 'declared',
        description: 'Comma-separated recipient addresses from this call (checked against scope)',
        required: false,
        constraint: { type: 'string', enforceable: ['subset'] },
      },
      allowed_domains: {
        source: 'declared',
        description: 'Comma-separated unique recipient domains from this call (checked against scope)',
        required: false,
        constraint: { type: 'string', enforceable: ['subset'] },
      },
      send_count_daily: {
        source: 'cumulative',
        cumulativeField: '_count',
        window: 'daily',
        description: 'Running daily send/draft count',
        required: true,
        constraint: { type: 'number', enforceable: ['max'] },
      },
    },
  },

  requiredGates: ['bounds', 'intent', 'commitment', 'mandate_owner'],

  ttl: { default: 86400, max: 86400 },
  retention_minimum: 7776000,
};

/**
 * v0.7 charge profile fixture — boundsSchema + scopeSchema.
 * Mirrors hap-profiles/charge/profile.json.
 */
export const CHARGE_PROFILE_V4: AgentProfile = {
  id: 'charge@0.7',
  version: '0.7',
  name: 'Financial Transactions',
  description: 'Financial authority — governs committing company money: charges, refunds, subscriptions, payouts',

  boundsSchema: {
    actionTypes: ['charge', 'refund', 'subscribe'],
    keyOrder: ['profile', 'amount_max', 'amount_daily_max', 'amount_monthly_max', 'transaction_count_daily_max'],
    fields: {
      profile: { type: 'string', required: true },
      amount_max: {
        type: 'number',
        required: true,
        description: 'Maximum monetary amount per transaction in currency units',
        boundType: { kind: 'per_transaction', of: 'amount' },
      },
      amount_daily_max: {
        type: 'number',
        required: true,
        description: 'Maximum cumulative charges per day in currency units',
        boundType: { kind: 'cumulative_sum', of: 'amount', window: 'daily' },
      },
      amount_monthly_max: {
        type: 'number',
        required: true,
        description: 'Maximum cumulative charges per month in currency units',
        boundType: { kind: 'cumulative_sum', of: 'amount', window: 'monthly' },
      },
      transaction_count_daily_max: {
        type: 'number',
        required: true,
        description: 'Maximum number of transactions per day',
        boundType: { kind: 'cumulative_count', window: 'daily' },
        appliesTo: ['charge', 'refund', 'subscribe'],
      },
    },
  },

  scopeSchema: {
    keyOrder: ['currency', 'action_type'],
    fields: {
      currency: {
        type: 'string',
        required: true,
        description: 'Permitted currency code',
        constraint: { type: 'string', enforceable: ['enum'] },
      },
      action_type: {
        type: 'string',
        required: true,
        description: 'Authorized financial operation (charge, refund, subscribe)',
        constraint: { type: 'string', enforceable: ['enum'] },
      },
    },
  },

  executionContextSchema: {
    fields: {
      action_type: {
        source: 'declared',
        description: 'Financial operation being performed',
        required: true,
        constraint: { type: 'string', enforceable: ['enum'] },
      },
      amount: {
        source: 'declared',
        description: 'Monetary amount in currency units',
        required: true,
        constraint: { type: 'number', enforceable: ['max'] },
      },
      currency: {
        source: 'declared',
        description: 'Currency code',
        required: true,
        constraint: { type: 'string', enforceable: ['enum'] },
      },
      amount_daily: {
        source: 'cumulative',
        cumulativeField: 'amount',
        window: 'daily',
        description: 'Running daily charge total (resolved from AS ticket history)',
        required: true,
        constraint: { type: 'number', enforceable: ['max'] },
      },
      amount_monthly: {
        source: 'cumulative',
        cumulativeField: 'amount',
        window: 'monthly',
        description: 'Running monthly charge total (resolved from AS ticket history)',
        required: true,
        constraint: { type: 'number', enforceable: ['max'] },
      },
      transaction_count_daily: {
        source: 'cumulative',
        cumulativeField: '_count',
        window: 'daily',
        description: 'Running daily transaction count (resolved from AS ticket history)',
        required: true,
        constraint: { type: 'number', enforceable: ['max'] },
      },
    },
  },

  requiredGates: ['bounds', 'intent', 'commitment', 'mandate_owner'],

  ttl: { default: 86400, max: 86400 },
  retention_minimum: 7776000,
};

/**
 * Test fixtures — profile data for unit tests.
 *
 * These mirror the profiles in hap-profiles/ but are kept as test fixtures
 * so tests don't depend on git fetching.
 */

import type { AgentProfile } from '../src/types';

export const SPEND_PROFILE: AgentProfile = {
  id: 'spend@0.3',
  version: '0.3',
  name: 'Financial Transactions',
  description: 'Financial authority — governs committing company money: charges, refunds, subscriptions, payouts',

  frameSchema: {
    keyOrder: ['profile', 'path', 'amount_max', 'currency', 'action_type'],
    fields: {
      profile: { type: 'string', required: true },
      path: { type: 'string', required: true },
      amount_max: {
        type: 'number',
        required: true,
        description: 'Maximum monetary amount per transaction in currency units',
        constraint: { type: 'number', enforceable: ['max'] },
      },
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
    },
  },

  executionPaths: {
    'spend-routine': {
      description: 'Day-to-day financial transactions within authorized bounds',
      requiredDomains: ['finance'],
    },
    'spend-reviewed': {
      description: 'Large or unusual transactions requiring dual authorization',
      requiredDomains: ['finance', 'compliance'],
      ttl: { default: 14400, max: 86400 },
    },
  },

  requiredGates: ['frame', 'problem', 'objective', 'tradeoff', 'commitment', 'decision_owner'],

  gateQuestions: {
    problem: { question: 'What problem does this financial authority address?', required: true },
    objective: { question: 'What outcome should this spending authority enable?', required: true },
    tradeoffs: { question: 'What financial risks do you accept with this authority?', required: true },
  },

  ttl: { default: 86400, max: 86400 },
  retention_minimum: 7776000,
};

export const EMAIL_PROFILE: AgentProfile = {
  id: 'email@0.3',
  version: '0.3',
  name: 'Email',
  description: 'Email authority — governs sending, drafting, and reading email via Gmail',

  frameSchema: {
    keyOrder: ['profile', 'path', 'recipient_max', 'send_daily_max', 'read_max_age_days', 'read_daily_max'],
    fields: {
      profile: { type: 'string', required: true },
      path: { type: 'string', required: true },
      recipient_max: {
        type: 'number',
        required: false,
        description: 'Maximum recipients per email (send/draft paths)',
        constraint: { type: 'number', enforceable: ['max'] },
      },
      send_daily_max: {
        type: 'number',
        required: false,
        description: 'Maximum emails sent or drafted per day',
        constraint: { type: 'number', enforceable: ['max'] },
      },
      read_max_age_days: {
        type: 'number',
        required: false,
        description: 'Maximum age in days for email search (read path)',
        constraint: { type: 'number', enforceable: ['max'] },
      },
      read_daily_max: {
        type: 'number',
        required: false,
        description: 'Maximum emails read per day (read path)',
        constraint: { type: 'number', enforceable: ['max'] },
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
      send_count_daily: {
        source: 'cumulative',
        cumulativeField: '_count',
        window: 'daily',
        description: 'Running daily send/draft count (resolved from execution log)',
        required: true,
        constraint: { type: 'number', enforceable: ['max'] },
      },
    },
  },

  executionPaths: {
    'email-draft': {
      description: 'Create email drafts for human review before sending',
      requiredDomains: ['communications'],
    },
    'email-send': {
      description: 'Send emails directly within authorized bounds',
      requiredDomains: ['communications'],
      ttl: { default: 14400, max: 86400 },
    },
    'email-read': {
      description: 'Read and search inbox within time and volume bounds',
      requiredDomains: ['communications'],
    },
  },

  requiredGates: ['frame', 'problem', 'objective', 'tradeoff', 'commitment', 'decision_owner'],

  gateQuestions: {
    problem: { question: 'What problem does this email authority address?', required: true },
    objective: { question: 'What outcome should this email authority enable?', required: true },
    tradeoffs: { question: 'What risks do you accept with this email authority?', required: true },
  },

  ttl: { default: 86400, max: 86400 },
  retention_minimum: 7776000,
};

/**
 * v0.4 spend profile fixture — uses boundsSchema + contextSchema instead of frameSchema.
 * Mirrors /hap-profiles/spend/profile.json at v0.4.
 */
export const SPEND_PROFILE_V4: AgentProfile = {
  id: 'spend@0.4',
  version: '0.4',
  name: 'Financial Transactions',
  description: 'Financial authority — governs committing company money: charges, refunds, subscriptions, payouts',

  boundsSchema: {
    keyOrder: ['profile', 'path', 'amount_max', 'amount_daily_max', 'amount_monthly_max', 'transaction_count_daily_max'],
    fields: {
      profile: { type: 'string', required: true },
      path: { type: 'string', required: true },
      amount_max: {
        type: 'number',
        required: true,
        description: 'Maximum monetary amount per transaction in currency units',
        constraint: { type: 'number', enforceable: ['max'] },
      },
      amount_daily_max: {
        type: 'number',
        required: true,
        description: 'Maximum cumulative spend per day in currency units',
        constraint: { type: 'number', enforceable: ['max'] },
      },
      amount_monthly_max: {
        type: 'number',
        required: true,
        description: 'Maximum cumulative spend per month in currency units',
        constraint: { type: 'number', enforceable: ['max'] },
      },
      transaction_count_daily_max: {
        type: 'number',
        required: true,
        description: 'Maximum number of transactions per day',
        constraint: { type: 'number', enforceable: ['max'] },
      },
    },
  },

  contextSchema: {
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
        description: 'Running daily spend total (resolved from execution log)',
        required: true,
        constraint: { type: 'number', enforceable: ['max'] },
      },
      amount_monthly: {
        source: 'cumulative',
        cumulativeField: 'amount',
        window: 'monthly',
        description: 'Running monthly spend total (resolved from execution log)',
        required: true,
        constraint: { type: 'number', enforceable: ['max'] },
      },
      transaction_count_daily: {
        source: 'cumulative',
        cumulativeField: '_count',
        window: 'daily',
        description: 'Running daily transaction count (resolved from execution log)',
        required: true,
        constraint: { type: 'number', enforceable: ['max'] },
      },
    },
  },

  executionPaths: {
    'spend-routine': {
      description: 'Day-to-day financial transactions within authorized bounds',
      requiredDomains: ['finance'],
      ttl: { default: 86400, max: 86400 },
    },
    'spend-reviewed': {
      description: 'Large or unusual transactions requiring dual authorization',
      requiredDomains: ['finance', 'compliance'],
      ttl: { default: 14400, max: 86400 },
    },
  },

  requiredGates: ['bounds', 'problem', 'objective', 'tradeoff', 'commitment', 'decision_owner'],

  gateQuestions: {
    problem: { question: 'What problem does this financial authority address?', required: true },
    objective: { question: 'What outcome should this spending authority enable?', required: true },
    tradeoffs: { question: 'What financial risks do you accept with this authority?', required: true },
  },

  ttl: { default: 86400, max: 86400 },
  retention_minimum: 7776000,
};

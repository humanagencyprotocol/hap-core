/**
 * Test fixtures — profile data for unit tests.
 *
 * These mirror the profiles in hap-profiles/ but are kept as test fixtures
 * so tests don't depend on git fetching.
 */

import type { AgentProfile } from '../src/types';

export const CHARGE_PROFILE: AgentProfile = {
  id: 'charge@0.3',
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
    'charge-routine': {
      description: 'Day-to-day financial transactions within authorized bounds',
      requiredDomains: ['finance'],
    },
    'charge-reviewed': {
      description: 'Large or unusual transactions requiring dual authorization',
      requiredDomains: ['finance', 'compliance'],
      ttl: { default: 14400, max: 86400 },
    },
  },

  requiredGates: ['frame', 'problem', 'objective', 'tradeoff', 'commitment', 'decision_owner'],

  gateQuestions: {
    problem: { question: 'What problem does this financial authority address?', required: true },
    objective: { question: 'What outcome should this charge authority enable?', required: true },
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
 * v0.4 email profile fixture — uses boundsSchema + contextSchema with subset constraints.
 */
export const EMAIL_PROFILE_V4: AgentProfile = {
  id: 'email@0.4',
  version: '0.4',
  name: 'Email',
  description: 'Email authority — governs sending, drafting, and reading email via Gmail',

  boundsSchema: {
    keyOrder: ['profile', 'path', 'recipient_max', 'send_daily_max'],
    fields: {
      profile: { type: 'string', required: true },
      path: { type: 'string', required: true },
      recipient_max: {
        type: 'number',
        required: false,
        description: 'Maximum recipients per email',
        constraint: { type: 'number', enforceable: ['max'] },
      },
      send_daily_max: {
        type: 'number',
        required: false,
        description: 'Maximum emails sent or drafted per day',
        constraint: { type: 'number', enforceable: ['max'] },
      },
    },
  },

  contextSchema: {
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
        description: 'Comma-separated recipient addresses from this call (checked against context)',
        required: false,
        constraint: { type: 'string', enforceable: ['subset'] },
      },
      allowed_domains: {
        source: 'declared',
        description: 'Comma-separated unique recipient domains from this call (checked against context)',
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

  executionPaths: {
    'email-send': {
      description: 'Send emails directly within authorized bounds',
      requiredDomains: ['communications'],
      ttl: { default: 14400, max: 86400 },
    },
    'email-draft': {
      description: 'Create email drafts for human review before sending',
      requiredDomains: ['communications'],
    },
  },

  requiredGates: ['bounds', 'problem', 'objective', 'tradeoff', 'commitment', 'decision_owner'],

  gateQuestions: {
    problem: { question: 'What problem does this email authority address?', required: true },
    objective: { question: 'What outcome should this email authority enable?', required: true },
    tradeoffs: { question: 'What risks do you accept with this email authority?', required: true },
  },

  ttl: { default: 86400, max: 86400 },
  retention_minimum: 7776000,
};

/**
 * v0.4 charge profile fixture — uses boundsSchema + contextSchema instead of frameSchema.
 * Mirrors /hap-profiles/charge/profile.json at v0.4.
 */
export const CHARGE_PROFILE_V4: AgentProfile = {
  id: 'charge@0.4',
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
        description: 'Maximum cumulative charges per day in currency units',
        constraint: { type: 'number', enforceable: ['max'] },
      },
      amount_monthly_max: {
        type: 'number',
        required: true,
        description: 'Maximum cumulative charges per month in currency units',
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
        description: 'Running daily charge total (resolved from execution log)',
        required: true,
        constraint: { type: 'number', enforceable: ['max'] },
      },
      amount_monthly: {
        source: 'cumulative',
        cumulativeField: 'amount',
        window: 'monthly',
        description: 'Running monthly charge total (resolved from execution log)',
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
    'charge-routine': {
      description: 'Day-to-day financial transactions within authorized bounds',
      requiredDomains: ['finance'],
      ttl: { default: 86400, max: 86400 },
    },
    'charge-reviewed': {
      description: 'Large or unusual transactions requiring dual authorization',
      requiredDomains: ['finance', 'compliance'],
      ttl: { default: 14400, max: 86400 },
    },
  },

  requiredGates: ['bounds', 'problem', 'objective', 'tradeoff', 'commitment', 'decision_owner'],

  gateQuestions: {
    problem: { question: 'What problem does this financial authority address?', required: true },
    objective: { question: 'What outcome should this charge authority enable?', required: true },
    tradeoffs: { question: 'What financial risks do you accept with this authority?', required: true },
  },

  ttl: { default: 86400, max: 86400 },
  retention_minimum: 7776000,
};

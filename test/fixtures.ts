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

export const PUBLISH_PROFILE: AgentProfile = {
  id: 'publish@0.3',
  version: '0.3',
  description: 'External communication authority — governs sending anything externally as the company',

  frameSchema: {
    keyOrder: ['profile', 'path', 'channel', 'audience', 'recipient_max', 'scope'],
    fields: {
      profile: { type: 'string', required: true },
      path: { type: 'string', required: true },
      channel: {
        type: 'string',
        required: true,
        description: 'Communication channel (email, webhook, notification)',
        constraint: { type: 'string', enforceable: ['enum'] },
      },
      audience: {
        type: 'string',
        required: true,
        description: 'Audience scope (individual, segment, all)',
        constraint: { type: 'string', enforceable: ['enum'] },
      },
      recipient_max: {
        type: 'number',
        required: true,
        description: 'Maximum recipients per send operation',
        constraint: { type: 'number', enforceable: ['max'] },
      },
      scope: {
        type: 'string',
        required: true,
        description: 'Impact scope (external = real customers, internal = test accounts)',
        constraint: { type: 'string', enforceable: ['enum'] },
      },
    },
  },

  executionContextSchema: {
    fields: {
      channel: {
        source: 'declared',
        description: 'Communication channel being used',
        required: true,
        constraint: { type: 'string', enforceable: ['enum'] },
      },
      audience: {
        source: 'declared',
        description: 'Audience scope for this send',
        required: true,
        constraint: { type: 'string', enforceable: ['enum'] },
      },
      recipient_count: {
        source: 'declared',
        description: 'Number of recipients in this send',
        required: true,
        constraint: { type: 'number', enforceable: ['max'] },
      },
      scope: {
        source: 'declared',
        description: 'Impact scope of this send',
        required: true,
        constraint: { type: 'string', enforceable: ['enum'] },
      },
    },
  },

  executionPaths: {
    'publish-transactional': {
      description: 'System emails — password resets, receipts, notifications',
      requiredDomains: ['engineering'],
    },
    'publish-marketing': {
      description: 'Campaigns and announcements to segments',
      requiredDomains: ['marketing', 'product'],
      ttl: { default: 7200, max: 86400 },
    },
  },

  requiredGates: ['frame', 'problem', 'objective', 'tradeoff', 'commitment', 'decision_owner'],

  gateQuestions: {
    problem: { question: 'What problem does this communication authority address?', required: true },
    objective: { question: 'What outcome should this communication authority enable?', required: true },
    tradeoffs: { question: 'What communication risks do you accept with this authority?', required: true },
  },

  ttl: { default: 86400, max: 86400 },
  retention_minimum: 7776000,
};

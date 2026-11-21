import type { SuppressionsDto } from '../types.js';

/** The local preview's Suppressions section: one active rule and one suggestion. */
export const SUPPRESSIONS_FIXTURE: SuppressionsDto = {
  maxDays: 90,
  rules: [
    {
      id: 'sup_01JDEMO0000000000000000000',
      projectKey: 'PAY',
      stride: 'DenialOfService',
      title: 'Unauthenticated endpoint abused for resource exhaustion',
      reason: 'Every PAY endpoint sits behind the gateway rate limiter (platform standard PS-12).',
      createdBy: '712020:champion',
      createdAt: '2026-11-01T10:00:00.000Z',
      expiresAt: '2027-01-30T10:00:00.000Z',
      status: 'active',
      evidence: ['PAY-12', 'PAY-15', 'PAY-21'],
      matches: 4,
    },
  ],
  suggestions: [
    {
      projectKey: 'PAY',
      stride: 'InformationDisclosure',
      title: 'Customer email leaks in webhook logs',
      component: 'webhook endpoint',
      workItems: 3,
      suggestedReason: 'Dismissed as already mitigated on 3 work items (PAY-31, PAY-28, PAY-22).',
      evidence: [
        { issueKey: 'PAY-31', title: 'Customer email leaks in webhook logs', reason: 'already_mitigated', actor: '712020:champion', at: '2026-11-17T09:00:00.000Z' },
        { issueKey: 'PAY-28', title: 'Customer email written to webhook logs', reason: 'already_mitigated', actor: '712020:champion', at: '2026-11-10T09:00:00.000Z' },
        { issueKey: 'PAY-22', title: 'Customer email leaks in webhook logs', reason: 'false_positive', actor: '712020:lead', at: '2026-11-02T09:00:00.000Z' },
      ],
    },
  ],
};

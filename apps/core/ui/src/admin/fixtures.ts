import type { AdminPolicyDto, RunDto, SitePolicy, UsageDto } from '../types.js';

/** The local preview's policy (the shipped defaults with PAY turned on). */
export const POLICY_FIXTURE: SitePolicy = {
  blockAtOrAbove: 'High',
  guardedTransitions: ['Done'],
  enabledProjects: ['PAY'],
  reviewIssueTypes: ['Epic', 'Story'],
  techLeadGroup: 'threatline-tech-leads',
  championGroup: 'threatline-security-champions',
  maxExpiryDays: { Critical: 30, default: 90 },
  techLeadMaxSeverity: 'Medium',
  agentSamples: 3,
  agentTimeoutMinutes: 15,
  warnOnly: [],
  attestationTtlHours: 24,
  sensitivePaths: ['src/auth/**', '**/auth/**', '**/payments/**', '**/crypto/**', 'infra/**', '.github/workflows/**', '**/*.pem'],
  budget: { tokensInPerReview: 40000, tokensOutPerReview: 8000, reviewsPerMonth: 500 },
};

export const ADMIN_POLICY_FIXTURE: AdminPolicyDto = {
  policy: POLICY_FIXTURE,
  saved: true,
  ops: null,
  digest: null,
  recentReviewAuthors: [{ accountId: '712020:automation-owner', runs: 42, lastAt: '2026-11-18T09:31:00.000Z' }],
};

const t = (m: number) => new Date(Date.UTC(2026, 10, 18, 9, m)).toISOString();
export const RUNS_FIXTURE: RunDto[] = [
  {
    reviewId: 'rev_10044_1', issueKey: 'PAY-9', revision: 1, status: 'agent_timeout', failureReason: null, partial: false, samplesExpected: 3, samplesReceived: 1,
    tokensIn: 0, tokensOut: 0, promptVersion: '1.2.0', createdAt: t(30), durationMs: 15 * 60_000,
    stages: [
      { stage: 'gather', status: 'done', at: t(30), ms: 0 },
      { stage: 'agent_1', status: 'done', at: t(31), ms: 60_000 },
      { stage: 'agent', status: 'failed', error: 'agent_timeout', at: t(45), ms: 14 * 60_000 },
    ],
  },
  {
    reviewId: 'rev_10042_2', issueKey: 'PAY-7', revision: 2, status: 'ready', failureReason: null, partial: false, samplesExpected: 3, samplesReceived: 3,
    tokensIn: 0, tokensOut: 0, promptVersion: '1.2.0', createdAt: t(0), durationMs: 47_000,
    stages: [
      { stage: 'first_look', status: 'done', at: t(0), ms: 0 },
      { stage: 'gather', status: 'done', at: t(0), ms: 0 },
      { stage: 'agent_1', status: 'done', at: new Date(Date.parse(t(0)) + 21_000).toISOString(), ms: 21_000 },
      { stage: 'assemble', status: 'done', at: new Date(Date.parse(t(0)) + 47_000).toISOString(), ms: 26_000 },
      { stage: 'comment', status: 'done', at: new Date(Date.parse(t(0)) + 48_000).toISOString(), ms: 1_000 },
    ],
  },
  {
    reviewId: 'rev_10050_1', issueKey: 'PAY-12', revision: 1, status: 'failed', failureReason: 'budget', partial: false, samplesExpected: 0, samplesReceived: 0,
    tokensIn: 0, tokensOut: 0, promptVersion: '1.2.0', createdAt: t(-60), durationMs: 0,
    stages: [{ stage: 'gather', status: 'failed', error: 'budget', at: t(-60), ms: 0 }],
  },
];

export const USAGE_FIXTURE: UsageDto = {
  month: '2026-11', reviews: 42, tokensIn: 0, tokensOut: 0, agentSamples: 118, agentSamplesPerReview: 3,
  budget: POLICY_FIXTURE.budget, paused: { budget: false, credits: false },
};

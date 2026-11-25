import type { Accuracy, DrillDto, PostureDto, ReleaseReadinessResult } from '../types.js';

const day = (n: number) => new Date(Date.UTC(2026, 10, 17 - n)).toISOString().slice(0, 10);

const few = (n: number) => ({ n, share: null, low: null, high: null, enough: false });

/**
 * Accuracy here (docs/ACCURACY.md), believable for a team a quarter in: PAY has enough decisions for every figure; OPS is
 * new and has too few champion decisions and closed blocking requirements for a percentage. Overall = PAY + OPS.
 */
export const ACCURACY_FIXTURE: Accuracy = {
  windowDays: 90,
  since: '2026-08-19T12:00:00.000Z',
  champion: { confirmed: 14, dismissed: 3, notCounted: 2, rate: { n: 17, share: 0.8235, low: 0.5897, high: 0.9381, enough: true } },
  blocking: { fixed: 24, accepted: 7, dismissed: 3, notCounted: 1, medianHoursToVerify: 52, rate: { n: 34, share: 0.9118, low: 0.7704, high: 0.9695, enough: true } },
  verifier: { kept: 118, doubted: 18, rate: { n: 136, share: 0.8676, low: 0.8005, high: 0.9146, enough: true } },
  byProject: [
    {
      project: 'OPS',
      champion: { confirmed: 2, dismissed: 1, notCounted: 0, rate: few(3) },
      blocking: { fixed: 3, accepted: 0, dismissed: 1, notCounted: 0, medianHoursToVerify: 70, rate: few(4) },
      verifier: { kept: 14, doubted: 3, rate: { n: 17, share: 0.8235, low: 0.5897, high: 0.9381, enough: true } },
    },
    {
      project: 'PAY',
      champion: { confirmed: 12, dismissed: 2, notCounted: 2, rate: { n: 14, share: 0.8571, low: 0.6006, high: 0.9599, enough: true } },
      blocking: { fixed: 21, accepted: 7, dismissed: 2, notCounted: 1, medianHoursToVerify: 50, rate: { n: 30, share: 0.9333, low: 0.7868, high: 0.9815, enough: true } },
      verifier: { kept: 104, doubted: 15, rate: { n: 119, share: 0.8739, low: 0.8024, high: 0.9221, enough: true } },
    },
  ],
};

/** No decision in the window yet (a new install): the card's empty state. */
export const ACCURACY_EMPTY: Accuracy = {
  windowDays: 90,
  since: '2026-08-19T12:00:00.000Z',
  champion: { confirmed: 0, dismissed: 0, notCounted: 0, rate: few(0) },
  blocking: { fixed: 0, accepted: 0, dismissed: 0, notCounted: 0, medianHoursToVerify: null, rate: few(0) },
  verifier: { kept: 0, doubted: 0, rate: few(0) },
  byProject: [],
};

/** A believable PAY posture for the local preview and the UI tests. */
export const POSTURE_FIXTURE: PostureDto = {
  openBySeverity: { Low: 2, Medium: 10, High: 21, Critical: 3 },
  byTeamComponent: [
    { team: 'PAY', component: 'payments', open: 30, maxSeverity: 'Critical' },
    { team: 'PAY', component: 'None', open: 4, maxSeverity: 'High' },
    { team: 'OPS', component: 'gateway', open: 2, maxSeverity: 'Medium' },
  ],
  overdue: { total: 4, bySeverity: { Low: 0, Medium: 1, High: 1, Critical: 2 } },
  expiringIn14d: 1,
  meanTimeToVerifyHours: 18.4,
  topRiskyComponents: [
    { component: 'payments', score: 377 },
    { component: 'gateway', score: 6 },
  ],
  projects: ['PAY', 'OPS'],
  issuesCounted: 5,
  expiring: [{ acceptanceId: 'acc_1', issueKey: 'PAY-7', requirementId: 'req_1', severity: 'High', expiresAt: '2026-11-24T00:00:00.000Z' }],
  hiddenExpiring: 0,
  truncated: false,
  trend: Array.from({ length: 10 }, (_, i) => ({ day: day(9 - i), openCritical: Math.max(3, 6 - Math.floor(i / 2)), openHigh: 26 - i + (i % 3 === 0 ? 1 : 0) })),
  trendShown: true,
  inFlight: 2,
  accuracy: ACCURACY_FIXTURE,
};

export const DRILL_FIXTURE: DrillDto = {
  jql: 'key in (PAY-7, PAY-12) ORDER BY key ASC',
  searchUrl: `https://example.atlassian.net/issues/?jql=${encodeURIComponent('key in (PAY-7, PAY-12) ORDER BY key ASC')}`,
  issues: [
    { key: 'PAY-7', summary: 'Add AI support agent that can issue refunds', maxOpenSeverity: 'Critical', url: 'https://example.atlassian.net/browse/PAY-7' },
    { key: 'PAY-12', summary: 'Verify refund webhook signatures', maxOpenSeverity: 'High', url: 'https://example.atlassian.net/browse/PAY-12' },
  ],
  truncated: false,
};

export const RELEASE_FIXTURE = (fixVersion: string): ReleaseReadinessResult => ({
  fixVersion,
  call: 'No-go',
  answer: 'No-go',
  items: 3,
  outOfScope: 1,
  blockers: [{ issueKey: 'PAY-7', reasons: ['8 open security requirements at High or above.'] }],
  conditions: [],
  expiringSoon: [],
  truncated: false,
});

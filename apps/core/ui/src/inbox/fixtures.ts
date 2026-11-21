import type { InboxDto, InboxRow } from '../types.js';

const SITE = 'https://example.atlassian.net';
const row = (o: Partial<InboxRow> & Pick<InboxRow, 'threatId' | 'issueId' | 'issueKey' | 'title'>): InboxRow => ({
  reviewId: `rev_${o.issueId}_1`,
  summary: 'Password reset by magic link',
  url: `${SITE}/browse/${o.issueKey}`,
  plainLanguage: '',
  stride: 'Spoofing',
  severity: 'High',
  reasons: [{ code: 'needs_review', message: 'Threatline could not settle it by itself.' }],
  duplicateOf: null,
  raisedAt: '2026-11-12T09:00:00.000Z',
  ...o,
});

/** Local preview and tests: `?view=posture` → Champion inbox. Two clusters and a single, most urgent first. */
export const INBOX_FIXTURE: InboxDto = {
  now: '2026-11-18T09:00:00.000Z',
  total: 5,
  hidden: 1,
  truncated: false,
  cursor: null,
  clusters: [
    {
      id: 'thr_9_1',
      kind: 'similar',
      rows: [
        row({
          threatId: 'thr_9_1', issueId: '66409', issueKey: 'PAY-9', summary: 'Partner refunds API', title: 'Forged refund webhooks', severity: 'Critical',
          plainLanguage: 'Anyone could fake a refund event and get paid.', raisedAt: '2026-11-08T09:00:00.000Z',
          reasons: [{ code: 'injection', message: 'It rests on text that looked like instructions to an AI, so Threatline will not settle it by itself.' }],
        }),
        row({
          threatId: 'thr_7_1', issueId: '66407', issueKey: 'PAY-7', summary: 'Refund webhook', title: 'Forged refund webhooks',
          plainLanguage: 'Anyone could fake a refund event.',
          reasons: [{ code: 'verifier_doubt', message: 'The verifier doubted it: The quote does not say the webhook is unsigned.' }],
        }),
      ],
    },
    {
      id: 'thr_6_1',
      kind: 'duplicate',
      rows: [
        row({
          threatId: 'thr_6_1', issueId: '66406', issueKey: 'PAY-6', title: 'Magic links never expire', raisedAt: '2026-11-16T05:30:43.000Z',
          reasons: [{ code: 'verifier_doubt', message: 'The verifier doubted it: Expiry is not mentioned either way.' }],
        }),
        row({
          threatId: 'thr_6_2', issueId: '66406', issueKey: 'PAY-6', title: 'Old sign-in links reused after a password change', raisedAt: '2026-11-16T05:30:43.000Z',
          reasons: [{ code: 'duplicate', message: 'The verifier says it repeats “Magic links never expire”: Same attack and harm.' }],
          duplicateOf: { threatId: 'thr_6_1', title: 'Magic links never expire' },
        }),
      ],
    },
    {
      id: 'thr_3_1',
      kind: 'single',
      rows: [
        row({
          threatId: 'thr_3_1', issueId: '66403', issueKey: 'PAY-3', summary: 'Card vault logging', title: 'Card numbers written to logs', stride: 'InformationDisclosure', severity: 'Medium',
          raisedAt: '2026-11-17T12:00:00.000Z', reasons: [{ code: 'weak_evidence', message: 'Its quotes were not all found word for word in the sources.' }],
        }),
      ],
    },
  ],
};

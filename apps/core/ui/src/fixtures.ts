import type { FactDto, PanelDto, SeenBeforeDto, Threat, ThreatDiffDto } from './types.js';
import { REQUIREMENT_CONTROLS_FIXTURE } from './compliance-fixtures.js';
import { DIAGRAM_FIXTURE } from './diagram-fixture.js';

const now = '2026-11-16T05:31:25.000Z';
const fact = (id: string, title: string, over: Partial<FactDto> = {}): FactDto => ({
  id, sourceType: 'jira_issue', title, url: '/browse/PAY-6', trust: 'untrusted', injectionSuspected: false, injectionReasons: [], origin: 'rest', ...over,
});
export const FACTS: FactDto[] = [
  fact('fact_meta', 'PAY-6 (Story)', { trust: 'trusted' }),
  fact('fact_body', 'PAY-6 Password reset by magic link'),
  fact('fact_page', 'Magic link design', { sourceType: 'confluence_page', url: 'https://example.atlassian.net/wiki/spaces/PAY/pages/1' }),
];

const threat = (i: number, over: Partial<Threat>): Threat => ({
  id: `thr_${i}`, reviewId: 'rev_66405_1', stride: 'Spoofing', title: 'Magic links never expire', scenario: 'An attacker who finds an old email reuses the sign-in link weeks later.',
  component: 'password reset', likelihood: 4, impact: 4, severity: 'High', votes: 3, samples: 3, grounding: 'supported', confidence: 0.9, state: 'accepted', origin: 'agent',
  citations: [{ factId: 'fact_body', quote: 'Tokens are stored in the users table and do not expire until used.' }],
  mappings: [{ framework: 'ASVS5', refId: 'V2.1.1' }, { framework: 'CWE', refId: 'CWE-640' }],
  plainLanguage: 'Someone could reuse an old sign-in link to take over an account.', ...over,
});

const UNSORTED: Threat[] = [
  threat(1, { component: 'Magic link service' }),
  threat(2, { component: 'Reset API', stride: 'InformationDisclosure', title: 'Reset page reveals which emails have accounts', severity: 'Medium', votes: 2, plainLanguage: 'Anyone can learn which email addresses are customers.', citations: [{ factId: 'fact_body', quote: 'The reset page is public and accepts any email address.' }], mappings: [{ framework: 'CWE', refId: 'CWE-204' }] }),
  threat(3, { component: 'Account settings', stride: 'ElevationOfPrivilege', title: 'Account takeover by changing the email after sign-in', severity: 'Critical', votes: 3, plainLanguage: 'A stolen link lets an attacker lock the real owner out for good.', citations: [{ factId: 'fact_body', quote: 'After sign-in the customer can change the email address and phone number on the account.' }] }),
  threat(4, { component: 'reset-api', origin: 'baseline', stride: 'DenialOfService', title: 'Reset endpoint can be flooded', severity: 'Low', votes: 0, plainLanguage: 'Someone could send thousands of reset emails.', grounding: 'weak', state: 'needs_human', citations: [{ factId: 'fact_page', quote: 'The reset page is public' }] }),
];

const RANK = { Critical: 4, High: 3, Medium: 2, Low: 1 } as const;
/** Same order as the resolver: most severe first. */
export const THREATS: Threat[] = [...UNSORTED].sort((a, b) => RANK[b.severity] - RANK[a.severity]);

const base: PanelDto = {
  issueId: '66405', issueKey: 'PAY-6',
  verdict: { state: 'block', reviewId: 'rev_66405_1', revision: 1, blockingCount: 2, maxOpenSeverity: 'Critical', reasons: [{ code: 'open_requirement', message: '2 open security requirements at High or above.', requirementIds: ['req_1', 'req_2'] }], inheritedFrom: [], updatedAt: now, panelUrl: '/browse/PAY-6' },
  review: { id: 'rev_66405_1', issueId: '66405', issueKey: 'PAY-6', revision: 1, status: 'ready', contextHash: 'h', riskScore: 72, partial: false, promptVersion: 'v1.1.0', modelIds: [], samplesExpected: 3, samplesReceived: 3, tokensIn: 0, tokensOut: 0, createdAt: '2026-11-16T05:30:43.000Z', updatedAt: now },
  threats: THREATS, threatsCursor: null, threatsTotal: THREATS.length, hiddenThreats: 0, covered: [], hiddenDiscarded: 0, hiddenRequirements: 0,
  discarded: [{ title: 'Quantum computers break the token', stride: 'InformationDisclosure', reason: 'unsupported_citation' }, { title: 'SQL injection in reset form', stride: 'Tampering', reason: 'low_votes' }],
  facts: FACTS,
  requirements: [
    { id: 'req_1', threatId: 'thr_3', issueId: '66405', issueKey: 'PAY-6', title: 'Re-authenticate before changing the account email', criteria: [{ given: 'a signed-in customer', when: 'they change the email address', then: 'they must re-enter a one-time code sent to the old address' }], asvsIds: ['V2.1.1'], severity: 'Critical', status: 'Open', createdAt: '2026-11-01T09:00:00.000Z' },
    { id: 'req_2', threatId: 'thr_1', issueId: '66405', issueKey: 'PAY-6', title: 'Magic links expire after 15 minutes', criteria: [{ given: 'a magic link', when: 'it is older than 15 minutes or already used', then: 'sign-in is refused' }], asvsIds: [], severity: 'High', status: 'Open', createdAt: '2026-11-16T05:31:25.000Z' },
  ],
  acceptances: [],
  viewerAccountId: 'acc-dev',
  acceptancePolicy: { maxExpiryDays: { Critical: 30, default: 90 }, techLeadMaxSeverity: 'Medium', championGroup: 'threatline-security-champions', techLeadGroup: 'threatline-tech-leads' },
  history: [{ revision: 1, createdAt: '2026-11-16T05:30:43.000Z', riskScore: 72, status: 'ready', added: 4, removed: 0 }],
  samples: { received: 3, expected: 3 },
  roles: ['viewer', 'developer'],
  threatModelPage: null,
  requirementControls: REQUIREMENT_CONTROLS_FIXTURE,
  // Generated from the layout (apps/core/test/services/diagram.test.ts keeps it in step: `pnpm vitest run -u`).
  diagram: DIAGRAM_FIXTURE,
};

const withReview = (o: Partial<NonNullable<PanelDto['review']>>, rest: Partial<PanelDto> = {}): PanelDto => ({ ...base, review: { ...base.review!, ...o }, ...rest });

export const FIXTURES: Record<string, PanelDto> = {
  ready: base,
  not_reviewed: { ...base, review: null, verdict: { ...base.verdict!, reasons: [{ code: 'no_review', message: 'Threatline has not reviewed this work item yet.' }] }, threats: [], threatsTotal: 0, discarded: [], facts: [], requirements: [], history: [], samples: { received: 0, expected: 0 } },
  in_progress: withReview({ status: 'awaiting_agent', samplesReceived: 1, riskScore: 40 }, { samples: { received: 1, expected: 3 }, verdict: { ...base.verdict!, reasons: [{ code: 'agent_missing', message: 'Review in progress (1 of 3 agent runs received).' }] } }),
  partial: withReview({ partial: true }),
  failed: withReview({ status: 'failed', failureReason: 'context_unavailable' }, { verdict: { ...base.verdict!, reasons: [{ code: 'review_failed', message: 'The security review failed.', action: { label: 'Re-run review', href: '?rerun=1' } }] } }),
  timeout: withReview({ status: 'agent_timeout', samplesReceived: 1 }, { samples: { received: 1, expected: 3 }, verdict: { ...base.verdict!, reasons: [{ code: 'agent_missing', message: 'The AI review did not arrive in time, so the review is incomplete.' }] } }),
  budget: withReview({ status: 'failed', failureReason: 'budget' }, { verdict: { ...base.verdict!, reasons: [{ code: 'budget_paused', message: 'Reviews are paused at the AI budget. A security champion can confirm this work item.' }] } }),
  injection: { ...base, facts: FACTS.map((f) => (f.id === 'fact_page' ? { ...f, injectionSuspected: true, injectionReasons: ['ai_directive'] } : f)) },
  stale: { ...base, verdict: { ...base.verdict!, reasons: [...base.verdict!.reasons, { code: 'review_stale', message: 'The design or linked work changed since the last review.', action: { label: 'Re-run review', href: '?rerun=1' } }] } },
  revised: withReview({ revision: 2 }, { history: [{ revision: 1, createdAt: '2026-11-16T05:30:43.000Z', riskScore: 60, status: 'ready', added: 2, removed: 0 }, { revision: 2, createdAt: '2026-11-17T09:12:00.000Z', riskScore: 72, status: 'ready', added: 2, removed: 0 }] }),
  /** An incident on the component reopened the review (docs/INCIDENTS.md). */
  reopened: withReview({ revision: 2 }, { history: [{ revision: 1, createdAt: '2026-11-16T05:30:43.000Z', riskScore: 60, status: 'ready', added: 2, removed: 0 }, { revision: 2, createdAt: '2026-11-21T09:12:00.000Z', riskScore: 72, status: 'ready', added: 2, removed: 0, reopenedBy: { incidentKey: 'PAY-9', components: ['Payments API'], linked: false, at: '2026-11-21T09:11:00.000Z' } }] }),
  pass: { ...base, verdict: { ...base.verdict!, state: 'pass', blockingCount: 0, maxOpenSeverity: null, reasons: [] }, requirements: base.requirements.map((r) => ({ ...r, status: 'Verified' as const, verifiedBy: 'acc-dev', evidence: { kind: 'pr' as const, ref: 'https://bitbucket.org/acme/payments/pull-requests/42', attester: 'acc-dev' } })) },
};

/** R7 preview: what a re-run after one new design paragraph shows. */
export const DIFF_FIXTURE: ThreatDiffDto = {
  from: 1,
  to: 2,
  added: [
    { id: 'thr_n1', title: 'Forged manager refund approval in chat', stride: 'Spoofing', severity: 'High', state: 'accepted', component: 'refund tool' },
    { id: 'thr_n2', title: 'Order history emailed to an attacker address', stride: 'InformationDisclosure', severity: 'Medium', state: 'accepted', component: 'order export' },
  ],
  removed: [],
  changed: [],
  unchanged: 1,
  hidden: 0,
  summary: '2 new threats since last review',
};

/** "Seen before" for the ready preview (docs/MEMORY.md): an incident, and the same threat verified, accepted and dismissed elsewhere. */
export const SEEN_BEFORE_FIXTURE: SeenBeforeDto = {
  threats: {
    thr_1: [
      { kind: 'incident', key: 'INC-7', text: 'Incident · Old sign-in links reused to take over accounts (Sev-2, accounts)', summary: 'Old sign-in links reused to take over accounts', reason: 'same component accounts; shared words: account, link, sign, takeover' },
      { kind: 'verified', key: 'PAY-3', text: 'same threat · Verified with PR #41', evidence: { label: 'PR #41', url: 'https://bitbucket.org/acme/payments-service/pull-requests/41' }, reason: 'same CWE-640; shared words: expire, link, magic' },
    ],
    thr_3: [{ kind: 'accepted', key: 'PAY-9', text: 'same threat · risk accepted until 2027-01-31', until: '2027-01-31', reason: 'same STRIDE category (Elevation of privilege); shared words: account, change, email, takeover' }],
    thr_2: [{ kind: 'dismissed', key: 'PAY-4', text: 'same threat · dismissed as a false positive', reason: 'same STRIDE category (Information disclosure); same asset (Reset API); shared words: email, reset, reveal' }],
  },
  happenedBefore: { key: 'INC-7', summary: 'Old sign-in links reused to take over accounts', threatId: 'thr_1' },
};

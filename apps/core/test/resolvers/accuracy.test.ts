import { describe, expect, it } from 'vitest';
import { ok, type ContextFact, type Review, type Threat } from '@threatline/shared';
import { postureGet } from '../../src/resolvers/posture.js';
import { inboxDecide } from '../../src/resolvers/inbox.js';
import { getPostureSummary } from '../../src/actions/posture-summary.js';
import { setRequirementStatus } from '../../src/services/requirements-service.js';
import { ACCURACY_MAX_CONFIRMED_REVIEWS } from '../../src/services/accuracy-service.js';
import { coreDeps, jiraIssue, POLICY } from '../support/core-deps.js';

const CHAMPIONS = 'threatline-security-champions';
const CHAMP = 'acc-champ';
const ME = 'acc-plain';

const review = (o: Partial<Review> & { id: string; issueId: string; issueKey: string }): Review => ({
  revision: 1, status: 'ready', contextHash: 'h', riskScore: 40, partial: false, promptVersion: 'v1', modelIds: ['m'], samplesExpected: 3, samplesReceived: 3,
  tokensIn: 0, tokensOut: 0, createdAt: '2026-11-10T00:00:00.000Z', updatedAt: '2026-11-10T00:00:00.000Z', ...o,
});
const fact = (issueId: string): ContextFact => ({
  id: `f_${issueId}`, sourceAri: `ari:cloud:jira::issue/${issueId}`, sourceType: 'jira_issue', title: 'Work item', url: '', excerpt: 'text', trustLevel: 'untrusted', version: '1',
  injectionSuspected: false, injectionReasons: [], origin: 'rest',
});
const threat = (issueId: string, n: number, o: Partial<Threat> = {}): Threat => ({
  id: `thr_${issueId}_${n}`, reviewId: `rev_${issueId}`, stride: 'Spoofing', title: `Threat ${n} on ${issueId}`, scenario: 's', component: 'webhook', likelihood: 4, impact: 4, severity: 'High',
  votes: 3, samples: 3, grounding: 'supported', confidence: 0.9, state: 'needs_human', origin: 'agent', citations: [{ factId: `f_${issueId}`, quote: 'q' }], mappings: [],
  plainLanguage: 'p', verification: { keep: false, reason: 'doubted' }, ...o,
});

/**
 * PAY-1 (101) and PAY-2 (102) are Threatline work items; the plain viewer can browse PAY-1 only. OPS-1 (201) is in a
 * project that is not enabled. Each has six threats waiting for a champion (the verifier doubted them) and two it kept.
 */
async function site() {
  const issues = [
    jiraIssue({ id: '101', key: 'PAY-1' }),
    jiraIssue({ id: '102', key: 'PAY-2' }),
    jiraIssue({ id: '201', key: 'OPS-1', project: { id: '2', key: 'OPS' } }),
  ];
  const t = coreDeps({ issues, now: '2026-11-15T12:00:00.000Z' });
  t.jira.groupsOf = async (id) => ok(id === CHAMP ? [CHAMPIONS] : []);
  t.jira.canBrowse = async (acc, id) => ok(acc !== ME || id === '101' || id === 'PAY-1');
  // The posture JQL names the enabled projects only; this fake honours that.
  t.jira.search = async (jql) => ok(issues.filter((i) => jql.includes(`"${i.project.key}"`)));
  for (const i of issues) {
    await t.deps.reviews.create(review({ id: `rev_${i.id}`, issueId: i.id, issueKey: i.key }));
    await t.deps.reviews.saveFacts(`rev_${i.id}`, [fact(i.id)]);
    await t.deps.reviews.saveThreats(
      `rev_${i.id}`,
      [
        ...[1, 2, 3, 4, 5, 6].map((n) => threat(i.id, n)),
        threat(i.id, 7, { state: 'accepted', verification: { keep: true, reason: 'ok' } }),
        threat(i.id, 8, { state: 'accepted', verification: { keep: true, reason: 'ok' } }),
      ],
      [],
    );
  }
  const items = (issueId: string, ns: number[]) => ns.map((n) => ({ issueId, threatId: `thr_${issueId}_${n}` }));
  const decide = (body: Record<string, unknown>) => inboxDecide(t.deps, { accountId: CHAMP }, body);
  return { t, items, decide };
}

async function accuracy(t: Awaited<ReturnType<typeof site>>['t'], accountId: string, project?: string) {
  const p = await postureGet(t.deps, { accountId }, project ? { project } : {});
  if ('error' in p) throw new Error(p.error);
  return p.accuracy!;
}

describe('posture accuracy (docs/ACCURACY.md)', () => {
  it('measures champion decisions, closed blocking requirements and the verifier from what Threatline recorded', async () => {
    const { t, items, decide } = await site();
    expect(await decide({ decision: 'confirm', items: items('101', [1, 2, 3, 4]) })).toMatchObject({ decided: 4, failed: 0 });
    expect(await decide({ decision: 'dismiss', reason: 'false_positive', items: items('101', [5]) })).toMatchObject({ decided: 1 });
    expect(await decide({ decision: 'dismiss', reason: 'duplicate', items: items('101', [6]) })).toMatchObject({ decided: 1 });
    // A confirmed threat's requirement is fixed with evidence.
    const reqs = await t.deps.requirements.forIssue('101');
    const confirmed = reqs.ok ? reqs.value.find((r) => r.threatId === 'thr_101_1') : undefined;
    expect(confirmed).toBeDefined();
    const v = await setRequirementStatus(t.deps, { accountId: 'acc-dev', issueId: '101' }, { requirementId: confirmed!.id, status: 'Verified', evidence: { kind: 'pr', ref: 'https://bitbucket.org/acme/pay/pull-requests/9' } });
    expect(v.ok).toBe(true);

    const a = await accuracy(t, CHAMP);
    expect(a.champion).toMatchObject({ confirmed: 4, dismissed: 1, notCounted: 1, rate: { n: 5, share: 0.8, enough: true } });
    expect(a.blocking).toMatchObject({ fixed: 1, accepted: 0, dismissed: 0 });
    // The verifier judged 8 threats on each of PAY-1 and PAY-2 (OPS is not a Threatline project): 2 kept each.
    expect(a.verifier).toMatchObject({ kept: 4, doubted: 12, rate: { n: 16, share: 0.25 } });
    expect(a.byProject.map((p) => p.project)).toEqual(['PAY']);
    expect(a.windowDays).toBe(90);
  });

  it('security: counts only work items the viewer can browse, like the rest of posture', async () => {
    const { t, items, decide } = await site();
    await decide({ decision: 'confirm', items: items('101', [1, 2, 3, 4]) });
    await decide({ decision: 'dismiss', reason: 'false_positive', items: items('101', [5]) });
    // On PAY-2, which the plain viewer cannot browse: five dismissals.
    await decide({ decision: 'dismiss', reason: 'false_positive', items: items('102', [1, 2, 3, 4, 5]) });
    const champ = await accuracy(t, CHAMP);
    expect(champ.champion).toMatchObject({ confirmed: 4, dismissed: 6 });
    const plain = await accuracy(t, ME);
    expect(plain.champion).toMatchObject({ confirmed: 4, dismissed: 1 });
    expect(plain.verifier).toMatchObject({ kept: 2, doubted: 6 });
    expect(JSON.stringify(plain)).not.toContain('PAY-2');
    expect(JSON.stringify(plain)).not.toContain('102');
    // Nothing browsable: nothing counted.
    t.jira.browsable = async () => ok([]);
    const none = await accuracy(t, ME);
    expect([none.champion.rate.n, none.blocking.rate.n, none.verifier.rate.n, none.byProject.length]).toEqual([0, 0, 0, 0]);
  });

  it('a project filter narrows the figures to that project', async () => {
    const { t, items, decide } = await site();
    await t.deps.config.setSite({ ...POLICY, enabledProjects: ['PAY', 'OPS'] });
    await decide({ decision: 'dismiss', reason: 'not_applicable', items: items('201', [1, 2]) });
    await decide({ decision: 'confirm', items: items('101', [1]) });
    const all = await accuracy(t, CHAMP);
    expect(all.champion).toMatchObject({ confirmed: 1, dismissed: 2 });
    expect(all.byProject.map((p) => [p.project, p.champion.confirmed, p.champion.dismissed])).toEqual([
      ['OPS', 0, 2],
      ['PAY', 1, 0],
    ]);
    const ops = await accuracy(t, CHAMP, 'OPS');
    expect(ops.champion).toMatchObject({ confirmed: 0, dismissed: 2 });
  });

  it('says there are not enough decisions yet instead of giving a percentage below 5', async () => {
    const { t, items, decide } = await site();
    await decide({ decision: 'confirm', items: items('101', [1, 2]) });
    const a = await accuracy(t, CHAMP);
    expect(a.champion.rate).toEqual({ n: 2, share: null, low: null, high: null, enough: false });
  });

  it('is in the posture-summary action (Rovo and MCP), scoped to the caller', async () => {
    const { t, items, decide } = await site();
    await decide({ decision: 'dismiss', reason: 'false_positive', items: items('102', [1, 2, 3, 4, 5]) });
    const p = await getPostureSummary({ context: { accountId: ME } }, t.deps);
    if ('error' in p) throw new Error(p.error);
    expect(p.accuracy?.champion).toMatchObject({ confirmed: 0, dismissed: 0 });
    const c = await getPostureSummary({ context: { accountId: CHAMP } }, t.deps);
    expect('accuracy' in c && c.accuracy?.champion.dismissed).toBe(5);
  });

  it('reads are bounded: one ledger query and one threats query per batch of work items, never one per work item', async () => {
    const { t } = await site();
    const calls = { ledger: 0, latest: 0, threats: 0 };
    const forIssues = t.deps.ledger.forIssues.bind(t.deps.ledger);
    const latestThreats = t.deps.reviews.latestThreats.bind(t.deps.reviews);
    const threats = t.deps.reviews.threats.bind(t.deps.reviews);
    t.deps.ledger.forIssues = async (...a) => ((calls.ledger += 1), forIssues(...a));
    t.deps.reviews.latestThreats = async (...a) => ((calls.latest += 1), latestThreats(...a));
    t.deps.reviews.threats = async (...a) => ((calls.threats += 1), threats(...a));
    await accuracy(t, CHAMP);
    // Posture's acceptance query plus the accuracy one; one latest-threats query; no per-review reads.
    expect(calls).toEqual({ ledger: 2, latest: 1, threats: 0 });
    expect(ACCURACY_MAX_CONFIRMED_REVIEWS).toBe(25);
  });

  it('a failed read leaves the rest of posture standing, with no accuracy figures', async () => {
    const { t } = await site();
    t.deps.reviews.latestThreats = async () => ({ ok: false, error: { code: 'internal', message: 'sql down' } });
    const p = await postureGet(t.deps, { accountId: CHAMP }, {});
    if ('error' in p) throw new Error(p.error);
    expect(p.accuracy).toBeNull();
    expect(p.issuesCounted).toBe(2);
  });
});

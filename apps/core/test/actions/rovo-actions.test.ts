import { describe, expect, it } from 'vitest';
import { ok, type Requirement } from '@threatline/shared';
import { getReview } from '../../src/actions/get-review.js';
import { getSecurityRequirements } from '../../src/actions/get-security-requirements.js';
import { checkChangeRisk } from '../../src/actions/check-change-risk.js';
import { requestRiskAcceptance } from '../../src/actions/request-risk-acceptance.js';
import { verifyRequirement } from '../../src/actions/verify-requirement.js';
import { explainThreat } from '../../src/actions/explain-threat.js';
import { getReleaseReadiness } from '../../src/actions/release-readiness.js';
import { startReview } from '../../src/actions/start-review.js';
import { getPostureSummary } from '../../src/actions/posture-summary.js';
import { fitJson, MAX_ACTION_BYTES } from '../../src/actions/schemas.js';
import { callerOf, withCaller } from '../../src/actions/common.js';
import { jiraIssue } from '../support/core-deps.js';
import { appendLedger } from '@threatline/core';
import { verdictKey } from '../../src/services/verdict-service.js';
import { CHAMP, DEV, ISSUE, reviewed } from '../support/reviewed.js';

const ctx = (accountId?: string) => ({ context: accountId ? { accountId, agentId: 'agent-1', cloudId: 'c' } : {} });
const ME = 'acc-plain';
const bytes = (v: unknown) => Buffer.byteLength(JSON.stringify(v), 'utf8');

describe('every action validates its inputs with a schema message', () => {
  it.each([
    ['get-review', { issueKey: 'not a key' }, /issueKey/],
    ['get-security-requirements', { issueKey: 'PAY-7', status: 'Done' }, /status/],
    ['check-change-risk', { issueKey: 'PAY-7', changedPaths: ' , ' }, /changedPaths/],
    ['request-risk-acceptance', { requirementId: 'req_1', reason: 'r', controls: '', expiryDays: 0 }, /expiryDays/],
    ['explain-threat', { issueKey: 'PAY-7', threatId: '<script>' }, /threatId/],
    ['release-readiness', { fixVersion: '' }, /fixVersion/],
    ['start-review', { issueKey: 7 }, /issueKey/],
    ['posture-summary', { project: 'not a project!' }, /project/],
  ] as const)('%s', async (name, input, message) => {
    const { t } = await reviewed();
    const fns = {
      'get-review': getReview,
      'get-security-requirements': getSecurityRequirements,
      'check-change-risk': checkChangeRisk,
      'request-risk-acceptance': requestRiskAcceptance,
      'explain-threat': explainThreat,
      'release-readiness': getReleaseReadiness,
      'start-review': startReview,
      'posture-summary': getPostureSummary,
    } as const;
    const r = (await fns[name]({ ...(input as object), ...ctx(ME) } as never, t.deps)) as { error?: string; message?: string };
    expect(r.error).toBe('invalid_input');
    expect(r.message).toMatch(message);
  });
});

describe('permission: the caller must be able to see (or edit) the work item', () => {
  it('a caller who cannot browse gets not_found from every read action, and no caller is not_found too', async () => {
    const { t, req } = await reviewed();
    t.jira.canBrowse = async () => ok(false);
    for (const caller of [ME, undefined]) {
      expect(await getReview({ issueKey: 'PAY-7', ...ctx(caller) }, t.deps)).toEqual({ error: 'not_found' });
      expect(await getSecurityRequirements({ issueKey: 'PAY-7', ...ctx(caller) }, t.deps)).toEqual({ error: 'not_found' });
      expect(await checkChangeRisk({ issueKey: 'PAY-7', changedPaths: 'src/auth/session.ts', ...ctx(caller) }, t.deps)).toEqual({ error: 'not_found' });
      expect(await explainThreat({ issueKey: 'PAY-7', threatId: 'T-1', ...ctx(caller) }, t.deps)).toEqual({ error: 'not_found' });
    }
    expect(await getReview({ issueKey: 'PAY-404', ...ctx(ME) }, t.deps)).toEqual({ error: 'not_found' });
    void req;
  });

  it('writes need edit permission: request-risk-acceptance and start-review refuse a browse-only caller', async () => {
    const { t, req } = await reviewed();
    t.jira.canEdit = async () => ok(false);
    expect(await requestRiskAcceptance({ requirementId: req.id, reason: 'Compensating control in place until Q1', controls: 'WAF rule', expiryDays: 14, ...ctx(ME) }, t.deps)).toEqual({ error: 'not_found' });
    expect(await startReview({ issueKey: 'PAY-7', ...ctx(ME) }, t.deps)).toEqual({ error: 'not_found' });
    expect(t.pushed).toHaveLength(0);
  });

  it('release-readiness and posture-summary leave out work items the caller cannot browse', async () => {
    const { t } = await reviewed();
    const hidden = jiraIssue({ id: '10099', key: 'PAY-99', fixVersions: ['4.2'] });
    t.jira.search = async () => ok([jiraIssue({ id: ISSUE, key: 'PAY-7', fixVersions: ['4.2'] }), hidden]);
    t.jira.browsable = async (_a, ids) => ok(ids.filter((id) => id !== '10099'));
    const r = await getReleaseReadiness({ fixVersion: '4.2', ...ctx(ME) }, t.deps);
    expect('items' in r && r.items).toBe(1);
    expect(JSON.stringify(r)).not.toContain('PAY-99');
    const p = await getPostureSummary({ project: 'PAY', ...ctx(ME) }, t.deps);
    expect('issuesCounted' in p && p.issuesCounted).toBe(1);
  });
});

describe('acceptances on requirements the caller cannot see (same rule as the panel)', () => {
  async function withHiddenAcceptance(o: { allVerified?: boolean } = {}) {
    const s = await reviewed(o);
    // A requirement whose threat is in no review this caller can see (e.g. it cites a restricted page).
    await s.t.deps.requirements.upsert({ ...s.req, id: 'req_hidden', threatId: 'thr_0000000000000000', status: 'AcceptedRisk' });
    const expiresAt = new Date(s.t.clock.now().getTime() + 5 * 86_400_000).toISOString();
    await appendLedger(s.t.deps.ledger, s.t.deps.clock, 'acceptance.requested', { acceptanceId: 'acc_hidden', requirementId: 'req_hidden', issueId: ISSUE, severity: 'High', reason: 'secret', controls: '', expiresAt, needsApprover: 'none' }, CHAMP);
    s.t.jira.search = async () => ok([jiraIssue({ id: ISSUE, key: 'PAY-7', fixVersions: ['4.2'] })]);
    return s;
  }

  it('posture-summary does not list them, only counts them', async () => {
    const { t } = await withHiddenAcceptance();
    const r = await getPostureSummary({ project: 'PAY', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(JSON.stringify(r)).not.toContain('req_hidden');
    expect(r.expiring).toEqual([]);
    expect(r.hiddenExpiring).toBe(1);
  });

  it('release-readiness does not name them, but the call still accounts for them', async () => {
    const { t } = await withHiddenAcceptance({ allVerified: true });
    const r = await getReleaseReadiness({ fixVersion: '4.2', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(JSON.stringify(r)).not.toContain('req_hidden');
    expect(r.call).toBe('Conditional');
    expect(r.conditions.join(' ')).toMatch(/1 accepted risk on a requirement you cannot see/);
  });
});

describe('get-review', () => {
  it('returns the verdict, risk score, partial flag and threats with short refs and quoted citations', async () => {
    const { t } = await reviewed();
    const r = await getReview({ issueKey: 'pay-7', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(r.issueKey).toBe('PAY-7');
    expect(r.verdict?.state).toBe('block');
    expect(r.partial).toBe(false);
    expect(r.threats[0]!.ref).toBe('T-1');
    expect(r.threats.some((x) => /forged refund webhooks/i.test(x.title))).toBe(true);
    expect(r.threats[0]!.citations[0]!.quote.length).toBeGreaterThan(0);
    expect(r.panelUrl).toMatch(/^https:\/\/one-atlas-mefc\.atlassian\.net\/browse\/PAY-7/);
  });
});

describe('get-security-requirements', () => {
  it('filters by status and returns acceptance criteria, ASVS ids and file hints', async () => {
    const { t, req } = await reviewed();
    const r = await getSecurityRequirements({ issueKey: 'PAY-7', status: 'Open', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(r.requirements.map((x) => x.id)).toEqual([req.id]);
    expect(r.requirements[0]!.acceptanceCriteria[0]).toMatch(/^Given .+, when .+, then .+/);
    expect(Array.isArray(r.requirements[0]!.asvsIds)).toBe(true);
    expect(Array.isArray(r.requirements[0]!.fileHints)).toBe(true);
  });

  it('feature: with testLanguage, each requirement carries a ready-to-paste test skeleton; every one has its fix-by date', async () => {
    const { t, req } = await reviewed();
    const r = await getSecurityRequirements({ issueKey: 'PAY-7', status: 'Open', testLanguage: 'python', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    const dto = r.requirements.find((x) => x.id === req.id)!;
    expect(dto.testSkeleton).toMatch(/^def test_/m);
    expect(dto.testSkeleton).toContain(`Threatline requirement ${req.id}`);
    expect(dto).toMatchObject({ dueDate: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/), overdueDays: 0 });
    const plain = await getSecurityRequirements({ issueKey: 'PAY-7', status: 'Open', ...ctx(ME) }, t.deps);
    if ('error' in plain) throw new Error(plain.error);
    expect(plain.requirements[0]).not.toHaveProperty('testSkeleton');
    expect(await getSecurityRequirements({ issueKey: 'PAY-7', testLanguage: 'cobol', ...ctx(ME) }, t.deps)).toMatchObject({ error: 'invalid_input' });
  });

  it(`never returns more than ${MAX_ACTION_BYTES} bytes: a huge list is cut and marked truncated`, async () => {
    const { t, req } = await reviewed();
    const long = 'x'.repeat(1000);
    for (let i = 0; i < 400; i++)
      await t.deps.requirements.upsert({ ...req, id: `req_big_${i}`, status: 'Verified', title: `Requirement ${i} ${'y'.repeat(200)}`, criteria: [{ given: long, when: long, then: long }] } as Requirement);
    const r = await getSecurityRequirements({ issueKey: 'PAY-7', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(bytes(r)).toBeLessThanOrEqual(MAX_ACTION_BYTES);
    expect(r.truncated).toBe(true);
    expect(r.requirements.length).toBeGreaterThan(0);
  });
});

describe('fitJson', () => {
  it('halves the named arrays until the value fits, and says so', () => {
    const v = { items: Array.from({ length: 1000 }, (_, i) => ({ i, pad: 'z'.repeat(500) })), keep: 'me' };
    const out = fitJson(v, ['items'], 50_000);
    expect(bytes(out)).toBeLessThanOrEqual(50_000);
    expect(out.truncated).toBe(true);
    expect(out.keep).toBe('me');
    expect(fitJson({ items: [1] }, ['items'])).toEqual({ items: [1], truncated: false });
  });
});

describe('check-change-risk', () => {
  async function withSessionRequirement() {
    const s = await reviewed();
    const all = await s.reqs();
    const session = all.find((r) => r.id !== s.req.id)!;
    await s.t.deps.requirements.upsert({ ...session, title: 'Sessions expire after logout', status: 'Open', fileHints: ['**/auth/**', '**/session*'] });
    return { ...s, session };
  }

  it('src/auth/session.ts → wouldPass false, listing the session requirement and why', async () => {
    const { t, session } = await withSessionRequirement();
    const r = await checkChangeRisk({ issueKey: 'PAY-7', changedPaths: 'src/auth/session.ts, README.md', summary: 'rotate session ids', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(r.wouldPass).toBe(false);
    expect(r.needsAttestation).toBe(true);
    expect(r.touchedRequirements.map((x) => x.id)).toContain(session.id);
    expect(r.touchedRequirements.find((x) => x.id === session.id)?.paths).toEqual(['src/auth/session.ts']);
    expect(r.reasons.join(' ')).toMatch(/src\/auth\/session\.ts/);
  });

  it('a change that touches no sensitive path still passes (it merges freely)', async () => {
    const { t } = await withSessionRequirement();
    const r = await checkChangeRisk({ issueKey: 'PAY-7', changedPaths: 'README.md,docs/intro.md', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(r).toMatchObject({ wouldPass: true, needsAttestation: false, touchedRequirements: [] });
  });

  it('the gate\'s own configuration is sensitive here too, and a pass says it is a prediction', async () => {
    const { t } = await withSessionRequirement();
    for (const path of ['bitbucket-pipelines.yml', '.threatline/policy.yml', '.redline/policy.yml', '.github/actions/setup/action.yml']) {
      const r = await checkChangeRisk({ issueKey: 'PAY-7', changedPaths: path, ...ctx(ME) }, t.deps);
      if ('error' in r) throw new Error(r.error);
      expect(r, path).toMatchObject({ needsAttestation: true, sensitiveFiles: [path] });
    }
    const r = await checkChangeRisk({ issueKey: 'PAY-7', changedPaths: 'README.md', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(r.reasons.join(' ')).toMatch(/prediction.*Threatline settings.*policy\.yml/);
  });

  it('a sensitive change on a work item whose verdict passes would pass', async () => {
    const { t } = await reviewed({ allVerified: true });
    const r = await checkChangeRisk({ issueKey: 'PAY-7', changedPaths: 'src/payments/refund.ts', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(r).toMatchObject({ wouldPass: true, needsAttestation: true });
  });
});

describe('request-risk-acceptance', () => {
  it('creates a pending acceptance in the ledger and names the approver', async () => {
    const { t, req } = await reviewed();
    const r = await requestRiskAcceptance({ requirementId: req.id, reason: 'Provider signs payloads; we verify next sprint', controls: 'IP allow-list', expiryDays: 14, ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(r.acceptanceId).toMatch(/^acc_/);
    expect(r.state).toBe('pending');
    expect(r.message).toMatch(/approve/i);
    const rows = await t.deps.ledger.all();
    expect(rows.ok && rows.value.map((x) => x.eventType)).toContain('acceptance.requested');
  });

  it('an agent never grants risk: a tech lead asking through Rovo or MCP still needs a second person', async () => {
    const { t, req, reqs } = await reviewed();
    const medium = (await reqs()).find((r) => r.id !== req.id)!;
    await t.deps.requirements.upsert({ ...medium, severity: 'Medium', status: 'Open' });
    const r = await requestRiskAcceptance({ requirementId: medium.id, reason: 'Low exposure behind the VPN until Q1', controls: 'VPN only', expiryDays: 14, ...ctx(DEV) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(r).toMatchObject({ state: 'pending', needsApprover: 'tech_lead' });
    expect((await t.deps.requirements.get(medium.id)).ok && ((await t.deps.requirements.get(medium.id)) as { value: Requirement }).value.status).toBe('Open');
  });

  it('a refused request says why (e.g. expiry above the cap)', async () => {
    const { t, req } = await reviewed();
    const r = await requestRiskAcceptance({ requirementId: req.id, reason: 'Provider signs payloads; we verify next sprint', controls: 'IP allow-list', expiryDays: 200, ...ctx(ME) }, t.deps);
    expect(r).toMatchObject({ error: 'refused', message: expect.stringMatching(/at most \d+ days/) });
  });

  it('a request without compensating controls is refused and says what to add', async () => {
    const { t, req } = await reviewed();
    const r = await requestRiskAcceptance({ requirementId: req.id, reason: 'Provider signs payloads; we verify next sprint', expiryDays: 14, ...ctx(ME) }, t.deps);
    expect(r).toMatchObject({ error: 'refused', message: expect.stringMatching(/compensating controls/) });
  });

  it('an unknown requirement is not_found', async () => {
    const { t } = await reviewed();
    expect(await requestRiskAcceptance({ requirementId: 'req_nope', reason: 'Provider signs payloads; we verify next sprint', controls: 'IP allow-list', expiryDays: 14, ...ctx(ME) }, t.deps)).toEqual({ error: 'not_found' });
  });
});

describe('explain-threat', () => {
  it('accepts the T-n ref from get-review or the threat id, and answers without a model call', async () => {
    const { t } = await reviewed();
    const review = await getReview({ issueKey: 'PAY-7', ...ctx(ME) }, t.deps);
    if ('error' in review) throw new Error(review.error);
    const byRef = await explainThreat({ issueKey: 'PAY-7', threatId: 'T-1', ...ctx(ME) }, t.deps);
    const byId = await explainThreat({ issueKey: 'PAY-7', threatId: review.threats[0]!.id, ...ctx(ME) }, t.deps);
    if ('error' in byRef) throw new Error(byRef.error);
    expect(byRef.story.length).toBeGreaterThan(0);
    expect(byId).toEqual(byRef);
    expect(await explainThreat({ issueKey: 'PAY-7', threatId: 'T-99', ...ctx(ME) }, t.deps)).toEqual({ error: 'not_found' });
  });

  it('T-n means the same threat in get-review and explain-threat when a covered threat sorts first', async () => {
    const { t } = await reviewed();
    const latest = (await t.deps.reviews.latest(ISSUE)) as { ok: true; value: { id: string } };
    const all = (await t.deps.reviews.threats(latest.value.id)) as { ok: true; value: Array<{ id: string; severity: string }> };
    expect(all.value.length).toBeGreaterThan(1);
    // The most severe threat becomes covered: get-review drops it, so its T-1 is the next one.
    const [first, other] = all.value;
    await t.deps.reviews.updateThreat(first!.id, { state: 'covered', coveredBy: other!.id, severity: 'Critical' });
    const review = await getReview({ issueKey: 'PAY-7', ...ctx(ME) }, t.deps);
    if ('error' in review) throw new Error(review.error);
    expect(review.threats.map((x) => x.id)).not.toContain(first!.id);
    for (const listed of review.threats) {
      const e = await explainThreat({ issueKey: 'PAY-7', threatId: listed.ref, ...ctx(ME) }, t.deps);
      expect('error' in e ? e.error : e.threatId).toBe(listed.id);
    }
    expect(await explainThreat({ issueKey: 'PAY-7', threatId: `T-${review.threats.length + 1}`, ...ctx(ME) }, t.deps)).toEqual({ error: 'not_found' });
  });
});

describe('release-readiness', () => {
  it('No-go when a work item in the release is blocked; the JQL quotes the version', async () => {
    const { t } = await reviewed();
    const jql: string[] = [];
    t.jira.search = async (q) => (jql.push(q), ok([jiraIssue({ id: ISSUE, key: 'PAY-7', fixVersions: ['4.2'] })]));
    const r = await getReleaseReadiness({ fixVersion: '4.2 "beta"', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(jql[0]).toBe('fixVersion = "4.2 \\"beta\\"" ORDER BY key ASC');
    expect(r.call).toBe('No-go');
    expect(r.blockers[0]!.issueKey).toBe('PAY-7');
    expect(r.blockers[0]!.reasons.join(' ')).toMatch(/open security requirement/);
  });

  it('a fix version with no reviewable work items is not a Go: it says nothing was found', async () => {
    const { t } = await reviewed();
    t.jira.search = async () => ok([]);
    const r = await getReleaseReadiness({ fixVersion: '9.9', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(r.items).toBe(0);
    expect(r.call).toBe('Conditional');
    expect(r.conditions.join(' ')).toMatch(/No work items you can see in fix version 9\.9 are reviewed by Threatline/);
  });

  it('Go when everything passes; an enabled-project item with no review blocks (fail closed)', async () => {
    const { t } = await reviewed({ allVerified: true });
    t.jira.search = async () => ok([jiraIssue({ id: ISSUE, key: 'PAY-7', fixVersions: ['4.2'] })]);
    const go = await getReleaseReadiness({ fixVersion: '4.2', ...ctx(ME) }, t.deps);
    expect('call' in go && go.call).toBe('Go');
    t.jira.search = async () => ok([jiraIssue({ id: ISSUE, key: 'PAY-7' }), jiraIssue({ id: '10050', key: 'PAY-50' }), jiraIssue({ id: '20001', key: 'OPS-1', project: { id: '2', key: 'OPS' } })]);
    const r = await getReleaseReadiness({ fixVersion: '4.2', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(r.call).toBe('No-go');
    expect(r.blockers.map((b) => b.issueKey)).toEqual(['PAY-50']);
    expect(r.outOfScope).toBe(1);
  });
});

describe('start-review', () => {
  it('adds the re-run label and queues a gather as the caller', async () => {
    const { t } = await reviewed();
    const r = await startReview({ issueKey: 'PAY-7', ...ctx(ME) }, t.deps);
    expect(r).toMatchObject({ queued: true, issueKey: 'PAY-7' });
    expect(t.jira.labels).toContain('+threatline-review');
    expect(t.pushed).toContainEqual({ kind: 'gather', issueId: ISSUE, reason: 'rerun', actorAccountId: ME });
  });
});

describe('posture-summary', () => {
  it('counts open requirements by severity for the enabled projects; a project that is not enabled is refused', async () => {
    const { t } = await reviewed();
    t.jira.search = async () => ok([jiraIssue({ id: ISSUE, key: 'PAY-7' })]);
    const r = await getPostureSummary({ ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(r.projects).toEqual(['PAY']);
    expect(r.openBySeverity.High).toBeGreaterThanOrEqual(1);
    expect(r.topRiskyComponents[0]?.component).toBe('payments');
    const off = await getPostureSummary({ project: 'OPS', ...ctx(ME) }, t.deps);
    expect(off).toMatchObject({ error: 'invalid_input' });
  });

  it('lists active risk acceptances that expire within 31 days, soonest first ("which acceptances expire this month?")', async () => {
    const { t, req } = await reviewed();
    t.jira.search = async () => ok([jiraIssue({ id: ISSUE, key: 'PAY-7' })]);
    const expiresAt = (days: number) => new Date(t.clock.now().getTime() + days * 86_400_000).toISOString();
    for (const [id, days] of [['acc_a', 20], ['acc_b', 5], ['acc_c', 60]] as const)
      await appendLedger(t.deps.ledger, t.deps.clock, 'acceptance.requested', { acceptanceId: id, requirementId: req.id, issueId: ISSUE, severity: 'High', reason: 'r', controls: '', expiresAt: expiresAt(days), needsApprover: 'none' }, CHAMP);
    const r = await getPostureSummary({ project: 'PAY', ...ctx(ME) }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(r.expiring.map((a) => a.acceptanceId)).toEqual(['acc_b', 'acc_a']);
    expect(r.expiring[0]).toMatchObject({ issueKey: 'PAY-7', requirementId: req.id, severity: 'High', expiresAt: expiresAt(5) });
  });

  it('scale: posture and release readiness read only their work items\' acceptance events, never every one on the site', async () => {
    const { t, req } = await reviewed({ allVerified: true });
    const expiresAt = new Date(t.clock.now().getTime() + 5 * 86_400_000).toISOString();
    await appendLedger(t.deps.ledger, t.deps.clock, 'acceptance.requested', { acceptanceId: 'acc_x', requirementId: req.id, issueId: ISSUE, severity: 'High', reason: 'r', controls: '', expiresAt, needsApprover: 'none' }, CHAMP);
    const refuse = async () => ({ ok: false as const, error: { code: 'internal' as const, message: 'site-wide ledger read' } });
    t.deps.ledger = { ...t.deps.ledger, all: refuse, ofTypes: refuse };
    t.jira.search = async () => ok([jiraIssue({ id: ISSUE, key: 'PAY-7', fixVersions: ['4.2'] })]);
    const posture = await getPostureSummary({ project: 'PAY', ...ctx(ME) }, t.deps);
    expect('error' in posture ? posture.error : posture.expiring.map((a) => a.acceptanceId)).toEqual(['acc_x']);
    const release = await getReleaseReadiness({ fixVersion: '4.2', ...ctx(ME) }, t.deps);
    expect('error' in release ? release.error : release.expiringSoon.map((a) => a.requirementId)).toEqual([req.id]);
  });
});

describe('caller identity for MCP calls', () => {
  it('MCP invocations carry the user in the Forge context principal, not payload.context (seen live); Rovo keeps payload.context', () => {
    const mcp = withCaller({ project: 'PAY', context: { cloudId: 'c', moduleKey: 'posture-summary' } }, { principal: { accountId: 'acc-mcp' } });
    expect(callerOf(mcp)).toBe('acc-mcp');
    // Forge's principal is authoritative: a payload accountId (which an MCP client might try to pass) never overrides it.
    const spoofed = withCaller({ context: { accountId: 'acc-victim', cloudId: 'c' } }, { principal: { accountId: 'acc-real' } });
    expect(callerOf(spoofed)).toBe('acc-real');
    // Rovo invocations without a principal keep the payload's accountId (the verified Automation path).
    expect(callerOf(withCaller({ context: { accountId: 'acc-rovo' } }, {}))).toBe('acc-rovo');
    expect(callerOf(withCaller({ context: {} }, {}))).toBe('');
    expect(callerOf(withCaller({}, { principal: { accountId: 42 } }))).toBe('');
  });
});

describe('a break-glass or warn-only window that has ended is not reported as passing', () => {
  const lapsed = { state: 'pass', overridden: true, validUntil: '2026-11-15T11:00:00Z', blockingCount: 8, maxOpenSeverity: 'Critical', reasons: [{ code: 'open_requirement', message: '8 open security requirements at High or above.' }], inheritedFrom: [], updatedAt: '2026-11-15T00:00:00Z' };
  it('get-review recomputes it: block, matching what the attestation says', async () => {
    const { t } = await reviewed();
    t.kv.data.set(verdictKey(ISSUE), lapsed);
    const r = await getReview({ issueKey: 'PAY-7', ...ctx(ME) }, t.deps);
    expect('verdict' in r && r.verdict?.state).toBe('block');
  });
  it('an active break-glass is labelled, so "pass" next to blocking reasons is explained', async () => {
    const { t } = await reviewed();
    t.kv.data.set(verdictKey(ISSUE), { ...lapsed, validUntil: '2026-11-16T00:00:00Z' });
    const r = await getReview({ issueKey: 'PAY-7', ...ctx(ME) }, t.deps);
    expect('verdict' in r && r.verdict).toMatchObject({ state: 'pass', overridden: true, validUntil: '2026-11-16T00:00:00Z' });
  });
  it('check-change-risk says the change would not pass', async () => {
    const { t } = await reviewed();
    t.kv.data.set(verdictKey(ISSUE), lapsed);
    const r = await checkChangeRisk({ issueKey: 'PAY-7', changedPaths: 'src/auth/session.ts', ...ctx(ME) }, t.deps);
    expect('wouldPass' in r && r.wouldPass).toBe(false);
  });
  it('release-readiness answers No-go', async () => {
    const { t } = await reviewed();
    t.jira.search = async () => ok([jiraIssue({ id: ISSUE, key: 'PAY-7', fixVersions: ['4.2'] })]);
    t.kv.data.set(verdictKey(ISSUE), lapsed);
    const r = await getReleaseReadiness({ fixVersion: '4.2', ...ctx(ME) }, t.deps);
    expect('answer' in r && r.answer).toBe('No-go');
  });
});

describe('verify-requirement: a coding agent closes the loop with the pull request as evidence', () => {
  it('marks the requirement Verified for the caller, ledgers it as made through an agent, and reports the verdict', async () => {
    const { t, req } = await reviewed();
    const r = await verifyRequirement({ requirementId: req.id, prUrl: 'https://bitbucket.org/acme/payments/pull-requests/42', note: 'test_webhook_rejects_bad_signature', ...ctx(ME) }, t.deps);
    expect(r).toMatchObject({ requirementId: req.id, status: 'Verified', verdict: 'pass', evidence: 'https://bitbucket.org/acme/payments/pull-requests/42' });
    const saved = await t.deps.requirements.get(req.id);
    expect(saved.ok && saved.value).toMatchObject({ status: 'Verified', verifiedBy: ME, evidence: { kind: 'pr', attester: ME } });
    const all = await t.deps.ledger.all();
    expect(all.ok && all.value.at(-1)).toMatchObject({ eventType: 'requirement.verified', actor: ME, payload: { requirementId: req.id, viaAgent: true } });
  });

  it('needs an https pull request link and edit permission', async () => {
    const { t, req } = await reviewed();
    expect(await verifyRequirement({ requirementId: req.id, prUrl: 'javascript:alert(1)', ...ctx(ME) }, t.deps)).toMatchObject({ error: 'invalid_input', message: expect.stringMatching(/prUrl/) });
    t.jira.canEdit = async () => ok(false);
    expect(await verifyRequirement({ requirementId: req.id, prUrl: 'https://x/pr/1', ...ctx(ME) }, t.deps)).toEqual({ error: 'not_found' });
    const saved = await t.deps.requirements.get(req.id);
    expect(saved.ok && saved.value?.status).toBe('Open');
  });

  it('stores the PR link itself as the evidence ref and the note beside it (a path-less link with a note works too)', async () => {
    const { t, req } = await reviewed();
    const url = 'https://bitbucket.org/acme/payments/pull-requests/42';
    expect(await verifyRequirement({ requirementId: req.id, prUrl: url, note: 'test_webhook_rejects_bad_signature', ...ctx(ME) }, t.deps)).toMatchObject({ status: 'Verified' });
    const saved = await t.deps.requirements.get(req.id);
    expect(saved.ok && saved.value?.evidence).toEqual({ kind: 'pr', ref: url, note: 'test_webhook_rejects_bad_signature', attester: ME });

    const other = await reviewed();
    expect(await verifyRequirement({ requirementId: other.req.id, prUrl: 'https://github.example', note: 'merged as abc123', ...ctx(ME) }, other.t.deps)).toMatchObject({ status: 'Verified' });
    const s2 = await other.t.deps.requirements.get(other.req.id);
    expect(s2.ok && s2.value?.evidence).toMatchObject({ ref: 'https://github.example', note: 'merged as abc123' });
  });
});

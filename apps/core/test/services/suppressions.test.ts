import { describe, expect, it } from 'vitest';
import { ok, type AgentThreatModel, type ContextFact, type Requirement, type SuppressionRule, type Threat, type Verdict } from '@threatline/shared';
import { refreshVerdict } from '../../src/services/verdict-service.js';
import { handleJob } from '../../src/consumers/review-consumer.js';
import { suppressionsCreate, suppressionsList, suppressionsRevoke, suppressionsUnhide } from '../../src/resolvers/suppressions.js';
import { threatsTriage } from '../../src/resolvers/threats.js';
import { expireRules, remindRules } from '../../src/services/suppression-service.js';
import { hourly, OPS_CONFIG_KEY } from '../../src/jobs/hourly.js';
import { daily } from '../../src/jobs/daily.js';
import { coreDeps, jiraIssue } from '../support/core-deps.js';

const ISSUE = '10042';
const CHAMPIONS = 'threatline-security-champions';
const CHAMP = { accountId: 'acc-champ' };
const LEAK = 'Customer email leaks in webhook logs';
const FORGED = 'Forged refund webhooks';
const REASON = 'Webhook logs are redacted by the platform logger in every PAY service.';

const model: AgentThreatModel = {
  schema: 'threatline.threatmodel.v1',
  issueKey: 'PAY-7',
  threats: [
    { stride: 'Spoofing', title: FORGED, scenario: 'An attacker posts a fake refund event.', component: 'webhook endpoint', likelihood: 4, impact: 4, evidence: [{ quote: 'Public webhook that receives refund events' }] },
    { stride: 'InformationDisclosure', title: LEAK, scenario: 'Logs keep the customer email address.', component: 'webhook endpoint', likelihood: 3, impact: 3, evidence: [{ quote: 'customer email address' }] },
  ],
};

function setup(o: { champion?: boolean; admin?: boolean } = {}) {
  const t = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })] });
  if (o.champion !== false) t.jira.groupsOf = async () => ok([CHAMPIONS]);
  if (o.admin) t.jira.isAdmin = async () => ok(true);
  return t;
}

async function review(t: ReturnType<typeof setup>, reason: 'created' | 'rerun' = 'created') {
  await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason });
  const rev = (await t.deps.reviews.latest(ISSUE)) as { ok: true; value: { id: string; revision: number } };
  for (let n = 1; n <= 3; n++) {
    await t.deps.reviews.saveSample(rev.value.id, n, model);
    await handleJob(t.deps, { kind: 'assemble', reviewId: rev.value.id });
  }
  const threats = ((await t.deps.reviews.threats(rev.value.id)) as { ok: true; value: Threat[] }).value;
  return { id: rev.value.id, threats, by: (title: string) => threats.find((x) => x.title === title)! };
}
const reqs = async (t: ReturnType<typeof setup>) => ((await t.deps.requirements.forIssue(ISSUE)) as { ok: true; value: Requirement[] }).value;
const ledgerTypes = (t: ReturnType<typeof setup>) => (t.deps.ledger as unknown as { _rows: Array<{ eventType: string; payload: Record<string, unknown>; actor: string }> })._rows;
const create = (t: ReturnType<typeof setup>, over: Record<string, unknown> = {}) =>
  suppressionsCreate(t.deps, CHAMP, { projectKey: 'PAY', stride: 'InformationDisclosure', title: 'Customer email leaks into logs', reason: REASON, ...over }) as Promise<SuppressionRule & { error?: string; message?: string }>;

describe('suppression rules: create and revoke (champions and admins, ledgered)', () => {
  it('a champion creates a rule: active for 90 days by default, its creation in the ledger', async () => {
    const t = setup();
    const r = await create(t, { evidence: ['PAY-1', 'PAY-2', 'PAY-3'] });
    expect(r).toMatchObject({ projectKey: 'PAY', status: 'active', createdBy: 'acc-champ', createdAt: '2026-11-15T12:00:00.000Z', expiresAt: '2027-02-13T12:00:00.000Z', evidence: ['PAY-1', 'PAY-2', 'PAY-3'] });
    const row = ledgerTypes(t).find((x) => x.eventType === 'suppression.created')!;
    expect(row).toMatchObject({ actor: 'acc-champ', payload: { ruleId: r.id, projectKey: 'PAY', reason: REASON, expiresAt: r.expiresAt } });
  });

  it('an admin may create one; anyone else may not', async () => {
    expect((await create(setup({ champion: false, admin: true }))).status).toBe('active');
    expect(await create(setup({ champion: false }))).toMatchObject({ error: 'forbidden' });
    expect(await suppressionsList(setup({ champion: false }).deps, CHAMP)).toMatchObject({ error: 'forbidden' });
  });

  it('validation: a reason, at most 90 days, a project key; no second rule for the same kind of threat', async () => {
    const t = setup();
    expect(await create(t, { reason: 'short' })).toMatchObject({ error: 'validation', message: 'Write a reason of at least 10 characters.' });
    expect(await create(t, { expiryDays: 91 })).toMatchObject({ error: 'validation', message: 'A rule lasts at most 90 days.' });
    expect(await create(t, { projectKey: 'pay' })).toMatchObject({ error: 'validation' });
    expect((await create(t, { expiryDays: 30 })).expiresAt).toBe('2026-12-15T12:00:00.000Z');
    expect(await create(t, { title: 'Customer email leaks into the logs' })).toMatchObject({ error: 'conflict' });
    expect((await create(t, { title: 'Customer email leaks into the logs', component: 'webhook endpoint' })).status).toBe('active');
  });

  it('a rule whose creation could not be ledgered never becomes active', async () => {
    const t = setup();
    t.deps.ledger.append = async () => ({ ok: false, error: { code: 'upstream', message: 'down' } });
    expect(await create(t)).toMatchObject({ error: 'unavailable' });
    expect((await t.deps.suppressions.list(['active'], 10)).ok && (await t.deps.suppressions.list(['active'], 10))).toEqual({ ok: true, value: [] });
  });

  it('revoke needs a reason, is ledgered, and only once', async () => {
    const t = setup();
    const r = await create(t);
    expect(await suppressionsRevoke(t.deps, CHAMP, { ruleId: r.id, reason: 'no' })).toMatchObject({ error: 'validation' });
    expect(await suppressionsRevoke(t.deps, CHAMP, { ruleId: r.id, reason: 'The logger change was rolled back.' })).toMatchObject({ status: 'revoked', endedBy: 'acc-champ' });
    expect(await suppressionsRevoke(t.deps, CHAMP, { ruleId: r.id, reason: 'The logger change was rolled back.' })).toMatchObject({ error: 'conflict' });
    expect(ledgerTypes(t).filter((x) => x.eventType === 'suppression.revoked')).toHaveLength(1);
    expect(await suppressionsRevoke(setup({ champion: false }).deps, CHAMP, { ruleId: r.id, reason: 'The logger change was rolled back.' })).toMatchObject({ error: 'forbidden' });
  });
});

describe('suppression rules in reviews', () => {
  it('hides a matching below-threshold threat in a new review: no requirement, the verdict ignores it, the match is counted', async () => {
    const t = setup();
    const before = await review(t);
    const leakReq = (await reqs(t)).find((r) => r.threatId === before.by(LEAK).id);
    expect(leakReq).toBeDefined();
    const rule = await create(t);
    const after = await review(t, 'rerun');
    expect(after.by(LEAK)).toMatchObject({ state: 'suppressed', suppression: { ruleId: rule.id, outcome: 'hidden', reason: REASON } });
    // The untouched requirement the earlier revision gave the same threat goes with it.
    expect((await reqs(t)).some((r) => r.id === leakReq!.id)).toBe(false);
    // The blocking threat is untouched and still blocks Done.
    expect(after.by(FORGED).state).toBe('accepted');
    const v = t.verdicts._written.get(ISSUE) as Verdict;
    expect(v.state).toBe('block');
    const list = await suppressionsList(t.deps, CHAMP);
    expect('rules' in list && list.rules).toEqual([expect.objectContaining({ id: rule.id, matches: 1 })]);
  });

  it('never hides a threat at or above the blocking threshold; the panel learns the rule matched', async () => {
    const t = setup();
    const rule = await create(t, { stride: 'Spoofing', title: 'Forged refund webhooks accepted' });
    const r = await review(t);
    expect(r.by(FORGED)).toMatchObject({ state: 'accepted', suppression: { ruleId: rule.id, outcome: 'blocking' } });
    expect((await reqs(t)).some((x) => x.threatId === r.by(FORGED).id)).toBe(true);
  });

  it('only reviews of that project', async () => {
    const t = setup();
    await suppressionsCreate(t.deps, CHAMP, { projectKey: 'OPS', stride: 'InformationDisclosure', title: LEAK, reason: REASON });
    expect((await review(t)).by(LEAK).state).toBe('accepted');
  });

  it('a revoked rule hides nothing in the next review', async () => {
    const t = setup();
    const rule = await create(t);
    expect((await review(t)).by(LEAK).state).toBe('suppressed');
    await suppressionsRevoke(t.deps, CHAMP, { ruleId: rule.id, reason: 'The logger change was rolled back.' });
    expect((await review(t, 'rerun')).by(LEAK).state).toBe('accepted');
  });

  it('a champion unhides it on this work item (ledgered): it is back with its requirement, and stays shown on re-runs', async () => {
    const t = setup();
    const rule = await create(t);
    const r = await review(t);
    const out = (await suppressionsUnhide(t.deps, { accountId: 'acc-champ', issueId: ISSUE }, { ruleId: rule.id })) as Threat[];
    expect(out.find((x) => x.id === r.by(LEAK).id)).toMatchObject({ state: 'accepted', suppression: { outcome: 'unhidden' } });
    expect((await reqs(t)).some((x) => x.threatId === r.by(LEAK).id)).toBe(true);
    expect(ledgerTypes(t).find((x) => x.eventType === 'suppression.unhidden')).toMatchObject({ actor: 'acc-champ', payload: { ruleId: rule.id, issueId: ISSUE, reviewId: r.id, threatIds: [r.by(LEAK).id] } });
    expect((await review(t, 'rerun')).by(LEAK)).toMatchObject({ state: 'accepted', suppression: { outcome: 'unhidden' } });
    // Nothing left to unhide.
    expect(await suppressionsUnhide(t.deps, { accountId: 'acc-champ', issueId: ISSUE }, { ruleId: rule.id })).toMatchObject({ error: 'not_found' });
  });

  it('unhide is for champions only', async () => {
    const t = setup();
    const rule = await create(t);
    await review(t);
    t.jira.groupsOf = async () => ok([]);
    expect(await suppressionsUnhide(t.deps, { accountId: 'acc-dev', issueId: ISSUE }, { ruleId: rule.id })).toMatchObject({ error: 'forbidden' });
    expect(await suppressionsUnhide(t.deps, { accountId: 'acc-dev', issueId: ISSUE }, { ruleId: 'nope' })).toMatchObject({ error: 'validation' });
  });

  it('fails closed: when the rules cannot be read, the review shows every threat', async () => {
    const t = setup();
    await create(t);
    t.deps.suppressions.activeFor = async () => ({ ok: false, error: { code: 'upstream', message: 'sql down' } });
    expect((await review(t)).by(LEAK).state).toBe('accepted');
  });
});

describe('suggestions, expiry and the monthly reminder', () => {
  it('dismissals with a reason on three work items of a project suggest a rule, with them as evidence', async () => {
    const issues = ['10042', '10043', '10044'].map((id, n) => jiraIssue({ id, key: `PAY-${7 + n}` }));
    const t = coreDeps({ issues });
    t.jira.groupsOf = async () => ok([CHAMPIONS]);
    for (const issue of issues) {
      await handleJob(t.deps, { kind: 'gather', issueId: issue.id, reason: 'created' });
      const rev = (await t.deps.reviews.latest(issue.id)) as { ok: true; value: { id: string } };
      for (let n = 1; n <= 3; n++) {
        await t.deps.reviews.saveSample(rev.value.id, n, { ...model, issueKey: `PAY-${issue.id}` });
        await handleJob(t.deps, { kind: 'assemble', reviewId: rev.value.id });
      }
      const leak = ((await t.deps.reviews.threats(rev.value.id)) as { ok: true; value: Threat[] }).value.find((x) => x.title === LEAK)!;
      await threatsTriage(t.deps, { accountId: 'acc-champ', issueId: issue.id }, { threatId: leak.id, op: 'dismiss', reason: 'false_positive' });
    }
    const list = await suppressionsList(t.deps, CHAMP);
    if (!('suggestions' in list)) throw new Error(JSON.stringify(list));
    expect(list.suggestions).toEqual([
      expect.objectContaining({ projectKey: 'PAY', stride: 'InformationDisclosure', title: LEAK, component: 'webhook endpoint', workItems: 3, evidence: expect.arrayContaining([expect.objectContaining({ issueKey: 'PAY-9', reason: 'false_positive', actor: 'acc-champ' })]) }),
    ]);
    // One click: the suggestion becomes a rule, and is no longer suggested.
    const s = list.suggestions[0]!;
    const r = await suppressionsCreate(t.deps, CHAMP, { projectKey: s.projectKey, stride: s.stride, title: s.title, component: s.component, reason: s.suggestedReason, evidence: s.evidence.map((e) => e.issueKey) });
    expect(r).toMatchObject({ status: 'active' });
    const again = await suppressionsList(t.deps, CHAMP);
    expect('suggestions' in again && again.suggestions).toEqual([]);
  });

  it('the hourly job expires rules past their expiry, ledgered once', async () => {
    const t = setup();
    const r = await create(t, { expiryDays: 1 });
    t.clock.set('2026-11-16T12:00:00Z');
    await hourly(t.deps);
    await hourly(t.deps);
    expect((await t.deps.suppressions.get(r.id)).ok && (await t.deps.suppressions.get(r.id))).toMatchObject({ value: { status: 'expired', endedBy: 'threatline' } });
    expect(ledgerTypes(t).filter((x) => x.eventType === 'suppression.expired')).toEqual([expect.objectContaining({ actor: 'threatline', payload: expect.objectContaining({ ruleId: r.id }) })]);
    expect(await expireRules(t.deps, t.clock.now())).toEqual({ ok: true, value: { expired: 0 } });
  });

  it('the daily job reminds the ops work item of active rules once a month, bounded', async () => {
    const t = setup();
    expect(await remindRules(t.deps, t.clock.now())).toEqual({ ok: true, value: false });
    await t.kv.set(OPS_CONFIG_KEY, { issueKey: 'OPS-1', accountIds: ['acc-admin'] });
    for (let n = 0; n < 22; n++) await create(t, { projectKey: `P${n}`, title: `Kind of threat number ${n}` });
    await daily(t.deps);
    await daily(t.deps);
    expect(t.jira.commented).toHaveLength(1);
    const text = JSON.stringify(t.jira.commented[0]!.adf);
    expect(text).toContain('22 team suppression rules');
    expect(text).toContain('And 2 more.');
    expect(text).toContain('Threatline admin → Suppressions');
    t.clock.set('2026-12-01T12:00:00Z');
    await daily(t.deps);
    expect(t.jira.commented).toHaveLength(2);
  });
});

describe('security review fixes', () => {
  const blockingIds = (t: ReturnType<typeof setup>) => (t.verdicts._written.get(ISSUE) as Verdict).reasons.flatMap((r) => r.requirementIds ?? []);

  it('fail closed: a suppressed threat counts for the gate once the policy threshold is lowered to its severity', async () => {
    const t = setup();
    await create(t);
    const r = await review(t);
    const leak = r.by(LEAK);
    expect(leak.state).toBe('suppressed');
    await refreshVerdict(t.deps, ISSUE);
    expect(blockingIds(t)).not.toContain(leak.id);
    const policy = await t.deps.config.site();
    if (!policy.ok) throw new Error('policy');
    await t.deps.config.setSite({ ...policy.value, blockAtOrAbove: 'Medium' });
    await refreshVerdict(t.deps, ISSUE);
    expect(blockingIds(t)).toContain(leak.id);
  });

  it('fail closed: the verdict checks the project’s active rules; a revoked rule, or a failed lookup, hides nothing', async () => {
    const t = setup();
    const rule = await create(t);
    await review(t);
    const calls: string[] = [];
    const real = t.deps.suppressions.activeFor.bind(t.deps.suppressions);
    t.deps.suppressions.activeFor = async (p, now) => (calls.push(p), real(p, now));
    await refreshVerdict(t.deps, ISSUE);
    expect(calls).toEqual(['PAY']);
    await suppressionsRevoke(t.deps, CHAMP, { ruleId: rule.id, reason: 'The logger change was rolled back.' });
    // Below the threshold the leak does not block either way; what matters is that it is no longer trusted as hidden.
    const policy = await t.deps.config.site();
    if (!policy.ok) throw new Error('policy');
    await t.deps.config.setSite({ ...policy.value, blockAtOrAbove: 'Medium' });
    t.deps.suppressions.activeFor = async () => ({ ok: false, error: { code: 'upstream', message: 'down' } });
    await refreshVerdict(t.deps, ISSUE);
    expect((t.verdicts._written.get(ISSUE) as Verdict).state).toBe('block');
  });

  it('triage on a hidden threat is refused until a champion unhides it here (edit, accept, dismiss, merge into it)', async () => {
    const t = setup();
    await create(t);
    const r = await review(t);
    const who = { accountId: 'acc-champ', issueId: ISSUE };
    const msg = `“${LEAK}” is hidden by a team rule (${r.by(LEAK).suppression!.ruleId}). Unhide it here first.`;
    expect(await threatsTriage(t.deps, who, { threatId: r.by(LEAK).id, op: 'edit', patch: { likelihood: 5, impact: 5 } })).toEqual({ error: 'validation', message: msg });
    expect(await threatsTriage(t.deps, who, { threatId: r.by(LEAK).id, op: 'accept' })).toEqual({ error: 'validation', message: msg });
    expect(await threatsTriage(t.deps, who, { threatId: r.by(LEAK).id, op: 'dismiss', reason: 'false_positive' })).toEqual({ error: 'validation', message: msg });
    expect(await threatsTriage(t.deps, who, { threatId: r.by(FORGED).id, op: 'merge', intoThreatId: r.by(LEAK).id })).toEqual({ error: 'validation', message: msg });
    const after = ((await t.deps.reviews.threats(r.id)) as { ok: true; value: Threat[] }).value;
    expect(after.find((x) => x.id === r.by(LEAK).id)).toMatchObject({ state: 'suppressed', severity: 'Medium' });
  });

  async function dismissedOnThree() {
    const issues = ['10042', '10043', '10044'].map((id, n) => jiraIssue({ id, key: `PAY-${7 + n}` }));
    const t = coreDeps({ issues });
    t.jira.groupsOf = async () => ok([CHAMPIONS]);
    const leaks: Array<{ issueId: string; reviewId: string; threat: Threat }> = [];
    for (const issue of issues) {
      await handleJob(t.deps, { kind: 'gather', issueId: issue.id, reason: 'created' });
      const rev = (await t.deps.reviews.latest(issue.id)) as { ok: true; value: { id: string } };
      for (let n = 1; n <= 3; n++) {
        await t.deps.reviews.saveSample(rev.value.id, n, { ...model, issueKey: `PAY-${issue.id}` });
        await handleJob(t.deps, { kind: 'assemble', reviewId: rev.value.id });
      }
      const leak = ((await t.deps.reviews.threats(rev.value.id)) as { ok: true; value: Threat[] }).value.find((x) => x.title === LEAK)!;
      await threatsTriage(t.deps, { accountId: 'acc-champ', issueId: issue.id }, { threatId: leak.id, op: 'dismiss', reason: 'false_positive' });
      leaks.push({ issueId: issue.id, reviewId: rev.value.id, threat: leak });
    }
    const suggested = async (accountId = 'acc-champ') => {
      const list = await suppressionsList(t.deps, { accountId });
      if (!('suggestions' in list)) throw new Error(JSON.stringify(list));
      return list.suggestions;
    };
    expect(await suggested()).toHaveLength(1);
    return { t, leaks, suggested };
  }

  it('suggestions use only dismissals on work items the caller can browse', async () => {
    const { t, suggested } = await dismissedOnThree();
    t.jira.browsable = async (_a, ids) => ok(ids.filter((id) => id !== '10044'));
    expect(await suggested()).toEqual([]);
    t.jira.browsable = async () => ({ ok: false, error: { code: 'upstream', message: 'down' } });
    expect(await suppressionsList(t.deps, CHAMP)).toMatchObject({ error: 'unavailable' });
  });

  it('suggestions leave out dismissed threats that cite a source the caller cannot open', async () => {
    const { t, leaks, suggested } = await dismissedOnThree();
    const { reviewId, threat } = leaks[2]!;
    const facts = ((await t.deps.reviews.facts(reviewId)) as { ok: true; value: ContextFact[] }).value;
    const secret: ContextFact = { ...facts[0]!, id: 'fact_secret', sourceAri: 'ari:t:issue/99999', title: 'Restricted incident' };
    await t.deps.reviews.saveFacts(reviewId, [...facts, secret]);
    await t.deps.reviews.updateThreat(threat.id, { citations: [{ factId: 'fact_secret', quote: 'customer email address' }] });
    t.jira.canBrowse = async (_a, id) => ok(id !== '99999');
    expect(await suggested()).toEqual([]);
    // Someone who can open it still gets the suggestion.
    t.jira.canBrowse = async () => ok(true);
    expect(await suggested()).toHaveLength(1);
  });
});

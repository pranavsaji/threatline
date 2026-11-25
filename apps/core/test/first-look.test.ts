import { describe, expect, it } from 'vitest';
import { contextHash, normalizeFact } from '@threatline/core';
import { ok, type ContextBundle, type Review, type Threat } from '@threatline/shared';
import { FakeLlm } from '../../../packages/core/test/fakes/fake-llm.js';
import type { ConfluenceClient } from '../src/adapters/confluence.js';
import { handleJob } from '../src/consumers/review-consumer.js';
import { panelGet, panelStatus, type PanelDto, type StatusDto } from '../src/resolvers/panel.js';
import { FIRST_LOOK_STAGE } from '../src/services/first-look.js';
import { coreDeps, drain, jiraIssue, POLICY } from './support/core-deps.js';

const ISSUE = '10042';
const viewer = { accountId: 'acc-1', issueId: ISSUE };
const QUOTE = 'Public webhook that receives refund events with customer email address';
const keyIn = (user: string) => /^Review ([A-Z][A-Z0-9_]*-\d+)\./m.exec(user)?.[1] ?? /"issueKey": "([A-Z][A-Z0-9_]*-\d+)"/.exec(user)?.[1] ?? 'PAY-1';

/** Threatline Engine with a model that answers every stage (nothing is called until the gather has stored the first look). */
const engineLlm = () =>
  new FakeLlm({
    extract: (req) =>
      JSON.stringify({
        sketch: { components: ['webhook endpoint'], dataStores: [], externalServices: [], trustBoundaries: [], flows: [], dataClasses: ['pii'], exposure: 'public', llmFeatures: false, injectionSuspected: false },
        evidence: [{ id: 'E1', factId: /id="([^"]+)"/.exec(req.user)?.[1] ?? 'x', quote: QUOTE, about: 'public refund webhook', tags: ['public'] }],
      }),
    propose: (req) =>
      JSON.stringify({
        schema: 'threatline.threatmodel.v1',
        issueKey: keyIn(req.user),
        threats: [{ stride: 'Spoofing', title: 'Forged refund webhook events', scenario: 'An attacker posts fake refund events.', component: 'webhook endpoint', likelihood: 4, impact: 4, evidence: [{ quote: QUOTE }] }],
      }),
    gaps: (req) => JSON.stringify({ schema: 'threatline.threatmodel.v1', issueKey: keyIn(req.user), threats: [] }),
    verify: (req) => JSON.stringify({ verdicts: [...req.user.matchAll(/^(T\d+) \[/gm)].map((m) => ({ id: m[1], keep: true, reason: 'quoted' })) }),
  });

const engine = () => {
  const llm = engineLlm();
  return { ...coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })], policy: { ...POLICY, reviewMode: 'engine' }, llm }), llm };
};
const get = async (t: ReturnType<typeof coreDeps>): Promise<PanelDto> => {
  const d = await panelGet(t.deps, viewer);
  if ('error' in d) throw new Error(d.error);
  return d;
};
const status = async (t: ReturnType<typeof coreDeps>): Promise<StatusDto> => {
  const d = await panelStatus(t.deps, viewer);
  if ('error' in d) throw new Error(d.error);
  return d;
};

describe('the first look: rule-based threats in seconds, before any model call', () => {
  it('the gather stores the rule-based floor for the revision before any model is called', async () => {
    const t = engine();
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    expect(t.llm.calls).toHaveLength(0);
    expect(t.pushed).toContainEqual({ kind: 'engine', reviewId: `rev_${ISSUE}_1`, stage: 'extract' });
    const s = (await t.deps.reviews.stage(`rev_${ISSUE}_1`, FIRST_LOOK_STAGE)) as { ok: true; value: { status: string; checkpoint: { threats: Threat[] } } };
    expect(s.value.status).toBe('done');
    const titles = s.value.checkpoint.threats.map((x) => x.title);
    expect(titles.length).toBeGreaterThan(0);
    expect(s.value.checkpoint.threats.every((x) => x.origin === 'baseline')).toBe(true);
    expect(titles).toContain('Personal data exposed to unauthorised users');
  });

  it('the panel shows it while the review runs, with its stage of six; the gate keeps blocking and nothing is ledgered', async () => {
    const t = engine();
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    const running = await get(t);
    expect(running.review?.status).toBe('awaiting_agent');
    expect(running.verdict?.state).toBe('block');
    expect(running.firstLook).toMatchObject({ hidden: 0, stage: { n: 2, of: 6, name: 'Injection check' } });
    expect(running.firstLook!.risks).toBe(running.firstLook!.threats.length);
    for (const x of running.firstLook!.threats) expect(x).toMatchObject({ origin: 'baseline', severity: expect.any(String), plainLanguage: expect.any(String), citations: [{ quote: expect.any(String) }] });
    expect(await t.deps.ledger.all()).toEqual({ ok: true, value: [] });

    // Once the injection check is done, the runs are under way: stage 3.
    const extract = t.pushed.splice(0).filter((j) => j.kind === 'engine');
    for (const j of extract) await handleJob(t.deps, j);
    expect((await get(t)).firstLook?.stage).toEqual({ n: 3, of: 6, name: 'Independent AI runs, 0 of 3 done' });
  });

  it('it disappears once the review is in, and the settled review holds every first-look threat (the floor)', async () => {
    const t = engine();
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    const first = (await get(t)).firstLook!.threats.map((x) => x.id);
    await drain((j) => handleJob(t.deps, j), t.pushed, 100);
    const settled = await get(t);
    expect(settled.review?.status).toBe('ready');
    expect(settled).not.toHaveProperty('firstLook');
    const stored = ((await t.deps.reviews.threats(settled.review!.id)) as { ok: true; value: Threat[] }).value.map((x) => x.id);
    expect(stored).toEqual(expect.arrayContaining(first));
    expect(await status(t)).not.toHaveProperty('firstLook');
  });

  it('panel.status carries only the count, and stays cheap: one extra read while running, none once settled', async () => {
    const t = engine();
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    let reads = 0;
    const stage = t.deps.reviews.stage.bind(t.deps.reviews);
    t.deps.reviews.stage = (id, name) => (reads++, stage(id, name));
    const s = await status(t);
    expect(s.firstLook).toEqual({ risks: (await get(t)).firstLook!.risks });
    reads = 0;
    await status(t);
    expect(reads).toBe(1);
    expect(JSON.stringify(s)).not.toMatch(/quote|citations|plainLanguage/);
    await drain((j) => handleJob(t.deps, j), t.pushed, 100);
    reads = 0;
    expect(await status(t)).not.toHaveProperty('firstLook');
    expect(reads).toBe(0);
  });

  it('a Rovo agent review shows it without engine stages; a rules-only review settles at once and has none', async () => {
    const agent = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })] });
    await handleJob(agent.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    const a = await get(agent);
    expect(a.firstLook!.threats.length).toBeGreaterThan(0);
    expect(a.firstLook).not.toHaveProperty('stage');

    const rules = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })], policy: { ...POLICY, reviewMode: 'rules_only' } });
    await handleJob(rules.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    expect(await rules.deps.reviews.stage(`rev_${ISSUE}_1`, FIRST_LOOK_STAGE)).toEqual({ ok: true, value: null });
    expect(await get(rules)).not.toHaveProperty('firstLook');
  });

  it('scoped to the viewer: a first-look threat citing a page they cannot open is counted, never shown', async () => {
    const t = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })] });
    const facts = [
      normalizeFact({ sourceAri: `ari:cloud:jira:c:issue/${ISSUE}`, sourceType: 'jira_issue', title: 'PAY-7 Refunds', url: '', text: 'Refunds for orders placed this year.', version: '1', trusted: false, origin: 'rest' }),
      normalizeFact({ sourceAri: 'ari:cloud:confluence:c:page/777', sourceType: 'confluence_page', title: 'Login design', url: '', text: 'Customers sign in with a password and a session token kept for 30 days.', version: '1', trusted: false, origin: 'rest' }),
    ];
    const bundle: ContextBundle = { issueId: ISSUE, issueKey: 'PAY-7', facts, partial: false, partialReasons: [], contextHash: contextHash(facts), gatheredAt: '2026-11-15T12:00:00.000Z', components: [] };
    t.deps.gatherer = { gather: async () => ok(bundle) };
    t.deps.confluence = { canRead: async () => ok(false) } as unknown as ConfluenceClient;
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    const stored = (await t.deps.reviews.stage(`rev_${ISSUE}_1`, FIRST_LOOK_STAGE)) as { ok: true; value: { checkpoint: { threats: Threat[] } } };
    const onPage = stored.value.checkpoint.threats.filter((x) => x.citations.every((c) => c.factId === facts[1]!.id));
    expect(onPage.length).toBeGreaterThan(0);
    const d = await get(t);
    expect(d.firstLook!.hidden).toBe(onPage.length);
    expect(d.firstLook!.risks).toBe(stored.value.checkpoint.threats.length);
    expect(JSON.stringify(d.firstLook)).not.toMatch(/session token|Login design/);
    // A viewer who can open the page sees them.
    t.deps.confluence = { canRead: async () => ok(true) } as unknown as ConfluenceClient;
    expect((await get(t)).firstLook!.hidden).toBe(0);
  });

  it('an unreadable or malformed stored first look is left out, never an error', async () => {
    const t = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })] });
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    const review = ((await t.deps.reviews.latest(ISSUE)) as { ok: true; value: Review }).value;
    await t.deps.reviews.saveStage(review.id, FIRST_LOOK_STAGE, 'done', { threats: [{ not: 'a threat' }] });
    expect(await get(t)).not.toHaveProperty('firstLook');
    expect(await status(t)).not.toHaveProperty('firstLook');
  });
});

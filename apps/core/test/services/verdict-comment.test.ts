import { readFileSync } from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { appError, err, type AgentThreatModel, type ContextFact, type Requirement, type Review, type Threat } from '@threatline/shared';
import { VERDICT, OVERRIDDEN } from '@threatline/shared/verdict-words';
import { FakeLlm } from '../../../../packages/core/test/fakes/fake-llm.js';
import { handleJob } from '../../src/consumers/review-consumer.js';
import type { ReviewJob } from '../../src/jobs/types.js';
import { sweep } from '../../src/jobs/sweeper.js';
import { OWN_ACCOUNT_KEY } from '../../src/services/own-account.js';
import { BULLET, COMMENT_STAGE, commentOnSettle, lastCommentKey, verdictCommentDoc, verdictCommentLines, type CommentInput } from '../../src/services/verdict-comment.js';
import { APP_ACCOUNT, coreDeps, drain, jiraIssue, POLICY } from '../support/core-deps.js';

const ISSUE = '10042';
const QUOTE = 'Public webhook that receives refund events';

const model = (plain = 'Anyone on the internet could post a fake refund and get money back.'): AgentThreatModel =>
  ({
    schema: 'threatline.threatmodel.v1',
    issueKey: 'PAY-7',
    threats: [{ stride: 'Spoofing', title: 'Forged refund webhooks', scenario: 'An attacker posts a fake refund event.', component: 'webhook endpoint', likelihood: 4, impact: 4, plainLanguage: plain, evidence: [{ quote: QUOTE }] }],
  }) as AgentThreatModel;

/** The comment as plain lines: a paragraph per line, list items prefixed like the builder's input. */
function textOf(adf: unknown): string[] {
  const doc = adf as { content: Array<{ type: string; content: Array<{ text?: string; content?: Array<{ content: Array<{ text: string }> }> }> }> };
  return doc.content.flatMap((n) => (n.type === 'bulletList' ? n.content.map((li) => `${BULLET}${li.content![0]!.content[0]!.text}`) : [n.content.map((c) => c.text).join('')]));
}

const onItem = (t: ReturnType<typeof coreDeps>) => t.jira.commented.filter((c) => c.issueId === ISSUE);

/** A Rovo agent review of PAY-7: gathered, then its three runs land and the last assembly settles it. */
async function agentReview(o: { policy?: typeof POLICY; t?: ReturnType<typeof coreDeps>; reason?: 'created' | 'rerun'; runs?: AgentThreatModel } = {}) {
  const t = o.t ?? coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })], ...(o.policy ? { policy: o.policy } : {}) });
  await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: o.reason ?? 'created' });
  const rev = (await t.deps.reviews.latest(ISSUE)) as { ok: true; value: Review };
  for (let n = 1; n <= 3; n++) {
    await t.deps.reviews.saveSample(rev.value.id, n, o.runs ?? model());
    await handleJob(t.deps, { kind: 'assemble', reviewId: rev.value.id });
  }
  t.pushed.length = 0;
  return { t, reviewId: rev.value.id };
}

const stageOf = async (t: ReturnType<typeof coreDeps>, reviewId: string) => ((await t.deps.reviews.stage(reviewId, COMMENT_STAGE)) as { ok: true; value: { status: string; checkpoint?: unknown } | null }).value;

describe('the verdict comment when a review settles', () => {
  it('posts one plain comment, as Threatline: verdict, what blocks, counts by severity, the top risk, requirements, the panel', async () => {
    const { t, reviewId } = await agentReview();
    const posted = onItem(t);
    expect(posted).toHaveLength(1);
    const expected = readFileSync(new URL('../fixtures/comments/verdict-pay-7-blocks.txt', import.meta.url), 'utf8').trimEnd().split('\n');
    expect(textOf(posted[0]!.adf)).toEqual(expected);
    // ADF only: the verdict line in bold, the reasons as a list, no mentions or links.
    const doc = posted[0]!.adf as { type: string; version: number; content: Array<{ type: string; content: Array<{ marks?: unknown }> }> };
    expect([doc.type, doc.version]).toEqual(['doc', 1]);
    expect(doc.content.map((n) => n.type)).toEqual(['paragraph', 'paragraph', 'bulletList', 'paragraph', 'paragraph', 'paragraph', 'paragraph']);
    expect(doc.content[0]!.content[0]!.marks).toEqual([{ type: 'strong' }]);
    expect(JSON.stringify(posted[0]!.adf)).not.toMatch(/"mention"|"link"/);
    expect(await stageOf(t, reviewId)).toMatchObject({ status: 'done', checkpoint: { state: 'block', blockingCount: 3 } });
    expect(t.kv.data.get(lastCommentKey(ISSUE))).toEqual({ reviewId, revision: 1, state: 'block', blockingCount: 3 });
    // Its author is remembered as Threatline's own account (so its comments are never read back as context).
    expect(t.kv.data.get(OWN_ACCOUNT_KEY)).toBe(APP_ACCOUNT);
  });

  it('idempotent: a redelivered assembly or a second settle call posts nothing more', async () => {
    const { t, reviewId } = await agentReview();
    await handleJob(t.deps, { kind: 'assemble', reviewId });
    await commentOnSettle(t.deps, reviewId);
    await commentOnSettle(t.deps, reviewId);
    expect(onItem(t)).toHaveLength(1);
  });

  it('idempotent under concurrency: two settle calls at once post exactly one comment (the stage is claimed first)', async () => {
    let policy = { ...POLICY, postReviewComments: false };
    const t = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })] });
    t.deps.config.site = async () => ({ ok: true, value: policy });
    const { reviewId } = await agentReview({ t });
    expect(onItem(t)).toHaveLength(0);
    policy = { ...POLICY, postReviewComments: true };
    await Promise.all([commentOnSettle(t.deps, reviewId), commentOnSettle(t.deps, reviewId), commentOnSettle(t.deps, reviewId)]);
    expect(onItem(t)).toHaveLength(1);
  });

  it('a re-run comments only when the verdict state or the blocking count changed since the last comment', async () => {
    const first = await agentReview();
    const t = first.t;
    expect(onItem(t)).toHaveLength(1);
    // Same verdict (blocks, 3 open): quiet, and recorded as skipped so a redelivery does not reconsider it.
    const second = await agentReview({ t, reason: 'rerun' });
    expect(second.reviewId).not.toBe(first.reviewId);
    expect(onItem(t)).toHaveLength(1);
    expect(await stageOf(t, second.reviewId)).toMatchObject({ status: 'done', checkpoint: { skipped: 'unchanged', since: 1 } });
    // The threshold rises, so nothing blocks any more: the verdict changed, so the re-run comments.
    await t.deps.config.setSite({ ...POLICY, blockAtOrAbove: 'Critical' });
    const third = await agentReview({ t, reason: 'rerun' });
    expect(onItem(t)).toHaveLength(2);
    expect(textOf(onItem(t)[1]!.adf).slice(0, 2)).toEqual([`Threatline security review: ${VERDICT.pass.icon} ${VERDICT.pass.label}`, 'Nothing stands between this work item and Done or merge.']);
    expect(t.kv.data.get(lastCommentKey(ISSUE))).toMatchObject({ reviewId: third.reviewId, revision: 3, state: 'pass', blockingCount: 0 });
  });

  it('the site policy toggle: postReviewComments false posts nothing and claims nothing', async () => {
    const { t, reviewId } = await agentReview({ policy: { ...POLICY, postReviewComments: false } });
    expect(onItem(t)).toHaveLength(0);
    expect(await stageOf(t, reviewId)).toBeNull();
  });

  it('a failed comment is logged and never fails the review or its job', async () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const t = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })] });
      t.jira.comment = async () => err(appError('upstream', 'Jira is down'));
      const { reviewId } = await agentReview({ t });
      expect(((await t.deps.reviews.get(reviewId)) as { ok: true; value: Review }).value.status).toBe('ready');
      expect(await stageOf(t, reviewId)).toMatchObject({ status: 'failed' });
      // A Jira client that throws is caught the same way.
      const t2 = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })] });
      t2.jira.comment = async () => {
        throw new Error('socket hang up');
      };
      const r = await agentReview({ t: t2 });
      expect(((await t2.deps.reviews.get(r.reviewId)) as { ok: true; value: Review }).value.status).toBe('ready');
      const events = spy.mock.calls.map((c) => JSON.parse(String(c[0])) as Record<string, unknown>);
      expect(events.filter((e) => e.event === 'notify.comment_failed')).toHaveLength(2);
      expect(events.filter((e) => e.event === 'review.comment' && e.outcome === 'failed')).toHaveLength(2);
    } finally {
      spy.mockRestore();
    }
  });

  it('a superseded revision never comments', async () => {
    const t = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })] });
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    const old = (await t.deps.reviews.latest(ISSUE)) as { ok: true; value: Review };
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'rerun' });
    await t.deps.reviews.update(old.value.id, { status: 'ready' });
    await commentOnSettle(t.deps, old.value.id);
    expect(onItem(t)).toHaveLength(0);
  });

  it('rules-only mode comments at once, and says the review came from the rule-based checks', async () => {
    const t = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })], policy: { ...POLICY, reviewMode: 'rules_only' } });
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    const lines = textOf(onItem(t)[0]!.adf);
    expect(onItem(t)).toHaveLength(1);
    expect(lines[0]).toBe(`Threatline security review: ${VERDICT.block.icon} ${VERDICT.block.label}`);
    expect(lines).toContain("From Threatline's rule-based checks: AI review is off on this site.");
  });

  it('a review that timed out with no run comments once the sweeper settles it', async () => {
    const t = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })] });
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    expect(onItem(t)).toHaveLength(0);
    t.clock.advance(16 * 60_000);
    await sweep(t.deps);
    const lines = textOf(onItem(t)[0]!.adf);
    expect(lines).toContain(`${BULLET}The AI review did not arrive in time, so the review is incomplete.`);
    expect(lines).toContain('Done and merge stay blocked until the review runs again: re-run it from the Threatline panel.');
  });

  describe('Threatline Engine: the comment waits for the verifier', () => {
    const keyIn = (user: string) => /^Review ([A-Z][A-Z0-9_]*-\d+)\./m.exec(user)?.[1] ?? /"issueKey": "([A-Z][A-Z0-9_]*-\d+)"/.exec(user)?.[1] ?? 'PAY-1';
    const LONG = 'Public webhook that receives refund events with customer email address';
    const llm = () =>
      new FakeLlm({
        extract: (req) =>
          JSON.stringify({
            sketch: { components: ['webhook endpoint'], dataStores: [], externalServices: [], trustBoundaries: [], flows: [], dataClasses: ['pii'], exposure: 'public', llmFeatures: false, injectionSuspected: false },
            evidence: [{ id: 'E1', factId: /id="([^"]+)"/.exec(req.user)?.[1] ?? 'x', quote: LONG, about: 'public refund webhook', tags: ['public'] }],
          }),
        propose: (req) => JSON.stringify({ ...model(), issueKey: keyIn(req.user), threats: model().threats.map((x) => ({ ...x, evidence: [{ quote: LONG }] })) }),
        gaps: (req) => JSON.stringify({ schema: 'threatline.threatmodel.v1', issueKey: keyIn(req.user), threats: [] }),
        verify: (req) => JSON.stringify({ verdicts: [...req.user.matchAll(/^(T\d+) \[/gm)].map((m) => ({ id: m[1], keep: true, reason: 'quoted' })) }),
      });

    it('ready after assembly is not final: no comment until the verifier has run, then exactly one', async () => {
      const t = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })], policy: { ...POLICY, reviewMode: 'engine' }, llm: llm() });
      await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
      const held: ReviewJob[] = [];
      await drain((j) => (j.kind === 'engine' && j.stage === 'verify' ? (held.push(j), Promise.resolve()) : handleJob(t.deps, j)), t.pushed, 100);
      const review = (await t.deps.reviews.latest(ISSUE)) as { ok: true; value: Review };
      expect(review.value.status).toBe('ready');
      expect(held.length).toBeGreaterThan(0);
      expect(onItem(t)).toHaveLength(0);
      t.pushed.push(...held);
      await drain((j) => handleJob(t.deps, j), t.pushed, 100);
      expect(onItem(t)).toHaveLength(1);
      expect(textOf(onItem(t)[0]!.adf)[0]).toBe(`Threatline security review: ${VERDICT.block.icon} ${VERDICT.block.label}`);
    });
  });
});

describe('verdictCommentLines: wording and the leak rule', () => {
  const fact = (id: string, over: Partial<ContextFact> = {}): ContextFact =>
    ({ id, sourceAri: `ari:cloud:jira:c:issue/${ISSUE}`, sourceType: 'jira_issue', title: 'PAY-7 Refunds', url: '', excerpt: 'x', trustLevel: 'untrusted', injectionSuspected: false, injectionReasons: [], origin: 'rest', version: '1', ...over }) as ContextFact;
  const ISSUE_FACT = fact('f_issue');
  const PAGE_FACT = fact('f_page', { sourceAri: 'ari:cloud:confluence:c:page/777', sourceType: 'confluence_page', title: 'Secret merger plan' });
  const PARENT_FACT = fact('f_parent', { sourceAri: 'ari:cloud:jira:c:issue/10040', title: 'Parent SEC-9 Acquisition' });
  const threat = (id: string, over: Partial<Threat> = {}): Threat => ({
    id, reviewId: 'rev', stride: 'Spoofing', title: `Title ${id}`, scenario: 's', component: 'c', likelihood: 4, impact: 4, severity: 'High', votes: 3, samples: 3,
    grounding: 'supported', confidence: 1, state: 'accepted', origin: 'agent', citations: [{ factId: 'f_issue', quote: 'q' }], mappings: [], plainLanguage: `Plain ${id}`, ...over,
  });
  const input = (over: Partial<CommentInput> = {}): CommentInput => ({
    issueId: ISSUE,
    review: { status: 'ready', modelIds: ['claude-opus-5'] },
    verdict: { state: 'block', blockingCount: 1, reasons: [{ code: 'open_requirement', message: '1 open security requirement at High or above.' }] },
    threats: [threat('t1')],
    facts: [ISSUE_FACT, PAGE_FACT, PARENT_FACT],
    requirements: [],
    ...over,
  });

  it('uses the panel\'s verdict wording for every state (one shared source of words)', () => {
    expect(verdictCommentLines(input())[0]).toBe(`Threatline security review: ${VERDICT.block.icon} ${VERDICT.block.label}`);
    expect(verdictCommentLines(input({ verdict: { state: 'pass', blockingCount: 0, reasons: [] } }))[0]).toBe('Threatline security review: ✓ Ready for Done');
    const warn = verdictCommentLines(input({ verdict: { state: 'warn', blockingCount: 1, reasons: [{ code: 'open_requirement', message: 'x' }] } }));
    expect(warn.slice(0, 2)).toEqual(['Threatline security review: ! Warn only', 'Warn only: Done and merge go through for now, but 1 thing stands in the way.']);
    expect(verdictCommentLines(input({ verdict: { state: 'pass', overridden: true, blockingCount: 1, reasons: [{ code: 'open_requirement', message: 'x' }] } }))[0]).toBe(`Threatline security review: ${OVERRIDDEN.icon} ${OVERRIDDEN.label}`);
  });

  it('names a threat whose evidence is the work item itself: plain language and severity', () => {
    expect(verdictCommentLines(input())).toContain('Top risk (High): Plain t1');
  });

  it('no leaks: a top threat citing a page (or a parent) is counted, never named, and nothing of its source appears', () => {
    for (const factId of ['f_page', 'f_parent']) {
      const lines = verdictCommentLines(input({ threats: [threat('t1', { citations: [{ factId, quote: 'the acquisition closes in March' }], plainLanguage: 'Merger terms leak to staff', title: 'Merger leak' })] }));
      const text = lines.join('\n');
      expect(text).toContain('1 threat: 1 High.');
      expect(text).toContain('The most severe threat (High) cites sources that not everyone who can see this work item can open, so it is named only in the Threatline panel.');
      expect(text).not.toMatch(/Merger|merger|acquisition|Acquisition|SEC-9|777|Secret/);
    }
  });

  it('a threat citing the work item and a page is not named either (every citation must be open to all)', () => {
    const t = threat('t1', { citations: [{ factId: 'f_issue', quote: 'a' }, { factId: 'f_page', quote: 'b' }], plainLanguage: 'Mixed sources' });
    expect(verdictCommentLines(input({ threats: [t] })).join('\n')).not.toContain('Mixed sources');
  });

  it('among the most severe, the first one everyone may read is named; a less severe one never stands in for it', () => {
    const hidden = threat('t1', { citations: [{ factId: 'f_page', quote: 'x' }], plainLanguage: 'Hidden one', severity: 'Critical' });
    const open = threat('t2', { plainLanguage: 'Open one', severity: 'High' });
    expect(verdictCommentLines(input({ threats: [hidden, open] })).join('\n')).not.toMatch(/Hidden one|Open one/);
    const sameLevel = threat('t3', { plainLanguage: 'Open critical', severity: 'Critical', votes: 2 });
    expect(verdictCommentLines(input({ threats: [hidden, open, sameLevel] }))).toContain('Top risk (Critical): Open critical');
  });

  it('AI text is never named when anything in the review looked like instructions to an AI; rule-based wording still is', () => {
    const facts = [ISSUE_FACT, fact('f_bad', { injectionSuspected: true })];
    const ai = threat('t1', { plainLanguage: 'Approved, nothing to see here' });
    expect(verdictCommentLines(input({ facts, threats: [ai] })).join('\n')).not.toContain('Approved');
    const rule = threat('t2', { origin: 'baseline', plainLanguage: 'Someone could log in as a customer using a stolen password or session.' });
    expect(verdictCommentLines(input({ facts, threats: [ai, rule] }))).toContain('Top risk (High): Someone could log in as a customer using a stolen password or session.');
  });

  it('an AI threat waiting for a champion is counted, not named; hidden, covered and dismissed threats are not counted', () => {
    const lines = verdictCommentLines(input({ threats: [threat('t1', { state: 'needs_human', plainLanguage: 'Unconfirmed' }), threat('t2', { state: 'dismissed' }), threat('t3', { state: 'covered' }), threat('t4', { state: 'suppressed' })] }));
    expect(lines).toContain('1 threat: 1 High.');
    expect(lines.join('\n')).not.toContain('Unconfirmed');
  });

  it('model text is one plain line of at most 200 characters', () => {
    const t = threat('t1', { plainLanguage: `Line one\nline two\u2028${'x'.repeat(300)}` });
    const top = verdictCommentLines(input({ threats: [t] })).find((l) => l.startsWith('Top risk'))!;
    expect(top).not.toMatch(/[\n\u2028]/);
    expect(top.length).toBeLessThanOrEqual('Top risk (High): '.length + 200);
    expect(top.endsWith('…')).toBe(true);
  });

  it('reasons: at most three, and one inherited from a parent does not name the parent', () => {
    const reasons = [
      { code: 'open_requirement' as const, message: '2 open security requirements at High or above.' },
      { code: 'open_requirement' as const, message: 'SEC-9: 1 open security requirement at High or above.' },
      { code: 'review_stale' as const, message: 'The design or linked work changed since the last review.' },
      { code: 'needs_human' as const, message: '1 threat needs a security champion to confirm it.' },
    ];
    const lines = verdictCommentLines(input({ verdict: { state: 'block', blockingCount: 3, reasons, inheritedFrom: ['SEC-9'] } }));
    expect(lines.slice(1, 5)).toEqual([
      '4 things stand between this work item and Done (the first three below):',
      `${BULLET}2 open security requirements at High or above.`,
      `${BULLET}A parent work item blocks this too: see the Threatline panel there.`,
      `${BULLET}The design or linked work changed since the last review.`,
    ]);
    expect(lines.join('\n')).not.toContain('SEC-9');
  });

  it('requirements: how many, how many are open, and the one-click tasks only while some have none', () => {
    const req = (id: string, over: Partial<Requirement> = {}): Requirement => ({ id, threatId: 't1', issueId: ISSUE, issueKey: 'PAY-7', title: 'R', criteria: [{ given: 'g', when: 'w', then: 't' }], asvsIds: [], severity: 'High', status: 'Open', ...over });
    const t2 = threat('t2');
    const lines = verdictCommentLines(input({ threats: [threat('t1'), t2], requirements: [req('r1'), req('r2', { threatId: 't2', status: 'Verified' }), req('r3', { threatId: 'gone' })] }));
    expect(lines).toContain('2 security requirements (1 open). It can become a task in one click: Threatline panel → Requirements → Create sub-tasks.');
    const tasked = verdictCommentLines(input({ requirements: [req('r1', { subtaskKey: 'PAY-8' })] }));
    expect(tasked).toContain('1 security requirement.');
  });

  it('a failed review says how to get out; a paused one leaves it to its reason', () => {
    const failed = verdictCommentLines(input({ review: { status: 'failed', failureReason: 'upstream', modelIds: [] }, threats: [], verdict: { state: 'block', blockingCount: 0, reasons: [{ code: 'review_failed', message: 'The security review failed (upstream).' }] } }));
    expect(failed).toEqual([
      'Threatline security review: ✕ Blocks Done and merge',
      '1 thing stands between this work item and Done:',
      `${BULLET}The security review failed (upstream).`,
      'Done and merge stay blocked until the review runs again: re-run it from the Threatline panel.',
      'Evidence, requirements and next steps are in the Threatline panel on this work item.',
    ]);
    const paused = verdictCommentLines(input({ review: { status: 'failed', failureReason: 'budget', modelIds: [] }, threats: [], verdict: { state: 'block', blockingCount: 0, reasons: [{ code: 'budget_paused', message: 'Reviews are paused at the AI budget. A security champion can confirm this work item.' }] } }));
    expect(paused.join('\n')).not.toContain('re-run');
  });

  it('a settled review with no threats says so', () => {
    expect(verdictCommentLines(input({ threats: [], verdict: { state: 'pass', blockingCount: 0, reasons: [] } }))).toContain('No threats found.');
  });

  it('the ADF: bold verdict, one paragraph per line, consecutive reasons as one bullet list', () => {
    const doc = verdictCommentDoc(['V', 'H:', `${BULLET}a`, `${BULLET}b`, 'C']);
    expect(doc.content.map((n) => n.type)).toEqual(['paragraph', 'paragraph', 'bulletList', 'paragraph']);
    expect(doc.content[2]!.content).toHaveLength(2);
    expect(doc.content[0]!.content![0]).toEqual({ type: 'text', text: 'V', marks: [{ type: 'strong' }] });
  });
});

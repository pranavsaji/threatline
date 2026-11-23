import { describe, expect, it } from 'vitest';
import type { LlmPort } from '@threatline/core';
import type { Review, Threat } from '@threatline/shared';
import { handleJob } from '../src/consumers/review-consumer.js';
import { verificationPending, VERIFY_WAIT_MS } from '../src/services/engine.js';
import { applyTriage } from '../src/services/triage-service.js';
import type { JiraIssue } from '../src/adapters/jira.js';
import type { ReviewJob } from '../src/jobs/types.js';
import { FakeLlm } from '../../../packages/core/test/fakes/fake-llm.js';
import { coreDeps, drain, POLICY } from './support/core-deps.js';

const ISSUE = '10042';
const QUOTE = 'Public webhook that receives refund events with customer email address';
const factIdIn = (user: string) => /id="([^"]+)"/.exec(user)?.[1] ?? 'missing';
const keyIn = (user: string) => /^Review ([A-Z][A-Z0-9_]*-\d+)\./m.exec(user)?.[1] ?? 'PAY-1';
const extract = (req: { user: string }) =>
  JSON.stringify({
    sketch: { components: ['webhook endpoint'], dataStores: [], externalServices: [], trustBoundaries: [], flows: [], dataClasses: ['pii'], exposure: 'public', llmFeatures: false, injectionSuspected: false },
    evidence: [{ id: 'E1', factId: factIdIn(req.user), quote: QUOTE, about: 'public refund webhook', tags: ['public'] }],
  });
const RUN = (req: { user: string }) =>
  JSON.stringify({
    schema: 'threatline.threatmodel.v1',
    issueKey: keyIn(req.user),
    threats: [
      { stride: 'Spoofing', title: 'Forged refund webhook events', scenario: 'An attacker posts fake refund events to the public webhook.', component: 'webhook endpoint', likelihood: 4, impact: 4, evidence: [{ quote: QUOTE }] },
      { stride: 'Repudiation', title: 'No audit of refund events', scenario: 'Refund events cannot be traced to their sender.', component: 'webhook endpoint', likelihood: 2, impact: 3, evidence: [{ quote: QUOTE }] },
    ],
  });
/** Rejects every threat it is shown. */
const rejectAll = (req: { user: string }) =>
  JSON.stringify({ verdicts: [...req.user.matchAll(/^(T\d+) \[[^\]]+\] (.+)$/gm)].map((m) => ({ id: m[1]!, keep: false, reason: 'not supported by the quote' })) });

const enginePolicy = { ...POLICY, reviewMode: 'engine' as const };

/** A model whose verifier call lets `during` run first: a champion triaging while the verifier thinks. */
function racingLlm(fake: FakeLlm, during: () => Promise<void>): LlmPort {
  return {
    complete: async (req) => {
      if (req.purpose === 'verify') await during();
      return fake.complete(req);
    },
  };
}

const threatsOf = async (t: ReturnType<typeof coreDeps>, reviewId: string) => ((await t.deps.reviews.threats(reviewId)) as { ok: true; value: Threat[] }).value;
const latest = async (t: ReturnType<typeof coreDeps>) => ((await t.deps.reviews.latest(ISSUE)) as { ok: true; value: Review }).value;

describe('Threatline Engine verifier and human triage', () => {
  it('a threat a champion edits while the verifier runs keeps the champion’s decision; untouched threats take the verdicts', async () => {
    let hook: () => Promise<void> = async () => undefined;
    const fake = new FakeLlm({ extract, propose: RUN, verify: rejectAll });
    const t = coreDeps({ policy: enginePolicy, llm: racingLlm(fake, () => hook()) });
    hook = async () => {
      const review = await latest(t);
      const all = await threatsOf(t, review.id);
      const audit = all.find((x) => x.title === 'No audit of refund events')!;
      const issue = ((await t.deps.jira.issue(ISSUE)) as { ok: true; value: JiraIssue }).value;
      const r = await applyTriage(t.deps, 'acc-champion', issue, review, all, audit, { op: 'edit', patch: { title: 'No audit trail of refund events' } }, new Set(all.map((x) => x.id)));
      expect(r.ok).toBe(true);
    };
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    await drain((j) => handleJob(t.deps, j), t.pushed, 100);

    const review = await latest(t);
    const threats = await threatsOf(t, review.id);
    expect(fake.calls.some((c) => c.purpose === 'verify')).toBe(true);
    // The champion's edit stands: not dismissed by the verdict computed before it.
    const audit = threats.find((x) => x.title === 'No audit trail of refund events')!;
    expect(audit.state).toBe('accepted');
    expect(audit.verification).toBeUndefined();
    // The untouched High threat still takes its verdict (doubted → a champion decides).
    expect(threats.find((x) => x.title === 'Forged refund webhook events')).toMatchObject({ state: 'needs_human', verification: { keep: false } });
    const reqs = await t.deps.requirements.forIssue(ISSUE);
    expect(reqs.ok && reqs.value.some((r) => r.threatId === audit.id)).toBe(true);
  });

  it('a merge target the champion chose is not dismissed by the verifier either', async () => {
    let hook: () => Promise<void> = async () => undefined;
    const fake = new FakeLlm({ extract, propose: RUN, verify: rejectAll });
    const t = coreDeps({ policy: enginePolicy, llm: racingLlm(fake, () => hook()) });
    let intoId = '';
    hook = async () => {
      const review = await latest(t);
      const all = await threatsOf(t, review.id);
      const forged = all.find((x) => x.title === 'Forged refund webhook events')!;
      const audit = all.find((x) => x.title === 'No audit of refund events')!;
      intoId = audit.id;
      const issue = ((await t.deps.jira.issue(ISSUE)) as { ok: true; value: JiraIssue }).value;
      const r = await applyTriage(t.deps, 'acc-champion', issue, review, all, forged, { op: 'merge', intoThreatId: audit.id }, new Set(all.map((x) => x.id)));
      expect(r.ok).toBe(true);
    };
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    await drain((j) => handleJob(t.deps, j), t.pushed, 100);
    const threats = await threatsOf(t, (await latest(t)).id);
    expect(threats.find((x) => x.id === intoId)).toMatchObject({ state: 'accepted' });
  });
});

describe('verificationPending (the panel keeps polling until the verifier has run)', () => {
  async function untilVerify() {
    const fake = new FakeLlm({ extract, propose: RUN, verify: rejectAll });
    const t = coreDeps({ policy: enginePolicy, llm: fake });
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    const held: ReviewJob[] = [];
    await drain(async (j) => (j.kind === 'engine' && j.stage === 'verify' ? held.push(j) : handleJob(t.deps, j)), t.pushed, 100);
    return { t, held };
  }

  it('is true for a ready engine review whose verifier has not run, and false once it has', async () => {
    const { t, held } = await untilVerify();
    const review = await latest(t);
    expect(review.status).toBe('ready');
    expect(held).toHaveLength(1);
    expect(await verificationPending(t.deps, review)).toBe(true);
    // The first verify job runs the gap check and queues the verifier itself: still pending until that has run.
    await handleJob(t.deps, held[0]!);
    expect(await verificationPending(t.deps, await latest(t))).toBe(true);
    await drain((j) => handleJob(t.deps, j), t.pushed, 100);
    expect(await verificationPending(t.deps, await latest(t))).toBe(false);
  });

  it('stops waiting after VERIFY_WAIT_MS (a lost job must not poll for ever) and is false for a review not run by the Engine', async () => {
    const { t } = await untilVerify();
    const review = await latest(t);
    const later = { ...t.deps, clock: { now: () => new Date(new Date(review.updatedAt).getTime() + VERIFY_WAIT_MS + 1000) } };
    expect(await verificationPending(later, review)).toBe(false);

    const agent = coreDeps({ policy: POLICY });
    await handleJob(agent.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    const r = await latest(agent);
    expect(await verificationPending(agent.deps, { ...r, status: 'ready' })).toBe(false);
  });
});

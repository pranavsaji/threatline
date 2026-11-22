import { describe, expect, it } from 'vitest';
import { ok, type AgentThreatModel, type Requirement, type Threat, type Verdict } from '@threatline/shared';
import { handleJob } from '../../src/consumers/review-consumer.js';
import { reviewConfirm, threatsTriage } from '../../src/resolvers/threats.js';
import { OPS_CONFIG_KEY } from '../../src/jobs/hourly.js';
import { coreDeps, jiraIssue } from '../support/core-deps.js';

const ISSUE = '10042';
const who = { accountId: 'acc-champ', issueId: ISSUE };
const CHAMPIONS = 'threatline-security-champions';

const twoThreats: AgentThreatModel = {
  schema: 'threatline.threatmodel.v1',
  issueKey: 'PAY-7',
  threats: [
    { stride: 'Spoofing', title: 'Forged refund webhooks', scenario: 'An attacker posts a fake refund event.', component: 'webhook endpoint', likelihood: 4, impact: 4, evidence: [{ quote: 'Public webhook that receives refund events' }] },
    { stride: 'InformationDisclosure', title: 'Customer email leaks in webhook logs', scenario: 'Logs keep the customer email address.', component: 'webhook endpoint', likelihood: 3, impact: 3, evidence: [{ quote: 'customer email address' }] },
  ],
};

async function settled(champion = true) {
  const t = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })] });
  if (champion) t.jira.groupsOf = async () => ok([CHAMPIONS]);
  await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
  const rev = (await t.deps.reviews.latest(ISSUE)) as { ok: true; value: { id: string } };
  for (let n = 1; n <= 3; n++) {
    await t.deps.reviews.saveSample(rev.value.id, n, twoThreats);
    await handleJob(t.deps, { kind: 'assemble', reviewId: rev.value.id });
  }
  t.pushed.length = 0;
  const all = async () => ((await t.deps.reviews.threats(rev.value.id)) as { ok: true; value: Threat[] }).value;
  const threats = await all();
  const forged = threats.find((x) => x.title === 'Forged refund webhooks')!;
  const leak = threats.find((x) => x.title === 'Customer email leaks in webhook logs')!;
  return { t, reviewId: rev.value.id, all, forged, leak };
}
const verdict = (t: ReturnType<typeof coreDeps>) => t.verdicts._written.get(ISSUE) as Verdict & { message: string };
const reqs = async (t: ReturnType<typeof coreDeps>) => ((await t.deps.requirements.forIssue(ISSUE)) as { ok: true; value: Requirement[] }).value;

describe('feature: covered rule-based threats come back when their covering AI threat goes', () => {
  const covering: AgentThreatModel = {
    ...twoThreats,
    threats: [
      ...twoThreats.threats,
      { stride: 'InformationDisclosure', title: 'Another customer’s personal data returned by the refund lookup', scenario: 'A caller passes another customer’s order id and gets their email address.', component: 'refund lookup', likelihood: 4, impact: 4, evidence: [{ quote: 'customer email address' }] },
    ],
  };
  async function coveredSetup() {
    const t = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7' })] });
    t.jira.groupsOf = async () => ok([CHAMPIONS]);
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    const rev = (await t.deps.reviews.latest(ISSUE)) as { ok: true; value: { id: string } };
    for (let n = 1; n <= 3; n++) {
      await t.deps.reviews.saveSample(rev.value.id, n, covering);
      await handleJob(t.deps, { kind: 'assemble', reviewId: rev.value.id });
    }
    const all = async () => ((await t.deps.reviews.threats(rev.value.id)) as { ok: true; value: Threat[] }).value;
    return { t, all };
  }

  it('dismissing the covering AI threat makes the rule-based one active again, with its requirement', async () => {
    const { t, all } = await coveredSetup();
    const before = await all();
    const pii = before.find((x) => x.origin === 'baseline' && x.title === 'Personal data exposed to unauthorised users')!;
    const cover = before.find((x) => x.id === pii.coveredBy)!;
    expect(pii.state).toBe('covered');
    expect((await reqs(t)).some((r) => r.threatId === pii.id)).toBe(false);
    await threatsTriage(t.deps, who, { threatId: cover.id, op: 'dismiss', reason: 'false_positive' });
    const after = (await all()).find((x) => x.id === pii.id)!;
    expect(after.state).toBe('accepted');
    expect(after.coveredBy).toBeUndefined();
    expect((await reqs(t)).some((r) => r.threatId === pii.id)).toBe(true);
  });

  it('merging the covering AI threat into another one also brings the rule-based one back', async () => {
    const { t, all } = await coveredSetup();
    const before = await all();
    const pii = before.find((x) => x.origin === 'baseline' && x.title === 'Personal data exposed to unauthorised users')!;
    // Merged into a threat of another kind (Spoofing), which could not cover it.
    const other = before.find((x) => x.title === 'Forged refund webhooks')!;
    await threatsTriage(t.deps, who, { threatId: pii.coveredBy!, op: 'merge', intoThreatId: other.id });
    expect((await all()).find((x) => x.id === pii.id)!.state).toBe('accepted');
  });
});

describe('threats.triage (TM-7)', () => {
  it('only a security champion can triage', async () => {
    const { t, forged } = await settled(false);
    expect(await threatsTriage(t.deps, who, { threatId: forged.id, op: 'dismiss', reason: 'false_positive' })).toMatchObject({ error: 'forbidden' });
  });

  it('dismiss needs a reason code', async () => {
    const { t, forged } = await settled();
    expect(await threatsTriage(t.deps, who, { threatId: forged.id, op: 'dismiss' })).toMatchObject({ error: 'validation' });
    expect(await threatsTriage(t.deps, who, { threatId: forged.id, op: 'dismiss', reason: 'because' })).toMatchObject({ error: 'validation' });
  });

  it('dismiss with a reason records feedback for later reviews (TM-5) and unblocks that threat', async () => {
    const { t, forged, all } = await settled();
    await handleJob(t.deps, { kind: 'verdict', issueId: ISSUE });
    const before = verdict(t).blockingCount;
    const out = await threatsTriage(t.deps, who, { threatId: forged.id, op: 'dismiss', reason: 'already_mitigated', note: 'HMAC check exists' });
    expect(Array.isArray(out)).toBe(true);
    expect((await all()).find((x) => x.id === forged.id)).toMatchObject({ state: 'dismissed', dismissReason: 'already_mitigated' });
    const fb = await t.deps.feedback.dismissedFor('webhook endpoint');
    expect(fb.ok && fb.value).toContainEqual({ title: 'Forged refund webhooks', stride: 'Spoofing', reason: 'already_mitigated' });
    expect(verdict(t).blockingCount).toBe(before - 1);
    expect(t.pushed).toContainEqual({ kind: 'propagate', issueId: ISSUE });
  });

  it('accept turns a needs-human threat into an accepted one with a requirement row', async () => {
    const { t, forged, all } = await settled();
    await t.deps.reviews.updateThreat(forged.id, { state: 'needs_human' });
    const r0 = (await reqs(t)).filter((r) => r.threatId === forged.id);
    await t.deps.requirements.upsert({ ...r0[0]!, id: 'unrelated', threatId: 'thr_other' });
    await threatsTriage(t.deps, who, { threatId: forged.id, op: 'accept' });
    expect((await all()).find((x) => x.id === forged.id)?.state).toBe('accepted');
    expect((await reqs(t)).some((r) => r.threatId === forged.id)).toBe(true);
  });

  it('edit recomputes severity from likelihood and impact and keeps the requirement severity in step', async () => {
    const { t, leak, all } = await settled();
    const out = await threatsTriage(t.deps, who, { threatId: leak.id, op: 'edit', patch: { likelihood: 5, impact: 5, title: 'Customer emails leak into logs' } });
    expect(Array.isArray(out)).toBe(true);
    const after = (await all()).find((x) => x.id === leak.id)!;
    expect(after).toMatchObject({ likelihood: 5, impact: 5, severity: 'Critical', title: 'Customer emails leak into logs' });
    expect((await reqs(t)).find((r) => r.threatId === leak.id)?.severity).toBe('Critical');
  });

  it('edit rejects unknown or out-of-range fields', async () => {
    const { t, leak } = await settled();
    expect(await threatsTriage(t.deps, who, { threatId: leak.id, op: 'edit', patch: { likelihood: 9 } })).toMatchObject({ error: 'validation' });
    expect(await threatsTriage(t.deps, who, { threatId: leak.id, op: 'edit', patch: { state: 'dismissed' } })).toMatchObject({ error: 'validation' });
  });

  it('merge dismisses the source as a duplicate and moves its citations onto the target', async () => {
    const { t, forged, leak, all } = await settled();
    await threatsTriage(t.deps, who, { threatId: leak.id, op: 'merge', intoThreatId: forged.id });
    const now = await all();
    expect(now.find((x) => x.id === leak.id)).toMatchObject({ state: 'dismissed', dismissReason: 'duplicate' });
    const target = now.find((x) => x.id === forged.id)!;
    expect(target.citations.map((c) => c.quote)).toEqual(expect.arrayContaining(leak.citations.map((c) => c.quote)));
  });

  it('split replaces a threat with accepted parts, each with its own requirement', async () => {
    const { t, forged, all } = await settled();
    await threatsTriage(t.deps, who, { threatId: forged.id, op: 'split', parts: [{ title: 'Unsigned refund webhooks' }, { title: 'Replayed refund webhooks', component: 'webhook replay' }] });
    const now = await all();
    expect(now.find((x) => x.id === forged.id)).toMatchObject({ state: 'dismissed', dismissReason: 'duplicate' });
    const parts = now.filter((x) => x.id.startsWith(`${forged.id}_s`));
    expect(parts.map((p) => p.title)).toEqual(['Unsigned refund webhooks', 'Replayed refund webhooks']);
    expect(parts.every((p) => p.state === 'accepted' && p.citations.length > 0)).toBe(true);
    const rq = await reqs(t);
    for (const p of parts) expect(rq.some((r) => r.threatId === p.id)).toBe(true);
  });

  it('split needs 2 to 5 parts', async () => {
    const { t, forged } = await settled();
    expect(await threatsTriage(t.deps, who, { threatId: forged.id, op: 'split', parts: [{ title: 'only one' }] })).toMatchObject({ error: 'validation' });
  });

  it('triage waits until every agent run is in (assembly would overwrite it)', async () => {
    const { t, forged, reviewId } = await settled();
    await t.deps.reviews.update(reviewId, { status: 'awaiting_agent' });
    expect(await threatsTriage(t.deps, who, { threatId: forged.id, op: 'accept' })).toMatchObject({ error: 'conflict' });
  });

  it('a threat the champion cannot see is not_found', async () => {
    const { t } = await settled();
    expect(await threatsTriage(t.deps, who, { threatId: 'thr_nope', op: 'accept' })).toMatchObject({ error: 'not_found' });
  });

  it('every decision is ledgered (who, which threat, the change and the dismissal reason), before it is saved', async () => {
    const { t, forged, leak, reviewId } = await settled();
    await t.deps.reviews.updateThreat(forged.id, { state: 'needs_human' });
    await threatsTriage(t.deps, who, { threatId: forged.id, op: 'accept' });
    await threatsTriage(t.deps, who, { threatId: leak.id, op: 'dismiss', reason: 'already_mitigated', note: 'Logs are scrubbed' });
    const rows = await t.deps.ledger.ofTypes(['threat.triaged']);
    expect(rows.ok && rows.value.map((r) => ({ actor: r.actor, ...r.payload }))).toEqual([
      { actor: 'acc-champ', issueId: ISSUE, issueKey: 'PAY-7', reviewId, threatId: forged.id, title: 'Forged refund webhooks', severity: forged.severity, from: 'needs_human', op: 'accept' },
      { actor: 'acc-champ', issueId: ISSUE, issueKey: 'PAY-7', reviewId, threatId: leak.id, title: leak.title, severity: leak.severity, from: 'accepted', op: 'dismiss', reason: 'already_mitigated', note: 'Logs are scrubbed' },
    ]);
  });

  it('a decision that could not be saved is marked failed in the ledger, so the ledger never shows a change that never happened', async () => {
    const { t, forged } = await settled();
    t.deps.reviews.updateThreat = async () => ({ ok: false, error: { code: 'internal', message: 'db down' } });
    expect(await threatsTriage(t.deps, who, { threatId: forged.id, op: 'accept' })).toMatchObject({ error: 'unavailable' });
    const recorded = await t.deps.ledger.ofTypes(['threat.triaged', 'threat.triage_failed']);
    expect(recorded.ok && recorded.value.map((r) => r.eventType)).toEqual(['threat.triaged', 'threat.triage_failed']);
    const [triaged, failed] = recorded.ok ? recorded.value : [];
    expect(failed!.payload).toMatchObject({ threatId: forged.id, issueId: ISSUE, failedEntryHash: triaged!.entryHash, code: 'internal' });
  });

  it('nothing changes when the ledger cannot record the decision (fail closed)', async () => {
    const { t, forged, all } = await settled();
    t.deps.ledger.append = async () => ({ ok: false, error: { code: 'internal', message: 'ledger down' } });
    expect(await threatsTriage(t.deps, who, { threatId: forged.id, op: 'dismiss', reason: 'false_positive' })).toMatchObject({ error: 'unavailable' });
    expect((await all()).find((x) => x.id === forged.id)?.state).toBe('accepted');
  });
});

describe('review.confirm', () => {
  it('a developer cannot confirm', async () => {
    const { t, reviewId, forged } = await settled(false);
    await t.deps.reviews.updateThreat(forged.id, { state: 'needs_human' });
    expect(await reviewConfirm(t.deps, who, { reviewId, kind: 'review' })).toMatchObject({ error: 'forbidden' });
  });

  it('a champion confirms threats that need a human: ledgered once, and the verdict stops asking', async () => {
    const { t, reviewId, forged } = await settled();
    await t.deps.reviews.updateThreat(forged.id, { state: 'needs_human' });
    await handleJob(t.deps, { kind: 'verdict', issueId: ISSUE });
    expect(verdict(t).reasons.map((r) => r.code)).toContain('needs_human');
    const row = await reviewConfirm(t.deps, who, { reviewId, kind: 'review' });
    expect(row).toMatchObject({ eventType: 'review.champion_confirmed', actor: 'acc-champ', payload: { reviewId, issueId: ISSUE, issueKey: 'PAY-7' } });
    expect(verdict(t).reasons.map((r) => r.code)).not.toContain('needs_human');
    const again = await reviewConfirm(t.deps, who, { reviewId, kind: 'review' });
    expect(again).toEqual(row);
    const ledger = await t.deps.ledger.all();
    expect(ledger.ok && ledger.value.filter((r) => r.eventType === 'review.champion_confirmed')).toHaveLength(1);
  });

  it('confirming when nothing needs it is a validation error', async () => {
    const { t, reviewId } = await settled();
    expect(await reviewConfirm(t.deps, who, { reviewId, kind: 'budget' })).toMatchObject({ error: 'validation' });
  });

  it('a budget confirmation is ledgered and alerts the admin on the ops work item', async () => {
    const { t, reviewId } = await settled();
    t.kv.data.set('ingest:recent', [false, false, false]);
    t.kv.data.set(OPS_CONFIG_KEY, { issueKey: 'OPS-1', accountIds: ['acc-admin'] });
    const row = await reviewConfirm(t.deps, who, { reviewId, kind: 'budget' });
    expect(row).toMatchObject({ eventType: 'budget.champion_confirmed' });
    expect(t.jira.commented).toHaveLength(1);
    expect(t.jira.commented[0]!.issueId).toBe('OPS-1');
    expect(JSON.stringify(t.jira.commented[0]!.adf)).toMatch(/PAY-7/);
    expect(verdict(t).reasons.map((r) => r.code)).not.toContain('budget_paused');
  });

  it('only the latest review of this work item can be confirmed', async () => {
    const { t } = await settled();
    expect(await reviewConfirm(t.deps, who, { reviewId: 'rev_999_1', kind: 'review' })).toMatchObject({ error: 'not_found' });
    expect(await reviewConfirm(t.deps, who, { reviewId: 'x', kind: 'nope' })).toMatchObject({ error: 'validation' });
  });
});

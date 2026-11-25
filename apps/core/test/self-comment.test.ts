import { describe, expect, it } from 'vitest';
import { ok, type Review } from '@threatline/shared';
import type { ConfluenceClient } from '../src/adapters/confluence.js';
import type { JiraComment } from '../src/adapters/jira.js';
import { restGatherer } from '../src/adapters/rest-gatherer.js';
import { handleJob } from '../src/consumers/review-consumer.js';
import { OWN_ACCOUNT_KEY, ownAccountId } from '../src/services/own-account.js';
import { readVerdict } from '../src/services/verdict-service.js';
import { onIssueChange } from '../src/triggers/on-issue-change.js';
import { APP_ACCOUNT, coreDeps, drain, jiraIssue, POLICY } from './support/core-deps.js';

const ISSUE = '10042';
const PERSON = 'acc-person';

/**
 * No feedback loop (docs/ENGINE.md): Threatline gathers the work item's comments as review context and marks a review
 * out of date when its context changes. Its own verdict comment must be neither context nor part of the context hash,
 * and must never mark the review out of date or start a re-review. These run the real gatherer over a Jira fake whose
 * comments are the ones Threatline posted (by Threatline's account) plus one by a person.
 */
function setup() {
  const t = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7', summary: 'Refund webhook', description: 'Public webhook that receives refund events with customer email address' })], policy: { ...POLICY, reviewMode: 'rules_only' } });
  const text = (adf: unknown): string => JSON.stringify(adf).match(/"text":"([^"]*)"/g)?.map((m) => m.slice(8, -1)).join('\n') ?? '';
  const human: JiraComment = { id: '200', body: 'Refunds over 500 EUR need a second approver.', author: PERSON, created: '2026-11-15T11:00:00.000Z', restricted: false };
  // Newest first, as Jira returns them.
  t.jira.comments = async () => ok([...t.jira.commented.map((c, n): JiraComment => ({ id: String(30001 + n), body: text(c.adf), author: APP_ACCOUNT, created: '2026-11-15T12:00:00.000Z', restricted: false })).reverse(), human]);
  t.deps.gatherer = restGatherer({ jira: t.jira, confluence: {} as ConfluenceClient, reviews: t.deps.reviews, issues: t.deps.issues, clock: t.clock, cloudId: 'c0ffee', ownAccount: () => ownAccountId(t.kv) });
  return t;
}

const edit = (atlassianId: string, items: Array<Record<string, string>> | null) => ({
  eventType: 'avi:jira:updated:issue',
  atlassianId,
  issue: { id: ISSUE, key: 'PAY-7', fields: { issuetype: { name: 'Story' }, project: { key: 'PAY' } } },
  ...(items ? { changelog: { items } } : {}),
});
const LABELS = [{ field: 'labels', fieldId: 'labels', fromString: '', toString: 'backend' }];

const latest = async (t: ReturnType<typeof coreDeps>) => ((await t.deps.reviews.latest(ISSUE)) as { ok: true; value: Review }).value;
const reasons = async (t: ReturnType<typeof coreDeps>) => {
  const v = await readVerdict(t.deps, ISSUE);
  return v.ok && v.value ? v.value.reasons.map((r) => r.code) : [];
};

describe('no feedback loop: Threatline never reads its own comments back', () => {
  it("its verdict comment is neither review context nor part of the context hash; a person's comment still is", async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    const first = await latest(t);
    expect(t.jira.commented.filter((c) => c.issueId === ISSUE)).toHaveLength(1);
    expect(t.kv.data.get(OWN_ACCOUNT_KEY)).toBe(APP_ACCOUNT);

    // A re-run gathers again with the verdict comment on the work item: same hash, and no comment text of Threatline's.
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'rerun' });
    const second = await latest(t);
    expect(second.revision).toBe(2);
    expect(second.contextHash).toBe(first.contextHash);
    const facts = ((await t.deps.reviews.facts(second.id)) as { ok: true; value: Array<{ sourceType: string; excerpt: string }> }).value;
    const comments = facts.filter((f) => f.sourceType === 'jira_comment');
    expect(comments.map((f) => f.excerpt)).toEqual(['Refunds over 500 EUR need a second approver.']);
    expect(JSON.stringify(facts)).not.toContain('Threatline security review');
    // Same verdict on the re-run: no second comment either.
    expect(t.jira.commented.filter((c) => c.issueId === ISSUE)).toHaveLength(1);
  });

  it('a later edit by a person re-checks the context: the verdict comment does not mark the review out of date', async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    expect(await reasons(t)).not.toContain('review_stale');
    await drain((j) => handleJob(t.deps, j), t.pushed);
    await onIssueChange(t.deps, edit(PERSON, LABELS));
    expect(t.pushed).toEqual([{ kind: 'gather', issueId: ISSUE, reason: 'updated', actorAccountId: PERSON }]);
    await drain((j) => handleJob(t.deps, j), t.pushed);
    expect((await latest(t)).revision).toBe(1);
    expect(await reasons(t)).not.toContain('review_stale');
    expect(t.jira.commented.filter((c) => c.issueId === ISSUE)).toHaveLength(1);
  });

  it('control: were the comment read back (no known own account), the same edit would mark the review out of date', async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    t.kv.data.delete(OWN_ACCOUNT_KEY);
    await onIssueChange(t.deps, edit(PERSON, LABELS));
    await drain((j) => handleJob(t.deps, j), t.pushed);
    expect(await reasons(t)).toContain('review_stale');
  });

  it("an issue event by Threatline's own account queues nothing (defence in depth behind the manifest's ignoreSelf)", async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    t.pushed.length = 0;
    await onIssueChange(t.deps, edit(APP_ACCOUNT, LABELS));
    await onIssueChange(t.deps, edit(APP_ACCOUNT, [{ field: 'labels', fieldId: 'labels', fromString: '', toString: 'threatline-review' }]));
    expect(t.pushed).toEqual([]);
  });

  it('an update that only adds a comment (no changed field) queues no review or staleness check', async () => {
    const t = setup();
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    t.pushed.length = 0;
    await onIssueChange(t.deps, edit(PERSON, null));
    await onIssueChange(t.deps, edit(PERSON, []));
    expect(t.pushed).toEqual([]);
  });
});

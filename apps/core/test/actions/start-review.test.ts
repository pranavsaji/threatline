import { describe, expect, it } from 'vitest';
import { handleJob } from '../../src/consumers/review-consumer.js';
import { startReview } from '../../src/actions/start-review.js';
import { STILL_RUNNING_MESSAGE } from '../../src/resolvers/panel.js';
import { coreDeps, jiraIssue } from '../support/core-deps.js';

const ctx = (accountId: string) => ({ context: { accountId, agentId: 'agent-1', cloudId: 'c' } });
const ME = 'acc-plain';

describe('start-review refusals reach the agent in words', () => {
  it('a work item in a project Threatline is not on for is refused, and nothing is queued or spent', async () => {
    const t = coreDeps({ issues: [jiraIssue({ id: '10042', key: 'OPS-7', project: { id: '1', key: 'OPS' } })] });
    const r = await startReview({ issueKey: 'OPS-7', ...ctx(ME) }, t.deps);
    expect(r).toEqual({ error: 'refused', message: expect.stringContaining('not turned on for project OPS') });
    expect(t.pushed).toEqual([]);
    expect(t.jira.labels).toEqual([]);
  });

  it('a work item whose review is still running is refused', async () => {
    const t = coreDeps();
    await handleJob(t.deps, { kind: 'gather', issueId: '10042', reason: 'created' });
    const latest = await t.deps.reviews.latest('10042');
    if (!latest.ok || !latest.value) throw new Error('review');
    await t.deps.reviews.update(latest.value.id, { samplesReceived: 1 });
    t.pushed.length = 0;
    expect(await startReview({ issueKey: 'PAY-7', ...ctx(ME) }, t.deps)).toEqual({ error: 'refused', message: STILL_RUNNING_MESSAGE });
    expect(t.pushed).toEqual([]);
  });
});

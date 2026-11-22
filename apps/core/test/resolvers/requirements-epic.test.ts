import { describe, expect, it } from 'vitest';
import { ok, type AgentThreatModel, type Requirement, type Threat } from '@threatline/shared';
import { handleJob } from '../../src/consumers/review-consumer.js';
import { requirementsCreate } from '../../src/resolvers/requirements.js';
import type { AdfDoc } from '../../src/adapters/jira.js';
import { coreDeps, jiraIssue } from '../support/core-deps.js';

const ISSUE = '10042';
const dev = { accountId: 'acc-dev', issueId: ISSUE };

const sample: AgentThreatModel = {
  schema: 'threatline.threatmodel.v1',
  issueKey: 'PAY-7',
  threats: [
    {
      stride: 'Spoofing',
      title: 'Forged refund webhooks',
      scenario: 'An attacker posts a fake refund event.',
      component: 'webhook endpoint',
      likelihood: 4,
      impact: 4,
      evidence: [{ quote: 'Public webhook that receives refund events' }],
    },
  ],
};

type Types = Array<{ id: string; name: string; subtask: boolean }>;

/** A settled review of an epic, with a Jira fake that records sub-tasks and standard work items separately. */
async function settledEpic(types: Types) {
  const t = coreDeps({ issues: [jiraIssue({ id: ISSUE, key: 'PAY-7', issueType: { id: '10000', name: 'Epic', subtask: false } })] });
  const subtasks: string[] = [];
  const issues: Array<{ projectId: string; issueTypeId: string; summary: string; description: AdfDoc; labels: string[]; parentId?: string }> = [];
  t.jira.createSubtask = async (parentId) => {
    subtasks.push(parentId);
    return { ok: false, error: { code: 'validation', message: 'sub-tasks cannot be created under an epic' } };
  };
  t.jira.createIssue = async (f) => {
    issues.push(f);
    return ok({ id: String(30000 + issues.length), key: `PAY-${199 + issues.length}` });
  };
  t.jira.projectInfo = async (key) => ok({ id: '10000', key, issueTypes: types });
  await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
  const rev = (await t.deps.reviews.latest(ISSUE)) as { ok: true; value: { id: string } };
  for (let n = 1; n <= 3; n++) {
    await t.deps.reviews.saveSample(rev.value.id, n, sample);
    await handleJob(t.deps, { kind: 'assemble', reviewId: rev.value.id });
  }
  const threats = ((await t.deps.reviews.threats(rev.value.id)) as { ok: true; value: Threat[] }).value;
  const agent = threats.find((x) => x.origin === 'agent' && x.state === 'accepted')!;
  return { t, agent, subtasks, issues };
}

const reqFor = async (t: ReturnType<typeof coreDeps>, threatId: string) =>
  ((await t.deps.requirements.forIssue(ISSUE)) as { ok: true; value: Requirement[] }).value.find((r) => r.threatId === threatId)!;

describe('requirements.create on an epic (Jira forbids sub-tasks under epics)', () => {
  const STANDARD: Types = [
    { id: '10001', name: 'Story', subtask: false },
    { id: '10002', name: 'Task', subtask: false },
    { id: '10003', name: 'Sub-task', subtask: true },
    { id: '10000', name: 'Epic', subtask: false },
  ];

  it('creates a child Task with the epic as parent (never a sub-task), labelled threatline, and remembers its key', async () => {
    const { t, agent, subtasks, issues } = await settledEpic(STANDARD);
    const r = await requirementsCreate(t.deps, dev, { threatIds: [agent.id] });
    expect(r).toEqual({ created: [{ requirementId: expect.stringMatching(/^req_/), subtaskKey: 'PAY-200' }], skipped: [] });
    expect(subtasks).toHaveLength(0);
    expect(issues).toHaveLength(1);
    expect(issues[0]).toMatchObject({ projectId: '10000', issueTypeId: '10002', parentId: ISSUE, labels: ['threatline'] });
    expect(JSON.stringify(issues[0]!.description)).toMatch(/Given/);
    expect((await reqFor(t, agent.id)).subtaskKey).toBe('PAY-200');
    // Idempotent like sub-tasks: a second click creates nothing.
    expect(await requirementsCreate(t.deps, dev, { threatIds: [agent.id] })).toEqual({ created: [], skipped: [{ threatId: agent.id, reason: 'exists' }] });
    expect(issues).toHaveLength(1);
  });

  it('uses Story when the project has no Task type', async () => {
    const { t, agent, issues } = await settledEpic(STANDARD.filter((x) => x.name !== 'Task'));
    await requirementsCreate(t.deps, dev, { threatIds: [agent.id] });
    expect(issues[0]).toMatchObject({ issueTypeId: '10001', parentId: ISSUE });
  });

  it('with neither Task nor Story, nothing is created and the threat is skipped with no_child_type', async () => {
    const { t, agent, subtasks, issues } = await settledEpic([{ id: '10003', name: 'Sub-task', subtask: true }, { id: '10000', name: 'Epic', subtask: false }]);
    const r = await requirementsCreate(t.deps, dev, { threatIds: [agent.id] });
    expect(r).toEqual({ created: [], skipped: [{ threatId: agent.id, reason: 'no_child_type' }] });
    expect(subtasks).toHaveLength(0);
    expect(issues).toHaveLength(0);
    expect((await reqFor(t, agent.id)).subtaskKey).toBeUndefined();
    // The double-click lock is released, so adding the work type and trying again works.
    t.jira.projectInfo = async (key) => ok({ id: '10000', key, issueTypes: STANDARD });
    const again = await requirementsCreate(t.deps, dev, { threatIds: [agent.id] });
    expect(again).toMatchObject({ created: [{ subtaskKey: 'PAY-200' }] });
  });
});

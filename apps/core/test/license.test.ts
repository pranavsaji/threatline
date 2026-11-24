import { afterEach, describe, expect, it, vi } from 'vitest';
import { ok } from '@threatline/shared';
import { handleJob } from '../src/consumers/review-consumer.js';
import { startReview } from '../src/actions/start-review.js';
import { submitThreatModel } from '../src/actions/submit-threat-model.js';
import { getMergeAttestation } from '../src/actions/get-merge-attestation.js';
import { panelGet, panelRerun } from '../src/resolvers/panel.js';
import { adminGetPolicy, adminSeed } from '../src/resolvers/admin.js';
import { onIssueChange } from '../src/triggers/on-issue-change.js';
import { onPageChange } from '../src/triggers/on-page-change.js';
import { validateTransition } from '../src/validators/validate-transition.js';
import { LICENSE_INACTIVE_MESSAGE } from '../src/services/license.js';
import { FakeLlm } from '../../../packages/core/test/fakes/fake-llm.js';
import { coreDeps, drain, POLICY } from './support/core-deps.js';
import { DEV, reviewed } from './support/reviewed.js';

const ISSUE = '10042';
const ME = 'acc-plain';
const ctx = (accountId: string) => ({ context: { accountId, agentId: 'agent-1', cloudId: 'c' } });
const issueEvent = (o: { eventType?: string; type?: string; items?: Array<Record<string, unknown>> } = {}) => ({
  eventType: o.eventType ?? 'avi:jira:updated:issue',
  atlassianId: 'acc-editor',
  issue: { id: ISSUE, key: 'PAY-7', fields: { issuetype: { name: o.type ?? 'Story' }, project: { key: 'PAY' }, parent: undefined } },
  changelog: { items: o.items ?? [{ field: 'description', fieldId: 'description' }] },
});
const unlicensed = () => coreDeps({ license: 'unlicensed' });
const logged = () => {
  const spy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
  return () => spy.mock.calls.map((c) => JSON.parse(String(c[0])) as { event: string; where?: string });
};

afterEach(() => vi.restoreAllMocks());

describe('Paid via Atlassian, inactive license: no new AI work (docs/LICENSING.md)', () => {
  it('the message starts with the plain reason', () => {
    expect(LICENSE_INACTIVE_MESSAGE).toMatch(/^Threatline's license for this site is inactive/);
  });

  it('start-review (Rovo) is refused in words; nothing is queued, labelled or counted', async () => {
    const t = unlicensed();
    expect(await startReview({ issueKey: 'PAY-7', ...ctx(ME) }, t.deps)).toEqual({ error: 'refused', message: LICENSE_INACTIVE_MESSAGE });
    expect(t.pushed).toEqual([]);
    expect(t.jira.labels).toEqual([]);
  });

  it('the panel Re-run is refused with the message', async () => {
    const t = unlicensed();
    const events = logged();
    expect(await panelRerun(t.deps, { accountId: ME, issueId: ISSUE })).toEqual({ error: 'validation', message: LICENSE_INACTIVE_MESSAGE });
    expect(t.pushed).toEqual([]);
    expect(events()).toContainEqual(expect.objectContaining({ event: 'license.refused', where: 'panel.rerun' }));
  });

  it('a person without edit permission is still told that first (the license is not checked before access)', async () => {
    const t = unlicensed();
    t.jira.canEdit = async () => ok(false);
    expect(await panelRerun(t.deps, { accountId: ME, issueId: ISSUE })).toMatchObject({ error: 'not_found' });
  });

  it('the admin demo data (which queues reviews) is refused', async () => {
    const t = unlicensed();
    t.jira.isAdmin = async () => ok(true);
    expect(await adminSeed(t.deps, { accountId: 'acc-admin' }, { projectKey: 'PAY' })).toEqual({ error: 'validation', message: LICENSE_INACTIVE_MESSAGE });
    expect(t.pushed).toEqual([]);
  });

  it('the issue trigger queues no gather (created, edited or label re-run), but still queues verdict refreshes', async () => {
    const t = unlicensed();
    await onIssueChange(t.deps, issueEvent({ eventType: 'avi:jira:created:issue', items: [] }));
    await onIssueChange(t.deps, issueEvent());
    await onIssueChange(t.deps, issueEvent({ items: [{ field: 'labels', fieldId: 'labels', fromString: '', toString: 'threatline-review' }] }));
    expect(t.pushed).toEqual([]);
    await onIssueChange(t.deps, issueEvent({ type: 'Task' }));
    expect(t.pushed).toEqual([{ kind: 'verdict', issueId: ISSUE }]);
  });

  it('the issue trigger queues no incident re-review', async () => {
    const event = issueEvent({ type: 'Bug', items: [{ field: 'labels', fieldId: 'labels', fromString: '', toString: 'incident' }] });
    const licensed = coreDeps();
    await onIssueChange(licensed.deps, event);
    expect(licensed.pushed).toContainEqual(expect.objectContaining({ kind: 'incident' }));
    const t = unlicensed();
    await onIssueChange(t.deps, event);
    expect(t.pushed.filter((j) => j.kind === 'incident' || j.kind === 'gather')).toEqual([]);
  });

  it('the page trigger queues nothing', async () => {
    const t = unlicensed();
    await t.deps.issues.linkPage(ISSUE, '98305');
    await onPageChange(t.deps, { content: { id: '98305' }, atlassianId: 'acc-writer' });
    expect(t.pushed).toEqual([]);
  });

  it('a gather already queued creates no review and makes no model call', async () => {
    const llm = new FakeLlm({});
    const t = coreDeps({ license: 'unlicensed', llm, policy: { ...POLICY, reviewMode: 'engine' } });
    const events = logged();
    expect((await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' })).ok).toBe(true);
    await drain((j) => handleJob(t.deps, j), t.pushed);
    expect(await t.deps.reviews.latest(ISSUE)).toEqual({ ok: true, value: null });
    expect(llm.calls).toEqual([]);
    const usage = await t.deps.usage.get('2026-11');
    expect(usage.ok && usage.value.reviews).toBe(0);
    expect(events()).toContainEqual(expect.objectContaining({ event: 'license.refused', where: 'consumer.gather' }));
  });

  it('an Engine review that was running when the license lapsed makes no further model call', async () => {
    const llm = new FakeLlm({});
    const t = coreDeps({ llm, policy: { ...POLICY, reviewMode: 'engine' } });
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    expect(t.pushed.some((j) => j.kind === 'engine')).toBe(true);
    t.setLicense('unlicensed');
    await drain((j) => handleJob(t.deps, j), t.pushed);
    expect(llm.calls).toEqual([]);
    const review = await t.deps.reviews.latest(ISSUE);
    const stages = review.ok && review.value ? await t.deps.reviews.stages(review.value.id) : null;
    expect(stages?.ok && stages.value.find((s) => s.stage === 'engine_extract')).toMatchObject({ status: 'failed', error: 'license_inactive' });
  });

  it('submit-threat-model (the Rovo agent) saves nothing and says why', async () => {
    const t = unlicensed();
    expect(await submitThreatModel({ issueKey: 'PAY-7', threatModelJson: '{}', submissionToken: 'x', ...ctx(ME) }, t.deps)).toEqual({
      saved: false,
      error: 'license_inactive',
      message: LICENSE_INACTIVE_MESSAGE,
    });
    expect(await t.deps.reviews.latest(ISSUE)).toEqual({ ok: true, value: null });
  });
});

describe('Paid via Atlassian, inactive license: nothing is trapped and data stays readable', () => {
  it('the Done gate lets a blocked work item through and logs license.gate_open', async () => {
    const t = coreDeps();
    await handleJob(t.deps, { kind: 'gather', issueId: ISSUE, reason: 'created' });
    expect(await validateTransition(t.deps, { issue: { key: 'PAY-7', id: ISSUE } })).toMatchObject({ result: false });
    t.setLicense('unlicensed');
    const events = logged();
    expect(await validateTransition(t.deps, { issue: { key: 'PAY-7', id: ISSUE } })).toEqual({ result: true });
    expect(events()).toContainEqual(expect.objectContaining({ event: 'license.gate_open', project: 'PAY' }));
  });

  it('the gate also opens for a work item never reviewed', async () => {
    const t = unlicensed();
    expect(await validateTransition(t.deps, { issue: { key: 'PAY-7', id: ISSUE } })).toEqual({ result: true });
  });

  it('a merge attestation for a finished review is still issued', async () => {
    const { t } = await reviewed({ allVerified: true });
    t.setLicense('unlicensed');
    const r = await getMergeAttestation({ context: { accountId: DEV }, issueKey: 'PAY-7', repo: 'acme/payments', commitSha: 'a'.repeat(40) }, t.deps);
    expect(r).toMatchObject({ issued: true, token: expect.stringMatching(/^threatline-att\.v1\./) });
  });

  it('the panel still shows the review, flagged licenseInactive for the banner', async () => {
    const { t } = await reviewed();
    t.setLicense('unlicensed');
    const dto = await panelGet(t.deps, { accountId: DEV, issueId: ISSUE });
    expect(dto).toMatchObject({ licenseInactive: true, review: { issueId: ISSUE }, requirements: expect.arrayContaining([expect.objectContaining({ issueId: ISSUE })]) });
  });

  it('the admin page policy carries licenseInactive; licensed and not applicable carry nothing', async () => {
    const t = unlicensed();
    t.jira.isAdmin = async () => ok(true);
    expect(await adminGetPolicy(t.deps, { accountId: 'acc-admin' })).toMatchObject({ licenseInactive: true });
    for (const s of ['licensed', 'not_applicable'] as const) {
      t.setLicense(s);
      expect(await adminGetPolicy(t.deps, { accountId: 'acc-admin' })).not.toHaveProperty('licenseInactive');
      expect(await panelGet(t.deps, { accountId: ME, issueId: ISSUE })).not.toHaveProperty('licenseInactive');
    }
  });

  it('licensed (or not applicable) changes nothing: the panel Re-run queues the gather', async () => {
    for (const s of ['licensed', 'not_applicable'] as const) {
      const t = coreDeps({ license: s });
      expect(await panelRerun(t.deps, { accountId: ME, issueId: ISSUE })).toEqual({ ok: true });
      expect(t.pushed).toEqual([{ kind: 'gather', issueId: ISSUE, reason: 'rerun', actorAccountId: ME }]);
    }
  });
});

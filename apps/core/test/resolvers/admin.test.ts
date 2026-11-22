import { describe, expect, it } from 'vitest';
import { appendLedger, DEFAULT_SITE_POLICY } from '@threatline/core';
import { ok, type Review, type SitePolicy } from '@threatline/shared';
import type { ConfluenceClient } from '../../src/adapters/confluence.js';
import {
  adminResumeReviews,
  adminGetPolicy,
  adminInstallGate,
  adminProjectStatuses,
  adminPurgeProject,
  adminRuns,
  adminSetNotifications,
  adminSetPolicy,
  adminUsage,
  adminWarnOnly,
  adminWarnOnlyEnd,
  POLICY_VERSION_KEY,
  RUNS_LIMIT,
} from '../../src/resolvers/admin.js';
import { validateTransition } from '../../src/validators/validate-transition.js';
import { verdictKey } from '../../src/services/verdict-service.js';
import { DIGEST_CONFIG_KEY } from '../../src/services/digest.js';
import { OPS_CONFIG_KEY } from '../../src/services/ops-alert.js';
import { ADMIN, DEV, ISSUE, reviewed } from '../support/reviewed.js';

const A = { accountId: ADMIN };
const D = { accountId: DEV };
const gate = { issue: { key: 'PAY-7', id: ISSUE } };
const DAY = 86_400_000;
const EXT = 'ari:cloud:ecosystem::extension/13898a7c-6897-48d3-a512-079d9f9f5f00/511a7dd3-8745-4121-8c4d-664f8fff2fae/static/threatline-gate';

async function policyOf(r: Awaited<ReturnType<typeof reviewed>>): Promise<SitePolicy> {
  const p = await r.t.deps.config.site();
  if (!p.ok) throw new Error('policy');
  return p.value;
}
const ledger = async (r: Awaited<ReturnType<typeof reviewed>>) => {
  const all = await r.t.deps.ledger.all();
  return all.ok ? all.value : [];
};

describe('admin: only Jira administrators', () => {
  it.each([
    ['getPolicy', (r: Awaited<ReturnType<typeof reviewed>>) => adminGetPolicy(r.t.deps, D)],
    ['setPolicy', (r: Awaited<ReturnType<typeof reviewed>>) => adminSetPolicy(r.t.deps, D, { policy: DEFAULT_SITE_POLICY })],
    ['warnOnly', (r: Awaited<ReturnType<typeof reviewed>>) => adminWarnOnly(r.t.deps, D, { projectKey: 'PAY', days: 3 })],
    ['warnOnlyEnd', (r: Awaited<ReturnType<typeof reviewed>>) => adminWarnOnlyEnd(r.t.deps, D, { projectKey: 'PAY' })],
    ['runs', (r: Awaited<ReturnType<typeof reviewed>>) => adminRuns(r.t.deps, D)],
    ['usage', (r: Awaited<ReturnType<typeof reviewed>>) => adminUsage(r.t.deps, D)],
    ['setNotifications', (r: Awaited<ReturnType<typeof reviewed>>) => adminSetNotifications(r.t.deps, D, { ops: null })],
    ['projectStatuses', (r: Awaited<ReturnType<typeof reviewed>>) => adminProjectStatuses(r.t.deps, D, { projectKey: 'PAY' })],
    ['installGate', (r: Awaited<ReturnType<typeof reviewed>>) => adminInstallGate(r.t.deps, D, EXT)],
  ])('%s: a non-admin is forbidden and nothing changes', async (_n, call) => {
    const r = await reviewed();
    const before = await policyOf(r);
    expect(await call(r)).toMatchObject({ error: 'forbidden' });
    expect(await policyOf(r)).toEqual(before);
    expect((await ledger(r)).filter((e) => e.eventType.startsWith('policy.'))).toEqual([]);
  });
});

describe('admin.getPolicy / admin.setPolicy', () => {
  it('first run: returns the policy in force, marked as not yet saved, with no notifications configured', async () => {
    const r = await reviewed();
    expect(await adminGetPolicy(r.t.deps, A)).toEqual({ policy: await policyOf(r), saved: false, ops: null, digest: null, recentReviewAuthors: [] });
  });

  it('security: lists who submitted the latest agent runs, newest first, and rejects a malformed review author', async () => {
    const r = await reviewed();
    for (const [actor, at] of [['acc-owner', '2026-11-15T10:00:00Z'], ['acc-dev', '2026-11-15T11:00:00Z'], ['acc-owner', '2026-11-15T12:00:00Z']] as const) {
      r.t.clock.set(at);
      await appendLedger(r.t.deps.ledger, r.t.deps.clock, 'review.sample', { issueId: '1' }, actor);
    }
    const dto = await adminGetPolicy(r.t.deps, A);
    expect('recentReviewAuthors' in dto && dto.recentReviewAuthors).toEqual([
      { accountId: 'acc-owner', runs: 2, lastAt: '2026-11-15T12:00:00.000Z' },
      { accountId: 'acc-dev', runs: 1, lastAt: '2026-11-15T11:00:00.000Z' },
    ]);
    expect(await adminSetPolicy(r.t.deps, A, { policy: { ...(await policyOf(r)), reviewAuthors: ['not an id'] } })).toMatchObject({ error: 'validation' });
    expect(await adminSetPolicy(r.t.deps, A, { policy: { ...(await policyOf(r)), reviewAuthors: ['712020:abc-123'] } })).toMatchObject({ policy: { reviewAuthors: ['712020:abc-123'] } });
  });

  it('round-trips a policy, and ledgers which fields changed', async () => {
    const r = await reviewed();
    const next = { ...(await policyOf(r)), blockAtOrAbove: 'Medium' as const, enabledProjects: ['PAY', 'OPS'], championGroup: 'appsec' };
    const saved = await adminSetPolicy(r.t.deps, A, { policy: next });
    expect(saved).toEqual({ policy: next });
    expect(await adminGetPolicy(r.t.deps, A)).toMatchObject({ policy: next, saved: true });
    const changed = (await ledger(r)).filter((e) => e.eventType === 'policy.changed');
    expect(changed).toHaveLength(1);
    expect(changed[0]).toMatchObject({ actor: ADMIN, payload: { fields: ['blockAtOrAbove', 'championGroup', 'enabledProjects'] } });
  });

  it('rejects an invalid policy with a plain message and stores nothing', async () => {
    const r = await reviewed();
    const before = await policyOf(r);
    expect(await adminSetPolicy(r.t.deps, A, { policy: { ...before, enabledProjects: ['pay x'] } })).toMatchObject({ error: 'validation', message: expect.stringMatching(/project key/i) });
    expect(await adminSetPolicy(r.t.deps, A, { policy: { ...before, reviewIssueTypes: [] } })).toMatchObject({ error: 'validation' });
    expect(await adminSetPolicy(r.t.deps, A, { policy: { ...before, championGroup: '' } })).toMatchObject({ error: 'validation' });
    expect(await policyOf(r)).toEqual(before);
  });

  it('refuses to enable a project Jira does not know', async () => {
    const r = await reviewed();
    r.t.jira.projectInfo = async (key) => (key === 'NOPE' ? { ok: false, error: { code: 'not_found', message: 'nf' } } : ok({ id: '1', key, issueTypes: [] }));
    const before = await policyOf(r);
    expect(await adminSetPolicy(r.t.deps, A, { policy: { ...before, enabledProjects: ['PAY', 'NOPE'] } })).toEqual({ error: 'validation', message: 'Jira project NOPE was not found.' });
  });

  it('security: warn-only cannot be switched on through setPolicy (only admin.warnOnly, which is capped and ledgered)', async () => {
    const r = await reviewed();
    const now = r.t.clock.now().getTime();
    const sneaky = { ...(await policyOf(r)), warnOnly: [{ projectKey: 'PAY', since: new Date(now).toISOString(), until: new Date(now + 90 * DAY).toISOString() }] };
    const saved = await adminSetPolicy(r.t.deps, A, { policy: sneaky });
    expect('policy' in saved && saved.policy.warnOnly).toEqual([]);
    expect((await policyOf(r)).warnOnly).toEqual([]);
  });

  it('security: tightening or loosening the policy takes effect at the gate at once (stored verdicts are rechecked)', async () => {
    const r = await reviewed();
    expect(await validateTransition(r.t.deps, gate)).toMatchObject({ result: false });
    await adminSetPolicy(r.t.deps, A, { policy: { ...(await policyOf(r)), blockAtOrAbove: 'Critical' } });
    expect(await validateTransition(r.t.deps, gate)).toEqual({ result: true });
    await adminSetPolicy(r.t.deps, A, { policy: { ...(await policyOf(r)), blockAtOrAbove: 'High' } });
    expect(await validateTransition(r.t.deps, gate)).toMatchObject({ result: false });
  });

  it('fails closed: after a policy change, a pass that cannot be rechecked blocks', async () => {
    const r = await reviewed({ allVerified: true });
    expect(await validateTransition(r.t.deps, gate)).toEqual({ result: true });
    await adminSetPolicy(r.t.deps, A, { policy: { ...(await policyOf(r)), blockAtOrAbove: 'Low' } });
    r.t.jira.issue = async () => ({ ok: false, error: { code: 'internal', message: 'down' } });
    r.t.deps.state.set = async () => Promise.reject(new Error('kvs down'));
    expect(await validateTransition(r.t.deps, gate)).toMatchObject({ result: false });
  });
});

describe('admin.warnOnly (ledgered, at most 14 days)', () => {
  it('rejects 20 days, and a project Threatline is not enabled for', async () => {
    const r = await reviewed();
    expect(await adminWarnOnly(r.t.deps, A, { projectKey: 'PAY', days: 20 })).toEqual({ error: 'validation', message: 'Warn-only lasts 1 to 14 days.' });
    expect(await adminWarnOnly(r.t.deps, A, { projectKey: 'PAY', days: 0 })).toMatchObject({ error: 'validation' });
    expect(await adminWarnOnly(r.t.deps, A, { projectKey: 'OPS', days: 3 })).toEqual({ error: 'validation', message: 'Threatline is not turned on for OPS.' });
    expect((await policyOf(r)).warnOnly).toEqual([]);
  });

  it('switches a project to warn-only from now, ledgers it, and the gate lets work through until it ends', async () => {
    const r = await reviewed();
    const now = r.t.clock.now();
    const until = new Date(now.getTime() + 14 * DAY).toISOString();
    const out = await adminWarnOnly(r.t.deps, A, { projectKey: 'PAY', days: 14 });
    expect(out).toMatchObject({ projectKey: 'PAY', since: now.toISOString(), until, entryHash: expect.any(String) });
    expect((await policyOf(r)).warnOnly).toEqual([{ projectKey: 'PAY', since: now.toISOString(), until }]);
    const e = (await ledger(r)).filter((x) => x.eventType === 'policy.warn_only');
    expect(e).toHaveLength(1);
    expect(e[0]).toMatchObject({ actor: ADMIN, payload: { projectKey: 'PAY', since: now.toISOString(), until, days: 14 } });
    expect(await validateTransition(r.t.deps, gate)).toEqual({ result: true });
  });

  it('switching it on again replaces the window (it never stacks past 14 days)', async () => {
    const r = await reviewed();
    await adminWarnOnly(r.t.deps, A, { projectKey: 'PAY', days: 14 });
    r.t.clock.set(new Date(r.t.clock.now().getTime() + 10 * DAY).toISOString());
    await adminWarnOnly(r.t.deps, A, { projectKey: 'PAY', days: 2 });
    expect((await policyOf(r)).warnOnly).toHaveLength(1);
  });

  it('security: ending warn-only early blocks at the gate at once (the stored warn verdict is not trusted)', async () => {
    const r = await reviewed();
    await adminWarnOnly(r.t.deps, A, { projectKey: 'PAY', days: 7 });
    expect(await validateTransition(r.t.deps, gate)).toEqual({ result: true });
    expect((r.t.kv.data.get(verdictKey(ISSUE)) as { state: string }).state).toBe('warn');
    const end = await adminWarnOnlyEnd(r.t.deps, A, { projectKey: 'PAY' });
    expect(end).toMatchObject({ projectKey: 'PAY', entryHash: expect.any(String) });
    expect((await policyOf(r)).warnOnly).toEqual([]);
    expect((await ledger(r)).filter((x) => x.eventType === 'policy.warn_only').at(-1)).toMatchObject({ payload: { projectKey: 'PAY', ended: true } });
    expect(await validateTransition(r.t.deps, gate)).toMatchObject({ result: false });
  });

  it('ending a project that is not in warn-only says so', async () => {
    const r = await reviewed();
    expect(await adminWarnOnlyEnd(r.t.deps, A, { projectKey: 'PAY' })).toEqual({ error: 'validation', message: 'PAY is not in warn-only mode.' });
  });

  it('bumps the policy version so every stored verdict is rechecked', async () => {
    const r = await reviewed();
    await adminWarnOnly(r.t.deps, A, { projectKey: 'PAY', days: 1 });
    expect(r.t.kv.data.get(POLICY_VERSION_KEY)).toBe(1);
  });
});

describe('admin.runs (last 50 reviews, with the stage trace)', () => {
  it('lists the newest runs first, with stage timings and failures', async () => {
    const r = await reviewed();
    const out = await adminRuns(r.t.deps, A);
    if ('error' in out) throw new Error(out.error);
    expect(out.runs).toHaveLength(1);
    const run = out.runs[0]!;
    expect(run).toMatchObject({ reviewId: expect.any(String), issueKey: expect.stringMatching(/^PAY-/), revision: 1, status: 'ready', samplesReceived: 3, samplesExpected: 3, failureReason: null });
    expect(run.stages.map((s) => s.stage).sort()).toEqual(['agent_1', 'agent_2', 'agent_3', 'assemble', 'gather']);
    for (const s of run.stages) expect(s).toMatchObject({ status: expect.any(String), at: expect.any(String), ms: expect.any(Number) });
  });

  it('shows why a run failed', async () => {
    const r = await reviewed();
    const base = (await r.t.deps.reviews.latest(ISSUE)) as { ok: true; value: Review };
    await r.t.deps.reviews.create({ ...base.value, id: 'rev_x', revision: 2, status: 'agent_timeout', createdAt: '2026-11-15T13:00:00.000Z', updatedAt: '2026-11-15T13:15:00.000Z' });
    await r.t.deps.reviews.saveStage('rev_x', 'agent', 'failed', undefined, 'agent_timeout', '2026-11-15T13:15:00.000Z');
    const out = await adminRuns(r.t.deps, A);
    if ('error' in out) throw new Error(out.error);
    expect(out.runs[0]).toMatchObject({ reviewId: 'rev_x', status: 'agent_timeout', durationMs: 15 * 60_000, stages: [{ stage: 'agent', status: 'failed', error: 'agent_timeout', ms: 15 * 60_000 }] });
  });

  it(`returns at most ${50} runs`, async () => {
    const r = await reviewed();
    const base = (await r.t.deps.reviews.latest(ISSUE)) as { ok: true; value: Review };
    for (let i = 0; i < 55; i++) await r.t.deps.reviews.create({ ...base.value, id: `rev_n${i}`, issueId: `9${i}`, createdAt: new Date(Date.UTC(2026, 10, 1, 0, i)).toISOString() });
    const out = await adminRuns(r.t.deps, A);
    expect(RUNS_LIMIT).toBe(50);
    expect('runs' in out && out.runs).toHaveLength(50);
  });
});

describe('admin.usage', () => {
  it('this month: reviews, tokens, agent samples, against the budget, and whether reviews are paused', async () => {
    const r = await reviewed();
    const out = await adminUsage(r.t.deps, A);
    const policy = await policyOf(r);
    expect(out).toEqual({
      month: '2026-11',
      reviews: 1,
      tokensIn: 0,
      tokensOut: 0,
      agentSamples: 3,
      agentSamplesPerReview: policy.agentSamples,
      budget: policy.budget,
      paused: { budget: false, credits: false },
    });
  });

  it('reports a pause when the month budget is spent, or the last three agent runs came back empty', async () => {
    const r = await reviewed();
    await r.t.deps.config.setSite({ ...(await policyOf(r)), budget: { ...(await policyOf(r)).budget, reviewsPerMonth: 1 } });
    r.t.kv.data.set('ingest:recent', [false, false, false]);
    expect(await adminUsage(r.t.deps, A)).toMatchObject({ paused: { budget: true, credits: true } });
  });
});

describe('admin.setPolicy reviewMode (feature: rules-only mode)', () => {
  it('an admin switches to rule-based checks only; the change is ledgered with the field name', async () => {
    const r = await reviewed();
    const out = await adminSetPolicy(r.t.deps, A, { policy: { ...(await policyOf(r)), reviewMode: 'rules_only' } });
    expect(out).toMatchObject({ policy: { reviewMode: 'rules_only' } });
    const changed = (await ledger(r)).filter((e) => e.eventType === 'policy.changed').at(-1);
    expect(changed?.payload).toMatchObject({ fields: expect.arrayContaining(['reviewMode']) });
    expect(await adminSetPolicy(r.t.deps, A, { policy: { ...(await policyOf(r)), reviewMode: 'llm' } })).toMatchObject({ error: 'validation' });
  });
});

describe('admin.resumeReviews (final review C3)', () => {
  it('an admin clears the out-of-credits pause; it is ledgered; a developer cannot', async () => {
    const r = await reviewed();
    r.t.kv.data.set('ingest:recent', [false, false, false]);
    expect(await adminResumeReviews(r.t.deps, D, {})).toMatchObject({ error: 'forbidden' });
    expect(await adminUsage(r.t.deps, A)).toMatchObject({ paused: { credits: true } });
    const out = await adminResumeReviews(r.t.deps, A, {});
    expect(out).toMatchObject({ resumed: true, entryHash: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect(await adminUsage(r.t.deps, A)).toMatchObject({ paused: { credits: false } });
    expect((await ledger(r)).map((e) => e.eventType)).toContain('reviews.resumed');
  });
});

describe('admin.setNotifications (ops alerts work item, weekly digest page)', () => {
  it('stores both, after checking the work item and the space exist', async () => {
    const r = await reviewed();
    r.t.deps.confluence = { spaceByKey: async (k: string) => (k === 'SEC' ? ok({ id: 'sp', homepageId: 'h' }) : { ok: false, error: { code: 'not_found', message: 'nf' } }) } as unknown as ConfluenceClient;
    const out = await adminSetNotifications(r.t.deps, A, { ops: { issueKey: 'PAY-7', accountIds: [ADMIN] }, digest: { spaceKey: 'SEC', parentPageId: '123' } });
    expect(out).toEqual({ ops: { issueKey: 'PAY-7', accountIds: [ADMIN] }, digest: { spaceKey: 'SEC', parentPageId: '123' } });
    expect(r.t.kv.data.get(OPS_CONFIG_KEY)).toEqual({ issueKey: 'PAY-7', accountIds: [ADMIN] });
    expect(r.t.kv.data.get(DIGEST_CONFIG_KEY)).toEqual({ spaceKey: 'SEC', parentPageId: '123' });
    expect(await adminGetPolicy(r.t.deps, A)).toMatchObject({ ops: { issueKey: 'PAY-7' }, digest: { spaceKey: 'SEC' } });
  });

  it('rejects a missing work item or space; null turns a notification off', async () => {
    const r = await reviewed();
    r.t.deps.confluence = { spaceByKey: async () => ({ ok: false, error: { code: 'not_found', message: 'nf' } }) } as unknown as ConfluenceClient;
    expect(await adminSetNotifications(r.t.deps, A, { ops: { issueKey: 'PAY-404', accountIds: [] } })).toEqual({ error: 'validation', message: 'Work item PAY-404 was not found.' });
    expect(await adminSetNotifications(r.t.deps, A, { digest: { spaceKey: 'NOPE' } })).toEqual({ error: 'validation', message: 'Confluence space NOPE was not found.' });
    expect(await adminSetNotifications(r.t.deps, A, { ops: { issueKey: 'not a key', accountIds: [] } })).toMatchObject({ error: 'validation' });
    r.t.kv.data.set(OPS_CONFIG_KEY, { issueKey: 'PAY-7', accountIds: [] });
    expect(await adminSetNotifications(r.t.deps, A, { ops: null })).toEqual({ ops: null, digest: null });
    expect(r.t.kv.data.has(OPS_CONFIG_KEY)).toBe(false);
  });
});

describe('admin.projectStatuses (for picking the guarded transition)', () => {
  it('lists the project’s workflow statuses', async () => {
    const r = await reviewed();
    r.t.jira.projectStatuses = async () => ok(['To Do', 'In Progress', 'Done']);
    expect(await adminProjectStatuses(r.t.deps, A, { projectKey: 'PAY' })).toEqual({ projectKey: 'PAY', statuses: ['To Do', 'In Progress', 'Done'] });
    expect(await adminProjectStatuses(r.t.deps, A, { projectKey: 'x y' })).toMatchObject({ error: 'validation' });
  });
});

describe('admin.purgeProject (privacy: delete a project’s reviews)', () => {
  it('is for Jira administrators only', async () => {
    const r = await reviewed();
    expect(await adminPurgeProject(r.t.deps, D, { projectKey: 'OLD', confirm: 'OLD' })).toMatchObject({ error: 'forbidden' });
    expect(r.t.purgedProjects).toEqual([]);
  });
  it('needs the project key typed again to confirm', async () => {
    const r = await reviewed();
    expect(await adminPurgeProject(r.t.deps, A, { projectKey: 'OLD', confirm: 'old' })).toEqual({ error: 'validation', message: 'Type OLD to confirm. This cannot be undone.' });
    expect(r.t.purgedProjects).toEqual([]);
  });
  it('refuses a project Threatline still reviews, because its gate would then block every work item', async () => {
    const r = await reviewed();
    const res = await adminPurgeProject(r.t.deps, A, { projectKey: 'PAY', confirm: 'PAY' });
    expect(res).toEqual({ error: 'validation', message: 'Threatline still reviews PAY. Turn it off under Projects and transitions first, then purge.' });
    expect(r.t.purgedProjects).toEqual([]);
  });
  it('ledgers the purge first, then deletes, and reports the counts', async () => {
    const r = await reviewed();
    const res = await adminPurgeProject(r.t.deps, A, { projectKey: 'OLD', confirm: 'OLD' });
    expect(res).toMatchObject({ projectKey: 'OLD', reviews: 3, requirements: 2 });
    expect(r.t.purgedProjects).toEqual(['OLD']);
    const last = (await ledger(r)).at(-1)!;
    expect(last).toMatchObject({ eventType: 'project.purged', actor: ADMIN, payload: { projectKey: 'OLD' } });
    expect((res as { entryHash: string }).entryHash).toBe(last.entryHash);
  });
});

describe('admin.installGate (one click instead of the workflow editor)', () => {
  it('adds the gate to the guarded transition of each enabled project, as the admin, and ledgers it', async () => {
    const r = await reviewed();
    const calls: unknown[][] = [];
    r.t.deps.jira.installGate = async (...args) => (calls.push(args), ok({ added: ['Software workflow for project PAY: Done'], already: [], readOnly: [] }));
    const res = await adminInstallGate(r.t.deps, A, EXT);
    const p = await policyOf(r);
    expect(calls).toEqual(p.enabledProjects.map((k) => [ADMIN, k, p.guardedTransitions[0], EXT]));
    expect(res).toMatchObject({ projects: [{ added: ['Software workflow for project PAY: Done'] }] });
    expect((await ledger(r)).filter((e) => e.eventType === 'policy.changed').at(-1)?.payload).toMatchObject({ fields: ['doneGate'] });
  });

  it('a project Jira refuses does not stop the others: what was added is ledgered and the failure named; every guarded transition is gated', async () => {
    const r = await reviewed();
    const p = await policyOf(r);
    await r.t.deps.config.setSite({ ...p, enabledProjects: ['PAY', 'OPS', 'WEB'], guardedTransitions: ['Done', 'Released'] });
    const calls: string[] = [];
    r.t.deps.jira.installGate = async (_a, key, status) => {
      calls.push(`${key}:${status}`);
      return key === 'OPS' ? { ok: false, error: { code: 'forbidden', message: '403' } } : ok({ added: [`${key} workflow: ${status}`], already: [], readOnly: [] });
    };
    const res = await adminInstallGate(r.t.deps, A, EXT);
    expect(calls).toEqual(['PAY:Done', 'PAY:Released', 'OPS:Done', 'WEB:Done', 'WEB:Released']);
    expect(res).toMatchObject({
      projects: [
        { projectKey: 'PAY', added: ['PAY workflow: Done', 'PAY workflow: Released'] },
        { projectKey: 'OPS', added: [] },
        { projectKey: 'WEB', added: ['WEB workflow: Done', 'WEB workflow: Released'] },
      ],
      failed: [{ projectKey: 'OPS', message: expect.stringContaining("Jira did not let you edit OPS's workflow") }],
    });
    const row = (await ledger(r)).filter((e) => e.eventType === 'policy.changed').at(-1);
    expect(row?.payload).toMatchObject({ fields: ['doneGate'], transitions: ['PAY workflow: Done', 'PAY workflow: Released', 'WEB workflow: Done', 'WEB workflow: Released'], projects: ['PAY', 'WEB'], failedProjects: ['OPS'] });
  });

  it('says so plainly when Jira refuses, or the environment is unknown, and ledgers nothing', async () => {
    const r = await reviewed();
    r.t.deps.jira.installGate = async () => ({ ok: false, error: { code: 'forbidden', message: '403' } });
    expect(await adminInstallGate(r.t.deps, A, EXT)).toMatchObject({ error: 'forbidden', message: expect.stringContaining('workflow editor') });
    expect(await adminInstallGate(r.t.deps, A, null)).toMatchObject({ error: 'unavailable', message: expect.stringContaining('workflow editor') });
    expect((await ledger(r)).filter((e) => e.eventType === 'policy.changed')).toEqual([]);
  });
});

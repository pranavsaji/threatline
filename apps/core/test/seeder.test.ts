import { describe, expect, it } from 'vitest';
import { scanForInjection } from '@threatline/core';
import { appError, err, ok } from '@threatline/shared';
import type { AdfDoc, JiraIssue } from '../src/adapters/jira.js';
import type { ConfluenceClient } from '../src/adapters/confluence.js';
import { DEMO_COMPONENT, DEMO_LABEL, DESIGN_PAGE_TITLE, designPageStorage, HIDDEN_DIRECTIVE } from '../src/seeder/content/demo.js';
import { seedDemo } from '../src/seeder/seed.js';
import { adminSeed, adminSetupStatus } from '../src/resolvers/admin.js';
import { coreDeps, jiraIssue } from './support/core-deps.js';
import { POLICY_VERSION_KEY } from '../src/services/verdict-service.js';

type Created = { projectId: string; issueTypeId: string; summary: string; description: AdfDoc; labels: string[]; components?: string[]; parentId?: string };

/** coreDeps with a Jira that stores created issues (search by label finds them) and a Confluence space PAY. */
function site() {
  const t = coreDeps();
  const issues: JiraIssue[] = [];
  const created: Created[] = [];
  const components = new Set<string>();
  const links: Array<{ issueId: string; url: string }> = [];
  let n = 100;
  t.jira.projectInfo = async (key) =>
    key === 'PAY'
      ? ok({ id: '10000', key: 'PAY', issueTypes: [{ id: '1', name: 'Epic', subtask: false }, { id: '2', name: 'Story', subtask: false }, { id: '3', name: 'Bug', subtask: false }, { id: '4', name: 'Subtask', subtask: true }] })
      : err(appError('not_found', 'no project'));
  t.jira.ensureComponent = async (_k, name) => (components.add(name), ok(undefined));
  t.jira.createIssue = async (f) => {
    created.push(f);
    const key = `PAY-${n}`;
    const typeName = { '1': 'Epic', '2': 'Story', '3': 'Bug' }[f.issueTypeId] ?? 'Task';
    issues.push(jiraIssue({ id: String(20000 + n), key, summary: f.summary, labels: f.labels, components: f.components ?? [], issueType: { id: f.issueTypeId, name: typeName, subtask: false } }));
    n++;
    return ok({ id: String(20000 + n - 1), key });
  };
  t.jira.search = async (jql) => ok(issues.filter((i) => jql.includes(`labels = ${DEMO_LABEL}`) && i.labels.includes(DEMO_LABEL)));
  t.jira.addRemoteLink = async (issueId, l) => (links.push({ issueId, url: l.url }), ok(undefined));
  const pages: Array<{ id: string; title: string; spaceId: string; parentId?: string; storage: string }> = [];
  const confluence: Partial<ConfluenceClient> = {
    spaceByKey: async (key) => (key === 'PAY' ? ok({ id: 'S1', homepageId: '1' }) : err(appError('not_found', 'no space'))),
    findPage: async (spaceId, title) => {
      const p = pages.find((x) => x.spaceId === spaceId && x.title === title);
      return ok(p ? { id: p.id, url: `https://x/wiki/pages/${p.id}` } : null);
    },
    createPage: async (i) => {
      const id = String(500 + pages.length);
      pages.push({ id, title: i.title, spaceId: i.spaceId, ...(i.parentId ? { parentId: i.parentId } : {}), storage: i.storage });
      return ok({ id, url: `https://x/wiki/pages/${id}` });
    },
  };
  t.deps.confluence = confluence as ConfluenceClient;
  return { t, issues, created, components, links, pages };
}

describe('demo seeder (Task 24)', () => {
  it('turning the demo project on is a policy change like the admin page makes: ledgered, and every stored verdict rechecked', async () => {
    const s = site();
    const before = await s.t.deps.config.site();
    if (!before.ok) throw new Error('policy');
    await s.t.deps.config.setSite({ ...before.value, enabledProjects: [] });
    await s.t.kv.set(POLICY_VERSION_KEY, 4);
    const r = await seedDemo(s.t.deps, { projectKey: 'PAY' }, 'acc-admin');
    if (!r.ok) throw new Error(r.error.message);
    const after = await s.t.deps.config.site();
    expect(after.ok && after.value.enabledProjects).toEqual(['PAY']);
    expect(s.t.kv.data.get(POLICY_VERSION_KEY)).toBe(5);
    const rows = await s.t.deps.ledger.latestOfTypes(['policy.changed'], 10);
    expect(rows.ok && rows.value).toEqual([expect.objectContaining({ actor: 'acc-admin', payload: { fields: ['enabledProjects'], source: 'demo', projectKey: 'PAY' } })]);
    // Loading it again changes no policy, so nothing more is ledgered or bumped.
    await seedDemo(s.t.deps, { projectKey: 'PAY' }, 'acc-admin');
    expect(s.t.kv.data.get(POLICY_VERSION_KEY)).toBe(5);
    const again = await s.t.deps.ledger.latestOfTypes(['policy.changed'], 10);
    expect(again.ok && again.value).toHaveLength(1);
  });

  it('works on a site without Confluence: the design, hidden instruction included, goes into the descriptions (audit finding)', async () => {
    const s = site();
    s.t.deps.confluence = {} as ConfluenceClient; // any Confluence call would throw
    const r = await seedDemo(s.t.deps, { projectKey: 'PAY' });
    if (!r.ok) throw new Error(r.error.message);
    expect(r.value.designPageUrl).toBeNull();
    expect(s.links).toEqual([]);
    const text = (c: Created) => c.description.content.map((p) => JSON.stringify(p)).join(' ');
    const [epic, story] = s.created;
    for (const c of [epic!, story!]) {
      expect(text(c)).toContain('issueRefund calls it with an order id and amount');
      expect(scanForInjection(text(c)).suspected).toBe(true);
    }
    expect(text(s.created[3]!)).not.toContain('issueRefund calls it'); // incidents stay as they were
  });

  it('a project without Story gets Task stories, and Task is added to the reviewed work types (audit finding)', async () => {
    const s = site();
    s.t.jira.projectInfo = async () => ok({ id: '10000', key: 'PAY', issueTypes: [{ id: '1', name: 'Epic', subtask: false }, { id: '5', name: 'Task', subtask: false }] });
    const r = await seedDemo(s.t.deps, { projectKey: 'PAY', spaceKey: 'PAY' });
    if (!r.ok) throw new Error(r.error.message);
    expect(r.value.addedReviewTypes).toEqual(['Task']);
    const policy = await s.t.deps.config.site();
    expect(policy.ok && policy.value.reviewIssueTypes).toEqual(expect.arrayContaining(['Task']));
    // Again: nothing more to add.
    const again = await seedDemo(s.t.deps, { projectKey: 'PAY', spaceKey: 'PAY' });
    expect(again.ok && again.value.addedReviewTypes).toEqual([]);
  });

  it('creates the epic, two stories under it, two incidents, the design page, links and the enabled project', async () => {
    const s = site();
    await s.t.deps.config.setSite({ ...(await s.t.deps.config.site() as { ok: true; value: Parameters<typeof s.t.deps.config.setSite>[0] }).value, enabledProjects: [] });
    const r = await seedDemo(s.t.deps, { projectKey: 'PAY', spaceKey: 'PAY' });
    if (!r.ok) throw new Error(r.error.message);
    expect(r.value).toEqual({ epicKey: 'PAY-100', storyKeys: ['PAY-101', 'PAY-102'], designPageUrl: 'https://x/wiki/pages/500', incidentKeys: ['PAY-103', 'PAY-104'], addedReviewTypes: [] });
    expect(s.created.map((c) => c.summary)).toEqual(['Add AI support agent', 'Agent can look up order status', 'Agent can issue refunds', expect.stringMatching(/delivery address/), expect.stringMatching(/refund requests/)]);
    expect(s.created[1]).toMatchObject({ parentId: '20100', components: [DEMO_COMPONENT], issueTypeId: '2' });
    expect(s.created[3]).toMatchObject({ issueTypeId: '3', labels: expect.arrayContaining(['incident', DEMO_LABEL]), components: [DEMO_COMPONENT] });
    expect(s.created.every((c) => c.labels.includes(DEMO_LABEL))).toBe(true);
    expect(s.components.has(DEMO_COMPONENT)).toBe(true);
    expect(s.pages[0]).toMatchObject({ title: DESIGN_PAGE_TITLE, spaceId: 'S1', parentId: '1' });
    // The epic links the design page too: the judge guide opens the epic and expects the poisoned page in its review.
    expect(s.links).toEqual([
      { issueId: '20100', url: 'https://x/wiki/pages/500' },
      { issueId: '20101', url: 'https://x/wiki/pages/500' },
      { issueId: '20102', url: 'https://x/wiki/pages/500' },
    ]);
    const policy = await s.t.deps.config.site();
    expect(policy.ok && policy.value.enabledProjects).toContain('PAY');
  });

  it('judge path: queues a review of the epic and each story as the admin who loaded the demo (the app\'s own creates do not trigger one)', async () => {
    const s = site();
    s.t.pushed.length = 0;
    const r = await seedDemo(s.t.deps, { projectKey: 'PAY', spaceKey: 'PAY' }, 'acc-admin');
    if (!r.ok) throw new Error(r.error.message);
    expect(s.t.pushed).toEqual([
      { kind: 'gather', issueId: '20100', reason: 'created', actorAccountId: 'acc-admin' },
      { kind: 'gather', issueId: '20101', reason: 'created', actorAccountId: 'acc-admin' },
      { kind: 'gather', issueId: '20102', reason: 'created', actorAccountId: 'acc-admin' },
    ]);
  });

  it('seeding twice reuses the existing items and page', async () => {
    const s = site();
    const first = await seedDemo(s.t.deps, { projectKey: 'PAY', spaceKey: 'PAY' });
    const second = await seedDemo(s.t.deps, { projectKey: 'PAY', spaceKey: 'PAY' });
    expect(second).toEqual(first);
    expect(s.created).toHaveLength(5);
    expect(s.pages).toHaveLength(1);
  });

  it('the design page carries one poisoned paragraph that Threatline detects as an injection attempt', () => {
    const storage = designPageStorage();
    expect(storage).toContain(HIDDEN_DIRECTIVE);
    expect(storage.match(/ignore previous instructions/gi)).toHaveLength(1);
    expect(scanForInjection(storage)).toMatchObject({ suspected: true, reasons: expect.arrayContaining(['ai_directive', 'hidden_unicode']) });
  });

  it('an unknown project or space is a validation error with nothing created', async () => {
    const s = site();
    expect(await seedDemo(s.t.deps, { projectKey: 'NOPE', spaceKey: 'PAY' })).toMatchObject({ ok: false, error: { code: 'validation' } });
    expect(await seedDemo(s.t.deps, { projectKey: 'PAY', spaceKey: 'NOPE' })).toMatchObject({ ok: false, error: { code: 'validation' } });
    expect(s.created).toHaveLength(0);
  });
});

describe('admin.seed / admin.setupStatus', () => {
  const admin = { accountId: 'acc-admin' };

  it('only a Jira admin can seed; keys are validated', async () => {
    const s = site();
    expect(await adminSeed(s.t.deps, admin, { projectKey: 'PAY', spaceKey: 'PAY' })).toMatchObject({ error: 'forbidden' });
    s.t.jira.isAdmin = async () => ok(true);
    expect(await adminSeed(s.t.deps, admin, { projectKey: 'pay; drop', spaceKey: 'PAY' })).toMatchObject({ error: 'validation' });
    expect(await adminSeed(s.t.deps, admin, { projectKey: 'PAY', spaceKey: 'PAY' })).toMatchObject({ epicKey: 'PAY-100' });
  });

  it('reports the setup checklist from what Threatline has seen', async () => {
    const s = site();
    s.t.jira.isAdmin = async () => ok(true);
    s.t.kv.data.set('schema:version', 3);
    s.t.kv.data.set('validator:seen', { PAY: '2026-11-15T10:00:00.000Z', OLD: '2026-09-01T00:00:00.000Z' });
    s.t.kv.data.set('ingest:lastAt', '2026-11-14T12:00:00.000Z');
    const status = await adminSetupStatus(s.t.deps, admin, { signingKeys: async () => true });
    expect(status).toMatchObject({ keys: true, sqlVersion: 3, validatorSeenOn: ['PAY'], automationRuleSeen: true, bitbucketKeyCopied: false, mcpEnabledHint: expect.stringMatching(/MCP/) });
    // The hint names the tools the MCP server really exposes (manifest rovo:mcp), never the agent-only review actions.
    expect((status as { mcpEnabledHint: string }).mcpEnabledHint).toMatch(/get-security-requirements/);
    expect((status as { mcpEnabledHint: string }).mcpEnabledHint).not.toMatch(/submit-threat-model|get-review-context/);
    s.t.kv.data.set('ingest:lastAt', '2026-11-01T12:00:00.000Z');
    expect(await adminSetupStatus(s.t.deps, admin, { signingKeys: async () => false })).toMatchObject({ keys: false, automationRuleSeen: false });
    s.t.jira.isAdmin = async () => ok(false);
    expect(await adminSetupStatus(s.t.deps, admin, { signingKeys: async () => true })).toMatchObject({ error: 'forbidden' });
  });
});

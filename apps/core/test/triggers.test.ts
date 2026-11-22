import { describe, expect, it } from 'vitest';
import { onIssueChange } from '../src/triggers/on-issue-change.js';
import { onPageChange } from '../src/triggers/on-page-change.js';
import { onInstallJobs } from '../src/triggers/on-install.js';
import { coreDeps } from './support/core-deps.js';
import { PAGE_KEY } from '../src/services/confluence-page.js';

const issueEvent = (o: { type?: string; project?: string; eventType?: string; items?: Array<Record<string, unknown>>; key?: string } = {}) => ({
  eventType: o.eventType ?? 'avi:jira:updated:issue',
  atlassianId: 'acc-editor',
  issue: { id: '10042', key: o.key ?? 'PAY-7', fields: { issuetype: { name: o.type ?? 'Story' }, project: { key: o.project ?? 'PAY' }, parent: undefined } },
  changelog: { items: o.items ?? [{ field: 'description', fieldId: 'description' }] },
});

describe('onIssueChange', () => {
  it('ignores issues outside enabled projects', async () => {
    const t = coreDeps();
    await onIssueChange(t.deps, issueEvent({ project: 'HR' }));
    expect(t.pushed).toEqual([]);
  });

  it('a created event pushes gather(created) with the actor', async () => {
    const t = coreDeps();
    await onIssueChange(t.deps, issueEvent({ eventType: 'avi:jira:created:issue', items: [] }));
    expect(t.pushed).toEqual([{ kind: 'gather', issueId: '10042', reason: 'created', actorAccountId: 'acc-editor' }]);
  });

  it('only relevant field changes push gather(updated)', async () => {
    const t = coreDeps();
    await onIssueChange(t.deps, issueEvent({ items: [{ field: 'assignee', fieldId: 'assignee' }, { field: 'priority', fieldId: 'priority' }] }));
    expect(t.pushed).toEqual([]);
    for (const f of ['summary', 'description', 'Link', 'Component', 'labels', 'IssueParentAssociation', 'project']) {
      t.pushed.length = 0;
      await onIssueChange(t.deps, issueEvent({ items: [{ field: f, fieldId: f.toLowerCase() }] }));
      expect(t.pushed.map((j) => j.kind)).toEqual(['gather']);
    }
  });

  it('adding the threatline-review label is a rerun', async () => {
    const t = coreDeps();
    await onIssueChange(t.deps, issueEvent({ items: [{ field: 'labels', fieldId: 'labels', fromString: 'pci', toString: 'pci threatline-review' }] }));
    expect(t.pushed).toEqual([{ kind: 'gather', issueId: '10042', reason: 'rerun', actorAccountId: 'acc-editor' }]);
  });

  it('label re-runs are rate-limited per work item (then count as ordinary updates)', async () => {
    const t = coreDeps();
    const toggle = issueEvent({ items: [{ field: 'labels', fieldId: 'labels', fromString: '', toString: 'threatline-review' }] });
    for (let i = 0; i < 12; i++) await onIssueChange(t.deps, toggle);
    expect(t.pushed.filter((j) => j.kind === 'gather' && j.reason === 'rerun').length).toBe(10);
    expect(t.pushed.slice(10)).toEqual([
      { kind: 'gather', issueId: '10042', reason: 'updated', actorAccountId: 'acc-editor' },
      { kind: 'gather', issueId: '10042', reason: 'updated', actorAccountId: 'acc-editor' },
    ]);
  });

  it('an Automation rule that labels many work items re-runs every one (the limit is per work item, not per actor)', async () => {
    const t = coreDeps();
    for (let i = 0; i < 15; i++) {
      const ev = issueEvent({ items: [{ field: 'labels', fieldId: 'labels', fromString: '', toString: 'threatline-review' }] });
      await onIssueChange(t.deps, { ...ev, issue: { ...ev.issue, id: String(20000 + i) } });
    }
    expect(t.pushed.filter((j) => j.kind === 'gather' && j.reason === 'rerun').length).toBe(15);
  });

  it('a limiter that cannot be read does not drop the label re-run', async () => {
    const t = coreDeps();
    t.deps.usage = { ...t.deps.usage, takeSlot: async () => ({ ok: false, error: { code: 'upstream', message: "Table 'rate_limits' doesn't exist" } }) };
    await onIssueChange(t.deps, issueEvent({ items: [{ field: 'labels', fieldId: 'labels', fromString: '', toString: 'threatline-review' }] }));
    expect(t.pushed).toEqual([{ kind: 'gather', issueId: '10042', reason: 'rerun', actorAccountId: 'acc-editor' }]);
  });

  it('removing the label is an ordinary update, not a rerun', async () => {
    const t = coreDeps();
    await onIssueChange(t.deps, issueEvent({ items: [{ field: 'labels', fieldId: 'labels', fromString: 'threatline-review', toString: '' }] }));
    expect(t.pushed).toEqual([{ kind: 'gather', issueId: '10042', reason: 'updated', actorAccountId: 'acc-editor' }]);
  });

  it('a move records the new key at once', async () => {
    const t = coreDeps();
    await t.deps.issues.upsert({ issueId: '10042', issueKey: 'PAY-7', projectKey: 'PAY' });
    await onIssueChange(t.deps, issueEvent({ key: 'PAY-77', items: [{ field: 'Key', fieldId: 'issuekey' }, { field: 'project', fieldId: 'project' }] }));
    expect(await t.deps.issues.get('10042')).toEqual({ ok: true, value: { issueId: '10042', issueKey: 'PAY-77', projectKey: 'PAY' } });
  });

  it('a non-reviewed issue type pushes a verdict job instead of a review', async () => {
    const t = coreDeps();
    await onIssueChange(t.deps, issueEvent({ type: 'Subtask' }));
    expect(t.pushed).toEqual([{ kind: 'verdict', issueId: '10042' }]);
  });

  it('a malformed event is ignored', async () => {
    const t = coreDeps();
    await onIssueChange(t.deps, { issue: { id: 'x' } } as never);
    expect(t.pushed).toEqual([]);
  });
});

describe('onPageChange', () => {
  it('pushes gather(page_changed) for every issue linked to the page', async () => {
    const t = coreDeps();
    await t.deps.issues.linkPage('10042', '98305');
    await t.deps.issues.linkPage('10043', '98305');
    await onPageChange(t.deps, { content: { id: '98305' }, atlassianId: 'acc-writer' });
    expect(t.pushed).toEqual([
      { kind: 'gather', issueId: '10042', reason: 'page_changed', actorAccountId: 'acc-writer' },
      { kind: 'gather', issueId: '10043', reason: 'page_changed', actorAccountId: 'acc-writer' },
    ]);
  });

  it('an unlinked page does nothing', async () => {
    const t = coreDeps();
    await onPageChange(t.deps, { content: { id: '1' } });
    expect(t.pushed).toEqual([]);
  });

  it("Threatline re-publishing a work item's threat-model page does not re-gather that work item (others linking it still are)", async () => {
    const t = coreDeps();
    await t.deps.issues.linkPage('10042', '98305');
    await t.deps.issues.linkPage('10043', '98305');
    await t.kv.set(PAGE_KEY('10042'), { pageId: '98305', parentId: '1', url: 'https://x/wiki/pages/98305' });
    await onPageChange(t.deps, { content: { id: '98305' } });
    expect(t.pushed).toEqual([{ kind: 'gather', issueId: '10043', reason: 'page_changed' }]);
  });
});

describe('onInstall', () => {
  it('queues a migration', () => {
    expect(onInstallJobs()).toEqual([{ kind: 'migrate' }]);
  });
});

describe('onIssueChange: hostile changelog shapes', () => {
  it('a changelog item with a non-string toString (or prototype keys) does not crash or count as a rerun', async () => {
    const t = coreDeps();
    await onIssueChange(t.deps, issueEvent({ items: [JSON.parse('{"field":"labels","toString":{"x":1},"__proto__":{"toString":"threatline-review"}}')] }));
    expect(t.pushed).toEqual([{ kind: 'gather', issueId: '10042', reason: 'updated', actorAccountId: 'acc-editor' }]);
  });
});

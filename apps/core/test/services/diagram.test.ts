import { describe, expect, it } from 'vitest';
import { layoutDiagram, normalizeFact } from '@threatline/core';
import { appError, err, ok, type ArchitectureSketch, type ContextFact, type Requirement, type Threat } from '@threatline/shared';
import { panelGet } from '../../src/resolvers/panel.js';
import { getReview } from '../../src/actions/get-review.js';
import { publishThreatModel } from '../../src/services/confluence-page.js';
import { resolvedThreatIds } from '../../src/services/diagram-service.js';
import type { ConfluenceClient, ConfluencePage } from '../../src/adapters/confluence.js';
import { ISSUE, reviewed } from '../support/reviewed.js';

const ME = 'acc-plain';
const viewer = { accountId: ME, issueId: ISSUE };
const ctx = { context: { accountId: ME, agentId: 'agent-1', cloudId: 'c' } };

const SKETCH: ArchitectureSketch = {
  components: ['Webhook endpoint', 'Refund agent'],
  dataStores: ['Orders DB'],
  externalServices: ['Stripe'],
  trustBoundaries: ['Stripe to webhook endpoint'],
  flows: [
    { from: 'Stripe', to: 'Webhook endpoint', data: 'refund event' },
    { from: 'Refund agent', to: 'Orders DB', data: 'order lookup' },
  ],
  dataClasses: ['payment'],
  exposure: 'public',
  llmFeatures: true,
  injectionSuspected: false,
};

/** PAY-7 reviewed (one open High "forged webhook" threat on "webhook endpoint"), with the engine's extracted sketch. */
async function withSketch(o: { secretPage?: boolean } = {}) {
  const r = await reviewed();
  const rev = ((await r.t.deps.reviews.latest(ISSUE)) as { ok: true; value: { id: string } }).value.id;
  await r.t.deps.reviews.saveStage(rev, 'extract', 'done', { sketch: SKETCH, evidence: [] });
  if (o.secretPage) {
    const facts = ((await r.t.deps.reviews.facts(rev)) as { ok: true; value: ContextFact[] }).value;
    const secret = normalizeFact({ sourceAri: 'ari:cloud:confluence:c:page/77', sourceType: 'confluence_page', title: 'Restricted design', url: '', text: 'secret', version: '1', trusted: false, origin: 'rest' });
    await r.t.deps.reviews.saveFacts(rev, [...facts, secret]);
    r.t.deps.confluence = { ...r.t.deps.confluence, canRead: async () => ok(false) };
  }
  return { ...r, rev };
}

describe('panel.get diagram', () => {
  it('draws the extracted sketch with the viewer’s threats placed on their component', async () => {
    const { t } = await withSketch();
    const dto = await panelGet(t.deps, viewer);
    if ('error' in dto) throw new Error(dto.error);
    const d = dto.diagram!;
    expect(d.sketchHidden).toBe(false);
    const webhook = d.nodes.find((n) => n.name === 'Webhook endpoint')!;
    expect(webhook.kind).toBe('process');
    expect(webhook.boundaryId).not.toBeNull();
    const forged = dto.threats.find((x) => /forged refund webhooks/i.test(x.title))!;
    expect(webhook.threatIds).toContain(forged.id);
    expect(webhook.maxSeverity).toBe('High');
    expect(d.edges.map((e) => e.data)).toEqual(['refund event', 'order lookup']);
    expect(d.edges[0]!.crossesBoundary).toBe(true);
    // Every listed threat is on the diagram (placed or not), and nothing the panel does not list.
    expect(d.threats.map((x) => x.id).sort()).toEqual(dto.threats.map((x) => x.id).sort());
  });

  it('security: leaves the sketch out (elements named by visible threats only) when the viewer cannot open every source', async () => {
    const { t } = await withSketch({ secretPage: true });
    const dto = await panelGet(t.deps, viewer);
    if ('error' in dto) throw new Error(dto.error);
    expect(dto.diagram!.sketchHidden).toBe(true);
    expect(dto.diagram!.edges).toEqual([]);
    const names = dto.diagram!.nodes.map((n) => n.name);
    expect(names).not.toContain('Orders DB');
    expect(names).not.toContain('Stripe');
    expect(JSON.stringify(dto.diagram)).not.toContain('order lookup');
    expect(names).toContain('webhook endpoint');
  });

  it('agent-mode reviews (no extract stage) draw the runs’ sketches and threats; a never-reviewed item has no diagram', async () => {
    const { t, rev } = await withSketch();
    await t.deps.reviews.saveStage(rev, 'extract', 'failed', undefined, 'schema');
    const samples = ((await t.deps.reviews.samples(rev)) as { ok: true; value: Array<Record<string, unknown>> }).value;
    t.deps.reviews.samples = async () => ok(samples.map((s, i) => (i === 0 ? { ...s, sketch: { components: ['Refund agent'], dataStores: ['Orders DB'] } } : s)) as never);
    const dto = await panelGet(t.deps, viewer);
    if ('error' in dto) throw new Error(dto.error);
    expect(dto.diagram!.nodes.map((n) => n.name)).toEqual(expect.arrayContaining(['Refund agent', 'Orders DB', 'webhook endpoint']));
    expect(dto.diagram!.edges).toEqual([]);
    t.deps.reviews.latest = async () => ok(null);
    const none = await panelGet(t.deps, viewer);
    if ('error' in none) throw new Error(none.error);
    expect(none.diagram).toBeUndefined();
  });

  it('a failed stage or samples read still draws the threats (fail safe: less, never more)', async () => {
    const { t } = await withSketch();
    t.deps.reviews.stage = async () => err(appError('internal', 'x'));
    t.deps.reviews.samples = async () => err(appError('internal', 'x'));
    const dto = await panelGet(t.deps, viewer);
    if ('error' in dto) throw new Error(dto.error);
    expect(dto.diagram!.edges).toEqual([]);
    expect(dto.diagram!.nodes.map((n) => n.name)).toContain('webhook endpoint');
  });
});

describe('resolvedThreatIds', () => {
  it('a threat is resolved when it has requirements and every one is closed', () => {
    const r = (threatId: string, status: Requirement['status']) => ({ threatId, status }) as Requirement;
    expect(resolvedThreatIds([r('a', 'Verified'), r('b', 'Open'), r('c', 'AcceptedRisk'), r('c', 'InProgress'), r('d', 'NotApplicable')]).sort()).toEqual(['a', 'd']);
  });
});

describe('get-review dataFlowDiagram', () => {
  it('the action description names dataFlowDiagram and fits Rovo’s 255 characters', async () => {
    const { readFileSync } = await import('node:fs');
    const { parse } = await import('yaml');
    const m = parse(readFileSync(new URL('../../manifest.yml', import.meta.url), 'utf8')) as { modules: { action: Array<{ key: string; description: string }> } };
    const d = m.modules.action.find((a) => a.key === 'get-review')!.description;
    expect(d).toContain('dataFlowDiagram');
    expect(d.length).toBeLessThanOrEqual(255);
  });

  it('adds a compact text DFD with the same T-n refs as the threats', async () => {
    const { t } = await withSketch();
    const r = await getReview({ issueKey: 'PAY-7', ...ctx }, t.deps);
    if ('error' in r) throw new Error(r.error);
    const forged = r.threats.find((x) => /forged refund webhooks/i.test(x.title))!;
    expect(r.dataFlowDiagram).toContain('Elements:');
    expect(r.dataFlowDiagram).toMatch(new RegExp(`\\[process\\] Webhook endpoint \\(in: Stripe to webhook endpoint\\) - .*${forged.ref}`));
    expect(r.dataFlowDiagram).toContain('1. Stripe -> Webhook endpoint: refund event [crosses a trust boundary]');
  });

  it('says when the architecture was left out for this caller', async () => {
    const { t } = await withSketch({ secretPage: true });
    const r = await getReview({ issueKey: 'PAY-7', ...ctx }, t.deps);
    if ('error' in r) throw new Error(r.error);
    expect(r.dataFlowDiagram).toMatch(/sources you cannot open/);
    expect(r.dataFlowDiagram).not.toContain('Orders DB');
  });
});

function fakeConfluence() {
  const pages = new Map<string, ConfluencePage>();
  pages.set('500', { id: '500', title: 'Refund agent design', spaceId: 'S1', version: 3, storage: '<p>design</p>', url: 'https://x/wiki/pages/500' });
  let next = 900;
  const c: ConfluenceClient & { pages: typeof pages } = {
    pages,
    page: async (id) => (pages.has(id) ? ok(structuredClone(pages.get(id)!)) : err(appError('not_found', 'nf'))),
    createPage: async (i) => {
      const id = String(next++);
      pages.set(id, { id, title: i.title, spaceId: i.spaceId, version: 1, storage: i.storage, url: `https://x/wiki/pages/${id}` });
      return ok({ id, url: `https://x/wiki/pages/${id}` });
    },
    updatePage: async () => ok(undefined),
    canRead: async () => ok(true),
    spaceByKey: async () => err(appError('not_found', 'nf')),
    findPage: async () => ok(null),
  };
  return c;
}

const pageFact = (id: string, title: string): ContextFact =>
  normalizeFact({ sourceAri: `ari:cloud:confluence:c:page/${id}`, sourceType: 'confluence_page', title, url: `https://x/wiki/pages/${id}`, text: 'design text', version: '1', trusted: false, origin: 'rest' });

describe('the Confluence page carries the diagram as tables', () => {
  async function publish(extra: ContextFact[]) {
    const { t, rev } = await withSketch();
    const conf = fakeConfluence();
    t.deps.confluence = conf;
    t.jira.addRemoteLink = async () => ok(undefined);
    const facts = ((await t.deps.reviews.facts(rev)) as { ok: true; value: ContextFact[] }).value;
    await t.deps.reviews.saveFacts(rev, [...facts, pageFact('500', 'Refund agent design'), ...extra]);
    const r = await publishThreatModel(t.deps, ISSUE);
    if (!r.ok) throw new Error(r.error.message);
    return conf.pages.get(r.value.pageId)!.storage;
  }

  it('when every source is open to the page’s readers: elements, flows and boundaries', async () => {
    const storage = await publish([]);
    expect(storage).toContain('<h2>Data-flow diagram</h2>');
    expect(storage).toContain('<td>1</td><td>Stripe</td><td>Webhook endpoint</td><td>refund event</td><td>Yes</td>');
    expect(storage).toContain('Stripe to webhook endpoint');
    expect(storage).not.toMatch(/not everyone who can read this page can open/);
  });

  it('security: a source beyond the work item and its design page drops the sketch from the page', async () => {
    const storage = await publish([pageFact('777', 'Fraud rules')]);
    expect(storage).toMatch(/not everyone who can read this page can open/);
    expect(storage).not.toContain('order lookup');
    expect(storage).not.toContain('Orders DB');
  });
});

describe('the local preview’s diagram fixture', () => {
  // A rich PAY-6 (password reset by magic link) sketch. The UI cannot import the layout, so its fixture is this model,
  // generated: after changing the layout or this sketch, run `pnpm vitest run apps/core/test/services/diagram.test.ts -u`.
  const sketch = {
    externalServices: ['Customer browser', 'Email provider (SendGrid)', 'Support staff'],
    components: ['Reset API', 'Magic link service', 'Session service', 'Account settings'],
    dataStores: ['Users table', 'Reset tokens table', 'Audit log'],
    trustBoundaries: ['Internet → Reset API', 'Core platform (Magic link service, Session service, Account settings, Users table, Reset tokens table, Audit log)', 'Admin network'],
    flows: [
      { from: 'Customer browser', to: 'Reset API', data: 'email address' },
      { from: 'Reset API', to: 'Magic link service', data: 'reset request' },
      { from: 'Magic link service', to: 'Reset tokens table', data: 'token (never expires)' },
      { from: 'Magic link service', to: 'Email provider (SendGrid)', data: 'sign-in link' },
      { from: 'Email provider (SendGrid)', to: 'Customer browser', data: 'sign-in link email' },
      { from: 'Customer browser', to: 'Session service', data: 'magic link token' },
      { from: 'Session service', to: 'Users table', data: 'account lookup' },
      { from: 'Account settings', to: 'Users table', data: 'email and phone change' },
      { from: 'Support staff', to: 'Account settings', data: 'manual email change' },
      { from: 'Session service', to: 'Audit log', data: 'sign-in event' },
    ],
  };

  it('is the layout of the fixture sketch and the fixture threats', async () => {
    // Loaded at run time: the UI's sources are not part of this TypeScript project.
    const path = '../../ui/src/fixtures.js';
    const { FIXTURES } = (await import(/* @vite-ignore */ path)) as { FIXTURES: Record<string, { threats: Threat[]; requirements: Requirement[] }> };
    const ready = FIXTURES.ready!;
    const model = { ...layoutDiagram({ sketch, threats: ready.threats, resolvedThreatIds: resolvedThreatIds(ready.requirements) }), sketchHidden: false };
    const source = [
      '// Generated by apps/core/test/services/diagram.test.ts from the PAY-6 fixture sketch and threats: do not edit.',
      '// After changing the layout or the fixtures, run `pnpm vitest run apps/core/test/services/diagram.test.ts -u`.',
      "import type { DiagramDto } from './types.js';",
      '',
      `export const DIAGRAM_FIXTURE: DiagramDto = ${JSON.stringify(model, null, 2)};`,
      '',
    ].join('\n');
    await expect(source).toMatchFileSnapshot('../../ui/src/diagram-fixture.ts');
  });
});

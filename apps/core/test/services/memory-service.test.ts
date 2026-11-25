import { describe, expect, it, vi } from 'vitest';
import { appendLedger, normalizeFact } from '@threatline/core';
import { appError, err, ok, type ContextFact, type Requirement, type Review, type Threat } from '@threatline/shared';
import { coreDeps, jiraIssue } from '../support/core-deps.js';
import { incidentSeverity, MEMORY_LIMITS, seenBefore } from '../../src/services/memory-service.js';
import { panelMemory } from '../../src/resolvers/memory.js';
import { panelStatus } from '../../src/resolvers/panel.js';
import { explainThreat } from '../../src/actions/explain-threat.js';
import type { JiraIssue } from '../../src/adapters/jira.js';

const NOW = '2026-11-24T12:00:00.000Z';
const ME = 'acc-dev';
const PAY7 = jiraIssue({ id: '10042', key: 'PAY-7', components: ['payments'] });
const items = {
  PAY3: jiraIssue({ id: '10003', key: 'PAY-3' }),
  PAY9: jiraIssue({ id: '10009', key: 'PAY-9' }),
  PAY4: jiraIssue({ id: '10004', key: 'PAY-4' }),
  PAY5: jiraIssue({ id: '10005', key: 'PAY-5' }),
  INC7: jiraIssue({
    id: '20007', key: 'INC-7', summary: 'Duplicate refunds after webhook retries', labels: ['incident', 'sev-2'], components: ['payments'],
    description: 'The payment provider retried the refund webhook five times and each retry issued another refund. Webhook events were not deduplicated.',
    issueType: { id: '10010', name: 'Bug', subtask: false }, created: '2026-10-01T00:00:00.000Z',
  }),
  INC8: jiraIssue({ id: '20008', key: 'INC-8', summary: 'Login page slow on Mondays', labels: ['incident'], components: ['payments'], description: 'The sign-in page took 9 seconds to load.' }),
};

const fact = (issueId: string, over: Partial<ContextFact> = {}): ContextFact => ({
  ...normalizeFact({ sourceAri: `ari:cloud:jira:e2e:issue/${issueId}`, sourceType: 'jira_issue', title: 'Item', url: '', text: 'Refund webhook from the payment provider', version: '1', trusted: false, origin: 'rest' }),
  ...over,
});
const review = (issue: JiraIssue, over: Partial<Review> = {}): Review => ({
  id: `rev_${issue.id}`, issueId: issue.id, issueKey: issue.key, revision: 1, status: 'ready', contextHash: 'h', riskScore: 40, partial: false, promptVersion: 'v', modelIds: [],
  samplesExpected: 3, samplesReceived: 3, tokensIn: 0, tokensOut: 0, createdAt: '2026-11-20T00:00:00.000Z', updatedAt: '2026-11-20T00:00:00.000Z', ...over,
});
const threat = (reviewId: string, factId: string, over: Partial<Threat> = {}): Threat => ({
  id: `thr_${reviewId}`, reviewId, stride: 'Tampering', title: 'Replayed refund webhooks issue duplicate refunds', scenario: 's', component: 'webhook endpoint',
  likelihood: 4, impact: 4, severity: 'High', votes: 3, samples: 3, grounding: 'supported', confidence: 1, state: 'accepted', origin: 'agent',
  citations: [{ factId, quote: 'Refund webhook' }], mappings: [{ framework: 'CWE', refId: 'CWE-20' }], plainLanguage: 'Someone who resends a refund webhook gets the refund paid again.', ...over,
});
const req = (t: Threat, issue: JiraIssue, over: Partial<Requirement> = {}): Requirement => ({
  id: `req_${t.id}`, threatId: t.id, issueId: issue.id, issueKey: issue.key, title: 'Deduplicate webhook events', criteria: [{ given: 'g', when: 'w', then: 't' }], asvsIds: [], severity: 'High', status: 'Open', ...over,
});

async function save(t: ReturnType<typeof coreDeps>, issue: JiraIssue, threats: (reviewId: string, factId: string) => Threat[], o: { review?: Partial<Review>; facts?: ContextFact[] } = {}) {
  const r = review(issue, o.review);
  await t.deps.reviews.create(r);
  const facts = o.facts ?? [fact(issue.id)];
  await t.deps.reviews.saveFacts(r.id, facts);
  const list = threats(r.id, facts[0]!.id);
  await t.deps.reviews.saveThreats(r.id, list, []);
  return { review: r, threats: list };
}

/** PAY-7 under review, with a site history: an incident, and the same threat verified, accepted, dismissed and left open elsewhere. */
async function site(o: { search?: (jql: string, max: number) => JiraIssue[] } = {}) {
  const t = coreDeps({ issues: [PAY7, ...Object.values(items)], now: NOW });
  const searches: Array<{ jql: string; max: number }> = [];
  t.jira.search = async (jql, _fields, max) => (searches.push({ jql, max }), ok(o.search ? o.search(jql, max) : [items.INC7, items.INC8]));
  const current = await save(t, PAY7, (id, f) => [threat(id, f), threat(id, f, { id: 'thr_low', severity: 'Low', stride: 'Repudiation', title: 'No audit trail for refunds', plainLanguage: 'Nobody can tell who refunded what.', mappings: [] })]);
  const p3 = await save(t, items.PAY3, (id, f) => [threat(id, f, { title: 'Replayed refund webhook pays duplicate refunds' })]);
  await t.deps.requirements.upsert(req(p3.threats[0]!, items.PAY3, { status: 'Verified', evidence: { kind: 'pr', ref: 'https://bitbucket.org/acme/payments/pull-requests/41', attester: 'acc-x' } }));
  const p9 = await save(t, items.PAY9, (id, f) => [threat(id, f, { title: 'Duplicate refunds from replayed webhooks' })]);
  const r9 = req(p9.threats[0]!, items.PAY9, { status: 'AcceptedRisk' });
  await t.deps.requirements.upsert(r9);
  await appendLedger(t.deps.ledger, t.deps.clock, 'acceptance.requested', { acceptanceId: 'acc_9', requirementId: r9.id, issueId: items.PAY9.id, severity: 'High', expiresAt: '2027-01-31T00:00:00.000Z', needsApprover: 'none' }, 'acc-lead');
  await save(t, items.PAY4, (id, f) => [threat(id, f, { title: 'Refund webhooks replayed to issue duplicate refunds', state: 'dismissed', dismissReason: 'false_positive' })]);
  // Open elsewhere (no outcome to learn from), and an unrelated threat: neither is shown.
  const p5 = await save(t, items.PAY5, (id, f) => [threat(id, f, { title: 'Replayed refund webhooks double refunds' }), threat(id, f, { id: 'thr_other', stride: 'Spoofing', title: 'Forged password reset links', plainLanguage: 'A fake link signs someone in.' })]);
  await t.deps.requirements.upsert(req(p5.threats[0]!, items.PAY5));
  return { t, current, searches };
}

const v = { accountId: ME, issueId: PAY7.id };

describe('Seen before: what is shown', () => {
  it('lists the incident and the same threat verified (with its PR), risk-accepted (with expiry) and dismissed elsewhere, at most three', async () => {
    const { t, current } = await site();
    const dto = await seenBefore(t.deps, v, PAY7);
    const items_ = dto.threats[current.threats[0]!.id]!;
    expect(items_.map((i) => `${i.key} · ${i.text}`)).toEqual([
      'INC-7 · Incident · Duplicate refunds after webhook retries (Sev-2, payments)',
      'PAY-3 · same threat · Verified with PR #41',
      'PAY-9 · same threat · risk accepted until 2027-01-31',
    ]);
    expect(items_[0]!.reason).toBe('same component payments; shared words: duplicate, refund, webhook');
    expect(items_[1]).toMatchObject({ kind: 'verified', evidence: { label: 'PR #41', url: 'https://bitbucket.org/acme/payments/pull-requests/41' } });
    expect(items_[1]!.reason).toMatch(/^same STRIDE category \(Tampering\); same asset \(webhook endpoint\); shared words: /);
    expect(items_[2]).toMatchObject({ kind: 'accepted', until: '2027-01-31' });
    // A Low threat that matches nothing gets no entry; the unrelated incident matches nothing.
    expect(dto.threats.thr_low).toBeUndefined();
    expect(JSON.stringify(dto)).not.toContain('INC-8');
    expect(JSON.stringify(dto)).not.toContain('PAY-5');
    // The blocking (High) threat happened before as an incident: the headline names it.
    expect(dto.happenedBefore).toEqual({ key: 'INC-7', summary: 'Duplicate refunds after webhook retries', threatId: current.threats[0]!.id });
    expect(dto.partial).toBeUndefined();
  });

  it('a false-positive dismissal shows when there is room', async () => {
    const { t, current } = await site({ search: () => [] });
    const dto = await seenBefore(t.deps, v, PAY7);
    expect(dto.threats[current.threats[0]!.id]!.map((i) => `${i.key} · ${i.text}`)).toEqual([
      'PAY-3 · same threat · Verified with PR #41',
      'PAY-9 · same threat · risk accepted until 2027-01-31',
      'PAY-4 · same threat · dismissed as a false positive',
    ]);
    expect(dto.happenedBefore).toBeNull();
  });

  it('a threat below the blocking level with an incident does not reach the headline', async () => {
    const { t } = await site();
    await t.deps.config.setSite({ ...(await t.deps.config.site() as { ok: true; value: import('@threatline/shared').SitePolicy }).value, blockAtOrAbove: 'Critical' });
    expect((await seenBefore(t.deps, v, PAY7)).happenedBefore).toBeNull();
  });

  it('nothing before the review is ready, and nothing when nothing matches', async () => {
    const t = coreDeps({ issues: [PAY7], now: NOW });
    await save(t, PAY7, (id, f) => [threat(id, f)], { review: { status: 'awaiting_agent' } });
    expect(await seenBefore(t.deps, v, PAY7)).toEqual({ threats: {}, happenedBefore: null });
    const empty = await site({ search: () => [] });
    for (const id of ['rev_10003', 'rev_10009', 'rev_10004', 'rev_10005']) await empty.t.deps.reviews.saveThreats(id, [], []);
    expect(await seenBefore(empty.t.deps, v, PAY7)).toEqual({ threats: {}, happenedBefore: null });
  });
});

describe('Seen before: permissions (only what the viewer can open)', () => {
  it('drops work items and incidents the viewer cannot browse, and never mentions them', async () => {
    const { t, current } = await site();
    t.jira.canBrowse = async (_a, id) => ok(id !== items.INC7.id && id !== items.PAY3.id);
    const dto = await seenBefore(t.deps, v, PAY7);
    const text = JSON.stringify(dto);
    expect(text).not.toContain('INC-7');
    expect(text).not.toContain('Duplicate refunds after webhook retries');
    expect(text).not.toContain('PAY-3');
    expect(dto.threats[current.threats[0]!.id]!.map((i) => i.key)).toEqual(['PAY-9', 'PAY-4']);
    expect(dto.happenedBefore).toBeNull();
  });

  it('asks Jira as the viewer, in one permission check for the batch', async () => {
    const { t } = await site();
    const browsable = vi.spyOn(t.jira, 'browsable');
    await seenBefore(t.deps, v, PAY7);
    expect(browsable).toHaveBeenCalledTimes(1);
    expect(browsable.mock.calls[0]![0]).toBe(ME);
    expect(new Set(browsable.mock.calls[0]![1])).toEqual(new Set([items.INC7.id, items.PAY3.id, items.PAY9.id, items.PAY4.id]));
  });

  it('a same-threat item whose threat cites only a page the viewer cannot read is not shown (as on that work item’s panel)', async () => {
    const { t, current } = await site();
    const page = normalizeFact({ sourceAri: 'ari:cloud:confluence:e2e:page/900', sourceType: 'confluence_page', title: 'Payments design', url: '', text: 'Refund webhook', version: '1', trusted: false, origin: 'rest' });
    await t.deps.reviews.saveFacts('rev_10003', [page]);
    await t.deps.reviews.saveThreats('rev_10003', [threat('rev_10003', page.id, { title: 'Replayed refund webhook pays duplicate refunds' })], []);
    t.deps.confluence = { canRead: async () => ok(false) } as unknown as typeof t.deps.confluence;
    const dto = await seenBefore(t.deps, v, PAY7);
    expect(dto.threats[current.threats[0]!.id]!.map((i) => i.key)).toEqual(['INC-7', 'PAY-9', 'PAY-4']);
    t.deps.confluence = { canRead: async () => ok(true) } as unknown as typeof t.deps.confluence;
    expect((await seenBefore(t.deps, v, PAY7)).threats[current.threats[0]!.id]!.map((i) => i.key)).toEqual(['INC-7', 'PAY-3', 'PAY-9']);
  });

  it('fails closed: when the permission check cannot be made, nothing is shown', async () => {
    const { t } = await site();
    t.jira.browsable = async () => err(appError('upstream', 'jira down'));
    expect(await seenBefore(t.deps, v, PAY7)).toEqual({ threats: {}, happenedBefore: null, partial: true });
  });

  it('only the threats this viewer can see on this work item get history', async () => {
    const { t } = await site();
    const page = normalizeFact({ sourceAri: 'ari:cloud:confluence:e2e:page/901', sourceType: 'confluence_page', title: 'Secret design', url: '', text: 'x', version: '1', trusted: false, origin: 'rest' });
    await t.deps.reviews.saveFacts('rev_10042', [page]);
    await t.deps.reviews.saveThreats('rev_10042', [threat('rev_10042', page.id)], []);
    t.deps.confluence = { canRead: async () => ok(false) } as unknown as typeof t.deps.confluence;
    expect(await seenBefore(t.deps, v, PAY7)).toEqual({ threats: {}, happenedBefore: null });
  });

  it('panel.memory refuses a viewer who cannot browse the work item, and panel.status is untouched', async () => {
    const { t } = await site();
    const before = await panelStatus(t.deps, v);
    t.jira.canBrowse = async () => ok(false);
    expect(await panelMemory(t.deps, v)).toEqual({ error: 'not_found' });
    t.jira.canBrowse = async () => ok(true);
    const dto = await panelMemory(t.deps, v);
    expect('threats' in dto && Object.keys(dto.threats).length).toBe(1);
    expect(await panelStatus(t.deps, v)).toEqual(before);
    expect(before).not.toHaveProperty('seenBefore');
  });
});

describe('Seen before: bounds and caching', () => {
  it('reads bounded: two incident searches of at most 25 and 50, in the last 365 days, and capped review and threat reads', async () => {
    const { t, searches } = await site();
    const updatedSince = vi.spyOn(t.deps.reviews, 'updatedSince');
    const threatsFor = vi.spyOn(t.deps.reviews, 'threatsFor');
    const forIssues = vi.spyOn(t.deps.requirements, 'forIssues');
    await seenBefore(t.deps, v, PAY7);
    expect(searches.map((s) => s.max).sort((a, b) => a - b)).toEqual([MEMORY_LIMITS.incidentsNearby, MEMORY_LIMITS.incidentsRecent]);
    expect(searches.every((s) => /created >= -365d/.test(s.jql) && /key != "PAY-7"/.test(s.jql) && /labels in \("incident"\) OR issuetype in \("Incident"\)/.test(s.jql))).toBe(true);
    expect(searches.some((s) => /issue in linkedIssues\("PAY-7"\) OR \(project = "PAY" AND component in \("payments"\)\)/.test(s.jql))).toBe(true);
    expect(updatedSince).toHaveBeenCalledWith('ready', '2025-11-24T12:00:00.000Z', MEMORY_LIMITS.reviews);
    expect(threatsFor.mock.calls[0]![0]).not.toContain('rev_10042');
    expect(threatsFor.mock.calls[0]![2]).toBe(MEMORY_LIMITS.threatRows);
    expect(forIssues.mock.calls[0]![0].length).toBeLessThanOrEqual(MEMORY_LIMITS.outcomeItems);
  });

  it('retries the incident search on labels alone when Jira refuses the work type', async () => {
    const { t, searches } = await site();
    t.jira.search = async (jql, _f, max) => (searches.push({ jql, max }), /issuetype/.test(jql) ? err(appError('validation', 'no such type')) : ok([items.INC7]));
    const dto = await seenBefore(t.deps, v, PAY7);
    expect(Object.values(dto.threats)[0]![0]!.key).toBe('INC-7');
    expect(searches.filter((s) => !/issuetype/.test(s.jql))).toHaveLength(2);
  });

  it('caches the matches per work item for 15 minutes, recomputes after, and for a new revision', async () => {
    const { t, searches } = await site();
    await seenBefore(t.deps, v, PAY7);
    await seenBefore(t.deps, { accountId: 'acc-other', issueId: PAY7.id }, PAY7);
    expect(searches).toHaveLength(2);
    t.clock.advance(MEMORY_LIMITS.cacheMs + 1);
    await seenBefore(t.deps, v, PAY7);
    expect(searches).toHaveLength(4);
    await t.deps.reviews.create(review(PAY7, { id: 'rev_10042_2', revision: 2 }));
    await t.deps.reviews.saveFacts('rev_10042_2', [fact(PAY7.id)]);
    await t.deps.reviews.saveThreats('rev_10042_2', [threat('rev_10042_2', fact(PAY7.id).id, { id: 'thr_new' })], []);
    const dto = await seenBefore(t.deps, v, PAY7);
    expect(searches).toHaveLength(6);
    expect(dto.threats.thr_new?.[0]?.key).toBe('INC-7');
  });

  it('still filters per viewer when the matches come from the cache', async () => {
    const { t } = await site();
    await seenBefore(t.deps, v, PAY7);
    t.jira.canBrowse = async (_a, id) => ok(id !== items.INC7.id);
    expect(JSON.stringify(await seenBefore(t.deps, v, PAY7))).not.toContain('INC-7');
  });

  it('a failed search is shown as partial and not cached', async () => {
    const { t, searches } = await site();
    t.jira.search = async (jql, _f, max) => (searches.push({ jql, max }), err(appError('upstream', 'jira down')));
    const dto = await seenBefore(t.deps, v, PAY7);
    expect(dto.partial).toBe(true);
    expect(Object.values(dto.threats)[0]!.map((i) => i.key)).toEqual(['PAY-3', 'PAY-9', 'PAY-4']);
    await seenBefore(t.deps, v, PAY7);
    expect(searches.length).toBeGreaterThan(2);
  });
});

describe('incident severity label', () => {
  it('reads a sev label or a priority named like one, and a high priority by name', () => {
    expect(incidentSeverity({ labels: ['incident', 'SEV-2'] })).toBe('Sev-2');
    expect(incidentSeverity({ labels: ['sev1'] })).toBe('Sev-1');
    expect(incidentSeverity({ labels: [], priority: 'P1 - Critical' })).toBe('P1');
    expect(incidentSeverity({ labels: [], priority: 'Sev 3' })).toBe('Sev-3');
    expect(incidentSeverity({ labels: [], priority: 'Highest' })).toBe('Highest');
    expect(incidentSeverity({ labels: [], priority: 'Medium' })).toBeNull();
    expect(incidentSeverity({ labels: [] })).toBeNull();
  });
});

describe('explain-threat includes Seen before, as the calling user', () => {
  const ctx = (accountId: string) => ({ context: { accountId } });
  it('adds the threat’s history with links, filtered by what the caller can open', async () => {
    const { t } = await site();
    const out = await explainThreat({ issueKey: 'PAY-7', threatId: 'T-1', ...ctx(ME) }, t.deps);
    if ('error' in out) throw new Error(out.error);
    expect(out.seenBefore.map((s) => s.line)).toEqual([
      'INC-7 · Incident · Duplicate refunds after webhook retries (Sev-2, payments)',
      'PAY-3 · same threat · Verified with PR #41',
      'PAY-9 · same threat · risk accepted until 2027-01-31',
    ]);
    expect(out.seenBefore[0]).toMatchObject({ key: 'INC-7', url: 'https://one-atlas-mefc.atlassian.net/browse/INC-7', reason: expect.stringMatching(/same component payments/) });
    await t.deps.state.delete('memory:v1:10042');
    t.jira.canBrowse = async (_a, id) => ok(id !== items.INC7.id);
    const hidden = await explainThreat({ issueKey: 'PAY-7', threatId: 'T-1', ...ctx('acc-other') }, t.deps);
    if ('error' in hidden) throw new Error(hidden.error);
    expect(JSON.stringify(hidden)).not.toContain('INC-7');
  });
});

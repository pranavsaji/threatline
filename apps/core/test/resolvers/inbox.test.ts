import { describe, expect, it } from 'vitest';
import { ok, type ContextFact, type Requirement, type Review, type Threat } from '@threatline/shared';
import { inboxDecide, inboxList, type InboxDto } from '../../src/resolvers/inbox.js';
import { buildInbox, INBOX_DECIDE_MAX, INBOX_SCAN } from '../../src/services/inbox-service.js';
import { resolverTable } from '../../src/resolvers/table.js';
import { coreDeps, jiraIssue } from '../support/core-deps.js';

const CHAMPIONS = 'threatline-security-champions';
const CHAMP = 'acc-champ';
const ADMIN = 'acc-admin';
const DEV = 'acc-dev';

const review = (o: Partial<Review> & { id: string; issueId: string; issueKey: string }): Review => ({
  revision: 1, status: 'ready', contextHash: 'h', riskScore: 40, partial: false, promptVersion: 'v1', modelIds: ['claude-x'], samplesExpected: 3, samplesReceived: 3,
  tokensIn: 0, tokensOut: 0, createdAt: '2026-11-10T00:00:00.000Z', updatedAt: '2026-11-10T00:00:00.000Z', ...o,
});
const fact = (id: string, o: Partial<ContextFact> = {}): ContextFact => ({
  id, sourceAri: `ari:cloud:jira::issue/${id.split('_')[1]}`, sourceType: 'jira_issue', title: 'Work item', url: '', excerpt: 'text', trustLevel: 'untrusted', version: '1',
  injectionSuspected: false, injectionReasons: [], origin: 'rest', ...o,
});
const pageFact = (id: string, page: string, o: Partial<ContextFact> = {}) => fact(id, { sourceAri: `ari:cloud:confluence::page/${page}`, sourceType: 'confluence_page', title: `Page ${page}`, ...o });
const threat = (o: Partial<Threat> & { id: string; reviewId: string; factId: string }): Threat => {
  const { factId, ...rest } = o;
  return {
    stride: 'Spoofing', title: 'Forged refund webhooks', scenario: 'An attacker posts a fake refund event.', component: 'webhook endpoint', likelihood: 4, impact: 4, severity: 'High',
    votes: 3, samples: 3, grounding: 'supported', confidence: 0.9, state: 'needs_human', origin: 'agent', citations: [{ factId, quote: 'Public webhook' }], mappings: [],
    plainLanguage: 'Anyone could fake a refund.', ...rest,
  };
};

/**
 * A site with:
 *  PAY-1 (101): two needs-human High threats; the verifier says the second repeats the first. One accepted threat.
 *  PAY-2 (102), older: a Critical needs-human threat resting on a page flagged for injection, similar to PAY-1's;
 *    and a needs-human threat citing only a page the champion cannot read (hidden).
 *  PAY-3 (103): a Medium needs-human threat with weak evidence.
 *  OPS-1 (201): needs-human, but OPS is not a Threatline project.  PAY-4 (104): the champion cannot browse it.
 *  PAY-5 (105): its latest review is still in progress.  PAY-6 (106): needs-human only on a superseded revision.
 */
async function site() {
  const issues = [
    jiraIssue({ id: '101', key: 'PAY-1', summary: 'Refund webhook' }),
    jiraIssue({ id: '102', key: 'PAY-2', summary: 'Partner refunds' }),
    jiraIssue({ id: '103', key: 'PAY-3', summary: 'Card vault logging' }),
    jiraIssue({ id: '104', key: 'PAY-4', summary: 'Secret project' }),
    jiraIssue({ id: '105', key: 'PAY-5', summary: 'In flight' }),
    jiraIssue({ id: '106', key: 'PAY-6', summary: 'Re-reviewed' }),
    jiraIssue({ id: '201', key: 'OPS-1', summary: 'Ops thing', project: { id: '2', key: 'OPS' } }),
  ];
  const t = coreDeps({ issues, now: '2026-11-15T12:00:00.000Z' });
  const groups: Record<string, string[]> = { [CHAMP]: [CHAMPIONS] };
  t.jira.groupsOf = async (id) => ok(groups[id] ?? []);
  t.jira.isAdmin = async (id) => ok(id === ADMIN);
  t.jira.canBrowse = async (_acc, id) => ok(id !== '104' && id !== 'PAY-4');
  t.deps.confluence = { canRead: async (id: string) => ok(id === '7') } as never;
  const { reviews } = t.deps;
  const add = async (r: Review, facts: ContextFact[], threats: Threat[]) => {
    await reviews.create(r);
    await reviews.saveFacts(r.id, facts);
    await reviews.saveThreats(r.id, threats, []);
  };
  await add(review({ id: 'rev_1', issueId: '101', issueKey: 'PAY-1', createdAt: '2026-11-12T00:00:00.000Z' }), [fact('f_101')], [
    threat({ id: 'thr_a', reviewId: 'rev_1', factId: 'f_101', verification: { keep: false, reason: 'The quote does not say the webhook is unsigned.' } }),
    threat({ id: 'thr_b', reviewId: 'rev_1', factId: 'f_101', title: 'Refund events replayed later', verification: { keep: false, reason: 'Repeats “Forged refund webhooks”', duplicateOf: 'thr_a' } }),
    threat({ id: 'thr_ok', reviewId: 'rev_1', factId: 'f_101', state: 'accepted', title: 'Unrelated', stride: 'Tampering' }),
  ]);
  await add(review({ id: 'rev_2', issueId: '102', issueKey: 'PAY-2', createdAt: '2026-11-08T00:00:00.000Z' }), [fact('f_102'), pageFact('p_7', '7', { injectionSuspected: true, injectionReasons: ['ai_directive'] }), pageFact('p_8', '8')], [
    threat({ id: 'thr_c', reviewId: 'rev_2', factId: 'p_7', severity: 'Critical', likelihood: 5, impact: 5, component: 'partner refund API' }),
    threat({ id: 'thr_hidden', reviewId: 'rev_2', factId: 'p_8', title: 'Secret roadmap leak', stride: 'InformationDisclosure' }),
  ]);
  await add(review({ id: 'rev_3', issueId: '103', issueKey: 'PAY-3', createdAt: '2026-11-11T00:00:00.000Z' }), [fact('f_103')], [
    threat({ id: 'thr_d', reviewId: 'rev_3', factId: 'f_103', title: 'Card numbers written to logs', stride: 'InformationDisclosure', severity: 'Medium', likelihood: 3, impact: 3, grounding: 'weak' }),
  ]);
  await add(review({ id: 'rev_ops', issueId: '201', issueKey: 'OPS-1' }), [fact('f_201')], [threat({ id: 'thr_ops', reviewId: 'rev_ops', factId: 'f_201', severity: 'Critical' })]);
  await add(review({ id: 'rev_4', issueId: '104', issueKey: 'PAY-4' }), [fact('f_104')], [threat({ id: 'thr_nb', reviewId: 'rev_4', factId: 'f_104', severity: 'Critical' })]);
  await add(review({ id: 'rev_5', issueId: '105', issueKey: 'PAY-5', status: 'modeling' }), [fact('f_105')], [threat({ id: 'thr_wip', reviewId: 'rev_5', factId: 'f_105' })]);
  await add(review({ id: 'rev_6a', issueId: '106', issueKey: 'PAY-6', revision: 1 }), [fact('f_106')], [threat({ id: 'thr_old', reviewId: 'rev_6a', factId: 'f_106' })]);
  await add(review({ id: 'rev_6b', issueId: '106', issueKey: 'PAY-6', revision: 2 }), [fact('f_106')], [threat({ id: 'thr_new', reviewId: 'rev_6b', factId: 'f_106', state: 'accepted' })]);
  t.pushed.length = 0;
  return t;
}

const list = async (t: Awaited<ReturnType<typeof site>>, accountId = CHAMP, payload: Record<string, unknown> = {}) => (await inboxList(t.deps, { accountId }, payload)) as InboxDto;
const rowsOf = (dto: InboxDto) => dto.clusters.flatMap((c) => c.rows);
const threatOf = async (t: Awaited<ReturnType<typeof site>>, reviewId: string, id: string) => ((await t.deps.reviews.threats(reviewId)) as { ok: true; value: Threat[] }).value.find((x) => x.id === id)!;

describe('champion inbox: who can open it', () => {
  it('only security champions and Jira admins (server-checked); everyone else is forbidden', async () => {
    const t = await site();
    expect(await inboxList(t.deps, { accountId: DEV }, {})).toMatchObject({ error: 'forbidden' });
    expect(await inboxList(t.deps, { accountId: '' }, {})).toMatchObject({ error: 'not_found' });
    expect(rowsOf(await list(t, CHAMP)).length).toBeGreaterThan(0);
    expect(rowsOf(await list(t, ADMIN)).length).toBeGreaterThan(0);
  });

  it('fails closed when the role lookup fails', async () => {
    const t = await site();
    t.jira.groupsOf = async () => ({ ok: false, error: { code: 'upstream', message: 'down' } });
    t.jira.isAdmin = async () => ({ ok: false, error: { code: 'upstream', message: 'down' } });
    expect(await inboxList(t.deps, { accountId: CHAMP }, {})).toMatchObject({ error: 'forbidden' });
    expect(await inboxDecide(t.deps, { accountId: CHAMP }, { decision: 'confirm', items: [{ issueId: '101', threatId: 'thr_a' }] })).toMatchObject({ error: 'forbidden' });
  });

  it('is registered in the resolver table', () => {
    const table = resolverTable({ enricher: () => ({ enrich: async () => ok({ facts: [], partial: false, reasons: [] }) }), signingKeysReady: async () => true });
    expect(typeof table['inbox.list']).toBe('function');
    expect(typeof table['inbox.decide']).toBe('function');
  });
});

describe('champion inbox: what it lists', () => {
  it('every open needs-human threat on the latest settled review in enabled projects the viewer can browse, most severe then oldest first', async () => {
    const t = await site();
    const dto = await list(t);
    const rows = rowsOf(dto);
    expect(rows.map((r) => r.threatId)).toEqual(['thr_c', 'thr_a', 'thr_b', 'thr_d']);
    expect(dto.total).toBe(4);
    expect(dto.cursor).toBeNull();
    expect(dto.truncated).toBe(false);
    const c = rows[0]!;
    expect(c).toMatchObject({ issueId: '102', issueKey: 'PAY-2', summary: 'Partner refunds', url: 'https://one-atlas-mefc.atlassian.net/browse/PAY-2', title: 'Forged refund webhooks', stride: 'Spoofing', severity: 'Critical', raisedAt: '2026-11-08T00:00:00.000Z', reviewId: 'rev_2' });
  });

  it('security: never shows a threat resting only on sources the viewer cannot open (same rule as the panel); it is only counted', async () => {
    const t = await site();
    const dto = await list(t);
    expect(JSON.stringify(dto)).not.toContain('Secret roadmap');
    expect(JSON.stringify(dto)).not.toContain('PAY-4');
    expect(JSON.stringify(dto)).not.toContain('OPS-1');
    expect(dto.hidden).toBe(1);
    // A failed permission check hides too (fail closed).
    t.deps.confluence = { canRead: async () => ({ ok: false, error: { code: 'upstream', message: 'x' } }) } as never;
    expect(rowsOf(await list(t)).map((r) => r.threatId)).not.toContain('thr_c');
  });

  it('says why each threat needs a person: verifier doubt, injection-flagged text, duplicate, weak evidence', async () => {
    const t = await site();
    const by = new Map(rowsOf(await list(t)).map((r) => [r.threatId, r]));
    expect(by.get('thr_a')!.reasons).toEqual([{ code: 'verifier_doubt', message: 'The verifier doubted it: The quote does not say the webhook is unsigned.' }]);
    expect(by.get('thr_b')!.reasons.map((r) => r.code)).toEqual(['duplicate']);
    expect(by.get('thr_b')!.reasons[0]!.message).toMatch(/repeats “Forged refund webhooks”/);
    expect(by.get('thr_b')!.duplicateOf).toEqual({ threatId: 'thr_a', title: 'Forged refund webhooks' });
    expect(by.get('thr_c')!.reasons.map((r) => r.code)).toEqual(['injection']);
    expect(by.get('thr_d')!.reasons.map((r) => r.code)).toEqual(['weak_evidence']);
  });

  it('groups threats the verifier marked as duplicates and similar threats across work items, so a champion decides a cluster at once', async () => {
    const t = await site();
    const dto = await list(t);
    expect(dto.clusters.map((c) => [c.kind, c.rows.map((r) => r.threatId)])).toEqual([
      ['similar', ['thr_c', 'thr_a', 'thr_b']],
      ['single', ['thr_d']],
    ]);
    // Without the cross-work-item match, the verifier's duplicate still groups PAY-1's two threats.
    await t.deps.reviews.updateThreat('thr_c', { title: 'Partner API keys shared by email', stride: 'InformationDisclosure' });
    const again = await list(t);
    expect(again.clusters.map((c) => [c.kind, c.rows.map((r) => r.threatId)])).toEqual([
      ['single', ['thr_c']],
      ['duplicate', ['thr_a', 'thr_b']],
      ['single', ['thr_d']],
    ]);
  });

  it('pages in bounded chunks without splitting a cluster, with the total for the badge', async () => {
    const t = await site();
    const first = await list(t, CHAMP, { pageSize: 2 });
    expect(first.clusters.map((c) => c.rows.length)).toEqual([3]);
    expect(first.total).toBe(4);
    expect(first.cursor).toBe(1);
    const second = await list(t, CHAMP, { cursor: first.cursor, pageSize: 2 });
    expect(rowsOf(second).map((r) => r.threatId)).toEqual(['thr_d']);
    expect(second.cursor).toBeNull();
    expect(await inboxList(t.deps, { accountId: CHAMP }, { cursor: -1 })).toMatchObject({ error: 'validation' });
    expect(await inboxList(t.deps, { accountId: CHAMP }, { pageSize: 10_000 })).toMatchObject({ error: 'validation' });
  });

  it('reads through the bounded, indexed needs-human query, and says when it was cut off', async () => {
    const t = await site();
    const calls: number[] = [];
    const real = t.deps.reviews.needsHuman.bind(t.deps.reviews);
    t.deps.reviews.needsHuman = async (limit) => (calls.push(limit), real(limit));
    t.deps.reviews.byStatus = async () => {
      throw new Error('no full scans');
    };
    await list(t);
    expect(calls).toEqual([INBOX_SCAN]);
    expect(calls[0]).toBeLessThanOrEqual(500);
    const cut = await buildInbox(t.deps, CHAMP, { scan: 3 });
    expect(cut.ok && cut.value.truncated).toBe(true);
    expect(cut.ok && cut.value.total).toBeLessThanOrEqual(3);
  });

  it('is unavailable (not empty) when the store fails', async () => {
    const t = await site();
    t.deps.reviews.needsHuman = async () => ({ ok: false, error: { code: 'internal', message: 'db' } });
    expect(await inboxList(t.deps, { accountId: CHAMP }, {})).toMatchObject({ error: 'unavailable' });
  });
});

describe('champion inbox: decisions', () => {
  const reqs = async (t: Awaited<ReturnType<typeof site>>, issueId: string) => ((await t.deps.requirements.forIssue(issueId)) as { ok: true; value: Requirement[] }).value;

  it('confirm accepts the threat, which becomes a requirement exactly as in the panel, ledgered', async () => {
    const t = await site();
    const out = await inboxDecide(t.deps, { accountId: CHAMP }, { decision: 'confirm', items: [{ issueId: '101', threatId: 'thr_a' }] });
    expect(out).toEqual({ results: [{ issueId: '101', threatId: 'thr_a', ok: true, state: 'accepted' }], decided: 1, failed: 0 });
    expect((await threatOf(t, 'rev_1', 'thr_a')).state).toBe('accepted');
    expect((await reqs(t, '101')).some((r) => r.threatId === 'thr_a')).toBe(true);
    const led = await t.deps.ledger.ofTypes(['threat.triaged']);
    expect(led.ok && led.value.map((r) => [r.actor, r.payload.threatId, r.payload.op, r.payload.from])).toEqual([[CHAMP, 'thr_a', 'accept', 'needs_human']]);
    expect(t.verdicts._written.has('101')).toBe(true);
    expect(t.pushed).toContainEqual({ kind: 'propagate', issueId: '101' });
    expect(rowsOf(await list(t)).map((r) => r.threatId)).not.toContain('thr_a');
  });

  it('a dismissal needs a reason; with one it is ledgered with the reason and note', async () => {
    const t = await site();
    expect(await inboxDecide(t.deps, { accountId: CHAMP }, { decision: 'dismiss', items: [{ issueId: '103', threatId: 'thr_d' }] })).toMatchObject({ error: 'validation' });
    expect(await inboxDecide(t.deps, { accountId: CHAMP }, { decision: 'dismiss', reason: 'because', items: [{ issueId: '103', threatId: 'thr_d' }] })).toMatchObject({ error: 'validation' });
    expect((await threatOf(t, 'rev_3', 'thr_d')).state).toBe('needs_human');
    const out = await inboxDecide(t.deps, { accountId: CHAMP }, { decision: 'dismiss', reason: 'already_mitigated', note: 'Vault masks PANs', items: [{ issueId: '103', threatId: 'thr_d' }] });
    expect(out).toMatchObject({ decided: 1, failed: 0 });
    expect(await threatOf(t, 'rev_3', 'thr_d')).toMatchObject({ state: 'dismissed', dismissReason: 'already_mitigated' });
    const led = await t.deps.ledger.ofTypes(['threat.triaged']);
    expect(led.ok && led.value[0]!.payload).toMatchObject({ threatId: 'thr_d', op: 'dismiss', reason: 'already_mitigated', note: 'Vault masks PANs', issueKey: 'PAY-3' });
  });

  it('bulk is N individual decisions, each authorised and validated, with partial failures reported per item', async () => {
    const t = await site();
    const items = [
      { issueId: '102', threatId: 'thr_c' },
      { issueId: '101', threatId: 'thr_a' },
      { issueId: '104', threatId: 'thr_nb' }, // cannot browse
      { issueId: '102', threatId: 'thr_hidden' }, // rests only on a page the champion cannot read
      { issueId: '101', threatId: 'thr_ok' }, // not waiting for a champion
      { issueId: '105', threatId: 'thr_wip' }, // review still running
      { issueId: '201', threatId: 'thr_ops' }, // not a Threatline project
      { issueId: '101', threatId: 'thr_c' }, // wrong work item for the threat
    ];
    const out = (await inboxDecide(t.deps, { accountId: CHAMP }, { decision: 'dismiss', reason: 'duplicate', items })) as { results: Array<{ threatId: string; ok: boolean; error?: string }>; decided: number; failed: number };
    expect(out.results.map((r) => [r.threatId, r.ok ? 'ok' : r.error])).toEqual([
      ['thr_c', 'ok'],
      ['thr_a', 'ok'],
      ['thr_nb', 'not_found'],
      ['thr_hidden', 'not_found'],
      ['thr_ok', 'conflict'],
      ['thr_wip', 'conflict'],
      ['thr_ops', 'not_found'],
      ['thr_c', 'not_found'],
    ]);
    expect(out).toMatchObject({ decided: 2, failed: 6 });
    expect((await threatOf(t, 'rev_4', 'thr_nb')).state).toBe('needs_human');
    expect((await threatOf(t, 'rev_2', 'thr_hidden')).state).toBe('needs_human');
    expect((await threatOf(t, 'rev_ops', 'thr_ops')).state).toBe('needs_human');
    const led = await t.deps.ledger.ofTypes(['threat.triaged']);
    expect(led.ok && led.value.map((r) => r.payload.threatId)).toEqual(['thr_c', 'thr_a']);
  });

  it('only champions and admins decide; requests are bounded and checked', async () => {
    const t = await site();
    expect(await inboxDecide(t.deps, { accountId: DEV }, { decision: 'confirm', items: [{ issueId: '101', threatId: 'thr_a' }] })).toMatchObject({ error: 'forbidden' });
    expect((await threatOf(t, 'rev_1', 'thr_a')).state).toBe('needs_human');
    expect(await inboxDecide(t.deps, { accountId: ADMIN }, { decision: 'confirm', items: [{ issueId: '101', threatId: 'thr_a' }] })).toMatchObject({ decided: 1 });
    const many = Array.from({ length: INBOX_DECIDE_MAX + 1 }, (_, i) => ({ issueId: '101', threatId: `thr_${i}` }));
    expect(await inboxDecide(t.deps, { accountId: CHAMP }, { decision: 'confirm', items: many })).toMatchObject({ error: 'validation' });
    expect(await inboxDecide(t.deps, { accountId: CHAMP }, { decision: 'confirm', items: [] })).toMatchObject({ error: 'validation' });
    expect(await inboxDecide(t.deps, { accountId: CHAMP }, { decision: 'confirm', items: [{ issueId: 'PAY-1', threatId: 'thr_b' }] })).toMatchObject({ error: 'validation' });
    expect(await inboxDecide(t.deps, { accountId: CHAMP }, { decision: 'escalate', items: [{ issueId: '101', threatId: 'thr_b' }] })).toMatchObject({ error: 'validation' });
    // The same threat twice in one request is decided once.
    expect(await inboxDecide(t.deps, { accountId: CHAMP }, { decision: 'confirm', items: [{ issueId: '101', threatId: 'thr_b' }, { issueId: '101', threatId: 'thr_b' }] })).toMatchObject({ error: 'validation' });
  });

  it('a decision that could not be saved fails for that item only, and the ledger marks it failed', async () => {
    const t = await site();
    const real = t.deps.reviews.updateThreat.bind(t.deps.reviews);
    t.deps.reviews.updateThreat = async (id, patch) => (id === 'thr_a' ? { ok: false, error: { code: 'internal', message: 'db' } } : real(id, patch));
    const out = await inboxDecide(t.deps, { accountId: CHAMP }, { decision: 'confirm', items: [{ issueId: '101', threatId: 'thr_a' }, { issueId: '103', threatId: 'thr_d' }] });
    expect(out).toMatchObject({ decided: 1, failed: 1, results: [{ threatId: 'thr_a', ok: false, error: 'unavailable' }, { threatId: 'thr_d', ok: true }] });
    const led = await t.deps.ledger.ofTypes(['threat.triaged', 'threat.triage_failed']);
    expect(led.ok && led.value.map((r) => [r.eventType, r.payload.threatId])).toEqual([
      ['threat.triaged', 'thr_a'],
      ['threat.triage_failed', 'thr_a'],
      ['threat.triaged', 'thr_d'],
    ]);
  });
});

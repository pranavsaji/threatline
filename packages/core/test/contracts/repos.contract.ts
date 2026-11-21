import { describe, expect, it } from 'vitest';
import type { Requirement, Review, Threat } from '@threatline/shared';
import { GENESIS_HASH } from '@threatline/crypto';
import { appendLedger } from '../../src/ledger.js';
import type { AttestationRepo, FeedbackRepo, IssueRepo, LedgerRepo, RequirementRepo, ReviewRepo, UsageRepo, TreeHeadRepo } from '../../src/ports.js';
import { fixedClock } from '../fakes/fixed-clock.js';

export interface RepoFactory {
  reviews(): Promise<ReviewRepo>;
  requirements(): Promise<RequirementRepo>;
  ledger(): Promise<LedgerRepo>;
  feedback(): Promise<FeedbackRepo>;
  issues(): Promise<IssueRepo>;
  attestations(): Promise<AttestationRepo>;
  usage(): Promise<UsageRepo>;
  treeHeads(): Promise<TreeHeadRepo>;
}

const review = (o: Partial<Review> = {}): Review => ({
  id: 'rev_1', issueId: '10001', issueKey: 'PROJ-1', revision: 1, status: 'awaiting_agent', contextHash: 'h1', riskScore: 0, partial: false,
  promptVersion: 'v1', modelIds: ['m1'], samplesExpected: 3, samplesReceived: 0, tokensIn: 0, tokensOut: 0,
  createdAt: '2026-11-15T00:00:00.000Z', updatedAt: '2026-11-15T00:00:00.000Z', ...o,
});
const threat = (o: Partial<Threat> = {}): Threat => ({
  id: 'thr_1', reviewId: 'rev_1', stride: 'Tampering', title: 'T', scenario: 's', component: 'c', likelihood: 3, impact: 4, severity: 'High',
  votes: 3, samples: 3, grounding: 'supported', confidence: 1, state: 'accepted', origin: 'agent', citations: [{ factId: 'f', quote: 'q' }],
  mappings: [{ framework: 'ASVS5', refId: 'V1.1.1' }], plainLanguage: 'p', ...o,
});
const req = (o: Partial<Requirement> = {}): Requirement => ({
  id: 'req_1', threatId: 'thr_1', issueId: '10001', issueKey: 'PROJ-1', title: 'R', criteria: [{ given: 'g', when: 'w', then: 't' }],
  asvsIds: ['V1.1.1'], severity: 'High', status: 'Open', ...o,
});

/** Behaviour every ReviewRepo/LedgerRepo/... implementation must share (memory fakes and SQL). */
export function repoContract(name: string, f: RepoFactory): void {
  describe(`${name} repository contract`, () => {
    it('reviews: create, latest, get, history, update, byStatus', async () => {
      const r = await f.reviews();
      await r.create(review());
      await r.create(review({ id: 'rev_2', revision: 2, status: 'ready', updatedAt: '2026-11-15T01:00:00.000Z' }));
      expect((await r.create(review())).ok).toBe(false);
      const latest = await r.latest('10001');
      expect(latest.ok && latest.value?.id).toBe('rev_2');
      expect((await r.latest('nope')).ok && (await r.latest('nope'))).toEqual({ ok: true, value: null });
      await r.update('rev_1', { status: 'agent_timeout', samplesReceived: 1 });
      const got = await r.get('rev_1');
      expect(got.ok && got.value).toMatchObject({ status: 'agent_timeout', samplesReceived: 1, modelIds: ['m1'], partial: false });
      const hist = await r.history('10001');
      expect(hist.ok && hist.value.map((x) => x.revision)).toEqual([1, 2]);
      const stale = await r.byStatus('agent_timeout', '2026-11-16T00:00:00.000Z');
      expect(stale.ok && stale.value.map((x) => x.id)).toEqual(['rev_1']);
    });

    it('reviews: facts, threats, discarded, samples and stages round-trip', async () => {
      const r = await f.reviews();
      await r.create(review());
      const fact = { id: 'f1', sourceAri: 'a', sourceType: 'jira_issue' as const, title: 't', url: 'u', excerpt: 'e', trustLevel: 'untrusted' as const, version: '1', injectionSuspected: false, injectionReasons: [], origin: 'rest' as const };
      await r.saveFacts('rev_1', [fact]);
      expect((await r.facts('rev_1')).ok && (await r.facts('rev_1'))).toEqual({ ok: true, value: [fact] });
      await r.saveThreats('rev_1', [threat(), threat({ id: 'thr_2', title: 'U' })], [{ title: 'x', reason: 'low_votes' }]);
      await r.saveThreats('rev_1', [threat()], [{ title: 'y', reason: 'schema' }]);
      const ts = await r.threats('rev_1');
      expect(ts.ok && ts.value.map((t) => t.id)).toEqual(['thr_1']);
      expect((await r.discarded('rev_1')).ok && (await r.discarded('rev_1'))).toEqual({ ok: true, value: [{ title: 'y', reason: 'schema' }] });
      await r.updateThreat('thr_1', { state: 'dismissed', dismissReason: 'false_positive' });
      const t2 = await r.threats('rev_1');
      expect(t2.ok && t2.value[0]).toMatchObject({ state: 'dismissed', dismissReason: 'false_positive', citations: [{ factId: 'f', quote: 'q' }] });
      expect((await r.updateThreat('missing', { state: 'accepted' })).ok).toBe(false);
      await r.saveSample('rev_1', 1, { failed: 'schema' });
      await r.saveSample('rev_1', 0, { schema: 'threatline.threatmodel.v1', issueKey: 'PROJ-1', threats: [] });
      // Race fix: a run number is taken once; a concurrent save of the same number conflicts instead of overwriting.
      const again = await r.saveSample('rev_1', 1, { failed: 'no_json' });
      expect(!again.ok && again.error.code).toBe('conflict');
      const s = await r.samples('rev_1');
      expect(s.ok && s.value).toEqual([{ schema: 'threatline.threatmodel.v1', issueKey: 'PROJ-1', threats: [] }, { failed: 'schema' }]);
      await r.saveStage('rev_1', 'extract', 'running');
      await r.saveStage('rev_1', 'extract', 'done', { sketch: { a: 1 } });
      expect((await r.stage('rev_1', 'extract')).ok && (await r.stage('rev_1', 'extract'))).toMatchObject({ ok: true, value: { status: 'done', checkpoint: { sketch: { a: 1 } } } });
      expect((await r.stage('rev_1', 'none')).ok && (await r.stage('rev_1', 'none'))).toEqual({ ok: true, value: null });
    });

    it('reviews: saveThreats refuses duplicate threat ids (conflict) and leaves the stored set as it was', async () => {
      const r = await f.reviews();
      await r.create(review());
      await r.saveThreats('rev_1', [threat(), threat({ id: 'thr_2', title: 'U' })], []);
      const dup = await r.saveThreats('rev_1', [threat({ title: 'new' }), threat({ id: 'thr_3' }), threat({ component: 'other' })], [{ title: 'z', reason: 'schema' }]);
      expect(!dup.ok && dup.error.code).toBe('conflict');
      const ts = await r.threats('rev_1');
      expect(ts.ok && ts.value.map((t) => [t.id, t.title])).toEqual([['thr_1', 'T'], ['thr_2', 'U']]);
      // Saving the same set again is idempotent.
      await r.saveThreats('rev_1', [threat({ id: 'thr_2', title: 'U' }), threat()], []);
      await r.saveThreats('rev_1', [threat({ id: 'thr_2', title: 'U' }), threat()], []);
      const again = await r.threats('rev_1');
      expect(again.ok && again.value.map((t) => t.id)).toEqual(['thr_2', 'thr_1']);
    });

    it('reviews: updatedSince lists one status updated in a window, newest first, bounded', async () => {
      const r = await f.reviews();
      await r.create(review({ id: 'rev_a', issueId: '1', status: 'failed', createdAt: '2026-11-15T09:00:00.000Z', updatedAt: '2026-11-15T09:00:00.000Z' }));
      await r.create(review({ id: 'rev_b', issueId: '2', status: 'failed', createdAt: '2026-11-15T11:10:00.000Z', updatedAt: '2026-11-15T11:20:00.000Z' }));
      await r.create(review({ id: 'rev_c', issueId: '3', status: 'failed', createdAt: '2026-11-15T11:30:00.000Z', updatedAt: '2026-11-15T11:40:00.000Z' }));
      await r.create(review({ id: 'rev_d', issueId: '4', status: 'ready', createdAt: '2026-11-15T11:30:00.000Z', updatedAt: '2026-11-15T11:45:00.000Z' }));
      const w = await r.updatedSince('failed', '2026-11-15T11:00:00.000Z', 10);
      expect(w.ok && w.value.map((x) => x.id)).toEqual(['rev_c', 'rev_b']);
      const one = await r.updatedSince('failed', '2026-11-15T11:00:00.000Z', 1);
      expect(one.ok && one.value.map((x) => x.id)).toEqual(['rev_c']);
    });

    it('reviews (scale): needsHuman lists needs-human threats on each work item’s latest review, most severe then oldest first, bounded', async () => {
      const r = await f.reviews();
      // Work item 1: revision 1 (superseded) and revision 2 (latest), each with a needs-human threat.
      await r.create(review({ id: 'rev_1a', issueId: '1', issueKey: 'A-1', revision: 1, status: 'ready', createdAt: '2026-11-10T00:00:00.000Z' }));
      await r.create(review({ id: 'rev_1b', issueId: '1', issueKey: 'A-1', revision: 2, status: 'ready', createdAt: '2026-11-12T00:00:00.000Z' }));
      await r.create(review({ id: 'rev_2', issueId: '2', issueKey: 'A-2', revision: 1, status: 'ready', createdAt: '2026-11-11T00:00:00.000Z' }));
      await r.create(review({ id: 'rev_3', issueId: '3', issueKey: 'A-3', revision: 1, status: 'ready', createdAt: '2026-11-09T00:00:00.000Z' }));
      await r.saveThreats('rev_1a', [threat({ id: 'thr_old', reviewId: 'rev_1a', state: 'needs_human' })], []);
      await r.saveThreats('rev_1b', [threat({ id: 'thr_1h', reviewId: 'rev_1b', state: 'needs_human', severity: 'High' }), threat({ id: 'thr_1a', reviewId: 'rev_1b', state: 'accepted' })], []);
      await r.saveThreats('rev_2', [threat({ id: 'thr_2c', reviewId: 'rev_2', state: 'needs_human', severity: 'Critical' }), threat({ id: 'thr_2h', reviewId: 'rev_2', state: 'needs_human', severity: 'High' })], []);
      await r.saveThreats('rev_3', [threat({ id: 'thr_3m', reviewId: 'rev_3', state: 'needs_human', severity: 'Medium' }), threat({ id: 'thr_3d', reviewId: 'rev_3', state: 'dismissed', dismissReason: 'false_positive' })], []);
      const all = await r.needsHuman(50);
      expect(all.ok && all.value.map((x) => [x.threat.id, x.review.id])).toEqual([
        ['thr_2c', 'rev_2'],
        ['thr_2h', 'rev_2'],
        ['thr_1h', 'rev_1b'],
        ['thr_3m', 'rev_3'],
      ]);
      const two = await r.needsHuman(2);
      expect(two.ok && two.value.map((x) => x.threat.id)).toEqual(['thr_2c', 'thr_2h']);
      // A decision moves the threat out of the list (the state column is kept in step with the stored threat).
      await r.updateThreat('thr_2c', { state: 'accepted' });
      const after = await r.needsHuman(50);
      expect(after.ok && after.value.map((x) => x.threat.id)).toEqual(['thr_2h', 'thr_1h', 'thr_3m']);
    });

    it('reviews: updateWhere writes only while the stored review still matches (compare-and-set)', async () => {
      const r = await f.reviews();
      await r.create(review({ samplesReceived: 2 }));
      expect(await r.updateWhere('rev_1', { status: 'ready' }, { status: 'agent_timeout' })).toEqual({ ok: true, value: false });
      expect(await r.updateWhere('rev_1', { status: 'awaiting_agent', samplesReceivedAtMost: 1 }, { status: 'ready', samplesReceived: 1 })).toEqual({ ok: true, value: false });
      expect(await r.updateWhere('rev_1', { status: 'awaiting_agent', samplesReceivedAtMost: 3 }, { status: 'ready', samplesReceived: 3, riskScore: 7 })).toEqual({ ok: true, value: true });
      const g = await r.get('rev_1');
      expect(g.ok && g.value).toMatchObject({ status: 'ready', samplesReceived: 3, riskScore: 7 });
      expect(await r.updateWhere('missing', {}, { status: 'ready' })).toEqual({ ok: true, value: false });
    });

    it('reviews: recent lists newest first (optionally since a time); stages lists the trace in time order', async () => {
      const r = await f.reviews();
      await r.create(review({ id: 'rev_a', issueId: '1', createdAt: '2026-11-01T00:00:00.000Z' }));
      await r.create(review({ id: 'rev_b', issueId: '2', createdAt: '2026-11-03T00:00:00.000Z' }));
      await r.create(review({ id: 'rev_c', issueId: '3', createdAt: '2026-11-02T00:00:00.000Z' }));
      const all = await r.recent(2);
      expect(all.ok && all.value.map((x) => x.id)).toEqual(['rev_b', 'rev_c']);
      const since = await r.recent(10, '2026-11-02T00:00:00.000Z');
      expect(since.ok && since.value.map((x) => x.id)).toEqual(['rev_b', 'rev_c']);
      await r.saveStage('rev_a', 'gather', 'done', undefined, undefined, '2026-11-01T00:00:05.000Z');
      await r.saveStage('rev_a', 'assemble', 'failed', undefined, 'schema', '2026-11-01T00:01:00.000Z');
      await r.saveStage('rev_a', 'agent_1', 'done', { big: 'x' }, undefined, '2026-11-01T00:00:40.000Z');
      const trace = await r.stages('rev_a');
      expect(trace).toEqual({
        ok: true,
        value: [
          { stage: 'gather', status: 'done', at: '2026-11-01T00:00:05.000Z' },
          { stage: 'agent_1', status: 'done', at: '2026-11-01T00:00:40.000Z' },
          { stage: 'assemble', status: 'failed', error: 'schema', at: '2026-11-01T00:01:00.000Z' },
        ],
      });
      expect(await r.stages('rev_none')).toEqual({ ok: true, value: [] });
    });

    it('tree heads: add, latest, list newest first, mark published; a size is stored once', async () => {
      const r = await f.treeHeads();
      expect(await r.latest()).toEqual({ ok: true, value: null });
      const h = (n: number) => ({ treeSize: n, rootHash: String(n).padStart(64, 'a'), timestamp: `2026-11-1${n}T00:00:00.000Z`, kid: 'k1', signature: 's'.repeat(86) });
      await r.add(h(3));
      await r.add(h(7));
      expect((await r.add(h(7))).ok).toBe(false);
      expect(await r.latest()).toEqual({ ok: true, value: h(7) });
      await r.markPublished(7, '9001');
      const list = await r.list(10);
      expect(list).toEqual({ ok: true, value: [{ ...h(7), publishedPageId: '9001' }, h(3)] });
      expect(await r.lastPublished()).toEqual({ ok: true, value: { ...h(7), publishedPageId: '9001' } });
    });

    it('requirements: upsert, get, forIssue', async () => {
      const r = await f.requirements();
      await r.upsert(req());
      await r.upsert(req({ status: 'Verified', evidence: { kind: 'pr', ref: 'https://x/pr/1', attester: 'u1' } }));
      await r.upsert(req({ id: 'req_2', issueId: '999' }));
      const list = await r.forIssue('10001');
      expect(list.ok && list.value).toHaveLength(1);
      expect(list.ok && list.value[0]).toMatchObject({ status: 'Verified', evidence: { kind: 'pr' } });
      expect((await r.get('nope')).ok && (await r.get('nope'))).toEqual({ ok: true, value: null });
    });

    it('requirements: upsertIf saves only while the stored status is an expected one (compare-and-set)', async () => {
      const r = await f.requirements();
      expect(await r.upsertIf(req({ status: 'Verified' }), ['Open'])).toEqual({ ok: true, value: false });
      expect(await r.get(req().id)).toEqual({ ok: true, value: null });
      await r.upsert(req({ status: 'AcceptedRisk' }));
      expect(await r.upsertIf(req({ status: 'Verified' }), ['Open', 'InProgress'])).toEqual({ ok: true, value: false });
      expect(await r.get(req().id)).toMatchObject({ ok: true, value: { status: 'AcceptedRisk' } });
      await r.upsert(req({ status: 'InProgress' }));
      const ci = req({ status: 'Verified', evidence: { kind: 'ci', ref: 'https://ci.example/run/1', commitSha: 'a'.repeat(40), repo: 'acme/pay', attester: 'ci:x' } });
      expect(await r.upsertIf(ci, ['Open', 'InProgress'])).toEqual({ ok: true, value: true });
      expect(await r.get(req().id)).toMatchObject({ ok: true, value: { status: 'Verified', evidence: { kind: 'ci', commitSha: 'a'.repeat(40) } } });
      expect(await r.forIssue(req().issueId)).toMatchObject({ ok: true, value: [{ status: 'Verified' }] });
    });

    it('reviews: reserveUsage reserves atomically only while the total stays under the caps (security: no parallel overshoot)', async () => {
      const r = await f.reviews();
      await r.create(review({ tokensIn: 0, tokensOut: 0 }));
      const cap = { tokensIn: 1000, tokensOut: 100 };
      const tries = await Promise.all([1, 2, 3].map(() => r.reserveUsage('rev_1', { tokensIn: 300, tokensOut: 40 }, cap)));
      expect(tries.filter((x) => x.ok && x.value)).toHaveLength(2);
      const g = await r.get('rev_1');
      expect(g.ok && g.value).toMatchObject({ tokensIn: 600, tokensOut: 80 });
      await r.addUsage('rev_1', { tokensIn: -100, tokensOut: -30, modelIds: [] });
      const h = await r.get('rev_1');
      expect(h.ok && h.value).toMatchObject({ tokensIn: 500, tokensOut: 50 });
    });

    it('reviews: addUsage increments tokens and merges model ids, and update writes only the patched fields', async () => {
      const r = await f.reviews();
      await r.create(review({ tokensIn: 5, tokensOut: 1, modelIds: ['m1'] }));
      await r.addUsage('rev_1', { tokensIn: 10, tokensOut: 4, modelIds: ['m2', 'm1'] });
      await r.update('rev_1', { status: 'ready' });
      await r.addUsage('rev_1', { tokensIn: 1, tokensOut: 1, modelIds: [] });
      const g = await r.get('rev_1');
      expect(g.ok && g.value).toMatchObject({ status: 'ready', tokensIn: 16, tokensOut: 6, modelIds: ['m1', 'm2'] });
    });

    it('ledger: append-only, conflict on reused prevHash or seq, concurrent appends serialise', async () => {
      const l = await f.ledger();
      const clock = fixedClock('2026-11-15T00:00:00Z');
      const first = await appendLedger(l, clock, 'acceptance.requested', { acceptanceId: 'a' }, 'u1');
      expect(first.ok).toBe(true);
      const dup = await l.append({ seq: 2, eventType: 'key.rotated', payload: {}, actor: 'u', createdAt: 't', prevHash: GENESIS_HASH, entryHash: 'x'.repeat(64) });
      expect(!dup.ok && dup.error.code).toBe('conflict');
      const results = await Promise.all([1, 2, 3].map((i) => appendLedger(l, clock, 'acceptance.approved', { acceptanceId: `a${i}` }, 'u2')));
      expect(results.every((r) => r.ok)).toBe(true);
      const all = await l.all();
      expect(all.ok && all.value.map((r) => r.seq)).toEqual([1, 2, 3, 4]);
      const head = await l.head();
      expect(head.ok && head.value?.seq).toBe(4);
      const range = await l.range(2, 3);
      expect(range.ok && range.value.map((r) => r.seq)).toEqual([2, 3]);
      expect(all.ok && all.value[0]!.payload).toEqual({ acceptanceId: 'a' });
    });

    it('ledger: ofTypes returns only the named event types, in seq order (final review I5)', async () => {
      const l = await f.ledger();
      const clock = fixedClock('2026-11-15T00:00:00Z');
      await appendLedger(l, clock, 'attestation.issued', { issueKey: 'PAY-1' }, 'u');
      await appendLedger(l, clock, 'acceptance.requested', { acceptanceId: 'a' }, 'u');
      await appendLedger(l, clock, 'review.sample', { n: 1 }, 'u');
      await appendLedger(l, clock, 'override.breakglass', { issueId: '1', until: 'x' }, 'u');
      const r = await l.ofTypes(['acceptance.requested', 'override.breakglass']);
      expect(r.ok && r.value.map((x) => [x.seq, x.eventType])).toEqual([[2, 'acceptance.requested'], [4, 'override.breakglass']]);
      expect((await l.ofTypes([])).ok && (await l.ofTypes([]))).toEqual({ ok: true, value: [] });
    });

    it('ledger (scale): forIssues reads one work item\'s events through the issue index, plus rows without an issue', async () => {
      const l = await f.ledger();
      const clock = fixedClock('2026-11-15T00:00:00Z');
      await appendLedger(l, clock, 'acceptance.requested', { acceptanceId: 'a', issueId: '1' }, 'u');
      await appendLedger(l, clock, 'acceptance.requested', { acceptanceId: 'b', issueId: '2' }, 'u');
      await appendLedger(l, clock, 'acceptance.approved', { acceptanceId: 'a', issueId: '1' }, 'u');
      await appendLedger(l, clock, 'acceptance.expired', { acceptanceId: 'c' }, 'u');
      await appendLedger(l, clock, 'override.breakglass', { issueId: '3', until: 'x' }, 'u');
      await appendLedger(l, clock, 'review.sample', { issueId: '1' }, 'u');
      const r = await l.forIssues(['acceptance.requested', 'acceptance.approved', 'acceptance.expired', 'override.breakglass'], ['1', '3']);
      // Rows that name no work item (older entries) are always included, so nothing is missed.
      expect(r.ok && r.value.map((x) => x.seq)).toEqual([1, 3, 4, 5]);
      expect((await l.forIssues(['acceptance.requested'], [])).ok && (await l.forIssues(['acceptance.requested'], []))).toEqual({ ok: true, value: [] });
    });

    it('ledger (scale): latestOfTypes returns the newest rows of those types, in seq order', async () => {
      const l = await f.ledger();
      const clock = fixedClock('2026-11-15T00:00:00Z');
      for (let n = 1; n <= 5; n++) await appendLedger(l, clock, 'review.sample', { n }, 'u');
      await appendLedger(l, clock, 'policy.changed', { fields: [] }, 'u');
      const r = await l.latestOfTypes(['review.sample'], 2);
      expect(r.ok && r.value.map((x) => x.seq)).toEqual([4, 5]);
    });

    it('ledger (scale): entryHashes pages seq and entry hash only, in seq order after a seq', async () => {
      const l = await f.ledger();
      const clock = fixedClock('2026-11-15T00:00:00Z');
      for (let n = 1; n <= 5; n++) await appendLedger(l, clock, 'review.sample', { n }, 'u');
      const all = (await l.all()) as { ok: true; value: Array<{ seq: number; entryHash: string }> };
      const first = await l.entryHashes(0, 2);
      expect(first).toEqual({ ok: true, value: all.value.slice(0, 2).map((r) => ({ seq: r.seq, entryHash: r.entryHash })) });
      const rest = await l.entryHashes(2, 10);
      expect(rest.ok && rest.value.map((r) => r.seq)).toEqual([3, 4, 5]);
      expect(rest.ok && Object.keys(rest.value[0]!).sort()).toEqual(['entryHash', 'seq']);
      expect(await l.entryHashes(5, 10)).toEqual({ ok: true, value: [] });
    });

    it('ledger (scale): ofTypesSince returns only rows of those types created at or after a time, in seq order', async () => {
      const l = await f.ledger();
      const clock = fixedClock('2025-01-01T00:00:00Z');
      await appendLedger(l, clock, 'acceptance.requested', { acceptanceId: 'old' }, 'u');
      clock.set('2026-11-01T00:00:00Z');
      await appendLedger(l, clock, 'acceptance.requested', { acceptanceId: 'new' }, 'u');
      await appendLedger(l, clock, 'review.sample', { n: 1 }, 'u');
      await appendLedger(l, clock, 'acceptance.approved', { acceptanceId: 'new' }, 'u');
      const r = await l.ofTypesSince(['acceptance.requested', 'acceptance.approved'], '2026-01-01T00:00:00.000Z');
      expect(r.ok && r.value.map((x) => x.seq)).toEqual([2, 4]);
      expect(await l.ofTypesSince([], '2020-01-01T00:00:00.000Z')).toEqual({ ok: true, value: [] });
    });

    it('feedback: dismissals are returned per component', async () => {
      const fb = await f.feedback();
      await fb.record({ threatId: 't1', component: 'agent', title: 'A', stride: 'Spoofing', actor: 'c', action: 'dismiss', reason: 'false_positive' });
      await fb.record({ threatId: 't2', component: 'agent', title: 'B', stride: 'Spoofing', actor: 'c', action: 'accept' });
      await fb.record({ threatId: 't3', component: 'other', title: 'C', stride: 'Spoofing', actor: 'c', action: 'dismiss', reason: 'duplicate' });
      const d = await fb.dismissedFor('agent');
      expect(d.ok && d.value).toEqual([{ title: 'A', stride: 'Spoofing', reason: 'false_positive' }]);
    });

    it('issues: key changes on move keep the same issue id (Review Focus 4); pages map to issues', async () => {
      const i = await f.issues();
      await i.upsert({ issueId: '10001', issueKey: 'PROJ-1', projectKey: 'PROJ' });
      await i.upsert({ issueId: '10002', issueKey: 'PROJ-2', projectKey: 'PROJ', parentId: '10001' });
      await i.upsert({ issueId: '10001', issueKey: 'NEW-7', projectKey: 'NEW' });
      expect((await i.byKey('NEW-7')).ok && (await i.byKey('NEW-7'))).toMatchObject({ value: { issueId: '10001' } });
      expect((await i.byKey('PROJ-1')).ok && (await i.byKey('PROJ-1'))).toEqual({ ok: true, value: null });
      const kids = await i.children('10001');
      expect(kids.ok && kids.value.map((k) => k.issueKey)).toEqual(['PROJ-2']);
      await i.linkPage('10001', 'p1');
      await i.linkPage('10001', 'p1');
      await i.linkPage('10002', 'p1');
      const pages = await i.issuesForPage('p1');
      expect(pages.ok && [...pages.value].sort()).toEqual(['10001', '10002']);
    });

    it('usage: reserveReview counts a review atomically, only while the month stays within the cap', async () => {
      const u = await f.usage();
      await u.add('2026-11', { tokensIn: 0, tokensOut: 0, reviews: 4 });
      const tries = await Promise.all([1, 2, 3].map(() => u.reserveReview('2026-11', 5)));
      expect(tries.filter((x) => x.ok && x.value)).toHaveLength(1);
      expect((await u.get('2026-11')).ok && (await u.get('2026-11'))).toMatchObject({ value: { reviews: 5 } });
      const fresh = await Promise.all([1, 2].map(() => u.reserveReview('2026-12', 1)));
      expect(fresh.filter((x) => x.ok && x.value)).toHaveLength(1);
      expect(await u.reserveReview('2027-01', 0)).toEqual({ ok: true, value: false });
    });

    it('attestations and usage', async () => {
      const a = await f.attestations();
      await a.record({ id: 'att_1', issueKey: 'PROJ-1', repo: 'r', commitSha: 'c'.repeat(40), kid: 'k', expiresAt: 'e', nonce: 'n' });
      expect((await a.forIssue('PROJ-1')).ok && (await a.forIssue('PROJ-1'))).toMatchObject({ value: [{ id: 'att_1' }] });
      const u = await f.usage();
      await u.add('2026-11', { tokensIn: 10, tokensOut: 2, reviews: 1 });
      await u.add('2026-11', { tokensIn: 5, tokensOut: 1, reviews: 1 });
      expect((await u.get('2026-11')).ok && (await u.get('2026-11'))).toEqual({ ok: true, value: { tokensIn: 15, tokensOut: 3, reviews: 2 } });
      expect((await u.get('2026-10')).ok && (await u.get('2026-10'))).toEqual({ ok: true, value: { tokensIn: 0, tokensOut: 0, reviews: 0 } });
    });

    it('usage.takeSlot hands out at most `limit` slots per bucket and window, even to parallel callers', async () => {
      const u = await f.usage();
      const got = await Promise.all(Array.from({ length: 15 }, () => u.takeSlot('rl:acc-1', '2026-11-15T12', 10)));
      expect(got.every((r) => r.ok)).toBe(true);
      const taken = got.map((r) => (r.ok ? r.value : 'err')).filter((n) => n !== null);
      expect(taken.length).toBe(10);
      expect(taken.every((n) => typeof n === 'number' && n >= 1 && n <= 10)).toBe(true);
      expect(await u.takeSlot('rl:acc-1', '2026-11-15T12', 10)).toEqual({ ok: true, value: null });
      expect(await u.takeSlot('rl:acc-2', '2026-11-15T12', 10)).toEqual({ ok: true, value: 1 });
      // A new window starts from zero again.
      expect(await u.takeSlot('rl:acc-1', '2026-11-15T13', 10)).toEqual({ ok: true, value: 1 });
      expect(await u.takeSlot('rl:acc-1', '2026-11-15T13', 10)).toEqual({ ok: true, value: 2 });
    });
  });
}

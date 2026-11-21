import { describe, expect, it } from 'vitest';
import type { SuppressionRule } from '@threatline/shared';
import type { FeedbackRepo } from '../../src/ports.js';
import type { SuppressionRepo } from '../../src/suppressions.js';

export interface SuppressionRepoFactory {
  suppressions(): Promise<SuppressionRepo>;
  feedback(): Promise<FeedbackRepo>;
}

export const rule = (o: Partial<SuppressionRule> = {}): SuppressionRule => ({
  id: 'sup_1', projectKey: 'PAY', stride: 'DenialOfService', title: 'Reset endpoint can be flooded', reason: 'Rate limited at the gateway for every PAY service.',
  createdBy: 'acc-champ', createdAt: '2026-11-01T00:00:00.000Z', expiresAt: '2027-01-30T00:00:00.000Z', status: 'active', evidence: ['PAY-1', 'PAY-2', 'PAY-3'], ...o,
});

/** Behaviour every SuppressionRepo (and FeedbackRepo.dismissalsSince) implementation shares: memory fakes and SQL. */
export function suppressionContract(name: string, f: SuppressionRepoFactory): void {
  describe(`${name} suppression repository contract`, () => {
    it('create, get, list by status (newest first); an id already taken is a conflict', async () => {
      const s = await f.suppressions();
      expect((await s.create(rule())).ok).toBe(true);
      await s.create(rule({ id: 'sup_2', createdAt: '2026-11-02T00:00:00.000Z', component: 'reset api', status: 'pending' }));
      const again = await s.create(rule({ reason: 'other' }));
      expect(again.ok || again.error.code).toBe('conflict');
      expect(await s.get('sup_2')).toEqual({ ok: true, value: rule({ id: 'sup_2', createdAt: '2026-11-02T00:00:00.000Z', component: 'reset api', status: 'pending' }) });
      expect(await s.get('nope')).toEqual({ ok: true, value: null });
      const all = await s.list(['active', 'pending'], 10);
      expect(all.ok && all.value.map((r) => r.id)).toEqual(['sup_2', 'sup_1']);
      const active = await s.list(['active'], 10);
      expect(active.ok && active.value.map((r) => r.id)).toEqual(['sup_1']);
    });

    it('activeFor: only the project’s active rules that have not expired', async () => {
      const s = await f.suppressions();
      await s.create(rule());
      await s.create(rule({ id: 'sup_old', expiresAt: '2026-11-10T00:00:00.000Z' }));
      await s.create(rule({ id: 'sup_other', projectKey: 'OPS' }));
      await s.create(rule({ id: 'sup_pending', status: 'pending' }));
      const r = await s.activeFor('PAY', '2026-11-15T00:00:00.000Z');
      expect(r.ok && r.value.map((x) => x.id)).toEqual(['sup_1']);
    });

    it('transition is a compare-and-set and records who ended the rule', async () => {
      const s = await f.suppressions();
      await s.create(rule({ status: 'pending' }));
      expect(await s.transition('sup_1', 'active', 'revoked')).toEqual({ ok: true, value: false });
      expect(await s.transition('sup_1', 'pending', 'active')).toEqual({ ok: true, value: true });
      const both = await Promise.all([1, 2].map(() => s.transition('sup_1', 'active', 'revoked', { by: 'acc-admin', at: '2026-11-16T00:00:00.000Z', reason: 'No longer holds' })));
      expect(both.filter((x) => x.ok && x.value)).toHaveLength(1);
      expect(await s.get('sup_1')).toMatchObject({ value: { status: 'revoked', endedBy: 'acc-admin', endedAt: '2026-11-16T00:00:00.000Z', endReason: 'No longer holds' } });
      expect(await s.transition('missing', 'active', 'revoked')).toEqual({ ok: true, value: false });
    });

    it('matches count work items once; unhide is per rule and work item, and idempotent', async () => {
      const s = await f.suppressions();
      await s.recordMatch('sup_1', '10001', 'PAY-1', '2026-11-15T00:00:00.000Z');
      await s.recordMatch('sup_1', '10001', 'PAY-1', '2026-11-15T01:00:00.000Z');
      await s.recordMatch('sup_1', '10002', 'PAY-2', '2026-11-15T00:00:00.000Z');
      await s.recordMatch('sup_2', '10002', 'PAY-2', '2026-11-15T00:00:00.000Z');
      expect(await s.matchCounts(['sup_1', 'sup_2', 'sup_3'])).toEqual({ ok: true, value: { sup_1: 2, sup_2: 1 } });
      expect(await s.matchCounts([])).toEqual({ ok: true, value: {} });
      expect(await s.unhiddenOn('10001')).toEqual({ ok: true, value: [] });
      await s.unhide('sup_1', '10001', 'PAY-1', 'acc-champ', '2026-11-16T00:00:00.000Z');
      await s.unhide('sup_1', '10001', 'PAY-1', 'acc-champ', '2026-11-17T00:00:00.000Z');
      await s.unhide('sup_3', '10001', 'PAY-1', 'acc-champ', '2026-11-16T00:00:00.000Z');
      expect(await s.unhiddenOn('10001')).toEqual({ ok: true, value: ['sup_1', 'sup_3'] });
      expect(await s.unhiddenOn('10002')).toEqual({ ok: true, value: [] });
      expect(await s.matchCounts(['sup_1'])).toEqual({ ok: true, value: { sup_1: 2 } });
    });

    it('feedback.dismissalsSince: dismissals with a reason on a known work item, newest first, in the window', async () => {
      const fb = await f.feedback();
      const base = { component: 'reset api', title: 'Reset endpoint can be flooded', stride: 'DenialOfService' as const, actor: 'acc-champ' };
      await fb.record({ ...base, threatId: 't0', action: 'dismiss', reason: 'false_positive' });
      await fb.record({ ...base, threatId: 't1', action: 'dismiss', reason: 'false_positive', issueId: '10001', issueKey: 'PAY-1', projectKey: 'PAY', at: '2026-08-01T00:00:00.000Z' });
      await fb.record({ ...base, threatId: 't2', action: 'dismiss', reason: 'not_applicable', issueId: '10002', issueKey: 'PAY-2', projectKey: 'PAY', at: '2026-11-02T00:00:00.000Z' });
      await fb.record({ ...base, threatId: 't3', action: 'accept', issueId: '10003', issueKey: 'PAY-3', projectKey: 'PAY', at: '2026-11-03T00:00:00.000Z' });
      await fb.record({ ...base, threatId: 't4', action: 'dismiss', reason: 'already_mitigated', issueId: '10004', issueKey: 'OPS-4', projectKey: 'OPS', at: '2026-11-04T00:00:00.000Z' });
      const r = await fb.dismissalsSince('2026-09-01T00:00:00.000Z', 10);
      expect(r.ok && r.value).toEqual([
        { ...base, threatId: 't4', reason: 'already_mitigated', issueId: '10004', issueKey: 'OPS-4', projectKey: 'OPS', at: '2026-11-04T00:00:00.000Z' },
        { ...base, threatId: 't2', reason: 'not_applicable', issueId: '10002', issueKey: 'PAY-2', projectKey: 'PAY', at: '2026-11-02T00:00:00.000Z' },
      ]);
      const one = await fb.dismissalsSince('2026-01-01T00:00:00.000Z', 1);
      expect(one.ok && one.value.map((x) => x.threatId)).toEqual(['t4']);
      // The per-component lookup earlier reviews use is unchanged.
      expect((await fb.dismissedFor('reset api')).ok && (await fb.dismissedFor('reset api'))).toMatchObject({ value: { length: 4 } });
    });
  });
}

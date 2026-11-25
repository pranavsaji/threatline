import { describe, expect, it } from 'vitest';
import type { Review, Threat } from '@threatline/shared';
import { ACCURACY_MIN_DECISIONS, accuracySummary, rate, wilsonInterval, type AccuracyInput, type LedgerEventType, type LedgerRow } from '../src/index.js';
import { NOW, requirement, review, threat } from './fixtures/verdict.js';

const DAY = 86_400_000;
const ago = (d: number) => new Date(NOW.getTime() - d * DAY).toISOString();

/** Ledger rows in seq order; `at` is days ago. */
function ledger() {
  const rows: LedgerRow[] = [];
  const add = (eventType: LedgerEventType, payload: Record<string, unknown>, at = 1): LedgerRow => {
    const seq = rows.length + 1;
    const row: LedgerRow = { seq, eventType, payload, actor: 'champ', createdAt: ago(at), prevHash: `h${seq - 1}`, entryHash: `h${seq}` };
    rows.push(row);
    return row;
  };
  const triage = (o: { issueId?: string; threatId: string; title: string; from?: string; op: string; reason?: string; at?: number; patch?: Record<string, unknown>; reviewId?: string }) =>
    add('threat.triaged', { issueId: o.issueId ?? '10001', issueKey: 'PROJ-1', reviewId: o.reviewId ?? 'rev_1', threatId: o.threatId, title: o.title, severity: 'High', from: o.from ?? 'needs_human', op: o.op, ...(o.reason ? { reason: o.reason } : {}), ...(o.patch ? { patch: o.patch } : {}) }, o.at ?? 1);
  return { rows, add, triage };
}

const item = (o: Partial<AccuracyInput['items'][number]> = {}) => ({ issueId: '10001', project: 'PROJ', requirements: [], ...o });
const base = (o: Partial<AccuracyInput> = {}): AccuracyInput => ({ now: NOW, blockAtOrAbove: 'High', items: [item()], ledger: [], latest: [], ...o });
const row = (t: Partial<Threat>, r: Partial<Review> = {}) => ({ threat: threat(t), review: review({ createdAt: ago(3), ...r }) });

describe('wilsonInterval', () => {
  it('matches the published Wilson 95% bounds', () => {
    // 15 of 15 is the README's injection-resistance figure: 79.6–100%.
    const all = wilsonInterval(15, 15)!;
    expect(all.low).toBeCloseTo(0.796, 3);
    expect(all.high).toBeCloseTo(1, 9);
    const half = wilsonInterval(5, 10)!;
    expect(half.low).toBeCloseTo(0.2366, 3);
    expect(half.high).toBeCloseTo(0.7634, 3);
    const none = wilsonInterval(0, 20)!;
    expect(none.low).toBeCloseTo(0, 9);
    expect(none.high).toBeCloseTo(0.1611, 3);
  });
  it('has no interval without a single decision, and rejects impossible counts', () => {
    expect(wilsonInterval(0, 0)).toBeNull();
    expect(() => wilsonInterval(3, 2)).toThrow();
    expect(() => wilsonInterval(-1, 2)).toThrow();
  });
});

describe('rate', () => {
  it(`gives no percentage below ${ACCURACY_MIN_DECISIONS} decisions (only the count)`, () => {
    expect(rate(0, 0)).toEqual({ n: 0, share: null, low: null, high: null, enough: false });
    expect(rate(4, 4)).toEqual({ n: 4, share: null, low: null, high: null, enough: false });
  });
  it('gives the share and its Wilson interval from 5 decisions on', () => {
    const r = rate(4, 5);
    expect(r).toMatchObject({ n: 5, share: 0.8, enough: true });
    expect(r.low).toBeCloseTo(0.3755, 3);
    expect(r.high).toBeCloseTo(0.9638, 3);
  });
});

describe('accuracySummary: champion agreement', () => {
  it('zero: nothing decided in the window gives no decisions and no percentage', () => {
    const a = accuracySummary(base());
    expect(a.champion).toEqual({ confirmed: 0, dismissed: 0, notCounted: 0, rate: rate(0, 0) });
    expect(a.windowDays).toBe(90);
    expect(a.since).toBe(ago(90));
  });

  it('counts threats sent to a champion: confirmed vs dismissed as false positive or not applicable', () => {
    const l = ledger();
    l.triage({ threatId: 't1', title: 'Forged webhook', op: 'accept' });
    l.triage({ threatId: 't2', title: 'Replay', op: 'dismiss', reason: 'false_positive' });
    l.triage({ threatId: 't3', title: 'Log tampering', op: 'dismiss', reason: 'not_applicable' });
    l.triage({ threatId: 't4', title: 'Mass assignment', op: 'split' });
    // Real but already handled: the champion agrees it is a threat.
    l.triage({ threatId: 't5', title: 'Open redirect', op: 'dismiss', reason: 'already_mitigated' });
    // Says nothing about whether Threatline was right: not counted.
    l.triage({ threatId: 't6', title: 'Dup', op: 'dismiss', reason: 'duplicate' });
    l.triage({ threatId: 't7', title: 'Dup 2', op: 'merge' });
    const a = accuracySummary(base({ ledger: l.rows }));
    expect(a.champion).toMatchObject({ confirmed: 3, dismissed: 2, notCounted: 2 });
    expect(a.champion.rate).toMatchObject({ n: 5, share: 0.6, enough: true });
  });

  it('ignores decisions on threats that never waited for a champion', () => {
    const l = ledger();
    l.triage({ threatId: 't1', title: 'A', from: 'accepted', op: 'dismiss', reason: 'false_positive' });
    l.triage({ threatId: 't2', title: 'B', from: 'proposed', op: 'accept' });
    expect(accuracySummary(base({ ledger: l.rows })).champion.rate.n).toBe(0);
  });

  it('the latest decision on a threat wins (a champion who changes their mind is counted once)', () => {
    const l = ledger();
    l.triage({ threatId: 't1', title: 'Forged webhook', op: 'accept', at: 5 });
    l.triage({ threatId: 't1', title: 'Forged webhook', from: 'accepted', op: 'dismiss', reason: 'false_positive', at: 2 });
    expect(accuracySummary(base({ ledger: l.rows })).champion).toMatchObject({ confirmed: 0, dismissed: 1 });
  });

  it('re-runs are not double-counted: the same threat decided on two revisions is one decision', () => {
    const l = ledger();
    l.triage({ threatId: 'rev1_t', reviewId: 'rev_1', title: 'Forged Webhook', op: 'accept', at: 20 });
    l.triage({ threatId: 'rev2_t', reviewId: 'rev_2', title: 'forged webhook ', op: 'accept', at: 3 });
    expect(accuracySummary(base({ ledger: l.rows })).champion).toMatchObject({ confirmed: 1, dismissed: 0 });
  });

  it('a renamed threat stays one decision (the edit links the new title to the old)', () => {
    const l = ledger();
    l.triage({ threatId: 't1', title: 'Old name', op: 'edit', patch: { title: 'New name' }, at: 6 });
    l.triage({ threatId: 't1', title: 'New name', op: 'accept', at: 5 });
    l.triage({ threatId: 'rev2_t', reviewId: 'rev_2', title: 'New name', from: 'needs_human', op: 'dismiss', reason: 'false_positive', at: 2 });
    expect(accuracySummary(base({ ledger: l.rows })).champion).toMatchObject({ confirmed: 0, dismissed: 1 });
  });

  it('the same title on two work items is two decisions', () => {
    const l = ledger();
    l.triage({ issueId: '10001', threatId: 'a', title: 'Forged webhook', op: 'accept' });
    l.triage({ issueId: '10002', threatId: 'b', title: 'Forged webhook', op: 'accept' });
    const a = accuracySummary(base({ items: [item(), item({ issueId: '10002' })], ledger: l.rows }));
    expect(a.champion.confirmed).toBe(2);
  });

  it('a decision that did not take effect (triage_failed) is not counted', () => {
    const l = ledger();
    const d = l.triage({ threatId: 't1', title: 'A', op: 'dismiss', reason: 'false_positive' });
    l.add('threat.triage_failed', { issueId: '10001', threatId: 't1', failedEntryHash: d.entryHash, code: 'internal' });
    expect(accuracySummary(base({ ledger: l.rows })).champion.rate.n).toBe(0);
  });

  it('only the last 90 days count', () => {
    const l = ledger();
    l.triage({ threatId: 't1', title: 'Old', op: 'dismiss', reason: 'false_positive', at: 91 });
    l.triage({ threatId: 't2', title: 'New', op: 'accept', at: 89 });
    expect(accuracySummary(base({ ledger: l.rows })).champion).toMatchObject({ confirmed: 1, dismissed: 0 });
  });

  it('confirming a review as a whole confirms each threat still waiting on it', () => {
    const l = ledger();
    l.add('review.champion_confirmed', { reviewId: 'rev_1', issueId: '10001', issueKey: 'PROJ-1' }, 4);
    const latest = [
      row({ id: 'w1', title: 'Waiting one', state: 'needs_human' }),
      row({ id: 'w2', title: 'Waiting two', state: 'needs_human' }),
      row({ id: 'a1', title: 'Accepted', state: 'accepted' }),
    ];
    // A later decision on one of them wins.
    l.triage({ threatId: 'w2', title: 'Waiting two', op: 'dismiss', reason: 'false_positive', at: 2 });
    const a = accuracySummary(base({ ledger: l.rows, latest }));
    expect(a.champion).toMatchObject({ confirmed: 1, dismissed: 1 });
  });

  it('a whole-review confirmation of an older revision uses that revision’s threats', () => {
    const l = ledger();
    l.add('review.champion_confirmed', { reviewId: 'rev_old', issueId: '10001', issueKey: 'PROJ-1' }, 30);
    const confirmedThreats = new Map([['rev_old', [threat({ id: 'o1', reviewId: 'rev_old', title: 'Old waiting', state: 'needs_human' })]]]);
    expect(accuracySummary(base({ ledger: l.rows, confirmedThreats })).champion.confirmed).toBe(1);
  });

  it('suppressed threats are never counted (they cannot be triaged while hidden)', () => {
    const l = ledger();
    l.add('review.champion_confirmed', { reviewId: 'rev_1', issueId: '10001', issueKey: 'PROJ-1' }, 4);
    const latest = [row({ id: 's1', title: 'Hidden', state: 'suppressed', suppression: { ruleId: 'r', reason: 'x', expiresAt: ago(-30), outcome: 'hidden', restoreTo: 'needs_human' } })];
    expect(accuracySummary(base({ ledger: l.rows, latest })).champion.rate.n).toBe(0);
  });
});

describe('accuracySummary: blocking requirements that held up', () => {
  const evidence = { kind: 'pr' as const, ref: 'https://bitbucket.org/acme/pay/pull-requests/42', attester: 'dev' };

  it('fixed (Verified with evidence) and risk accepted hold up; dismissed as false positive or not applicable does not', () => {
    const l = ledger();
    const reqs = [
      requirement({ id: 'fixed', threatId: 'tf', status: 'Verified', evidence, createdAt: ago(10), verifiedAt: ago(8) }),
      requirement({ id: 'fixed2', threatId: 'tf2', status: 'Verified', evidence, createdAt: ago(10), verifiedAt: ago(6), severity: 'Critical' }),
      requirement({ id: 'accepted', threatId: 'ta', status: 'AcceptedRisk' }),
      requirement({ id: 'na', threatId: 'tn', status: 'NotApplicable' }),
      requirement({ id: 'dismissed', threatId: 'td', status: 'Open' }),
      requirement({ id: 'mitigated', threatId: 'tm', status: 'Open' }),
      requirement({ id: 'open', threatId: 'to', status: 'Open' }),
    ];
    l.add('acceptance.requested', { acceptanceId: 'acc_1', requirementId: 'accepted', issueId: '10001', severity: 'High', expiresAt: ago(-30) }, 5);
    l.add('acceptance.approved', { acceptanceId: 'acc_1', requirementId: 'accepted', issueId: '10001', severity: 'High' }, 4);
    l.add('requirement.status_changed', { requirementId: 'na', issueId: '10001', from: 'Open', to: 'NotApplicable' }, 3);
    l.triage({ threatId: 'td', title: 'Dismissed', from: 'accepted', op: 'dismiss', reason: 'false_positive', at: 2 });
    l.triage({ threatId: 'tm', title: 'Mitigated', from: 'accepted', op: 'dismiss', reason: 'already_mitigated', at: 2 });
    const a = accuracySummary(base({ items: [item({ requirements: reqs })], ledger: l.rows }));
    expect(a.blocking).toMatchObject({ fixed: 2, accepted: 1, dismissed: 2, notCounted: 1 });
    expect(a.blocking.rate).toMatchObject({ n: 5, share: 0.6 });
    // Fixed in 48 h and 96 h.
    expect(a.blocking.medianHoursToVerify).toBe(72);
  });

  it('only blocking requirements count (at or above the policy level)', () => {
    const reqs = [requirement({ id: 'm', severity: 'Medium', status: 'Verified', evidence, createdAt: ago(3), verifiedAt: ago(2) })];
    expect(accuracySummary(base({ items: [item({ requirements: reqs })] })).blocking.rate.n).toBe(0);
    expect(accuracySummary(base({ blockAtOrAbove: 'Medium', items: [item({ requirements: reqs })] })).blocking.fixed).toBe(1);
  });

  it('only closures in the last 90 days count, and a Verified requirement without evidence is not a fix', () => {
    const l = ledger();
    const reqs = [
      requirement({ id: 'old', status: 'Verified', evidence, createdAt: ago(120), verifiedAt: ago(100) }),
      requirement({ id: 'bare', status: 'Verified', createdAt: ago(5), verifiedAt: ago(4) }),
      requirement({ id: 'oldacc', status: 'AcceptedRisk' }),
    ];
    l.add('acceptance.requested', { acceptanceId: 'acc_o', requirementId: 'oldacc', issueId: '10001', severity: 'High', expiresAt: ago(-200), needsApprover: 'none' }, 95);
    expect(accuracySummary(base({ items: [item({ requirements: reqs })], ledger: l.rows })).blocking.rate.n).toBe(0);
  });

  it('a risk acceptance that needed no approver counts from its request', () => {
    const l = ledger();
    l.add('acceptance.requested', { acceptanceId: 'acc_1', requirementId: 'r', issueId: '10001', severity: 'High', expiresAt: ago(-30), needsApprover: 'none' }, 3);
    const a = accuracySummary(base({ items: [item({ requirements: [requirement({ id: 'r', status: 'AcceptedRisk' })] })], ledger: l.rows }));
    expect(a.blocking.accepted).toBe(1);
  });

  it('a status change that did not take effect is not counted', () => {
    const l = ledger();
    const na = l.add('requirement.status_changed', { requirementId: 'na', issueId: '10001', from: 'Open', to: 'NotApplicable' }, 3);
    l.add('requirement.status_change_failed', { requirementId: 'na', issueId: '10001', failedEntryHash: na.entryHash, code: 'internal' }, 3);
    const a = accuracySummary(base({ items: [item({ requirements: [requirement({ id: 'na', status: 'NotApplicable' })] })], ledger: l.rows }));
    expect(a.blocking.rate.n).toBe(0);
  });

  it('a dismissal that was later reversed leaves the requirement open (not closed)', () => {
    const l = ledger();
    l.triage({ threatId: 't', title: 'A', from: 'accepted', op: 'dismiss', reason: 'false_positive', at: 5 });
    l.triage({ threatId: 't', title: 'A', from: 'dismissed', op: 'accept', at: 3 });
    const a = accuracySummary(base({ items: [item({ requirements: [requirement({ id: 'r', threatId: 't', status: 'Open' })] })], ledger: l.rows }));
    expect(a.blocking.rate.n).toBe(0);
  });

  it('re-runs are not double-counted: one requirement row per threat across revisions', () => {
    const l = ledger();
    // Revision 1's threat was dismissed; revision 2 carried the dismissal over (its threat has a new id) and the
    // requirement row still points at revision 1's threat. One closure.
    l.triage({ threatId: 'rev1_t', reviewId: 'rev_1', title: 'A', from: 'accepted', op: 'dismiss', reason: 'false_positive', at: 10 });
    const a = accuracySummary(base({ items: [item({ requirements: [requirement({ id: 'r', threatId: 'rev1_t' })] })], ledger: l.rows }));
    expect(a.blocking).toMatchObject({ dismissed: 1, fixed: 0 });
  });
});

describe('accuracySummary: verifier keep rate', () => {
  const kept = (id: string) => ({ id, verification: { keep: true, reason: 'supported' } });
  const doubted = (id: string) => ({ id, state: 'dismissed' as const, verification: { keep: false, reason: 'not in the sources' } });

  it('kept vs doubted on each work item’s latest settled review in the window', () => {
    const latest = [row(kept('k1')), row(kept('k2')), row(kept('k3')), row(kept('k4')), row(doubted('d1')), row({ id: 'nv' })];
    expect(accuracySummary(base({ latest })).verifier).toMatchObject({ kept: 4, doubted: 1, rate: { n: 5, share: 0.8 } });
  });

  it('ignores reviews older than the window, reviews not settled, and suppressed threats', () => {
    const latest = [
      row(kept('old'), { createdAt: ago(100) }),
      row(kept('running'), { status: 'modeling' }),
      row({ ...kept('hidden'), state: 'suppressed', suppression: { ruleId: 'r', reason: 'x', expiresAt: ago(-30), outcome: 'hidden', restoreTo: 'accepted' } }),
    ];
    expect(accuracySummary(base({ latest })).verifier.rate.n).toBe(0);
  });
});

describe('accuracySummary: scope', () => {
  it('counts only the work items passed in (rows about other work items are ignored)', () => {
    const l = ledger();
    l.triage({ issueId: '99999', threatId: 'x', title: 'Elsewhere', op: 'dismiss', reason: 'false_positive' });
    l.add('requirement.status_changed', { requirementId: 'r', issueId: '99999', to: 'NotApplicable' });
    l.add('review.champion_confirmed', { reviewId: 'rev_x', issueId: '99999' });
    // A row that names no work item is never attributed to one.
    l.add('threat.triaged', { threatId: 'y', title: 'Nameless', from: 'needs_human', op: 'accept' });
    const latest = [row({ id: 'v', verification: { keep: false, reason: 'x' } }, { issueId: '99999' })];
    const a = accuracySummary(base({ ledger: l.rows, latest }));
    expect([a.champion.rate.n, a.blocking.rate.n, a.verifier.rate.n]).toEqual([0, 0, 0]);
  });

  it('breaks the figures down per project, and the overall figure is their sum', () => {
    const l = ledger();
    l.triage({ issueId: '1', threatId: 'a', title: 'A', op: 'accept' });
    l.triage({ issueId: '2', threatId: 'b', title: 'B', op: 'dismiss', reason: 'false_positive' });
    l.triage({ issueId: '3', threatId: 'c', title: 'C', op: 'accept' });
    const a = accuracySummary(base({ items: [item({ issueId: '1', project: 'PAY' }), item({ issueId: '2', project: 'OPS' }), item({ issueId: '3', project: 'PAY' })], ledger: l.rows }));
    expect(a.champion).toMatchObject({ confirmed: 2, dismissed: 1 });
    expect(a.byProject.map((p) => [p.project, p.champion.confirmed, p.champion.dismissed])).toEqual([
      ['OPS', 0, 1],
      ['PAY', 2, 0],
    ]);
  });
});

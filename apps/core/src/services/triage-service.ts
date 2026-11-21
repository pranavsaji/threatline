import { appendLedger, requirementsFor, severityOf, type LedgerRow } from '@threatline/core';
import { appError, err, ok, type Citation, type DismissReason, type Mapping, type Result, type Review, type Threat } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import type { JiraIssue } from '../adapters/jira.js';
import { isBudgetPaused } from './budget.js';
import { log } from '../adapters/log.js';
import { opsAlert } from './ops-alert.js';
import { refreshVerdict } from './verdict-service.js';

export type ThreatEdit = Partial<Pick<Threat, 'title' | 'scenario' | 'component' | 'likelihood' | 'impact' | 'plainLanguage' | 'stride'>>;
export type TriageOp =
  | { op: 'accept' }
  | { op: 'dismiss'; reason: DismissReason; note?: string }
  | { op: 'edit'; patch: ThreatEdit }
  | { op: 'merge'; intoThreatId: string }
  | { op: 'split'; parts: Array<{ title: string; scenario?: string; component?: string }> };

const IN_PROGRESS: ReadonlySet<Review['status']> = new Set(['queued', 'gathering', 'awaiting_agent', 'modeling']);
const MAX_CITATIONS = 20;

/** Triage edits the latest review only, and only once assembly is done (a later assembly would overwrite it). */
export function triageable(review: Review | null): Result<Review> {
  if (!review) return err(appError('not_found', 'no review'));
  if (IN_PROGRESS.has(review.status)) return err(appError('conflict', 'Wait until every agent run is in before triaging threats.'));
  return ok(review);
}

/** Keeps one requirement row per accepted / needs-human threat, in step with its severity. */
export async function syncRequirement(deps: CoreDeps, issue: JiraIssue, t: Threat): Promise<Result<void>> {
  const reqs = await deps.requirements.forIssue(issue.id);
  if (!reqs.ok) return reqs;
  const existing = reqs.value.find((r) => r.threatId === t.id);
  if (existing) return existing.severity === t.severity ? ok(undefined) : deps.requirements.upsert({ ...existing, severity: t.severity });
  const fresh = requirementsFor([t], { issueId: issue.id, issueKey: issue.key })[0];
  return fresh ? deps.requirements.upsert(fresh) : ok(undefined);
}

const uniq = <T>(xs: T[], key: (x: T) => string) => [...new Map(xs.map((x) => [key(x), x])).values()];

/** What the ledger records about the operation itself (the reason code and note of a dismissal, the edited fields…). */
function opDetails(op: TriageOp): Record<string, unknown> {
  switch (op.op) {
    case 'accept':
      return {};
    case 'dismiss':
      return { reason: op.reason, ...(op.note ? { note: op.note } : {}) };
    case 'edit':
      return { patch: op.patch };
    case 'merge':
      return { intoThreatId: op.intoThreatId };
    case 'split':
      return { parts: op.parts.map((p) => p.title) };
  }
}

/**
 * TM-7: a security champion accepts, dismisses (with a reason code, which feeds de-duplication of later reviews — TM-5),
 * edits, merges or splits a threat. `all` is every threat of the review; the caller has already checked that the champion
 * can see `t` (and the merge target). Returns the changed threats.
 *
 * Every decision is ledgered (`threat.triaged`) before anything is saved, so none is ever saved unrecorded; when the
 * ledger cannot record it, nothing changes. When a save then fails, a `threat.triage_failed` entry says the recorded
 * decision did not (fully) take effect. The issue panel and the champion inbox both decide through here.
 */
export async function applyTriage(
  deps: CoreDeps,
  actor: string,
  issue: JiraIssue,
  review: Review,
  all: readonly Threat[],
  t: Threat,
  op: TriageOp,
  visible: ReadonlySet<string>,
): Promise<Result<Threat[]>> {
  const refused = precheck(all, t, op, visible);
  if (refused) return refused;
  const ids = { issueId: issue.id, issueKey: issue.key, reviewId: review.id, threatId: t.id };
  const row = await appendLedger(deps.ledger, deps.clock, 'threat.triaged', { ...ids, title: t.title, severity: t.severity, from: t.state, op: op.op, ...opDetails(op) }, actor);
  if (!row.ok) return row;
  const r = await saveTriage(deps, actor, issue, review, all, t, op, visible);
  if (!r.ok) {
    const undo = await appendLedger(deps.ledger, deps.clock, 'threat.triage_failed', { ...ids, failedEntryHash: row.value.entryHash, code: r.error.code }, actor);
    if (!undo.ok) log('threat.triage_failed_unrecorded', { threatId: t.id, code: undo.error.code });
  }
  return r;
}

/** Refusals known before anything is written, so a refused decision leaves no ledger entry. */
function precheck(all: readonly Threat[], t: Threat, op: TriageOp, visible: ReadonlySet<string>): Result<never> | null {
  if (op.op === 'merge') {
    const into = all.find((x) => x.id === op.intoThreatId);
    if (!into || !visible.has(into.id) || into.id === t.id) return err(appError('not_found', 'merge target not found'));
    if (into.state === 'dismissed') return err(appError('validation', 'Cannot merge into a dismissed threat.'));
  }
  if (op.op === 'split' && op.parts.some((_, i) => all.some((x) => x.id === `${t.id}_s${i + 1}`))) return err(appError('conflict', 'This threat was already split.'));
  return null;
}

async function saveTriage(
  deps: CoreDeps,
  actor: string,
  issue: JiraIssue,
  review: Review,
  all: readonly Threat[],
  t: Threat,
  op: TriageOp,
  visible: ReadonlySet<string>,
): Promise<Result<Threat[]>> {
  const feedback = (action: 'dismiss' | 'accept' | 'edit', extra: { reason?: DismissReason; note?: string } = {}) =>
    deps.feedback.record({
      threatId: t.id, component: t.component, title: t.title, stride: t.stride, actor, action, ...extra,
      // Where and when: dismissals on several work items of a project suggest a team suppression rule.
      issueId: issue.id, issueKey: issue.key, projectKey: issue.project.key, at: deps.clock.now().toISOString(),
    });
  const update = async (id: string, patch: Partial<Threat>) => deps.reviews.updateThreat(id, patch);
  const changed: Threat[] = [];

  switch (op.op) {
    case 'accept': {
      const next = { ...t, state: 'accepted' as const };
      const u = await update(t.id, { state: 'accepted' });
      if (!u.ok) return u;
      await feedback('accept');
      const s = await syncRequirement(deps, issue, next);
      if (!s.ok) return s;
      changed.push(next);
      break;
    }
    case 'dismiss': {
      const u = await update(t.id, { state: 'dismissed', dismissReason: op.reason });
      if (!u.ok) return u;
      const f = await feedback('dismiss', { reason: op.reason, ...(op.note ? { note: op.note } : {}) });
      if (!f.ok) return f;
      changed.push({ ...t, state: 'dismissed', dismissReason: op.reason });
      break;
    }
    case 'edit': {
      const merged = { ...t, ...op.patch };
      const next: Threat = { ...merged, severity: severityOf(merged.likelihood, merged.impact) };
      const u = await update(t.id, { ...op.patch, severity: next.severity });
      if (!u.ok) return u;
      await feedback('edit', op.patch.title && op.patch.title !== t.title ? { note: `renamed to: ${op.patch.title}`.slice(0, 500) } : {});
      if (next.state === 'accepted' || next.state === 'needs_human') {
        const s = await syncRequirement(deps, issue, next);
        if (!s.ok) return s;
      }
      changed.push(next);
      break;
    }
    case 'merge': {
      const into = all.find((x) => x.id === op.intoThreatId);
      if (!into || !visible.has(into.id) || into.id === t.id) return err(appError('not_found', 'merge target not found'));
      if (into.state === 'dismissed') return err(appError('validation', 'Cannot merge into a dismissed threat.'));
      const likelihood = Math.max(into.likelihood, t.likelihood);
      const impact = Math.max(into.impact, t.impact);
      const target: Threat = {
        ...into,
        likelihood,
        impact,
        severity: severityOf(likelihood, impact),
        votes: Math.max(into.votes, t.votes),
        citations: uniq<Citation>([...into.citations, ...t.citations], (c) => `${c.factId}|${c.quote}`).slice(0, MAX_CITATIONS),
        mappings: uniq<Mapping>([...into.mappings, ...t.mappings], (m) => `${m.framework}|${m.refId}`),
      };
      const a = await update(into.id, { likelihood, impact, severity: target.severity, votes: target.votes, citations: target.citations, mappings: target.mappings });
      if (!a.ok) return a;
      const b = await update(t.id, { state: 'dismissed', dismissReason: 'duplicate' });
      if (!b.ok) return b;
      await feedback('dismiss', { reason: 'duplicate', note: `merged into: ${into.title}`.slice(0, 500) });
      if (target.state === 'accepted' || target.state === 'needs_human') {
        const s = await syncRequirement(deps, issue, target);
        if (!s.ok) return s;
      }
      changed.push(target, { ...t, state: 'dismissed', dismissReason: 'duplicate' });
      break;
    }
    case 'split': {
      const parts: Threat[] = op.parts.map((p, i) => {
        const { dismissReason: _d, suggestedRequirement: _s, ...base } = t;
        return { ...base, id: `${t.id}_s${i + 1}`, title: p.title, scenario: p.scenario ?? t.scenario, component: p.component ?? t.component, plainLanguage: p.title, state: 'accepted' };
      });
      if (parts.some((p) => all.some((x) => x.id === p.id))) return err(appError('conflict', 'This threat was already split.'));
      const discarded = await deps.reviews.discarded(review.id);
      if (!discarded.ok) return discarded;
      const original: Threat = { ...t, state: 'dismissed', dismissReason: 'duplicate' };
      // No dismissal feedback here: the next review should raise the original again rather than silently drop it.
      const saved = await deps.reviews.saveThreats(review.id, [...all.map((x) => (x.id === t.id ? original : x)), ...parts], discarded.value);
      if (!saved.ok) return saved;
      for (const p of parts) {
        const s = await syncRequirement(deps, issue, p);
        if (!s.ok) return s;
      }
      changed.push(original, ...parts);
      break;
    }
  }
  // A rule-based threat covered by a threat that is now dismissed (dismiss, merge, split) is active again, with its
  // requirement: dismissing the specific AI threat must never take the generic rule-based floor with it.
  const gone = new Set(changed.filter((c) => c.state === 'dismissed').map((c) => c.id));
  for (const b of all.filter((x) => x.state === 'covered' && x.coveredBy && gone.has(x.coveredBy))) {
    const { coveredBy: _c, ...rest } = b;
    const back: Threat = { ...rest, state: 'accepted' };
    const u = await deps.reviews.updateThreat(b.id, { state: 'accepted', coveredBy: undefined });
    if (!u.ok) return u;
    const s = await syncRequirement(deps, issue, back);
    if (!s.ok) return s;
    changed.push(back);
  }
  await refreshVerdict(deps, issue.id);
  await deps.queue.push([{ kind: 'propagate', issueId: issue.id }]);
  return ok(changed);
}

/**
 * A security champion confirms the latest review: `review` lets needs-human threats count as ordinary ones (they still
 * need their requirements resolved); `budget` lets the item through while reviews are paused at the AI budget, and
 * alerts the admin. Both are ledgered, once per review and kind.
 */
export async function confirmReview(deps: CoreDeps, actor: string, issue: JiraIssue, review: Review, kind: 'review' | 'budget'): Promise<Result<LedgerRow>> {
  const eventType = kind === 'review' ? 'review.champion_confirmed' : 'budget.champion_confirmed';
  const rows = await deps.ledger.forIssues([eventType], [issue.id]);
  if (!rows.ok) return rows;
  const existing = rows.value.find((r) => r.eventType === eventType && r.payload.reviewId === review.id);
  if (existing) return ok(existing);

  if (kind === 'review') {
    const threats = await deps.reviews.threats(review.id);
    if (!threats.ok) return threats;
    if (!threats.value.some((t) => t.state === 'needs_human')) return err(appError('validation', 'Nothing in this review needs a champion to confirm it.'));
  } else {
    const policy = await deps.config.site();
    if (!policy.ok) return policy;
    const paused = await isBudgetPaused(deps, policy.value, deps.clock.now());
    if (!paused.ok) return paused;
    if (!paused.value) return err(appError('validation', 'Reviews are not paused at the AI budget.'));
  }
  const row = await appendLedger(deps.ledger, deps.clock, eventType, { reviewId: review.id, issueId: issue.id, issueKey: issue.key }, actor);
  if (!row.ok) return row;
  if (kind === 'budget')
    await opsAlert(
      deps,
      `alert:budget-confirm:${review.id}`,
      `Threatline: a security champion let ${issue.key} through while reviews are paused at the AI budget (token budget or the site's Rovo credits). It is recorded in the ledger (entry ${row.value.seq}). Check the Threatline admin page (Budgets).`,
    );
  await refreshVerdict(deps, issue.id);
  await deps.queue.push([{ kind: 'propagate', issueId: issue.id }]);
  return row;
}

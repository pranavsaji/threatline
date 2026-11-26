import {
  severityRank,
  type Acceptance,
  type BlockReason,
  type FixCheckRecord,
  type Requirement,
  type Review,
  type Severity,
  type SitePolicy,
  type Threat,
  type Verdict,
} from '@threatline/shared';
import { fixHold } from './fix-check.js';
import { warnOnlyUntil } from './policy.js';
import { gateThreats } from './suppressions.js';

/** "1 threat", "2 threats": counts in messages read as words, never "threat(s)". */
export const count = (n: number, noun: string): string => `${n} ${noun}${n === 1 ? '' : 's'}`;

export interface VerdictInput {
  /** The work item being judged; break-glass overrides match it even before any review exists. */
  issueId?: string;
  review: Review | null;
  currentContextHash: string | null;
  threats: Threat[];
  requirements: Requirement[];
  acceptances: Acceptance[];
  policy: SitePolicy;
  projectKey: string;
  championConfirmations: Array<{ reviewId: string; kind: 'review' | 'budget' }>;
  breakGlass: Array<{ issueId: string; until: string }>;
  /** Reviews are paused at the AI budget now: a review that could not run then waits for a champion, not a re-run. */
  budgetPaused: boolean;
  injectionSuspected: boolean;
  now: Date;
  panelUrl: string;
  /**
   * The project's active suppression rule ids, when known. A suppressed threat whose rule is not among them counts as
   * the state it had. Without it, suppressions are still checked against the threshold and their expiry.
   */
  activeSuppressions?: ReadonlySet<string>;
  /** The work item's latest fix check (docs/FIX_CHECK.md): it can hold verified requirements, never release one. */
  fixCheck?: FixCheckRecord | null;
}

const IN_PROGRESS = new Set(['awaiting_agent', 'queued', 'gathering', 'modeling']);
const RESOLVED: ReadonlySet<Requirement['status']> = new Set(['Verified', 'NotApplicable']);

const isActive = (a: Acceptance, now: Date) => a.state === 'active' && now.getTime() < new Date(a.expiresAt).getTime();
/**
 * A re-review or champion triage can raise a requirement's severity under the same id. An acceptance only covers the
 * severity it was approved at: who could approve it and how long it may last both depend on that severity.
 */
export const acceptanceCovers = (a: Pick<Acceptance, 'severity'>, req: Pick<Requirement, 'severity'>) => severityRank(req.severity) <= severityRank(a.severity);

/**
 * The single source of truth both gates read (via the precomputed property). Fails closed: every unknown or
 * in-between state is a block with a reason that says exactly what to do.
 */
export function computeVerdict(i: VerdictInput): Verdict {
  const reasons: BlockReason[] = [];
  const rerun = { label: 'Re-run review', href: `${i.panelUrl}?rerun=1` };
  const updatedAt = i.now.toISOString();
  const threshold = severityRank(i.policy.blockAtOrAbove);
  let blockingCount = 0;
  let maxOpen: Severity | null = null;
  const bump = (s: Severity) => {
    blockingCount++;
    if (maxOpen === null || severityRank(s) > severityRank(maxOpen)) maxOpen = s;
  };

  const r = i.review;
  if (!r) {
    reasons.push({ code: 'no_review', message: 'Threatline has not reviewed this work item yet.', action: { label: 'Run review', href: `${i.panelUrl}?rerun=1` } });
  } else {
    // A review that never ran because reviews were paused is the budget case (a champion can confirm it), not a failure.
    const pausedReview = r.status === 'failed' && r.failureReason === 'budget';
    if (r.status === 'failed' && !pausedReview) reasons.push({ code: 'review_failed', message: `The security review failed${r.failureReason ? ` (${r.failureReason})` : ''}.`, action: rerun });
    else if (r.status === 'agent_timeout') reasons.push({ code: 'agent_missing', message: 'The AI review did not arrive in time, so the review is incomplete.', action: rerun });
    else if (IN_PROGRESS.has(r.status))
      reasons.push({ code: 'agent_missing', message: `Review in progress (${r.samplesReceived} of ${r.samplesExpected} agent runs received).` });

    if (i.currentContextHash === null)
      reasons.push({ code: 'review_stale', message: 'Threatline could not confirm the current design and linked work, so the review may be out of date.', action: rerun });
    else if (i.currentContextHash !== r.contextHash)
      reasons.push({ code: 'review_stale', message: 'The design or linked work changed since the last review.', action: rerun });

    const confirmed = (kind: 'review' | 'budget') => i.championConfirmations.some((c) => c.reviewId === r.id && c.kind === kind);
    // Only work whose review could not run is held by a pause; a review that already ran keeps its own verdict. A
    // champion can confirm only while reviews are paused; once they resume, the way out is to run the review.
    if (pausedReview && !confirmed('budget'))
      reasons.push(
        i.budgetPaused
          ? { code: 'budget_paused', message: 'Reviews are paused at the AI budget. A security champion can confirm this work item.' }
          : { code: 'review_failed', message: 'The security review did not run because reviews were paused at the AI budget. Reviews have resumed, so run it again.', action: rerun },
      );

    const atThreshold = (t: Threat) => severityRank(t.severity) >= threshold;
    // A stored suppression counts only while it still holds (below the current threshold, not expired, rule active).
    const threats = gateThreats(i.threats, { blockAtOrAbove: i.policy.blockAtOrAbove, now: i.now, ...(i.activeSuppressions ? { activeRuleIds: i.activeSuppressions } : {}) });
    const humanOpen = threats.filter((t) => t.state === 'needs_human' && atThreshold(t));
    const reviewConfirmed = confirmed('review');
    if (humanOpen.length > 0 && !reviewConfirmed) {
      const injected = i.injectionSuspected && humanOpen.some((t) => t.origin === 'agent');
      reasons.push({
        code: injected ? 'injection_unconfirmed' : 'needs_human',
        message: injected
          ? `${count(humanOpen.length, 'threat')} came from content that looked like instructions to the AI. A security champion must confirm ${humanOpen.length === 1 ? 'it' : 'them'}.`
          : `${count(humanOpen.length, 'threat')} ${humanOpen.length === 1 ? 'needs' : 'need'} a security champion to confirm ${humanOpen.length === 1 ? 'it' : 'them'}.`,
        requirementIds: humanOpen.map((t) => t.id),
      });
      for (const t of humanOpen) bump(t.severity);
    }

    const mustResolve = threats.filter((t) => atThreshold(t) && (t.state === 'accepted' || (t.state === 'needs_human' && reviewConfirmed)));
    const open: Array<{ id: string; severity: Severity }> = [];
    const outgrown: Array<{ name: string; accepted: Severity; now: Severity }> = [];
    const fixPending: Array<{ id: string; severity: Severity }> = [];
    const fixHeld: Array<{ id: string; severity: Severity }> = [];
    for (const t of mustResolve) {
      const req = i.requirements.find((q) => q.threatId === t.id);
      if (!req) {
        open.push({ id: t.id, severity: t.severity });
        continue;
      }
      if (RESOLVED.has(req.status)) {
        // A verified requirement whose change the fix check could not show fixes it waits for a champion.
        const hold = fixHold(i.fixCheck, req, i.now);
        if (hold?.kind === 'pending') fixPending.push({ id: req.id, severity: req.severity });
        else if (hold) fixHeld.push({ id: req.id, severity: req.severity });
        continue;
      }
      const active = i.acceptances.filter((a) => a.requirementId === req.id && isActive(a, i.now));
      if (active.some((a) => acceptanceCovers(a, req))) continue;
      if (active[0]) outgrown.push({ name: req.subtaskKey ?? `a ${req.severity} requirement`, accepted: active[0].severity, now: req.severity });
      open.push({ id: req.id, severity: req.severity });
    }
    if (open.length > 0) {
      reasons.push({
        code: 'open_requirement',
        message: `${count(open.length, 'open security requirement')} at ${i.policy.blockAtOrAbove} or above.`,
        requirementIds: open.map((o) => o.id),
      });
      // Its own reason (no requirementIds): the gate message appends sub-task keys to the one above.
      for (const o of outgrown)
        reasons.push({
          code: 'open_requirement',
          message: `The risk acceptance for ${o.name} was accepted at ${o.accepted}, but the requirement is now ${o.now}, so it no longer counts. Revoke it and request a new risk acceptance in the Threatline panel.`,
        });
      for (const o of open) bump(o.severity);
    }
    if (fixPending.length > 0) {
      reasons.push({
        code: 'fix_check_pending',
        message: `Threatline is checking whether the pull request fixes ${count(fixPending.length, 'verified requirement')}.`,
        requirementIds: fixPending.map((o) => o.id),
      });
      for (const o of fixPending) bump(o.severity);
    }
    if (fixHeld.length > 0) {
      reasons.push({
        code: 'fix_unconfirmed',
        message: `The pull request does not show it fixes ${count(fixHeld.length, 'verified requirement')}. A security champion must confirm ${fixHeld.length === 1 ? 'it' : 'them'}, or the developer fixes and pushes again.`,
        requirementIds: fixHeld.map((o) => o.id),
      });
      for (const o of fixHeld) bump(o.severity);
    }
  }

  const base = { ...(r ? { reviewId: r.id, revision: r.revision } : {}), blockingCount, maxOpenSeverity: maxOpen, reasons, inheritedFrom: [], updatedAt };
  if (reasons.length === 0) return { state: 'pass', ...base };
  const target = i.issueId ?? r?.issueId;
  const glass = target ? i.breakGlass.filter((b) => b.issueId === target && i.now.getTime() < new Date(b.until).getTime()) : [];
  if (glass.length > 0) {
    const until = Math.max(...glass.map((b) => new Date(b.until).getTime()));
    return { state: 'pass', overridden: true, validUntil: new Date(until).toISOString(), ...base };
  }
  const warnEnd = warnOnlyUntil(i.policy, i.projectKey, i.now);
  return warnEnd ? { state: 'warn', validUntil: warnEnd.toISOString(), ...base } : { state: 'block', ...base };
}

/**
 * A warn-only or break-glass verdict is lenient only until `validUntil`. Once that has passed (or when it cannot be
 * read) the stored verdict no longer holds and must be recomputed before anyone relies on it.
 */
export function verdictLapsed(v: Pick<Verdict, 'state' | 'overridden' | 'validUntil'>, now: Date): boolean {
  if (v.state !== 'warn' && !v.overridden) return false;
  const end = v.validUntil ? Date.parse(v.validUntil) : Number.NaN;
  return Number.isNaN(end) || now.getTime() >= end;
}

/**
 * A child inherits blocks (and warnings) from reviewed ancestors; reasons are prefixed with the ancestor key. An
 * ancestor passing on a break-glass override is lenient too: a child that would pass only holds until that override
 * ends, after which the ancestor blocks again and so must the child.
 */
export function combineVerdicts(own: Verdict, ancestors: Array<{ issueKey: string; verdict: Verdict }>): Verdict {
  const lenientAncestor = ancestors.filter((a) => a.verdict.state !== 'pass' || a.verdict.overridden);
  if (lenientAncestor.length === 0) return own;
  const lenient = [...(own.state === 'warn' || own.overridden ? [own] : []), ...lenientAncestor.map((a) => a.verdict)];
  // Leniency is only as long as its shortest window; a lenient party with no end time cannot be trusted at all.
  const missingEnd = lenient.some((v) => !v.validUntil);
  const anyBlock = own.state === 'block' || lenientAncestor.some((a) => a.verdict.state === 'block') || missingEnd;
  const anyWarn = own.state === 'warn' || lenientAncestor.some((a) => a.verdict.state === 'warn');
  const state = anyBlock ? 'block' : anyWarn ? 'warn' : 'pass';
  // A block lists only what blocks now; an overridden ancestor's reasons are shown while its override is what passes.
  const relevant = state === 'block' ? lenientAncestor.filter((a) => a.verdict.state !== 'pass') : lenientAncestor;
  let maxOpen = own.maxOpenSeverity;
  for (const a of relevant) {
    const s = a.verdict.maxOpenSeverity;
    if (s && (maxOpen === null || severityRank(s) > severityRank(maxOpen))) maxOpen = s;
  }
  const { validUntil: _vu, overridden: _ov, ...rest } = own;
  const windowEnd = anyBlock ? undefined : new Date(Math.min(...lenient.map((v) => new Date(v.validUntil!).getTime()))).toISOString();
  return {
    ...rest,
    ...(windowEnd ? { validUntil: windowEnd } : {}),
    ...(state === 'pass' ? { overridden: true } : {}),
    state,
    reasons: [...own.reasons, ...relevant.flatMap((a) => a.verdict.reasons.map((r) => ({ ...r, message: `${a.issueKey}: ${r.message}` })))],
    inheritedFrom: [...own.inheritedFrom, ...relevant.map((a) => a.issueKey)],
    blockingCount: own.blockingCount + relevant.reduce((n, a) => n + a.verdict.blockingCount, 0),
    maxOpenSeverity: maxOpen,
  };
}

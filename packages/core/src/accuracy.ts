import { severityRank, type Requirement, type Severity, type Threat } from '@threatline/shared';
import type { LedgerEventType, LedgerRow, ReviewThreatRow } from './ports.js';
import { verifiedHours } from './posture.js';

/**
 * "How accurate is Threatline here?" (docs/ACCURACY.md): three figures measured from decisions people and the verifier
 * already made in production, over the last 90 days, on the work items the caller passes in (the caller scopes them to
 * what the viewer can browse). Pure: the ledger, the requirement rows and the latest reviews' threats come in.
 *
 * - Champion agreement: of the threats that waited for a security champion (`needs_human`), the share the champion
 *   said are real (confirmed, split, or dismissed as already mitigated) rather than not real (dismissed as a false
 *   positive or not applicable). Duplicates and merges say nothing either way and are not counted.
 * - Blocking requirements that held up: of the requirements at or above the blocking level that were closed in the
 *   window, the share closed by a fix (Verified with evidence) or an approved risk acceptance, rather than by deciding
 *   Threatline was wrong (the threat dismissed as a false positive or not applicable, or the requirement marked Not
 *   applicable). A threat dismissed as a duplicate or already mitigated closes its requirement without evidence either
 *   way, so it is not counted.
 * - Verifier keep rate: of the AI threats the adversarial verifier judged on each work item's latest settled review in
 *   the window, the share it kept (rather than doubted: dismissed, or sent to a champion when blocking).
 */

export const ACCURACY_WINDOW_DAYS = 90;
/** Below this many decisions a percentage is not shown: only the count ("not enough decisions yet"). */
export const ACCURACY_MIN_DECISIONS = 5;

/** The ledger events the figures read besides the acceptance events (which posture already reads). */
export const ACCURACY_EVENTS = [
  'threat.triaged',
  'threat.triage_failed',
  'review.champion_confirmed',
  'requirement.status_changed',
  'requirement.status_change_failed',
] as const satisfies readonly LedgerEventType[];

const Z95 = 1.959964;

/** The Wilson score interval for `count` successes in `total` trials (95% by default); null when there are none. */
export function wilsonInterval(count: number, total: number, z = Z95): { low: number; high: number } | null {
  if (!Number.isInteger(count) || !Number.isInteger(total) || count < 0 || total < 0 || count > total) throw new RangeError(`invalid proportion ${count}/${total}`);
  if (total === 0) return null;
  const p = count / total;
  const z2 = z * z;
  const denom = 1 + z2 / total;
  const centre = (p + z2 / (2 * total)) / denom;
  const margin = (z * Math.sqrt((p * (1 - p)) / total + z2 / (4 * total * total))) / denom;
  return { low: Math.max(0, centre - margin), high: Math.min(1, centre + margin) };
}

/** A share with its 95% interval. `share`, `low` and `high` are null below ACCURACY_MIN_DECISIONS, so nobody quotes 2 of 2 as 100%. */
export interface Rate {
  n: number;
  share: number | null;
  low: number | null;
  high: number | null;
  enough: boolean;
}

const round4 = (x: number) => Math.round(x * 10_000) / 10_000;

export function rate(count: number, total: number): Rate {
  const enough = total >= ACCURACY_MIN_DECISIONS;
  const ci = enough ? wilsonInterval(count, total) : null;
  return { n: total, share: enough ? round4(count / total) : null, low: ci ? round4(ci.low) : null, high: ci ? round4(ci.high) : null, enough };
}

export interface ChampionAgreement {
  /** Said to be real: confirmed (accepted or split) or dismissed as already mitigated. */
  confirmed: number;
  /** Dismissed as a false positive or not applicable. */
  dismissed: number;
  /** Decided as a duplicate or merged: neither. */
  notCounted: number;
  rate: Rate;
}

export interface BlockingHeldUp {
  /** Verified with evidence. */
  fixed: number;
  /** Closed by an approved (or approver-free) risk acceptance. */
  accepted: number;
  /** Its threat dismissed as a false positive or not applicable, or the requirement marked Not applicable. */
  dismissed: number;
  /** Its threat dismissed as a duplicate or already mitigated. */
  notCounted: number;
  /** Median hours from creation to verification of the fixed ones; null when there are none. */
  medianHoursToVerify: number | null;
  rate: Rate;
}

export interface VerifierKeep {
  kept: number;
  /** Judged not supported by its quotes: dismissed, or sent to a champion when at or above the blocking level. */
  doubted: number;
  rate: Rate;
}

export interface AccuracyFigures {
  champion: ChampionAgreement;
  blocking: BlockingHeldUp;
  verifier: VerifierKeep;
}

export interface Accuracy extends AccuracyFigures {
  windowDays: number;
  /** Start of the window (ISO). */
  since: string;
  /** The same figures per project, by project key. */
  byProject: Array<AccuracyFigures & { project: string }>;
}

export interface AccuracyItem {
  issueId: string;
  project: string;
  requirements: readonly Requirement[];
}

export interface AccuracyInput {
  now: Date;
  blockAtOrAbove: Severity;
  /** The work items to measure (already scoped to the viewer). Ledger rows and threats of any other work item are ignored. */
  items: readonly AccuracyItem[];
  /** ACCURACY_EVENTS and ACCEPTANCE_EVENTS rows for these work items, any order. */
  ledger: readonly LedgerRow[];
  /** The threats of each work item's latest review, with the review. */
  latest: readonly ReviewThreatRow[];
  /** Threats of older reviews a champion confirmed as a whole in the window, by review id. */
  confirmedThreats?: ReadonlyMap<string, readonly Threat[]>;
}

type Verdict = 'real' | 'not_real' | 'other';
const str = (v: unknown): string => (typeof v === 'string' ? v : '');
const normTitle = (t: string) => t.trim().replace(/\s+/g, ' ').toLowerCase();
/** Dismissal reasons that say Threatline was wrong. */
const NOT_REAL: readonly unknown[] = ['false_positive', 'not_applicable'];

/** What a triage decision says about the threat; null for one that decides nothing (an edit). */
function triageVerdict(p: Record<string, unknown>): Verdict | null {
  switch (p.op) {
    case 'accept':
    case 'split':
      return 'real';
    case 'merge':
      return 'other';
    case 'dismiss':
      return NOT_REAL.includes(p.reason) ? 'not_real' : p.reason === 'already_mitigated' ? 'real' : 'other';
    default:
      return null;
  }
}

/** Champion agreement, one decision per threat per work item; tagged with the work item for the per-project split. */
function championDecisions(rows: readonly LedgerRow[], since: number, allowed: ReadonlySet<string>, threatsOf: (reviewId: string) => readonly Threat[]): Array<{ issueId: string; verdict: Verdict }> {
  // A threat is one decision on a work item however many revisions raise it: same threat id, or same title (a re-run
  // gives the threat a new id but the same title), or a title an edit renamed it to.
  const byThreat = new Map<string, string>();
  const byTitle = new Map<string, string>();
  const keyOf = (issueId: string, threatId: string, title: string) => {
    const k = byThreat.get(`${issueId}|${threatId}`) ?? byTitle.get(`${issueId}|${normTitle(title)}`) ?? `${issueId}|${normTitle(title)}`;
    byThreat.set(`${issueId}|${threatId}`, k);
    byTitle.set(`${issueId}|${normTitle(title)}`, k);
    return k;
  };
  const units = new Map<string, { issueId: string; sent: boolean; verdict: Verdict | null }>();
  const unit = (k: string, issueId: string) => units.get(k) ?? (units.set(k, { issueId, sent: false, verdict: null }), units.get(k)!);

  for (const r of rows) {
    const issueId = str(r.payload.issueId);
    if (!allowed.has(issueId) || Date.parse(r.createdAt) < since) continue;
    if (r.eventType === 'threat.triaged') {
      const p = r.payload;
      const k = keyOf(issueId, str(p.threatId), str(p.title));
      const patch = p.patch as { title?: unknown } | undefined;
      if (p.op === 'edit' && typeof patch?.title === 'string') byTitle.set(`${issueId}|${normTitle(patch.title)}`, k);
      const u = unit(k, issueId);
      if (p.from === 'needs_human') u.sent = true;
      const v = triageVerdict(p);
      if (v) u.verdict = v;
    } else if (r.eventType === 'review.champion_confirmed') {
      // "Confirm threats" in the panel: every threat still waiting on that review counts as confirmed by a champion.
      for (const t of threatsOf(str(r.payload.reviewId))) {
        if (t.state !== 'needs_human') continue;
        const u = unit(keyOf(issueId, t.id, t.title), issueId);
        u.sent = true;
        u.verdict = 'real';
      }
    }
  }
  return [...units.values()].filter((u) => u.sent && u.verdict).map((u) => ({ issueId: u.issueId, verdict: u.verdict! }));
}

type Closure = 'fixed' | 'accepted' | 'dismissed' | 'other';

/** When each requirement's risk acceptance took effect (the approval, or the request when no approver was needed). */
function acceptanceTimes(rows: readonly LedgerRow[]): Map<string, number> {
  const reqOf = new Map<string, string>();
  const at = new Map<string, number>();
  const set = (req: string, t: number) => at.set(req, Math.max(at.get(req) ?? -Infinity, t));
  for (const r of rows) {
    const id = str(r.payload.acceptanceId);
    if (!id) continue;
    if (r.eventType === 'acceptance.requested') {
      reqOf.set(id, str(r.payload.requirementId));
      if (r.payload.needsApprover === 'none') set(str(r.payload.requirementId), Date.parse(r.createdAt));
    } else if (r.eventType === 'acceptance.approved') {
      const req = reqOf.get(id) ?? str(r.payload.requirementId);
      if (req) set(req, Date.parse(r.createdAt));
    }
  }
  return at;
}

function blockingClosures(items: readonly AccuracyItem[], rows: readonly LedgerRow[], since: number, block: Severity): Array<{ issueId: string; closure: Closure; hours: number | null }> {
  const accepted = acceptanceTimes(rows);
  const notApplicableAt = new Map<string, number>();
  const lastTriage = new Map<string, LedgerRow>();
  for (const r of rows) {
    if (r.eventType === 'requirement.status_changed') {
      const req = str(r.payload.requirementId);
      if (r.payload.to === 'NotApplicable') notApplicableAt.set(req, Date.parse(r.createdAt));
      else notApplicableAt.delete(req);
    }
    if (r.eventType === 'threat.triaged' && triageVerdict(r.payload)) lastTriage.set(`${str(r.payload.issueId)}|${str(r.payload.threatId)}`, r);
  }
  const out: Array<{ issueId: string; closure: Closure; hours: number | null }> = [];
  for (const it of items) {
    for (const q of it.requirements) {
      if (severityRank(q.severity) < severityRank(block)) continue;
      const add = (closure: Closure, at: number, hours: number | null = null) => {
        if (at >= since) out.push({ issueId: it.issueId, closure, hours });
      };
      if (q.status === 'Verified') {
        if (q.evidence && q.verifiedAt) add('fixed', Date.parse(q.verifiedAt), verifiedHours(q));
      } else if (q.status === 'AcceptedRisk') {
        const at = accepted.get(q.id);
        if (at !== undefined) add('accepted', at);
      } else if (q.status === 'NotApplicable') {
        const at = notApplicableAt.get(q.id);
        if (at !== undefined) add('dismissed', at);
      } else {
        // Still Open: closed only if the threat it stands for was dismissed (the gate no longer counts it).
        const t = lastTriage.get(`${it.issueId}|${q.threatId}`);
        const v = t ? triageVerdict(t.payload) : null;
        if (t && t.payload.op === 'dismiss') add(v === 'not_real' ? 'dismissed' : 'other', Date.parse(t.createdAt));
        else if (t && v === 'other') add('other', Date.parse(t.createdAt));
      }
    }
  }
  return out;
}

function median(xs: number[]): number | null {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
}

function figures(champ: Array<{ verdict: Verdict }>, closures: Array<{ closure: Closure; hours: number | null }>, verdicts: boolean[]): AccuracyFigures {
  const c = (v: Verdict) => champ.filter((x) => x.verdict === v).length;
  const confirmed = c('real');
  const dismissed = c('not_real');
  const k = (x: Closure) => closures.filter((y) => y.closure === x).length;
  const fixed = k('fixed');
  const accepted = k('accepted');
  const wrong = k('dismissed');
  const kept = verdicts.filter(Boolean).length;
  const hours = closures.filter((x) => x.closure === 'fixed' && x.hours !== null).map((x) => x.hours!);
  return {
    champion: { confirmed, dismissed, notCounted: c('other'), rate: rate(confirmed, confirmed + dismissed) },
    blocking: { fixed, accepted, dismissed: wrong, notCounted: k('other'), medianHoursToVerify: median(hours), rate: rate(fixed + accepted, fixed + accepted + wrong) },
    verifier: { kept, doubted: verdicts.length - kept, rate: rate(kept, verdicts.length) },
  };
}

/** The three figures over `items`, overall and per project. */
export function accuracySummary(i: AccuracyInput): Accuracy {
  const since = i.now.getTime() - ACCURACY_WINDOW_DAYS * 86_400_000;
  const projectOf = new Map(i.items.map((x) => [x.issueId, x.project]));
  const allowed = new Set(projectOf.keys());
  // A recorded decision that then failed to save did not happen: drop it.
  const voided = new Set(
    i.ledger.filter((r) => r.eventType === 'threat.triage_failed' || r.eventType === 'requirement.status_change_failed').map((r) => str(r.payload.failedEntryHash)),
  );
  const rows = i.ledger.filter((r) => allowed.has(str(r.payload.issueId)) && !voided.has(r.entryHash)).sort((a, b) => a.seq - b.seq);

  const byReview = new Map<string, Threat[]>();
  for (const x of i.latest) {
    if (!allowed.has(x.review.issueId)) continue;
    const list = byReview.get(x.review.id) ?? [];
    list.push(x.threat);
    byReview.set(x.review.id, list);
  }
  const threatsOf = (reviewId: string) => byReview.get(reviewId) ?? i.confirmedThreats?.get(reviewId) ?? [];

  const champ = championDecisions(rows, since, allowed, threatsOf);
  const closures = blockingClosures(i.items, rows, since, i.blockAtOrAbove);
  const verdicts = i.latest
    .filter((x) => allowed.has(x.review.issueId) && x.review.status === 'ready' && Date.parse(x.review.createdAt) >= since && x.threat.verification && x.threat.state !== 'suppressed')
    .map((x) => ({ issueId: x.review.issueId, keep: x.threat.verification!.keep }));

  const projects = [...new Set(projectOf.values())].sort();
  const inProject = (p: string) => (x: { issueId: string }) => projectOf.get(x.issueId) === p;
  return {
    windowDays: ACCURACY_WINDOW_DAYS,
    since: new Date(since).toISOString(),
    ...figures(champ, closures, verdicts.map((v) => v.keep)),
    byProject: projects.map((p) => ({ project: p, ...figures(champ.filter(inProject(p)), closures.filter(inProject(p)), verdicts.filter(inProject(p)).map((v) => v.keep)) })),
  };
}

import { severityRank, type DismissReason, type Result, type Severity, type Stride, type SuppressionRule, type SuppressionStatus, type Threat } from '@threatline/shared';
import { similar } from './threats/cluster.js';
import { normalizeText } from './threats/text.js';
import type { DismissalRow } from './ports.js';

/** Dismissals this recent count towards a suggestion. */
export const SUPPRESSION_WINDOW_DAYS = 90;
/** A kind of threat dismissed (with a reason) on this many different work items of a project suggests a rule. */
export const SUPPRESSION_MIN_WORK_ITEMS = 3;
/** At most this many active rules per project: an assembly reads them all. */
export const SUPPRESSION_MAX_ACTIVE_PER_PROJECT = 50;

export interface SuppressionEnd {
  by: string;
  at: string;
  reason?: string;
}

export interface SuppressionRepo {
  /** Inserts a rule; an id already taken is a `conflict` (never an overwrite). */
  create(r: SuppressionRule): Promise<Result<void>>;
  get(id: string): Promise<Result<SuppressionRule | null>>;
  /** Rules in these statuses, newest first, at most `limit` (capped at 500). */
  list(statuses: readonly SuppressionStatus[], limit: number): Promise<Result<SuppressionRule[]>>;
  /** What an assembly applies: the project's active rules not expired at `nowIso`, oldest first, at most 100. */
  activeFor(projectKey: string, nowIso: string): Promise<Result<SuppressionRule[]>>;
  /** Compare-and-set: moves the rule from `from` to `to` (recording who ended it); true when it was written. */
  transition(id: string, from: SuppressionStatus, to: SuppressionStatus, end?: SuppressionEnd): Promise<Result<boolean>>;
  /** Idempotent: the rule hid a threat on this work item. */
  recordMatch(ruleId: string, issueId: string, issueKey: string, at: string): Promise<Result<void>>;
  /** How many work items each rule has hidden a threat on (rules with none are left out). */
  matchCounts(ruleIds: readonly string[]): Promise<Result<Record<string, number>>>;
  /** Idempotent: a champion unhid this rule's threats on this work item, so its later reviews show them too. */
  unhide(ruleId: string, issueId: string, issueKey: string, by: string, at: string): Promise<Result<void>>;
  /** The rules unhidden on this work item. */
  unhiddenOn(issueId: string): Promise<Result<string[]>>;
}

/** What an assembly needs of a rule. */
export type ActiveSuppression = Pick<SuppressionRule, 'id' | 'stride' | 'title' | 'component' | 'reason' | 'expiresAt'>;

/** Same STRIDE category and a similar title (the anchor); when the rule names a component, a matching component too. */
export function ruleMatches(rule: Pick<SuppressionRule, 'stride' | 'title' | 'component'>, t: { stride: Stride; title: string; component: string }): boolean {
  return similar(t, { stride: rule.stride, title: rule.title, component: rule.component ?? t.component }, { ignoreComponent: rule.component === undefined });
}

const HIDEABLE: ReadonlySet<Threat['state']> = new Set(['accepted', 'needs_human', 'proposed']);

/**
 * In place, at assembly: a threat that a project rule matches becomes `suppressed` when it is below the blocking
 * threshold. One at or above it is never hidden: it keeps its state and records that the rule matched (`blocking`).
 * A rule a champion unhid on this work item only marks its threats (`unhidden`). Dismissed and covered threats are
 * left alone. Under suspected injection nothing is suppressed: attacker text must never steer what is hidden. Returns
 * the ids of the threats it hid.
 */
export function applySuppressions(
  threats: Threat[],
  rules: readonly ActiveSuppression[],
  o: { blockAtOrAbove: Severity; injectionSuspected: boolean; now: Date; unhidden?: ReadonlySet<string> },
): Set<string> {
  const hidden = new Set<string>();
  for (const t of threats) if (t.state !== 'suppressed' && t.suppression) delete t.suppression;
  if (o.injectionSuspected) return hidden;
  const live = rules.filter((r) => new Date(r.expiresAt).getTime() > o.now.getTime());
  for (const t of threats) {
    if (!HIDEABLE.has(t.state)) continue;
    const rule = live.find((r) => ruleMatches(r, t));
    if (!rule) continue;
    const base = { ruleId: rule.id, reason: rule.reason, expiresAt: rule.expiresAt };
    if (o.unhidden?.has(rule.id)) t.suppression = { ...base, outcome: 'unhidden' };
    else if (severityRank(t.severity) >= severityRank(o.blockAtOrAbove)) t.suppression = { ...base, outcome: 'blocking' };
    else {
      t.suppression = { ...base, outcome: 'hidden', restoreTo: t.state as 'accepted' | 'needs_human' | 'proposed' };
      t.state = 'suppressed';
      hidden.add(t.id);
    }
  }
  return hidden;
}

/**
 * Security, at the gate: a stored suppression is trusted only while it still holds. A `suppressed` threat counts as the
 * state it had (`restoreTo`) once its severity is at or above the current blocking threshold (triage, a re-score, a
 * lowered policy), once its rule's expiry has passed, or (when the caller knows the active rules) once its rule is no
 * longer active. A suppressed threat with no rule recorded is never trusted. Pure; nothing is stored.
 */
export function gateThreats<T extends Threat>(threats: readonly T[], o: { blockAtOrAbove: Severity; now: Date; activeRuleIds?: ReadonlySet<string> }): T[] {
  return threats.map((t) => {
    if (t.state !== 'suppressed') return t;
    const s = t.suppression;
    const holds =
      s !== undefined &&
      s.outcome === 'hidden' &&
      severityRank(t.severity) < severityRank(o.blockAtOrAbove) &&
      new Date(s.expiresAt).getTime() > o.now.getTime() &&
      (o.activeRuleIds === undefined || o.activeRuleIds.has(s.ruleId));
    return holds ? t : { ...t, state: s?.restoreTo ?? 'accepted' };
  });
}

/** A champion unhid it on this work item: the state it had before the rule hid it. */
export function unhidden(t: Threat): Threat {
  if (t.state !== 'suppressed' || !t.suppression) return t;
  const { restoreTo, ...rest } = t.suppression;
  return { ...t, state: restoreTo ?? 'accepted', suppression: { ...rest, outcome: 'unhidden' } };
}

export interface SuppressionSuggestion {
  projectKey: string;
  stride: Stride;
  title: string;
  component?: string;
  workItems: number;
  /** A reason to start from; whoever creates the rule writes their own. */
  suggestedReason: string;
  /** The dismissals behind it, newest first (at most 10). */
  evidence: Array<{ issueKey: string; title: string; reason: DismissReason; actor: string; at: string }>;
}

const REASON_LABEL: Record<DismissReason, string> = {
  false_positive: 'a false positive',
  not_applicable: 'not applicable',
  already_mitigated: 'already mitigated',
  duplicate: 'a duplicate',
  unconfirmed: 'not confirmed by the verifier',
};

const mostCommon = (xs: readonly string[]): string => {
  const n = new Map<string, number>();
  for (const x of xs) n.set(x, (n.get(x) ?? 0) + 1);
  return [...n.entries()].reduce((best, e) => (e[1] > best[1] ? e : best))[0];
};

/**
 * Suggestions from dismissals: in one project, the same kind of threat (STRIDE and a similar title) dismissed with a
 * reason on at least `minWorkItems` different work items. A duplicate is not a judgement on the threat, so it does
 * not count. Kinds an active rule already covers are left out. Deterministic; most work items first.
 */
export function suggestSuppressions(
  dismissals: readonly DismissalRow[],
  active: ReadonlyArray<Pick<SuppressionRule, 'projectKey' | 'stride' | 'title' | 'component'>>,
  o: { minWorkItems?: number; max?: number } = {},
): SuppressionSuggestion[] {
  const min = o.minWorkItems ?? SUPPRESSION_MIN_WORK_ITEMS;
  const rows = dismissals.filter((d) => d.reason !== 'duplicate').sort((a, b) => b.at.localeCompare(a.at) || a.threatId.localeCompare(b.threatId));
  const clusters: Array<{ projectKey: string; members: DismissalRow[] }> = [];
  for (const d of rows) {
    const c = clusters.find((x) => x.projectKey === d.projectKey && x.members.some((m) => similar(m, d, { ignoreComponent: true })));
    if (c) c.members.push(d);
    else clusters.push({ projectKey: d.projectKey, members: [d] });
  }
  const out: SuppressionSuggestion[] = [];
  for (const c of clusters) {
    const items = [...new Set(c.members.map((m) => m.issueId))];
    if (items.length < min) continue;
    const stride = c.members[0]!.stride;
    const title = mostCommon(c.members.map((m) => m.title));
    if (active.some((r) => r.projectKey === c.projectKey && ruleMatches(r, { stride, title, component: c.members[0]!.component }))) continue;
    const components = [...new Set(c.members.map((m) => normalizeText(m.component)))];
    const keys = [...new Set(c.members.map((m) => m.issueKey))];
    const reason = mostCommon(c.members.map((m) => m.reason)) as DismissReason;
    out.push({
      projectKey: c.projectKey,
      stride,
      title,
      ...(components.length === 1 && components[0] ? { component: c.members[0]!.component } : {}),
      workItems: items.length,
      suggestedReason: `Dismissed as ${REASON_LABEL[reason]} on ${items.length} work items (${keys.slice(0, 5).join(', ')}${keys.length > 5 ? ', …' : ''}).`.slice(0, 300),
      evidence: c.members.slice(0, 10).map((m) => ({ issueKey: m.issueKey, title: m.title, reason: m.reason, actor: m.actor, at: m.at })),
    });
  }
  return out.sort((a, b) => b.workItems - a.workItems || a.projectKey.localeCompare(b.projectKey) || a.title.localeCompare(b.title)).slice(0, o.max ?? 20);
}

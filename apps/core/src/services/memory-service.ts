import {
  ACCEPTANCE_EVENTS,
  DEFAULT_INCIDENT_POLICY,
  incidentPolicyOf,
  isIncident,
  matchIncident,
  matchPastThreat,
  MEMORY_MAX_PER_THREAT,
  pullRequestNumber,
  rebuildAcceptances,
  type MemoryIncident,
} from '@threatline/core';
import { severityRank, type IncidentPolicy, type Requirement, type Review, type SitePolicy, type Threat } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import type { JiraIssue } from '../adapters/jira.js';
import { log } from '../adapters/log.js';
import { scopedReview, type Viewer } from '../resolvers/panel.js';
import { newScopeCache, scopeForViewer } from './viewer-scope.js';

/**
 * "Seen before" (docs/MEMORY.md): for each active threat on a work item's latest review, related history from across
 * the site — past incidents (the site's incident rule, as in docs/INCIDENTS.md) and the same threat on other work items'
 * reviews that was verified, accepted as a risk, or dismissed as a false positive. Deterministic matching in
 * @threatline/core (memory.ts); everything here is fetching, bounding, caching and the per-viewer permission filter.
 */

/** Every read is bounded. */
export const MEMORY_LIMITS = {
  /** Incidents linked to the work item or on its components in its project (one JQL search). */
  incidentsNearby: 25,
  /** The most recent incidents anywhere on the site (one JQL search). */
  incidentsRecent: 50,
  /** Incidents and other reviews older than this are not read. */
  windowDays: 365,
  /** Most recently updated ready reviews read for the same threat elsewhere (one SQL query). */
  reviews: 150,
  /** Threat rows read from those reviews (SQL, newest reviews first). */
  threatRows: 1000,
  /** Threats of this review that are matched (most severe first). */
  threatsMatched: 50,
  /** Other work items whose requirements and acceptances are read for the outcome (one SQL query, one ledger read). */
  outcomeItems: 25,
  /** Candidates kept per threat before the viewer's permission filter. */
  perThreatCached: 6,
  /** Other reviews whose sources are checked for the viewer (a same-threat item is shown only if its threat would be). */
  scopedReviews: 10,
  /** How long matches are reused before they are computed again. */
  cacheMs: 15 * 60_000,
} as const;

export type SeenKind = 'incident' | 'verified' | 'accepted' | 'dismissed';

/** One line of history under a threat. `text` follows the key: "Incident · Duplicate refunds… (Sev-2, payments)". */
export interface SeenItem {
  kind: SeenKind;
  key: string;
  text: string;
  /** Why it matched, in one line: "same component payments; shared words: refund, webhook". */
  reason: string;
  /** Incidents: the summary on its own (for the headline). */
  summary?: string;
  /** Accepted risks: when the acceptance ends (YYYY-MM-DD). */
  until?: string;
  /** Verified: the part of `text` that links to the evidence ("PR #41"), and the https link. */
  evidence?: { label: string; url: string };
}

export interface SeenBeforeDto {
  /** By threat id: at most three items each, only threats this viewer can see, only work items they can open. */
  threats: Record<string, SeenItem[]>;
  /** A blocking threat that happened before as an incident: the panel's headline names it. */
  happenedBefore: { key: string; summary: string; threatId: string } | null;
  /** Some history could not be read (a search or query failed); what is shown is still permission-checked. */
  partial?: true;
}

/** Before the viewer filter: the item, and what the filter needs. */
interface Candidate {
  threatId: string;
  score: number;
  issueId: string;
  item: SeenItem;
  /** Same-threat items: the other review and the facts its threat cites (shown only if one is visible to the viewer). */
  source?: { issueId: string; reviewId: string; factIds: string[] };
}
interface Cached {
  v: 1;
  reviewId: string;
  at: string;
  candidates: Candidate[];
}

const cacheKey = (issueId: string) => `memory:v1:${issueId}`;
const ACTIVE: ReadonlySet<Threat['state']> = new Set(['accepted', 'proposed', 'needs_human']);
const KIND_ORDER: Record<SeenKind, number> = { incident: 0, verified: 1, accepted: 2, dismissed: 3 };
const jqlString = (s: string) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
const INCIDENT_FIELDS = ['summary', 'description', 'issuetype', 'labels', 'components', 'project', 'status', 'created', 'priority'];
const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1).trimEnd()}…` : s);

/** "Sev-2" from a sev label or a priority named like one; a priority of High or above by name; otherwise nothing. */
export function incidentSeverity(i: Pick<JiraIssue, 'labels' | 'priority'>): string | null {
  const label = i.labels.map((l) => /^sev[-_ ]?([0-9])$/i.exec(l)).find(Boolean);
  if (label) return `Sev-${label[1]}`;
  const p = i.priority?.trim() ?? '';
  const sev = /^(?:sev|p)[-_ ]?([0-9])\b/i.exec(p);
  if (sev) return /^p/i.test(p) ? `P${sev[1]}` : `Sev-${sev[1]}`;
  return /^(highest|high|critical|blocker|urgent)$/i.test(p) ? p : null;
}

/**
 * Two bounded searches as the app (the viewer filter runs later, per viewer): incidents linked to the work item or on
 * its components in its project, and the most recent incidents anywhere. Jira refuses a JQL naming a work type the site
 * does not have, so a refused search is retried on the labels alone.
 */
async function findIncidents(deps: CoreDeps, issue: JiraIssue, rule: Pick<IncidentPolicy, 'labels' | 'issueTypes'>): Promise<{ incidents: JiraIssue[]; partial: boolean }> {
  const clauses = (types: boolean) => [
    ...(rule.labels.length ? [`labels in (${rule.labels.map(jqlString).join(', ')})`] : []),
    ...(types && rule.issueTypes.length ? [`issuetype in (${rule.issueTypes.map(jqlString).join(', ')})`] : []),
  ];
  const run = async (scope: string, max: number) => {
    for (const types of [true, false]) {
      const match = clauses(types);
      if (match.length === 0) return { ok: true as const, value: [] as JiraIssue[] };
      const jql = `(${match.join(' OR ')}) AND key != ${jqlString(issue.key)} AND created >= -${MEMORY_LIMITS.windowDays}d${scope ? ` AND (${scope})` : ''} ORDER BY created DESC`;
      const r = await deps.jira.search(jql, INCIDENT_FIELDS, max);
      if (r.ok || r.error.code !== 'validation' || !types || rule.issueTypes.length === 0) return r;
    }
    return { ok: true as const, value: [] as JiraIssue[] };
  };
  const nearbyScope = `issue in linkedIssues(${jqlString(issue.key)})${issue.components.length ? ` OR (project = ${jqlString(issue.project.key)} AND component in (${issue.components.map(jqlString).join(', ')}))` : ''}`;
  const [nearby, recent] = await Promise.all([run(nearbyScope, MEMORY_LIMITS.incidentsNearby), run('', MEMORY_LIMITS.incidentsRecent)]);
  const seen = new Map<string, JiraIssue>();
  for (const r of [nearby, recent]) if (r.ok) for (const i of r.value) if (i.id !== issue.id && !seen.has(i.id) && isIncident({ labels: i.labels, issueType: i.issueType.name }, rule)) seen.set(i.id, i);
  return { incidents: [...seen.values()], partial: !nearby.ok || !recent.ok };
}

/** The latest ready review of each other work item updated in the window, newest first, and their threats. */
async function pastThreats(deps: CoreDeps, issueId: string): Promise<{ rows: Array<{ threat: Threat; review: Review }>; partial: boolean }> {
  const since = new Date(deps.clock.now().getTime() - MEMORY_LIMITS.windowDays * 86_400_000).toISOString();
  const recent = await deps.reviews.updatedSince('ready', since, MEMORY_LIMITS.reviews);
  if (!recent.ok) return { rows: [], partial: true };
  const latest = new Map<string, Review>();
  for (const r of recent.value) if (r.issueId !== issueId && (latest.get(r.issueId)?.revision ?? -1) < r.revision) latest.set(r.issueId, r);
  const reviews = [...latest.values()];
  if (reviews.length === 0) return { rows: [], partial: false };
  const threats = await deps.reviews.threatsFor(reviews.map((r) => r.id), ['accepted', 'needs_human', 'dismissed'], MEMORY_LIMITS.threatRows);
  if (!threats.ok) return { rows: [], partial: true };
  const byId = new Map(reviews.map((r) => [r.id, r]));
  // Rule-based threats are the same on every work item of a kind, so "seen before" would be on all of them: AI threats only.
  const rows = threats.value.flatMap((t) => {
    const review = byId.get(t.reviewId);
    if (!review || t.origin === 'baseline') return [];
    if (t.state === 'dismissed' && t.dismissReason !== 'false_positive') return [];
    return [{ threat: t, review }];
  });
  return { rows, partial: false };
}

function evidenceOf(r: Requirement): { text: string; evidence?: SeenItem['evidence'] } {
  const e = r.evidence;
  const https = e && e.ref.startsWith('https://') ? e.ref : null;
  if (!e) return { text: 'Verified' };
  if (e.kind === 'pr') {
    const n = pullRequestNumber(e.ref);
    const label = n ? `PR #${n}` : 'a pull request';
    return { text: `Verified with ${label}`, ...(https ? { evidence: { label, url: https } } : {}) };
  }
  if (e.kind === 'ci') return { text: 'Verified: tests passed in CI', ...(https ? { evidence: { label: 'tests passed in CI', url: https } } : {}) };
  // A Confluence page may be restricted, and a note is free text: neither is repeated here.
  return { text: e.kind === 'test' ? 'Verified with a test' : e.kind === 'confluence' ? 'Verified with a Confluence page' : 'Verified with a note' };
}

/** Matches for every active threat, before any viewer filter. Bounded reads only; never throws. */
async function computeCandidates(deps: CoreDeps, issue: JiraIssue, threats: readonly Threat[], policy: SitePolicy | null): Promise<{ candidates: Candidate[]; partial: boolean }> {
  const rule = policy ? incidentPolicyOf(policy) : DEFAULT_INCIDENT_POLICY;
  const active = threats
    .filter((t) => ACTIVE.has(t.state))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .slice(0, MEMORY_LIMITS.threatsMatched);
  if (active.length === 0) return { candidates: [], partial: false };
  const [inc, past] = await Promise.all([findIncidents(deps, issue, rule).catch(() => ({ incidents: [], partial: true })), pastThreats(deps, issue.id).catch(() => ({ rows: [], partial: true }))]);
  const linked = new Set(issue.links.map((l) => l.issue.id));
  const incidents: Array<{ issue: JiraIssue; m: MemoryIncident }> = inc.incidents.map((i) => ({
    issue: i,
    m: { id: i.id, key: i.key, summary: i.summary, description: i.description.slice(0, 2000), components: i.components, linked: linked.has(i.id) },
  }));

  const out: Candidate[] = [];
  const pastMatches: Array<{ threatId: string; score: number; reason: string; threat: Threat; review: Review }> = [];
  for (const t of active) {
    for (const { issue: i, m } of incidents) {
      const hit = matchIncident(t, issue.components, m);
      if (!hit) continue;
      const tags = [incidentSeverity(i), ...i.components.slice(0, 2)].filter((x): x is string => !!x);
      const summary = clip(i.summary, 120);
      out.push({ threatId: t.id, score: hit.score, issueId: i.id, item: { kind: 'incident', key: i.key, text: `Incident · ${summary}${tags.length ? ` (${tags.join(', ')})` : ''}`, reason: hit.reason, summary } });
    }
    const mine = past.rows.flatMap((p) => {
      const hit = matchPastThreat(t, p.threat);
      return hit ? [{ threatId: t.id, score: hit.score, reason: hit.reason, threat: p.threat, review: p.review }] : [];
    });
    pastMatches.push(...mine.sort((a, b) => b.score - a.score).slice(0, 10));
  }

  // Outcomes: one requirements query and one ledger read for the best-matching other work items.
  const itemIds = [...new Set([...pastMatches].sort((a, b) => b.score - a.score).map((p) => p.review.issueId))].slice(0, MEMORY_LIMITS.outcomeItems);
  let partial = inc.partial || past.partial;
  if (itemIds.length > 0) {
    const [reqs, ledger] = await Promise.all([deps.requirements.forIssues(itemIds), deps.ledger.forIssues(ACCEPTANCE_EVENTS, itemIds)]);
    if (!reqs.ok || !ledger.ok) partial = true;
    const requirements = reqs.ok ? reqs.value : [];
    const acceptances = ledger.ok ? rebuildAcceptances(ledger.value, deps.clock.now()) : [];
    const wanted = new Set(itemIds);
    for (const p of pastMatches) {
      if (!wanted.has(p.review.issueId)) continue;
      const req = requirements.find((r) => r.threatId === p.threat.id && r.issueId === p.review.issueId);
      let kind: SeenKind;
      let text: string;
      let extra: Partial<SeenItem> = {};
      if (p.threat.state === 'dismissed') {
        kind = 'dismissed';
        text = 'same threat · dismissed as a false positive';
      } else if (req?.status === 'Verified') {
        const e = evidenceOf(req);
        kind = 'verified';
        text = `same threat · ${e.text}`;
        if (e.evidence) extra = { evidence: e.evidence };
      } else if (req?.status === 'AcceptedRisk') {
        const a = acceptances.find((x) => x.requirementId === req.id && x.state === 'active');
        if (!a) continue;
        kind = 'accepted';
        extra = { until: a.expiresAt.slice(0, 10) };
        text = `same threat · risk accepted until ${a.expiresAt.slice(0, 10)}`;
      } else continue;
      out.push({
        threatId: p.threatId,
        score: p.score,
        issueId: p.review.issueId,
        item: { kind, key: p.review.issueKey, text, reason: p.reason, ...extra },
        source: { issueId: p.review.issueId, reviewId: p.review.id, factIds: [...new Set(p.threat.citations.map((c) => c.factId))] },
      });
    }
  }

  // Per threat: incidents first, then verified, accepted, dismissed; best match first; one line per work item.
  const kept: Candidate[] = [];
  for (const t of active) {
    const mine = out.filter((c) => c.threatId === t.id).sort((a, b) => KIND_ORDER[a.item.kind] - KIND_ORDER[b.item.kind] || b.score - a.score || a.item.key.localeCompare(b.item.key));
    const keys = new Set<string>();
    for (const c of mine) {
      if (keys.has(c.item.key)) continue;
      keys.add(c.item.key);
      kept.push(c);
      if (keys.size >= MEMORY_LIMITS.perThreatCached) break;
    }
  }
  log('memory.computed', { issueId: issue.id, incidents: incidents.length, pastThreats: past.rows.length, candidates: kept.length, partial });
  return { candidates: kept, partial };
}

/**
 * Security: only what this viewer may open. Work items go through one search as the viewer (`id in (…)`, Jira's own
 * permission and issue-security rules); a same-threat item also needs its threat to be visible to them on that work
 * item (at least one cited source they can read), exactly as that work item's panel would show it. Any failed check
 * hides the item.
 */
async function forViewer(deps: CoreDeps, accountId: string, candidates: readonly Candidate[]): Promise<{ kept: Candidate[]; partial: boolean }> {
  const ids = [...new Set(candidates.map((c) => c.issueId))];
  if (ids.length === 0) return { kept: [], partial: false };
  const allowed = await deps.jira.browsable(accountId, ids).catch(() => null);
  if (!allowed || !allowed.ok) return { kept: [], partial: true };
  const open = new Set(allowed.value);
  const browsable = candidates.filter((c) => open.has(c.issueId));
  const reviewIds = [...new Set([...browsable].filter((c) => c.source).sort((a, b) => b.score - a.score).map((c) => c.source!.reviewId))].slice(0, MEMORY_LIMITS.scopedReviews);
  const cache = newScopeCache();
  const visibleFacts = new Map<string, Set<string>>();
  await Promise.all(
    reviewIds.map(async (reviewId) => {
      const c = browsable.find((x) => x.source?.reviewId === reviewId)!;
      const facts = await deps.reviews.facts(reviewId).catch(() => null);
      if (!facts || !facts.ok) return;
      const scoped = await scopeForViewer(deps, accountId, c.source!.issueId, facts.value, [], cache).catch(() => null);
      if (scoped) visibleFacts.set(reviewId, new Set(scoped.facts.map((f) => f.id)));
    }),
  );
  const kept = browsable.filter((c) => !c.source || c.source.factIds.some((id) => visibleFacts.get(c.source!.reviewId)?.has(id)));
  return { kept, partial: false };
}

const EMPTY: SeenBeforeDto = { threats: {}, happenedBefore: null };

/**
 * Seen before for this viewer on this work item (the caller has checked they may browse it). Computed lazily on panel
 * load (and by explain-threat), cached per work item for MEMORY_LIMITS.cacheMs, filtered per viewer on every call.
 * `onlyThreatId`: just one threat (explain-threat).
 */
export async function seenBefore(deps: CoreDeps, v: Viewer, issue: JiraIssue, onlyThreatId?: string): Promise<SeenBeforeDto> {
  const latest = await deps.reviews.latest(v.issueId);
  if (!latest.ok) return { ...EMPTY, partial: true };
  const review = latest.value;
  if (!review || review.status !== 'ready') return EMPTY;
  const scoped = await scopedReview(deps, v, review.id);
  if (!scoped) return { ...EMPTY, partial: true };
  const visible = new Map(scoped.threats.filter((t) => ACTIVE.has(t.state) && (!onlyThreatId || t.id === onlyThreatId)).map((t) => [t.id, t]));
  if (visible.size === 0) return EMPTY;

  const site = await deps.config.site();
  const policy = site.ok ? site.value : null;
  let candidates: Candidate[] | null = null;
  let partial = false;
  const now = deps.clock.now().getTime();
  const cached = await deps.state.get<Cached>(cacheKey(v.issueId)).catch(() => undefined);
  if (cached?.v === 1 && cached.reviewId === review.id && now - Date.parse(cached.at) < MEMORY_LIMITS.cacheMs && Array.isArray(cached.candidates)) candidates = cached.candidates;
  if (!candidates) {
    // Matched on every active threat of the review (the cache is shared by viewers); shown only for those this viewer sees.
    const all = await deps.reviews.threats(review.id);
    if (!all.ok) return { ...EMPTY, partial: true };
    const computed = await computeCandidates(deps, issue, all.value, policy);
    candidates = computed.candidates;
    partial = computed.partial;
    // A partial result is not reused: the next load tries again.
    if (!computed.partial) await deps.state.set<Cached>(cacheKey(v.issueId), { v: 1, reviewId: review.id, at: new Date(now).toISOString(), candidates }).catch(() => undefined);
  }

  const filtered = await forViewer(deps, v.accountId, candidates.filter((c) => visible.has(c.threatId)));
  const threats: Record<string, SeenItem[]> = {};
  for (const c of filtered.kept) {
    const list = (threats[c.threatId] ??= []);
    if (list.length < MEMORY_MAX_PER_THREAT) list.push(c.item);
  }
  const block = policy?.blockAtOrAbove ?? 'High';
  const happened = filtered.kept
    .filter((c) => c.item.kind === 'incident' && severityRank(visible.get(c.threatId)!.severity) >= severityRank(block))
    .sort((a, b) => severityRank(visible.get(b.threatId)!.severity) - severityRank(visible.get(a.threatId)!.severity) || b.score - a.score)[0];
  return {
    threats,
    happenedBefore: happened ? { key: happened.item.key, summary: happened.item.summary ?? '', threatId: happened.threatId } : null,
    ...(partial || filtered.partial ? { partial: true as const } : {}),
  };
}

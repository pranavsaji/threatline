import { z } from 'zod';
import { ACCEPTANCE_EVENTS, rebuildAcceptances, reviewSignals, riskScore, threatDiff, whatIfScore, type DiscardedThreat, type Role } from '@threatline/core';
import { cweById, getAsvs, type ControlRef } from '@threatline/frameworks';
import { requirementControls } from '@threatline/core';
import { DataClassSchema, ExposureSchema, severityRank, type Acceptance, type DataClass, type Exposure, type Severity, type ContextFact, type Requirement, type Review, type Threat, type Verdict } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import type { JiraIssue } from '../adapters/jira.js';
import { log } from '../adapters/log.js';
import { RERUN_LABEL } from '../triggers/on-issue-change.js';
import { checkRerunLimit } from '../services/rate-limit.js';
import { rolesOf } from '../services/roles.js';
import { readVerdict, refreshVerdict, verdictKey } from '../services/verdict-service.js';
import { newScopeCache, scopeForViewer, type ScopeCache } from '../services/viewer-scope.js';
import { PAGE_KEY } from '../services/confluence-page.js';
import { reopenedBy, type ReopenedBy } from '../services/incident-reopen.js';
import { buildDiagram, type DiagramDto } from '../services/diagram-service.js';
import type { ApiError } from './errors.js';

export const PAGE_SIZE = 50;
const HISTORY_REVISIONS = 5;

/** Who is asking and about which work item: both come from the Forge invocation context, never the payload. */
export interface Viewer {
  accountId: string;
  issueId: string;
}

export interface FactDto {
  id: string;
  sourceType: ContextFact['sourceType'];
  title: string;
  url: string;
  trust: ContextFact['trustLevel'];
  injectionSuspected: boolean;
  injectionReasons: ContextFact['injectionReasons'];
  origin: ContextFact['origin'];
}

export interface PanelDto {
  issueId: string;
  issueKey: string;
  verdict: (Verdict & { panelUrl?: string }) | null;
  review: Review | null;
  threats: Threat[];
  threatsCursor: number | null;
  threatsTotal: number;
  hiddenThreats: number;
  /** Rule-based threats a more specific AI threat covers: not listed on their own, named on the covering threat. */
  covered: Array<{ title: string; coveredBy: string }>;
  /** Listed only when the viewer can see every source of the review (discarded entries do not record their sources). */
  discarded: DiscardedThreat[];
  hiddenDiscarded: number;
  facts: FactDto[];
  requirements: Requirement[];
  /** Per shown requirement, the compliance controls its ASVS ids map to (indicative, not an audit opinion). */
  requirementControls?: Record<string, ControlRef[]>;
  hiddenRequirements: number;
  /** Risk acceptances for the requirements this viewer can see (RL-1). */
  acceptances: Acceptance[];
  /** The caller, so the panel can hide Approve on their own request (the server refuses it anyway). */
  viewerAccountId: string;
  /** What the accept-risk form needs to cap expiry and preview the approver (RL-2). */
  acceptancePolicy: { maxExpiryDays: { Critical: number; default: number }; techLeadMaxSeverity: Severity; championGroup: string; techLeadGroup: string };
  /** `reopenedBy`: an incident caused this revision (docs/INCIDENTS.md); its key is null for a viewer who cannot open it. */
  history: Array<{ revision: number; createdAt: string; riskScore: number; status: Review['status']; added: number; removed: number; reopenedBy?: ReopenedBy }>;
  samples: { received: number; expected: number };
  roles: Role[];
  /** The published Confluence threat-model page, if any (RQ-5). */
  threatModelPage: { url: string } | null;
  /** The data-flow diagram of the latest review, scoped to this viewer (absent before the first review). */
  diagram?: DiagramDto;
}

type Denied = { error: 'not_found' | 'unavailable' | 'rate_limited' };

const bySeverity = (a: Threat, b: Threat) => severityRank(b.severity) - severityRank(a.severity) || b.votes - a.votes || a.title.localeCompare(b.title);

const toFactDto = (f: ContextFact): FactDto => ({
  id: f.id,
  sourceType: f.sourceType,
  title: f.title,
  url: f.url,
  trust: f.trustLevel,
  injectionSuspected: f.injectionSuspected,
  injectionReasons: f.injectionReasons,
  origin: f.origin,
});

/** The work item exists and the viewer may browse (or edit) it. Every resolver starts here. */
export async function authorise(deps: CoreDeps, v: Viewer, need: 'browse' | 'edit'): Promise<{ issueKey: string; issue: JiraIssue } | Denied> {
  if (!v.accountId || !/^\d{1,18}$/.test(v.issueId)) return { error: 'not_found' };
  const issue = await deps.jira.issue(v.issueId);
  if (!issue.ok) return { error: issue.error.code === 'not_found' || issue.error.code === 'forbidden' ? 'not_found' : 'unavailable' };
  const allowed = need === 'browse' ? await deps.jira.canBrowse(v.accountId, v.issueId) : await deps.jira.canEdit(v.accountId, v.issueId);
  if (!allowed.ok) return { error: 'unavailable' };
  return allowed.value ? { issueKey: issue.value.key, issue: issue.value } : { error: 'not_found' };
}

/**
 * The threats the panel lists, in its order (most severe first). A covered rule-based threat is named on the threat
 * covering it, not listed. Every T-n ref (get-review, explain-threat, the panel) numbers this list: T-1 is its first.
 */
export const listedThreats = (sorted: readonly Threat[]): Threat[] => sorted.filter((t) => t.state !== 'covered');
export const threatRef = (index: number): string => `T-${index + 1}`;
/** A threat by id (any the viewer may see) or by T-n ref (into listedThreats). */
export function findThreat(sorted: readonly Threat[], idOrRef: string): Threat | undefined {
  const ref = /^T-(\d+)$/i.exec(idOrRef);
  if (ref) return listedThreats(sorted)[Number(ref[1]) - 1];
  return sorted.find((t) => t.id === idOrRef.toLowerCase());
}

/** Threats and facts the viewer may see, most severe first. */
export async function scopedReview(deps: CoreDeps, v: Viewer, reviewId: string, cache: ScopeCache = newScopeCache()) {
  const [facts, threats] = await Promise.all([deps.reviews.facts(reviewId), deps.reviews.threats(reviewId)]);
  if (!facts.ok || !threats.ok) return null;
  const scoped = await scopeForViewer(deps, v.accountId, v.issueId, facts.value, threats.value, cache);
  return { ...scoped, threats: [...scoped.threats].sort(bySeverity), allThreatIds: threats.value.map((t) => t.id) };
}

/**
 * Security: the risk score as this viewer may see it. The stored score counts every threat and data class, including
 * those from sources the viewer cannot open; when anything is hidden it is recomputed from what they can see (without
 * agent-run data classes, which carry no citations), exactly as panel.whatIf's `current`.
 */
function viewerScore(stored: number, scoped: { threats: Threat[]; facts: ContextFact[]; hiddenFacts: number; hiddenThreats: number }): number {
  if (scoped.hiddenFacts === 0 && scoped.hiddenThreats === 0) return stored;
  return riskScore(scoped.threats, reviewSignals(scoped.facts, []));
}

const HIDDEN_PARENT = 'a parent work item';

/**
 * Security: an inherited reason names its ancestor ("SEC-9: …") and that ancestor's sub-tasks. For an ancestor this
 * viewer cannot browse, the reason says "A parent work item" and drops the ancestor's requirement ids and link; the
 * Done-gate message (built for everyone) is dropped too. A failed check counts as not browsable.
 */
async function scopeVerdict<V extends Verdict & { message?: unknown }>(deps: CoreDeps, accountId: string, verdict: V): Promise<V> {
  const keys = [...new Set(verdict.inheritedFrom)];
  if (keys.length === 0) return verdict;
  const browsable = await Promise.all(keys.map((k) => deps.jira.canBrowse(accountId, k).then((r) => r.ok && r.value, () => false)));
  const hidden = new Set(keys.filter((_, i) => !browsable[i]));
  if (hidden.size === 0) return verdict;
  const { message: _m, ...rest } = verdict;
  return {
    ...rest,
    inheritedFrom: verdict.inheritedFrom.map((k) => (hidden.has(k) ? HIDDEN_PARENT : k)),
    reasons: verdict.reasons.map((r) => {
      const from = [...hidden].find((k) => r.message.startsWith(`${k}: `));
      return from ? { code: r.code, message: `A parent work item you cannot open blocks this (${r.code.replace(/_/g, ' ')}).` } : r;
    }),
  } as V;
}

/** The stored verdict carries the unscoped score (indexed for JQL): the panel's copy gets the viewer's score, or none. */
function viewerVerdict<V extends object>(verdict: V | null, score: number | undefined): V | null {
  if (!verdict || !('riskScore' in verdict)) return verdict;
  const { riskScore: _r, ...rest } = verdict as V & { riskScore: unknown };
  return (score === undefined ? rest : { ...rest, riskScore: score }) as V;
}

export async function panelGet(deps: CoreDeps, v: Viewer): Promise<PanelDto | Denied> {
  const auth = await authorise(deps, v, 'browse');
  if ('error' in auth) return auth;
  const [latest, history, requirements, ledger, policy, stored] = await Promise.all([
    deps.reviews.latest(v.issueId),
    deps.reviews.history(v.issueId),
    deps.requirements.forIssue(v.issueId),
    deps.ledger.forIssues(ACCEPTANCE_EVENTS, [v.issueId]),
    deps.config.site(),
    readVerdict(deps, v.issueId).then((r) => (r.ok ? r.value : undefined)),
  ]);
  const page = await deps.state.get<{ url?: unknown }>(PAGE_KEY(v.issueId)).catch(() => undefined);
  if (!latest.ok || !history.ok || !requirements.ok || !ledger.ok || !policy.ok) return { error: 'unavailable' };
  const review = latest.value;
  let verdict = stored ?? null;
  if (!verdict && review) {
    // No KVS copy yet (reviewed before the mirror existed): compute it once, which also stores it.
    const fresh = await refreshVerdict(deps, v.issueId);
    if (fresh.ok) verdict = (await deps.state.get<Verdict & { panelUrl?: string }>(verdictKey(v.issueId)).catch(() => undefined)) ?? fresh.value;
  }
  if (verdict) verdict = await scopeVerdict(deps, v.accountId, verdict);
  const roles = await rolesOf(deps, v.accountId, v.issueId, policy.value);

  const cache = newScopeCache();
  let threats: Threat[] = [];
  let facts: FactDto[] = [];
  let hiddenThreats = 0;
  let covered: PanelDto['covered'] = [];
  let discarded: DiscardedThreat[] = [];
  let hiddenDiscarded = 0;
  let score = review?.riskScore ?? 0;
  let sketchVisible = false;
  if (review) {
    const scoped = await scopedReview(deps, v, review.id, cache);
    if (!scoped) return { error: 'unavailable' };
    score = viewerScore(review.riskScore, scoped);
    threats = listedThreats(scoped.threats);
    covered = scoped.threats.flatMap((t) => (t.state === 'covered' && t.coveredBy ? [{ title: t.title, coveredBy: t.coveredBy }] : []));
    facts = scoped.facts.map(toFactDto);
    hiddenThreats = scoped.hiddenThreats;
    const d = await deps.reviews.discarded(review.id);
    const all = d.ok ? d.value : [];
    // Discarded entries carry no citations, so they are shown only to a viewer who can see every source.
    sketchVisible = scoped.hiddenFacts === 0;
    if (scoped.hiddenFacts === 0) discarded = all;
    else hiddenDiscarded = all.length;
  }

  // Added/removed per revision count only threats this viewer can see (each revision scoped with its own facts).
  const revisions = history.value.slice(-HISTORY_REVISIONS);
  const scopedRevisions = await Promise.all(revisions.map((r) => scopedReview(deps, v, r.id, cache)));
  if (scopedRevisions.some((x) => x === null)) return { error: 'unavailable' };
  const threatSets = scopedRevisions.map((x) => x!.threats);
  const causes = await reopenedBy(deps, v.accountId, revisions.map((r) => r.id));
  const hist = revisions.map((r, i) => {
    const cur = threatSets[i] ?? [];
    const prev = i > 0 ? (threatSets[i - 1] ?? []) : [];
    const d = threatDiff(prev, cur);
    const cause = causes[i];
    return { revision: r.revision, createdAt: r.createdAt, riskScore: viewerScore(r.riskScore, scopedRevisions[i]!), status: r.status, added: d.added.length, removed: d.removed.length, ...(cause ? { reopenedBy: cause } : {}) };
  });

  // Fail closed: a requirement is shown only when its threat is visible to this viewer in the latest review or in one
  // of the scoped history revisions; everything else (hidden sources, revisions too old to scope) is only counted.
  const visibleThreatIds = new Set([...threats.map((t) => t.id), ...threatSets.flat().map((t) => t.id)]);
  const latestIds = new Set(threats.map((t) => t.id));
  const shownRequirements = requirements.value.filter((r) => (r.status === 'Open' ? latestIds.has(r.threatId) : visibleThreatIds.has(r.threatId)));
  const existingThreatIds = new Set(scopedRevisions.flatMap((x) => x!.allThreatIds));
  const hiddenRequirements = requirements.value.filter((r) => existingThreatIds.has(r.threatId) && !visibleThreatIds.has(r.threatId)).length;
  // Only acceptances of requirements this viewer can see: the reason may describe a source they cannot open.
  const shownIds = new Set(shownRequirements.map((r) => r.id));
  const acceptances = rebuildAcceptances(ledger.value, deps.clock.now()).filter((a) => shownIds.has(a.requirementId));
  const p = policy.value;
  const diagram = review ? await buildDiagram(deps, review.id, { threats, requirements: requirements.value, sketchVisible }) : undefined;

  return {
    issueId: v.issueId,
    issueKey: auth.issueKey,
    verdict: viewerVerdict(verdict, review ? score : undefined),
    review: review ? { ...review, riskScore: score } : null,
    threats: threats.slice(0, PAGE_SIZE),
    threatsCursor: threats.length > PAGE_SIZE ? PAGE_SIZE : null,
    threatsTotal: threats.length,
    hiddenThreats,
    covered,
    discarded,
    hiddenDiscarded,
    facts,
    requirements: shownRequirements,
    requirementControls: Object.fromEntries(shownRequirements.map((r) => [r.id, requirementControls(r)])),
    hiddenRequirements,
    acceptances,
    viewerAccountId: v.accountId,
    acceptancePolicy: { maxExpiryDays: p.maxExpiryDays, techLeadMaxSeverity: p.techLeadMaxSeverity, championGroup: p.championGroup, techLeadGroup: p.techLeadGroup },
    history: hist,
    samples: { received: review?.samplesReceived ?? 0, expected: review?.samplesExpected ?? 0 },
    roles,
    threatModelPage: page && typeof page.url === 'string' ? { url: page.url } : null,
    ...(diagram ? { diagram } : {}),
  };
}

export async function panelThreats(deps: CoreDeps, v: Viewer, p: { cursor?: unknown }): Promise<{ threats: Threat[]; cursor: number | null } | Denied> {
  const auth = await authorise(deps, v, 'browse');
  if ('error' in auth) return auth;
  const latest = await deps.reviews.latest(v.issueId);
  if (!latest.ok) return { error: 'unavailable' };
  if (!latest.value) return { threats: [], cursor: null };
  const scoped = await scopedReview(deps, v, latest.value.id);
  if (!scoped) return { error: 'unavailable' };
  const from = Number.isInteger(p.cursor) && (p.cursor as number) >= 0 ? (p.cursor as number) : 0;
  const listed = listedThreats(scoped.threats);
  const page = listed.slice(from, from + PAGE_SIZE);
  return { threats: page, cursor: from + PAGE_SIZE < listed.length ? from + PAGE_SIZE : null };
}

/** (Re-)adds the threatline-review label (visible in Jira; starts the Automation re-run rule) and queues the gather. */
export async function panelRerun(deps: CoreDeps, v: Viewer): Promise<{ ok: true } | Denied> {
  const auth = await authorise(deps, v, 'edit');
  if ('error' in auth) return auth;
  const limit = await checkRerunLimit(deps, v.accountId);
  if (!limit.ok) return { error: limit.error.code === 'budget' ? 'rate_limited' : 'unavailable' };
  // Automation's "Labels changed" trigger only fires on a change, so a label left over from the last re-run is removed first.
  if (auth.issue.labels.includes(RERUN_LABEL)) {
    const removed = await deps.jira.removeLabel(v.issueId, RERUN_LABEL);
    if (!removed.ok) log('panel.rerun.label_failed', { issueId: v.issueId, code: removed.error.code });
  }
  const label = await deps.jira.addLabel(v.issueId, RERUN_LABEL);
  if (!label.ok) log('panel.rerun.label_failed', { issueId: v.issueId, code: label.error.code });
  // The issue trigger ignores the app's own edits, so the gather is queued here as well.
  const pushed = await deps.queue.push([{ kind: 'gather', issueId: v.issueId, reason: 'rerun', actorAccountId: v.accountId }]);
  return pushed.ok ? { ok: true } : { error: 'unavailable' };
}

export interface ThreatExplanation {
  story: string;
  fixes: string[];
  refs: Array<{ framework: string; id: string; title: string; url: string }>;
}

/** "Explain like I'm new": built from the threat's own text and the bundled framework data, no model call. */
export async function threatExplain(deps: CoreDeps, v: Viewer, p: { reviewId?: unknown; threatId?: unknown }): Promise<ThreatExplanation | Denied> {
  if (typeof p.reviewId !== 'string' || typeof p.threatId !== 'string') return { error: 'not_found' };
  const review = await deps.reviews.get(p.reviewId);
  if (!review.ok) return { error: 'unavailable' };
  if (!review.value || review.value.issueId !== v.issueId) return { error: 'not_found' };
  const auth = await authorise(deps, v, 'browse');
  if ('error' in auth) return auth;
  const scoped = await scopedReview(deps, v, review.value.id);
  const t = scoped?.threats.find((x) => x.id === p.threatId);
  if (!t) return { error: 'not_found' };

  const refs: ThreatExplanation['refs'] = [];
  const fixes: string[] = [];
  for (const m of t.mappings) {
    if (m.framework === 'ASVS5') {
      const a = getAsvs(m.refId);
      refs.push({ framework: 'OWASP ASVS 5.0', id: m.refId, title: a?.text ?? m.refId, url: 'https://github.com/OWASP/ASVS/tree/master/5.0' });
      if (a) fixes.push(a.text);
    } else if (m.framework === 'CWE') {
      const n = m.refId.replace(/^CWE-/, '');
      refs.push({ framework: 'CWE', id: m.refId, title: cweById(m.refId)?.title ?? m.refId, url: `https://cwe.mitre.org/data/definitions/${n}.html` });
    } else {
      refs.push({ framework: m.framework === 'LLM10' ? 'OWASP Top 10 for LLM Applications' : 'OWASP Top 10 for Agentic Applications', id: m.refId, title: m.refId, url: 'https://genai.owasp.org/' });
    }
  }
  const sr = t.suggestedRequirement;
  if (sr) fixes.unshift(`${sr.title}: given ${sr.given}, when ${sr.when}, then ${sr.then}.`);
  return { story: [t.plainLanguage, t.scenario].filter(Boolean).join(' '), fixes: fixes.slice(0, 5), refs };
}

/**
 * Teamwork Graph enrichment, run as the viewer (graph is asUser only). The facts reflect what this viewer can see, so
 * they are returned to this viewer only and never stored in the shared review (another viewer may not see them).
 */
export async function panelEnrich(
  deps: CoreDeps,
  v: Viewer & { cloudId: string },
  enricher: { enrich(issueAri: string): Promise<import('@threatline/shared').Result<{ facts: ContextFact[]; partial: boolean; reasons: string[] }>> },
): Promise<{ added: number; partial: boolean; facts: FactDto[] } | Denied> {
  const auth = await authorise(deps, v, 'browse');
  if ('error' in auth) return auth;
  const r = await enricher.enrich(`ari:cloud:jira:${v.cloudId}:issue/${v.issueId}`);
  if (!r.ok) return { added: 0, partial: true, facts: [] };
  const facts = r.value.facts.filter((f) => f.origin === 'graph').map(toFactDto);
  return { added: facts.length, partial: r.value.partial, facts };
}

export interface ThreatBrief {
  id: string;
  title: string;
  stride: Threat['stride'];
  severity: Severity;
  state: Threat['state'];
  component: string;
}
export interface ThreatDiffDto {
  from: number;
  to: number;
  added: ThreatBrief[];
  removed: ThreatBrief[];
  changed: Array<{ before: ThreatBrief; after: ThreatBrief }>;
  unchanged: number;
  /** Threats in the newer revision this viewer cannot see (their sources are restricted); counted, never listed. */
  hidden: number;
  summary: string;
}

const brief = (t: Threat): ThreatBrief => ({ id: t.id, title: t.title, stride: t.stride, severity: t.severity, state: t.state, component: t.component });
const Rev = z.number().int().min(1).max(100_000);
const DiffSchema = z.object({ from: Rev.optional(), to: Rev.optional() }).strip();

function diffSummary(added: number, removed: number, from: number, to: number): string {
  const since = from === to - 1 ? 'since last review' : `since revision ${from}`;
  const head = added === 0 ? `No new threats ${since}` : `${added} new threat${added === 1 ? '' : 's'} ${since}`;
  return removed > 0 ? `${head}; ${removed} no longer raised` : head;
}

/** R7 `panel.diff`: what changed between two revisions of this work item's review (default: the last two), as the viewer may see it. */
export async function panelDiff(deps: CoreDeps, v: Viewer, payload: unknown): Promise<ThreatDiffDto | ApiError> {
  const auth = await authorise(deps, v, 'browse');
  if ('error' in auth) return auth;
  const p = DiffSchema.safeParse(payload ?? {});
  if (!p.success) return { error: 'validation', message: 'Revisions are whole numbers.' };
  const history = await deps.reviews.history(v.issueId);
  if (!history.ok) return { error: 'unavailable' };
  const revs = history.value;
  const to = p.data.to ?? revs.at(-1)?.revision;
  const from = p.data.from ?? (to !== undefined ? revs.filter((r) => r.revision < to).at(-1)?.revision : undefined);
  if (from !== undefined && to !== undefined && from >= to) return { error: 'validation', message: 'Compare an earlier revision with a later one.' };
  const a = revs.find((r) => r.revision === from);
  const b = revs.find((r) => r.revision === to);
  if (!a || !b) return { error: 'not_found' };
  const cache = newScopeCache();
  const [sa, sb] = await Promise.all([scopedReview(deps, v, a.id, cache), scopedReview(deps, v, b.id, cache)]);
  if (!sa || !sb) return { error: 'unavailable' };
  const d = threatDiff(sa.threats, sb.threats);
  return {
    from: a.revision,
    to: b.revision,
    added: d.added.map(brief),
    removed: d.removed.map(brief),
    changed: d.changed.map((c) => ({ before: brief(c.before), after: brief(c.after) })),
    unchanged: d.unchanged.length,
    hidden: sb.hiddenThreats,
    summary: diffSummary(d.added.length, d.removed.length, a.revision, b.revision),
  };
}

const WhatIfSchema = z
  .object({
    exposure: ExposureSchema.optional(),
    dataClasses: z.array(DataClassSchema).max(10).optional(),
  })
  .strip();

export interface WhatIfDto {
  /** The score as this viewer sees the review now, and with the change. */
  current: number;
  riskScore: number;
  signals: { exposure: Exposure; dataClasses: DataClass[] };
  /** The review's own exposure and data classes, to start the controls from. */
  baseline: { exposure: Exposure; dataClasses: DataClass[] };
  /** True when sources this viewer cannot open were left out of the estimate. */
  partial: boolean;
}

/**
 * R12 `panel.whatIf`: re-scores the latest review with a different exposure or data classes. Nothing is saved. Scored
 * from what this viewer may see (threats and facts scoped to them), so it never reveals restricted sources.
 */
export async function panelWhatIf(deps: CoreDeps, v: Viewer, payload: unknown): Promise<WhatIfDto | ApiError> {
  const auth = await authorise(deps, v, 'browse');
  if ('error' in auth) return auth;
  const p = WhatIfSchema.safeParse(payload ?? {});
  if (!p.success) return { error: 'validation', message: 'Exposure is internal, partner or public; data classes are pii, credentials, payment, health or secrets.' };
  const latest = await deps.reviews.latest(v.issueId);
  if (!latest.ok) return { error: 'unavailable' };
  if (!latest.value) return { error: 'not_found' };
  const [scoped, samples] = await Promise.all([scopedReview(deps, v, latest.value.id), deps.reviews.samples(latest.value.id)]);
  if (!scoped || !samples.ok) return { error: 'unavailable' };
  const s = reviewSignals(scoped.facts, scoped.hiddenFacts > 0 ? [] : samples.value);
  const baseline = { exposure: s.exposure, dataClasses: [...s.dataClasses] };
  const w = whatIfScore(scoped.threats, baseline, p.data);
  return { current: w.current, riskScore: w.riskScore, signals: w.signals, baseline, partial: scoped.hiddenFacts > 0 };
}

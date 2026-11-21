import { similar, type NeedsHumanRow } from '@threatline/core';
import { appError, err, ok, severityRank, type ContextFact, type Result, type Severity, type Stride, type Threat } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { authorise, scopedReview } from '../resolvers/panel.js';
import { applyTriage, triageable, type TriageOp } from './triage-service.js';
import { newScopeCache, scopeForViewer } from './viewer-scope.js';

/** Needs-human threats read per inbox build (the indexed query's bound); more is reported as truncated. */
export const INBOX_SCAN = 500;
/** Rows per page by default (a cluster is never split, so a page can run over by one cluster). */
export const INBOX_PAGE = 50;
export const INBOX_PAGE_MAX = 100;
/** Decisions per request; the UI sends a larger selection in batches. */
export const INBOX_DECIDE_MAX = 25;
const PARALLEL = 10;

export type InboxReasonCode = 'verifier_doubt' | 'duplicate' | 'injection' | 'weak_evidence' | 'needs_review';

export interface InboxRow {
  threatId: string;
  reviewId: string;
  issueId: string;
  issueKey: string;
  /** Filled in for the rows of the page being returned. */
  summary: string;
  url: string;
  title: string;
  plainLanguage: string;
  stride: Stride;
  severity: Severity;
  /** Why a person has to decide it. */
  reasons: Array<{ code: InboxReasonCode; message: string }>;
  /** The threat the verifier says this one repeats, when the viewer can see it. */
  duplicateOf: { threatId: string; title: string } | null;
  /** When the review that raised it started: the inbox's age. */
  raisedAt: string;
}

/** Rows a champion can decide at once: one threat, the verifier's duplicates on one work item, or similar threats across work items. */
export interface InboxCluster {
  id: string;
  kind: 'single' | 'duplicate' | 'similar';
  rows: InboxRow[];
}

export interface Inbox {
  clusters: InboxCluster[];
  /** Rows the viewer can see (the count badge). */
  total: number;
  /** Waiting threats on work items the viewer can browse that rest only on sources they cannot open: counted, never shown. */
  hidden: number;
  truncated: boolean;
}

const projectOf = (issueKey: string) => issueKey.slice(0, Math.max(0, issueKey.lastIndexOf('-')));

const byUrgency = (a: InboxRow, b: InboxRow) =>
  severityRank(b.severity) - severityRank(a.severity) || a.raisedAt.localeCompare(b.raisedAt) || a.issueKey.localeCompare(b.issueKey, 'en', { numeric: true }) || a.threatId.localeCompare(b.threatId);

async function inChunks<T, R>(xs: readonly T[], f: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  for (let i = 0; i < xs.length; i += PARALLEL) out.push(...(await Promise.all(xs.slice(i, i + PARALLEL).map(f))));
  return out;
}

function reasonsFor(t: Threat, facts: ReadonlyMap<string, ContextFact>, dupTitle: string | undefined): InboxRow['reasons'] {
  const out: InboxRow['reasons'] = [];
  const v = t.verification;
  if (v?.duplicateOf)
    out.push({ code: 'duplicate', message: `The verifier says it repeats ${dupTitle ? `“${dupTitle}”` : 'another threat on this work item'}: ${v.reason}` });
  else if (v && !v.keep) out.push({ code: 'verifier_doubt', message: `The verifier doubted it: ${v.reason}` });
  if (t.citations.some((c) => facts.get(c.factId)?.injectionSuspected))
    out.push({ code: 'injection', message: 'It rests on text that looked like instructions to an AI, so Threatline will not settle it by itself.' });
  if (t.grounding === 'weak') out.push({ code: 'weak_evidence', message: 'Its quotes were not all found word for word in the sources.' });
  if (out.length === 0) out.push({ code: 'needs_review', message: 'Threatline could not settle it by itself.' });
  return out;
}

/** The waiting threats of one review that this viewer may see, as rows; the rest are counted as hidden. */
async function rowsOfReview(deps: CoreDeps, accountId: string, group: NeedsHumanRow[], cache: ReturnType<typeof newScopeCache>, site: string): Promise<Result<{ rows: InboxRow[]; hidden: number }>> {
  const review = group[0]!.review;
  const facts = await deps.reviews.facts(review.id);
  if (!facts.ok) return facts;
  const waiting = group.map((g) => g.threat);
  const ids = new Set(waiting.map((t) => t.id));
  // The threats the verifier says these repeat, when they are not waiting themselves (their title names the duplicate).
  let targets: Threat[] = [];
  if (waiting.some((t) => t.verification?.duplicateOf && !ids.has(t.verification.duplicateOf))) {
    const all = await deps.reviews.threats(review.id);
    if (!all.ok) return all;
    const wanted = new Set(waiting.map((t) => t.verification?.duplicateOf).filter((x): x is string => !!x));
    targets = all.value.filter((t) => wanted.has(t.id) && !ids.has(t.id));
  }
  // Security: the panel's rule. Citations to sources the viewer cannot open are dropped, and a threat left without one is hidden.
  const scoped = await scopeForViewer(deps, accountId, review.issueId, facts.value, [...waiting, ...targets], cache);
  const shown = new Map(scoped.threats.map((t) => [t.id, t]));
  const factsById = new Map(scoped.facts.map((f) => [f.id, f]));
  const rows: InboxRow[] = [];
  for (const raw of waiting) {
    const t = shown.get(raw.id);
    if (!t) continue;
    const dupId = t.verification?.duplicateOf;
    const dup = dupId ? shown.get(dupId) : undefined;
    rows.push({
      threatId: t.id,
      reviewId: review.id,
      issueId: review.issueId,
      issueKey: review.issueKey,
      summary: '',
      url: `${site}/browse/${review.issueKey}`,
      title: t.title,
      plainLanguage: t.plainLanguage,
      stride: t.stride,
      severity: t.severity,
      reasons: reasonsFor(t, factsById, dup?.title),
      duplicateOf: dup ? { threatId: dup.id, title: dup.title } : null,
      raisedAt: review.createdAt,
    });
  }
  return ok({ rows, hidden: waiting.length - rows.length });
}

/**
 * Groups rows a champion should decide together: a threat and the one the verifier says it repeats (same review), and
 * similar threats (packages/core `similar`, as prior dismissals match) on different work items.
 */
function cluster(rows: readonly InboxRow[], threats: ReadonlyMap<string, Pick<Threat, 'stride' | 'title' | 'component' | 'verification'>>): InboxCluster[] {
  const parent = rows.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i]!)));
  const join = (a: number, b: number) => (parent[find(a)] = find(b));
  for (let i = 0; i < rows.length; i++)
    for (let j = i + 1; j < rows.length; j++) {
      const a = rows[i]!;
      const b = rows[j]!;
      const ta = threats.get(a.threatId)!;
      const tb = threats.get(b.threatId)!;
      const duplicate = a.reviewId === b.reviewId && (ta.verification?.duplicateOf === b.threatId || tb.verification?.duplicateOf === a.threatId);
      if (duplicate || (a.issueId !== b.issueId && similar(ta, tb, { ignoreComponent: true }))) join(i, j);
    }
  const groups = new Map<number, InboxRow[]>();
  rows.forEach((r, i) => groups.set(find(i), [...(groups.get(find(i)) ?? []), r]));
  const clusters = [...groups.values()].map((g): InboxCluster => {
    const sorted = [...g].sort(byUrgency);
    const kind = sorted.length === 1 ? 'single' : new Set(sorted.map((r) => r.issueId)).size > 1 ? 'similar' : 'duplicate';
    return { id: sorted[0]!.threatId, kind, rows: sorted };
  });
  return clusters.sort((a, b) => byUrgency(a.rows[0]!, b.rows[0]!));
}

/**
 * The champion inbox for one viewer (the caller has checked they are a champion or an admin): every needs-human threat
 * on the latest, settled review of work items in enabled projects that the viewer can browse, without the ones resting
 * only on sources they cannot open. Reads one bounded, indexed query plus the facts of the reviews it found.
 */
export async function buildInbox(deps: CoreDeps, accountId: string, opts: { scan?: number } = {}): Promise<Result<Inbox>> {
  const scan = opts.scan ?? INBOX_SCAN;
  const policy = await deps.config.site();
  if (!policy.ok) return policy;
  const enabled = new Set(policy.value.enabledProjects);
  const found = await deps.reviews.needsHuman(scan);
  if (!found.ok) return found;
  const candidates = found.value.filter((r) => enabled.has(projectOf(r.review.issueKey)) && triageable(r.review).ok);
  const issueIds = [...new Set(candidates.map((r) => r.review.issueId))];
  const browsable = issueIds.length ? await deps.jira.browsable(accountId, issueIds) : ok<string[]>([]);
  if (!browsable.ok) return browsable;
  const allowed = new Set(browsable.value);
  const byReview = new Map<string, NeedsHumanRow[]>();
  for (const r of candidates) if (allowed.has(r.review.issueId)) byReview.set(r.review.id, [...(byReview.get(r.review.id) ?? []), r]);

  const site = (await deps.siteUrl()).replace(/\/+$/, '');
  const cache = newScopeCache();
  const parts = await inChunks([...byReview.values()], (g) => rowsOfReview(deps, accountId, g, cache, site));
  const rows: InboxRow[] = [];
  let hidden = 0;
  for (const p of parts) {
    if (!p.ok) return p;
    rows.push(...p.value.rows);
    hidden += p.value.hidden;
  }
  const threats = new Map(candidates.map((r) => [r.threat.id, r.threat]));
  return ok({ clusters: cluster(rows, threats), total: rows.length, hidden, truncated: found.value.length >= scan });
}

/** One page of clusters from `cursor` (a cluster index), with each row's current key and summary read from Jira. */
export async function inboxPage(deps: CoreDeps, inbox: Inbox, cursor: number, size: number): Promise<{ clusters: InboxCluster[]; cursor: number | null }> {
  let end = cursor;
  let n = 0;
  while (end < inbox.clusters.length && n < size) n += inbox.clusters[end++]!.rows.length;
  const page = inbox.clusters.slice(cursor, end);
  const ids = [...new Set(page.flatMap((c) => c.rows.map((r) => r.issueId)))];
  const issues = await inChunks(ids, async (id) => [id, await deps.jira.issue(id).catch(() => null)] as const);
  const byId = new Map(issues.flatMap(([id, r]) => (r?.ok ? [[id, r.value] as const] : [])));
  const site = (await deps.siteUrl()).replace(/\/+$/, '');
  const clusters = page.map((c) => ({
    ...c,
    rows: c.rows.map((r) => {
      const i = byId.get(r.issueId);
      return i ? { ...r, issueKey: i.key, summary: i.summary, url: `${site}/browse/${i.key}` } : r;
    }),
  }));
  return { clusters, cursor: end < inbox.clusters.length ? end : null };
}

export type InboxDecision = { op: 'accept' } | Extract<TriageOp, { op: 'dismiss' }>;

/**
 * One inbox decision, authorised and validated exactly as the panel's triage: the viewer can browse the work item (in
 * an enabled project), its latest review is settled, the threat is one they can see on it, and it still waits for a
 * champion. Then the triage service decides it, which ledgers it, keeps its requirement in step and refreshes the
 * verdict. The caller has checked the viewer is a champion or an admin.
 */
export async function decideInboxItem(deps: CoreDeps, accountId: string, enabledProjects: readonly string[], item: { issueId: string; threatId: string }, op: InboxDecision): Promise<Result<Threat>> {
  const v = { accountId, issueId: item.issueId };
  const auth = await authorise(deps, v, 'browse');
  if ('error' in auth) return err(appError(auth.error === 'not_found' ? 'not_found' : 'upstream', 'work item not available'));
  if (!enabledProjects.includes(auth.issue.project.key)) return err(appError('not_found', 'not a Threatline project'));
  const latest = await deps.reviews.latest(item.issueId);
  if (!latest.ok) return latest;
  const review = triageable(latest.value);
  if (!review.ok) return review;
  const [scoped, all] = await Promise.all([scopedReview(deps, v, review.value.id), deps.reviews.threats(review.value.id)]);
  if (!scoped) return err(appError('upstream', 'could not read the review'));
  if (!all.ok) return all;
  const t = scoped.threats.find((x) => x.id === item.threatId);
  if (!t) return err(appError('not_found', 'threat not found'));
  const raw = all.value.find((x) => x.id === t.id)!;
  if (raw.state !== 'needs_human') return err(appError('conflict', 'Someone already decided this threat. Reload the inbox.'));
  const r = await applyTriage(deps, accountId, auth.issue, review.value, all.value, raw, op, new Set(scoped.threats.map((x) => x.id)));
  if (!r.ok) return r;
  return ok(r.value.find((x) => x.id === raw.id) ?? raw);
}

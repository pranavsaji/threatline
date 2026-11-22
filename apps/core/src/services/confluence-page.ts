import { ACCEPTANCE_EVENTS, DEFAULT_OWNER_NOTES, extractOwnerNotes, rebuildAcceptances, renderThreatModel } from '@threatline/core';
import { appError, err, ok, type Result } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { readVerdict } from './verdict-service.js';
import { citesOnlyTheWorkItem } from './viewer-scope.js';
import { buildDiagram } from './diagram-service.js';
import { THREAT_MODEL_LINK_PREFIX } from '../adapters/rest-gatherer.js';

/** KVS record of a work item's published threat-model page. Its presence turns on re-publishing (RQ-6). */
export const PAGE_KEY = (issueId: string) => `page:${issueId}`;
export interface PageRecord {
  pageId: string;
  parentId: string;
  url: string;
}

const PAGE_ID = /:page\/(\d{1,20})$/;
const MAX_TITLE = 255;

async function readRecord(deps: Pick<CoreDeps, 'state'>, issueId: string): Promise<PageRecord | null> {
  try {
    const r = await deps.state.get<PageRecord>(PAGE_KEY(issueId));
    return r && typeof r.pageId === 'string' && typeof r.parentId === 'string' ? r : null;
  } catch {
    return null;
  }
}

/** The id of the threat-model page Threatline published for this work item, or null (none, or unreadable). */
export async function ownPageId(deps: Pick<CoreDeps, 'state'>, issueId: string): Promise<string | null> {
  return (await readRecord(deps, issueId))?.pageId ?? null;
}

/** Whether this work item already has a published page (only then do new revisions re-publish automatically). */
export async function isPublished(deps: CoreDeps, issueId: string): Promise<boolean> {
  return (await readRecord(deps, issueId)) !== null;
}

/**
 * The first linked design page: the first Confluence page among the latest review's facts. The caller (resolver) checks
 * the person publishing can read it.
 */
export async function designPageOf(deps: CoreDeps, issueId: string): Promise<Result<string | null>> {
  const existing = await readRecord(deps, issueId);
  if (existing) return ok(existing.parentId);
  const latest = await deps.reviews.latest(issueId);
  if (!latest.ok) return latest;
  if (!latest.value) return ok(null);
  const facts = await deps.reviews.facts(latest.value.id);
  if (!facts.ok) return facts;
  const page = facts.value.find((f) => f.sourceType === 'confluence_page' && PAGE_ID.test(f.sourceAri));
  return ok(page ? PAGE_ID.exec(page.sourceAri)![1]! : null);
}

/**
 * RQ-5 / RQ-6: renders the latest ready review as a child page of the work item's first linked design page, or updates
 * the page published before (version + 1, owner notes kept). A threat whose citations go beyond the work item and that
 * parent page is shown without its text: the page's readers are the parent's readers, not the work item's.
 */
export async function publishThreatModel(deps: CoreDeps, issueId: string): Promise<Result<{ pageId: string; url: string; created: boolean }>> {
  const issue = await deps.jira.issue(issueId);
  if (!issue.ok) return issue;
  const history = await deps.reviews.history(issueId);
  if (!history.ok) return history;
  const ready = [...history.value].reverse().find((r) => r.status === 'ready');
  if (!ready) return err(appError('validation', 'There is no finished review to publish yet.'));
  const latestRevision = Math.max(...history.value.map((r) => r.revision));

  const parentId = await designPageOf(deps, issueId);
  if (!parentId.ok) return parentId;
  if (!parentId.value) return err(appError('validation', 'Link a Confluence design page to this work item first. Threatline publishes the threat model under it.'));

  const [facts, threats, requirements, ledger] = await Promise.all([
    deps.reviews.facts(ready.id),
    deps.reviews.threats(ready.id),
    deps.requirements.forIssue(issueId),
    deps.ledger.forIssues(ACCEPTANCE_EVENTS, [issueId]),
  ]);
  if (!facts.ok) return facts;
  if (!threats.ok) return threats;
  if (!requirements.ok) return requirements;
  if (!ledger.ok) return ledger;
  const read = await readVerdict(deps, issueId);
  const verdict = read.ok ? read.value : undefined;
  const threatIds = new Set(threats.value.map((t) => t.id));
  const reqIds = new Set(requirements.value.map((r) => r.id));
  const site = await deps.siteUrl();
  const panelUrl = `${site}/browse/${issue.value.key}`;
  const title = `Threat model: ${issue.value.key} ${issue.value.summary}`.slice(0, MAX_TITLE);

  // The page's readers are the parent page's readers: threats citing anything else are shown without text, and the
  // architecture sketch (extracted from every source) only when every source is the work item's or that parent page's.
  const redactedThreatIds = threats.value.filter((t) => !citesOnlyTheWorkItem(t, facts.value, issueId, [parentId.value!])).map((t) => t.id);
  const redacted = new Set(redactedThreatIds);
  const allSourcesOpen = citesOnlyTheWorkItem({ citations: facts.value.map((f) => ({ factId: f.id, quote: '' })) }, facts.value, issueId, [parentId.value]);
  const diagram = await buildDiagram(deps, ready.id, {
    threats: threats.value.filter((t) => !redacted.has(t.id)),
    requirements: requirements.value,
    sketchVisible: allSourcesOpen,
  });

  const record = await readRecord(deps, issueId);
  let existing = record ? await deps.confluence.page(record.pageId) : null;
  if (existing && !existing.ok && existing.error.code !== 'not_found') return existing;
  if (existing && !existing.ok) existing = null;

  const render = (ownerNotes: string) =>
    renderThreatModel({
      issueKey: issue.value.key,
      summary: issue.value.summary,
      review: ready,
      latestRevision,
      verdict: verdict && typeof verdict.state === 'string' ? { state: verdict.state, message: typeof verdict.message === 'string' ? verdict.message : '' } : null,
      threats: threats.value,
      // Requirements of this review's threats, plus those already closed out (their threat may be from an older revision).
      requirements: requirements.value.filter((r) => threatIds.has(r.threatId)),
      acceptances: rebuildAcceptances(ledger.value, deps.clock.now()).filter((a) => a.issueId === issueId || reqIds.has(a.requirementId)),
      history: history.value.slice(-10).map((r) => ({ revision: r.revision, createdAt: r.createdAt, riskScore: r.riskScore, status: r.status })),
      panelUrl,
      ownerNotes,
      redactedThreatIds,
      diagram,
      diagramPartial: diagram.sketchHidden,
    });

  if (existing?.ok) {
    let page = existing.value;
    for (let attempt = 0; attempt < 2; attempt++) {
      const u = await deps.confluence.updatePage({ id: page.id, title, version: page.version, storage: render(extractOwnerNotes(page.storage)) });
      if (u.ok) return ok({ pageId: page.id, url: page.url || record!.url, created: false });
      if (u.error.code !== 'conflict') return u;
      // Someone edited the page meanwhile: re-read it so their owner notes are kept, then try once more.
      const again = await deps.confluence.page(page.id);
      if (!again.ok) return again;
      page = again.value;
    }
    return err(appError('conflict', 'The page changed while Threatline was updating it. Try again.'));
  }

  const parent = await deps.confluence.page(parentId.value);
  if (!parent.ok) return parent.error.code === 'not_found' ? err(appError('validation', 'The linked design page no longer exists. Link another one.')) : parent;
  const created = await deps.confluence.createPage({ spaceId: parent.value.spaceId, parentId: parent.value.id, title, storage: render(DEFAULT_OWNER_NOTES) });
  if (!created.ok) return created;
  try {
    await deps.state.set(PAGE_KEY(issueId), { pageId: created.value.id, parentId: parent.value.id, url: created.value.url } satisfies PageRecord);
  } catch (e) {
    log('confluence.publish.record_failed', { issueId, error: e instanceof Error ? e.message : String(e) });
  }
  const link = await deps.jira.addRemoteLink(issueId, { globalId: `${THREAT_MODEL_LINK_PREFIX}${issueId}`, url: created.value.url, title });
  if (!link.ok) log('confluence.publish.link_failed', { issueId, code: link.error.code });
  return ok({ pageId: created.value.id, url: created.value.url, created: true });
}

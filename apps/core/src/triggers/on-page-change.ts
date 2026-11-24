import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import type { ReviewJob } from '../jobs/types.js';
import { ownPageId } from '../services/confluence-page.js';
import { isLicensed, licenseRefusal } from '../services/license.js';

type PageEvent = { content?: { id?: unknown }; page?: { id?: unknown }; atlassianId?: unknown };

/** Confluence page updated: every work item that cites the page is re-gathered, which marks its verdict review_stale. */
export async function onPageChange(deps: CoreDeps, raw: unknown): Promise<void> {
  const e = (raw ?? {}) as PageEvent;
  const id = String(e.content?.id ?? e.page?.id ?? '');
  if (!/^\d{1,20}$/.test(id)) return;
  const issues = await deps.issues.issuesForPage(id);
  if (!issues.ok) {
    log('trigger.page.lookup_failed', { pageId: id });
    return;
  }
  const actor = typeof e.atlassianId === 'string' && e.atlassianId.length <= 128 ? { actorAccountId: e.atlassianId } : {};
  const ids = issues.value.filter((i) => /^\d{1,18}$/.test(i));
  // Threatline's own threat-model page is not context (rest-gatherer.ts): its re-publishing must not re-gather the work
  // item it was published for (links recorded before that rule still map the page to it).
  const own = await Promise.all(ids.map((issueId) => ownPageId(deps, issueId)));
  const jobs: ReviewJob[] = ids.filter((_, n) => own[n] !== id).map((issueId) => ({ kind: 'gather', issueId, reason: 'page_changed', ...actor }));
  if (jobs.length === 0) return;
  // Paid via Atlassian: an inactive license queues no review (docs/LICENSING.md).
  if (!isLicensed(await deps.license.state())) {
    licenseRefusal('trigger.page', { pageId: id });
    return;
  }
  const pushed = await deps.queue.push(jobs);
  if (!pushed.ok) log('trigger.page.push_failed', { pageId: id, code: pushed.error.code });
}

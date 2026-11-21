import { appendLedger, incidentPolicyOf, isIncident } from '@threatline/core';
import { appError, err, ok, type Result } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import type { JiraIssue } from '../adapters/jira.js';
import { log } from '../adapters/log.js';
import { IncidentCauseSchema, type IncidentCause, type ReviewJob } from '../jobs/types.js';
import { monthOf, pauseReasons } from './budget.js';
import { notify } from './notify.js';
import { opsAlert } from './ops-alert.js';
import { checkRerunLimit } from './rate-limit.js';
import { RERUN_LABEL } from '../triggers/on-issue-change.js';

/** The review stage that records why a revision exists (its checkpoint is the IncidentCause). */
export const REOPENED_STAGE = 'reopened_by_incident';
/** The search reads at most this many open work items per incident before filtering (newest first). */
const MAX_SEARCH = 100;
/** Reviews read incidents created in the last 90 days (rest-gatherer), so an older one would not reach them. */
const INCIDENT_WINDOW_MS = 90 * 86_400_000;

type IncidentJob = Extract<ReviewJob, { kind: 'incident' }>;
const claimKey = (incidentId: string, issueId: string) => `incident:reopened:${incidentId}:${issueId}`;
const jqlString = (s: string) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
const upstream = (e: unknown) => err(appError('upstream', `kvs: ${e instanceof Error ? e.message : String(e)}`));
const list = (xs: readonly string[]) => (xs.length <= 1 ? (xs[0] ?? '') : `${xs.slice(0, -1).join(', ')} and ${xs.at(-1)}`);

/**
 * An incident appeared (created, or labelled as one): re-review the open, already reviewed work in enabled projects on
 * its components or linked to it, so their reviews read it as context (docs/INCIDENTS.md).
 *
 * Bounded: one search (open work in the incident's project, newest first, at most 100), at most `maxItems` re-reviews,
 * each work item at most once per incident and within the per-item re-run limit, and never past the month's review
 * budget (what does not fit is not queued, and the admin is alerted). Ledgered before anything is queued. A re-review
 * is an ordinary gather and never queues another fan-out. Only trusted metadata (keys, components) is used here: the
 * incident's text is read by the review itself, fenced as untrusted, and never written into a comment.
 */
export async function reopenForIncident(deps: CoreDeps, job: IncidentJob): Promise<Result<void>> {
  const skip = (reason: string) => (log('incident.skipped', { incidentId: job.issueId, reason }), ok(undefined));
  const policy = await deps.config.site();
  if (!policy.ok) return policy;
  const p = policy.value;
  const rule = incidentPolicyOf(p);
  if (!rule.enabled) return skip('disabled');
  const got = await deps.jira.issue(job.issueId);
  if (!got.ok) return got.error.code === 'not_found' || got.error.code === 'forbidden' ? skip('not_found') : got;
  const inc = got.value;
  if (!p.enabledProjects.includes(inc.project.key)) return skip('project_not_enabled');
  // The event said "incident"; Jira, read now, decides.
  if (!isIncident({ labels: inc.labels, issueType: inc.issueType.name }, rule)) return skip('not_an_incident');
  // Gathers are scoped to the person who caused them; with nobody, the re-review would leave the incident out.
  if (!job.actorAccountId) return skip('no_actor');
  const now = deps.clock.now();
  const created = inc.created ? Date.parse(inc.created) : NaN;
  if (Number.isFinite(created) && now.getTime() - created > INCIDENT_WINDOW_MS) return skip('too_old');
  const linked = new Set(inc.links.map((l) => l.issue.id));
  if (inc.components.length === 0 && linked.size === 0) return skip('no_components_or_links');

  // Reviews read incidents from the work item's own project (rest-gatherer), so the fan-out stays in that project too.
  const scope = `issue in linkedIssues(${jqlString(inc.key)})${inc.components.length ? ` OR component in (${inc.components.map(jqlString).join(', ')})` : ''}`;
  const jql = `project = ${jqlString(inc.project.key)} AND statusCategory != Done AND key != ${jqlString(inc.key)} AND (${scope}) ORDER BY created DESC`;
  const found = await deps.jira.search(jql, ['issuetype', 'labels', 'components', 'project', 'status', 'created'], MAX_SEARCH);
  if (!found.ok) return found;

  const at = now.toISOString();
  const eligible: Array<{ issue: JiraIssue; cause: IncidentCause }> = [];
  let capped = false;
  for (const c of found.value) {
    if (c.id === inc.id || c.status.category === 'done' || c.project.key !== inc.project.key) continue;
    if (!p.reviewIssueTypes.includes(c.issueType.name) || isIncident({ labels: c.labels, issueType: c.issueType.name }, rule)) continue;
    if (eligible.length >= rule.maxItems) {
      capped = true;
      break;
    }
    try {
      if ((await deps.state.get(claimKey(inc.id, c.id))) !== undefined) continue;
    } catch (e) {
      return upstream(e);
    }
    const latest = await deps.reviews.latest(c.id);
    if (!latest.ok) return latest;
    if (!latest.value) continue;
    const components = c.components.filter((x) => inc.components.includes(x)).slice(0, 10);
    eligible.push({ issue: c, cause: { id: inc.id, key: inc.key, components, linked: linked.has(c.id), at } });
  }
  if (eligible.length === 0) return skip('nothing_to_reopen');

  // Budget: re-reviews count like any review. Paused, nothing is queued; otherwise only what the month has room for.
  const reasons = await pauseReasons(deps, p, now);
  if (!reasons.ok) return reasons;
  const paused = reasons.value.budget || reasons.value.credits;
  let room = paused ? 0 : eligible.length;
  if (!paused && p.reviewMode !== 'rules_only') {
    const u = await deps.usage.get(monthOf(now));
    if (!u.ok) return u;
    room = Math.max(0, Math.min(room, p.budget.reviewsPerMonth - u.value.reviews));
  }
  const fits = eligible.slice(0, room);
  const heldForBudget = eligible.length - fits.length;

  // A storm of incidents on one component cannot re-run one work item without end: the per-item re-run limit applies.
  // A limiter that cannot be read does not drop the re-review (the budget still applies), as for label re-runs.
  const toQueue: typeof eligible = [];
  let rateLimited = 0;
  for (const e of fits) {
    const limit = await checkRerunLimit(deps, `incident:${e.issue.id}`);
    if (!limit.ok && limit.error.code === 'budget') rateLimited++;
    else toQueue.push(e);
  }

  // Claim each work item for this incident atomically, so a concurrent or redelivered fan-out does not queue it twice.
  const claimed: typeof eligible = [];
  try {
    for (const e of toQueue) if ((await deps.state.swap(claimKey(inc.id, e.issue.id), at)) === undefined) claimed.push(e);
  } catch (e) {
    await release(deps, inc.id, claimed);
    return upstream(e);
  }

  // Another fan-out for this incident claimed them all first: it ledgers and queues them.
  if (claimed.length === 0 && heldForBudget === 0 && rateLimited === 0) return skip('already_claimed');
  const row = await appendLedger(
    deps.ledger,
    deps.clock,
    'review.reopened_by_incident',
    {
      issueId: inc.id,
      incidentKey: inc.key,
      components: inc.components.slice(0, 10),
      queued: claimed.map((e) => e.issue.key),
      ...(heldForBudget > 0 ? { heldForBudget } : {}),
      ...(rateLimited > 0 ? { rateLimited } : {}),
      ...(capped ? { capped: true } : {}),
    },
    job.actorAccountId,
  );
  if (!row.ok) {
    await release(deps, inc.id, claimed);
    return row;
  }
  if (heldForBudget > 0)
    await opsAlert(
      deps,
      `alert:incident-budget:${inc.id}`,
      `Threatline: incident ${inc.key} touches ${eligible.length} open reviewed work ${eligible.length === 1 ? 'item' : 'items'}, but ${heldForBudget} of them ${heldForBudget === 1 ? 'was' : 'were'} not re-reviewed because reviews are paused at this month's review budget (or the site's Rovo credits). Raise the budget on the Threatline admin page (Budgets), then re-run them from each work item's panel. Recorded in the Threatline ledger (entry ${row.value.seq}).`,
    );
  if (claimed.length === 0) return ok(undefined);

  // Rovo agent mode: the Automation rule runs the agent on a label change (as the panel's Run review does).
  if (p.reviewMode === 'agent')
    for (const e of claimed) {
      if (e.issue.labels.includes(RERUN_LABEL)) await deps.jira.removeLabel(e.issue.id, RERUN_LABEL);
      const l = await deps.jira.addLabel(e.issue.id, RERUN_LABEL);
      if (!l.ok) log('incident.label_failed', { issueId: e.issue.id, code: l.error.code });
    }
  const pushed = await deps.queue.push(claimed.map((e) => ({ kind: 'gather', issueId: e.issue.id, reason: 'incident', actorAccountId: job.actorAccountId, incident: e.cause }) satisfies ReviewJob));
  if (!pushed.ok) {
    await release(deps, inc.id, claimed);
    return pushed;
  }
  if (rule.comment) {
    const where = inc.components.length ? ` (${inc.components.length === 1 ? 'component' : 'components'} ${list(inc.components)})` : '';
    await notify(
      deps,
      inc.id,
      [],
      `Threatline is re-reviewing ${claimed.length} open work ${claimed.length === 1 ? 'item' : 'items'} because of this incident${where}: ${claimed.map((e) => e.issue.key).join(', ')}. Their security reviews will include this incident as context.`,
    );
  }
  log('incident.reopened', { incidentId: inc.id, queued: claimed.length, heldForBudget, rateLimited, capped });
  return ok(undefined);
}

async function release(deps: Pick<CoreDeps, 'state'>, incidentId: string, claimed: ReadonlyArray<{ issue: { id: string } }>): Promise<void> {
  for (const e of claimed) await deps.state.delete(claimKey(incidentId, e.issue.id)).catch(() => log('incident.release_failed', { incidentId }));
}

/** What the panel shows for a revision an incident caused; the key only to a viewer who may open the incident. */
export interface ReopenedBy {
  incidentKey: string | null;
  components: string[];
  linked: boolean;
  at: string;
}

/** For each review id, why it exists when an incident reopened it (null otherwise). A failed read shows no reason. */
export async function reopenedBy(deps: Pick<CoreDeps, 'reviews' | 'jira'>, accountId: string, reviewIds: readonly string[]): Promise<Array<ReopenedBy | null>> {
  const causes = await Promise.all(
    reviewIds.map(async (id) => {
      const s = await deps.reviews.stage(id, REOPENED_STAGE);
      const c = s.ok && s.value ? IncidentCauseSchema.safeParse(s.value.checkpoint) : null;
      return c?.success ? c.data : null;
    }),
  );
  const ids = [...new Set(causes.flatMap((c) => (c ? [c.id] : [])))];
  const browsable = new Set(await Promise.all(ids.map((id) => deps.jira.canBrowse(accountId, id).then((r) => (r.ok && r.value ? id : null), () => null))));
  return causes.map((c) => (c ? { incidentKey: browsable.has(c.id) ? c.key : null, components: c.components, linked: c.linked, at: c.at } : null));
}

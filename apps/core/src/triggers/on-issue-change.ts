import { z } from 'zod';
import { incidentPolicyOf, isIncident } from '@threatline/core';
import type { SitePolicy } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import type { ReviewJob } from '../jobs/types.js';
import { checkRerunLimit } from '../services/rate-limit.js';

export const RERUN_LABEL = 'threatline-review';

const EventSchema = z.object({
  eventType: z.string().optional(),
  atlassianId: z.string().max(128).optional(),
  issue: z.object({
    id: z.string().regex(/^\d{1,18}$/),
    key: z.string().min(1).max(64),
    fields: z.object({
      issuetype: z.object({ name: z.string() }).nullish(),
      project: z.object({ key: z.string() }),
      parent: z.object({ id: z.string() }).nullish(),
      /** Read loosely: an unexpected shape means "not known here", never an ignored event. */
      labels: z.unknown().optional(),
    }),
  }),
  // Items are read with own-property access: a schema key named `toString` would match Object.prototype.toString.
  changelog: z.object({ items: z.array(z.record(z.string(), z.unknown())).nullish() }).nullish(),
});

/** Changelog fields whose change can change the threat model (Jira reports them under varying names). */
const RELEVANT = new Set(['summary', 'description', 'link', 'issuelinks', 'component', 'components', 'labels', 'parent', 'issueparentassociation', 'epic link', 'project', 'key', 'issuekey']);
const MOVED = new Set(['key', 'issuekey', 'project']);
type Item = { field: string; fieldId: string; from: string; to: string };
const own = (o: Record<string, unknown>, k: string): string => (Object.hasOwn(o, k) && typeof o[k] === 'string' ? (o[k] as string) : '');
const toItem = (o: Record<string, unknown>): Item => ({ field: own(o, 'field'), fieldId: own(o, 'fieldId'), from: own(o, 'fromString'), to: own(o, 'toString') });
const names = (i: Item) => [i.field, i.fieldId].filter(Boolean).map((x) => x.toLowerCase());
const words = (s: string) => s.split(/\s+/).filter(Boolean);

/**
 * Incidents reopen reviews (docs/INCIDENTS.md): an incident created, labelled as one, or turned into the incident work
 * type queues one `incident` job, which reads the work item again and decides. A created event that does not carry the
 * labels is checked against Jira here, so ordinary work items queue nothing. Only people's edits reach this trigger (the
 * app's own are ignored), so the re-reviews it causes, and the comment it writes, never come back as another fan-out.
 */
async function incidentJob(deps: CoreDeps, e: z.infer<typeof EventSchema>, items: Item[], policy: SitePolicy, actor: { actorAccountId?: string }): Promise<ReviewJob | null> {
  const rule = incidentPolicyOf(policy);
  if (!rule.enabled) return null;
  const isType = (name: string) => rule.issueTypes.some((t) => t.toLowerCase() === name.trim().toLowerCase());
  const job: ReviewJob = { kind: 'incident', issueId: e.issue.id, ...actor };
  if (e.eventType !== 'avi:jira:created:issue') {
    const match = items.some((i) => {
      if (names(i).includes('labels')) {
        const before = new Set(words(i.from));
        return words(i.to).some((l) => !before.has(l) && rule.labels.includes(l));
      }
      return names(i).includes('issuetype') && isType(i.to) && !isType(i.from);
    });
    return match ? job : null;
  }
  if (isType(e.issue.fields.issuetype?.name ?? '')) return job;
  const raw = e.issue.fields.labels;
  if (Array.isArray(raw) && raw.every((l) => typeof l === 'string')) return raw.some((l) => rule.labels.includes(l)) ? job : null;
  const issue = await deps.jira.issue(e.issue.id);
  if (issue.ok) return isIncident({ labels: issue.value.labels, issueType: issue.value.issueType.name }, rule) ? job : null;
  // Could not tell: the job reads it again (and retries), rather than an incident being missed.
  return issue.error.code === 'not_found' || issue.error.code === 'forbidden' ? null : job;
}

/** Jira issue created/updated trigger: decides whether to queue a review, a verdict refresh, or nothing. Never throws. */
export async function onIssueChange(deps: CoreDeps, raw: unknown): Promise<void> {
  const p = EventSchema.safeParse(raw);
  if (!p.success) {
    log('trigger.issue.ignored', { reason: 'shape' });
    return;
  }
  const e = p.data;
  const items = (e.changelog?.items ?? []).map(toItem);
  const actor = e.atlassianId ? { actorAccountId: e.atlassianId } : {};
  const projectKey = e.issue.fields.project.key;

  // A move changes the key; requirements stay keyed by issue id, so only the issues row needs the new key now.
  if (items.some((i) => names(i).some((n) => MOVED.has(n)))) {
    const r = await deps.issues.upsert({ issueId: e.issue.id, issueKey: e.issue.key, projectKey, ...(e.issue.fields.parent?.id ? { parentId: e.issue.fields.parent.id } : {}) });
    if (!r.ok) log('trigger.issue.upsert_failed', { issueId: e.issue.id });
  }

  const policy = await deps.config.site();
  if (!policy.ok) {
    log('trigger.issue.policy_unavailable', { issueId: e.issue.id });
    return;
  }
  if (!policy.value.enabledProjects.includes(projectKey)) return;

  let job: ReviewJob | null = null;
  if (!policy.value.reviewIssueTypes.includes(e.issue.fields.issuetype?.name ?? '')) job = { kind: 'verdict', issueId: e.issue.id };
  else if (e.eventType === 'avi:jira:created:issue') job = { kind: 'gather', issueId: e.issue.id, reason: 'created', ...actor };
  else {
    const rerun = items.some((i) => names(i).includes('labels') && words(i.to).includes(RERUN_LABEL) && !words(i.from).includes(RERUN_LABEL));
    // A label re-run creates a revision and spends model calls, so one work item can be re-run this way 10 times an
    // hour. The limit is per work item, not per person, so an Automation rule that labels many items at once still
    // re-runs every one of them; the monthly review budget caps total spend. Over the limit it is an ordinary update.
    // A limiter that cannot be read (SQL briefly down, or before the migration that adds it has run) does not drop
    // the re-run: the budget still applies.
    const limit = rerun ? await checkRerunLimit(deps, `label:${e.issue.id}`) : null;
    const allowed = rerun && (limit?.ok || limit?.error.code === 'upstream');
    if (limit && !limit.ok) log(limit.error.code === 'upstream' ? 'trigger.issue.rerun_limit_unavailable' : 'trigger.issue.rerun_limited', { issueId: e.issue.id });
    if (allowed) job = { kind: 'gather', issueId: e.issue.id, reason: 'rerun', ...actor };
    else if (items.some((i) => names(i).some((n) => RELEVANT.has(n)))) job = { kind: 'gather', issueId: e.issue.id, reason: 'updated', ...actor };
  }
  const jobs = [job, await incidentJob(deps, e, items, policy.value, actor)].filter((j): j is ReviewJob => j !== null);
  if (jobs.length === 0) return;
  const pushed = await deps.queue.push(jobs);
  if (!pushed.ok) log('trigger.issue.push_failed', { issueId: e.issue.id, code: pushed.error.code });
}

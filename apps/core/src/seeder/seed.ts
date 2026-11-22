import { appendLedger } from '@threatline/core';
import { appError, err, ok, type Result } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import type { AdfDoc, JiraIssue } from '../adapters/jira.js';
import { log } from '../adapters/log.js';
import { SYSTEM_ACTOR } from '../services/acceptance-service.js';
import { bumpPolicyVersion } from '../services/verdict-service.js';
import { DEMO_COMPONENT, DEMO_LABEL, DESIGN_PAGE_TITLE, designPageStorage, designPageText, EPIC, INCIDENTS, STORIES } from './content/demo.js';

export interface SeedResult {
  epicKey: string;
  storyKeys: string[];
  /** Null on a site without Confluence: the design then goes into the work items' descriptions. */
  designPageUrl: string | null;
  incidentKeys: string[];
  /** Work types added to the policy so the demo items are reviewed (a project without Story uses Task). */
  addedReviewTypes: string[];
}

const adf = (...paragraphs: string[]): AdfDoc => ({
  type: 'doc',
  version: 1,
  content: paragraphs.filter((t) => t.length > 0).map((text) => ({ type: 'paragraph', content: [{ type: 'text', text }] })),
});

/**
 * Loads the demo onto a site (Task 24): an epic with two stories under it, a design page (with one poisoned paragraph)
 * linked from both stories, two recent incidents on the same component, and the project enabled in the policy.
 * Idempotent: items are matched by summary among those labelled `threatline-demo`, the page by title.
 * Confluence is optional for Threatline, so it is for the demo too: without a space key the design (hidden instruction
 * included) goes into the epic's and stories' descriptions instead of a linked page.
 */
export async function seedDemo(deps: CoreDeps, i: { projectKey: string; spaceKey?: string }, actorAccountId?: string): Promise<Result<SeedResult>> {
  const project = await deps.jira.projectInfo(i.projectKey);
  if (!project.ok) return project.error.code === 'not_found' || project.error.code === 'validation' ? err(appError('validation', `Project ${i.projectKey} was not found.`)) : project;
  const space = i.spaceKey ? await deps.confluence.spaceByKey(i.spaceKey) : null;
  if (space && !space.ok) return space.error.code === 'not_found' || space.error.code === 'validation' ? err(appError('validation', `Confluence space ${i.spaceKey} was not found.`)) : space;

  const typeOf = (...names: string[]) => names.map((n) => project.value.issueTypes.find((t) => !t.subtask && t.name.toLowerCase() === n.toLowerCase())).find(Boolean);
  const typeId = (...names: string[]) => typeOf(...names)?.id;
  const epicType = typeId('Epic');
  const storyType = typeOf('Story', 'Task');
  const incidentType = typeId('Incident', 'Bug', 'Task');
  if (!epicType || !storyType || !incidentType) return err(appError('validation', `Project ${i.projectKey} needs Epic and Story (or Task) work types.`));

  const comp = await deps.jira.ensureComponent(project.value.key, DEMO_COMPONENT);
  if (!comp.ok) return comp;

  let pageUrl: string | null = null;
  if (space) {
    const found = await deps.confluence.findPage(space.value.id, DESIGN_PAGE_TITLE);
    if (!found.ok) return found;
    pageUrl = found.value?.url ?? null;
    if (!pageUrl) {
      const created = await deps.confluence.createPage({ spaceId: space.value.id, ...(space.value.homepageId ? { parentId: space.value.homepageId } : {}), title: DESIGN_PAGE_TITLE, storage: designPageStorage() });
      if (!created.ok) return created;
      pageUrl = created.value.url;
    }
  }
  const design = pageUrl ? [] : [`${DESIGN_PAGE_TITLE}.`, ...designPageText()];
  const link = (issueId: string) =>
    pageUrl ? deps.jira.addRemoteLink(issueId, { globalId: `threatline-demo-design-${issueId}`, url: pageUrl, title: DESIGN_PAGE_TITLE }) : Promise.resolve(ok(undefined));

  const existing = await deps.jira.search(`project = ${project.value.key} AND labels = ${DEMO_LABEL}`, ['summary', 'labels', 'issuetype', 'project'], 100);
  if (!existing.ok) return existing;
  const bySummary = new Map<string, JiraIssue>(existing.value.map((x) => [x.summary, x]));
  const ensure = async (summary: string, description: string, issueTypeId: string, extra: { labels?: string[]; parentId?: string; components?: string[]; design?: boolean }) => {
    const found = bySummary.get(summary);
    if (found) return ok({ id: found.id, key: found.key, created: false });
    const c = await deps.jira.createIssue({
      projectId: project.value.id,
      issueTypeId,
      summary,
      description: adf(description, ...(extra.design ? design : [])),
      labels: [DEMO_LABEL, ...(extra.labels ?? [])],
      ...(extra.components ? { components: extra.components } : {}),
      ...(extra.parentId ? { parentId: extra.parentId } : {}),
    });
    return c.ok ? ok({ ...c.value, created: true }) : c;
  };

  const epic = await ensure(EPIC.summary, EPIC.description, epicType, { design: true });
  if (!epic.ok) return epic;
  // The epic links the design page as well, so a review of the epic reads it (and flags its hidden instruction).
  const epicLink = await link(epic.value.id);
  if (!epicLink.ok) return epicLink;
  const storyKeys: string[] = [];
  const reviewIds = [epic.value.id];
  for (const s of STORIES) {
    const story = await ensure(s.summary, s.description, storyType.id, { parentId: epic.value.id, components: [DEMO_COMPONENT], design: true });
    if (!story.ok) return story;
    storyKeys.push(story.value.key);
    reviewIds.push(story.value.id);
    const linked = await link(story.value.id);
    if (!linked.ok) return linked;
  }
  const incidentKeys: string[] = [];
  for (const inc of INCIDENTS) {
    const r = await ensure(inc.summary, inc.description, incidentType, { labels: ['incident'], components: [DEMO_COMPONENT] });
    if (!r.ok) return r;
    incidentKeys.push(r.value.key);
  }

  const policy = await deps.config.site();
  if (!policy.ok) return policy;
  // A project without Story gets Task stories; Threatline reviews only the policy's work types, so add it (otherwise the
  // gate reads "a work type Threatline does not review" and posture leaves the demo out).
  const reviewed = (name: string) => policy.value.reviewIssueTypes.some((t) => t.toLowerCase() === name.toLowerCase());
  const addedReviewTypes = [storyType.name].filter((n) => !reviewed(n));
  if (!policy.value.enabledProjects.includes(project.value.key) || addedReviewTypes.length > 0) {
    // A policy change like any other (admin.setPolicy): ledgered first, then saved, then every stored verdict is marked
    // for a recheck, so the gate stops calling the demo project "not turned on" at once.
    const fields = [...(policy.value.enabledProjects.includes(project.value.key) ? [] : ['enabledProjects']), ...(addedReviewTypes.length > 0 ? ['reviewIssueTypes'] : [])];
    const row = await appendLedger(deps.ledger, deps.clock, 'policy.changed', { fields, source: 'demo', projectKey: project.value.key }, actorAccountId ?? SYSTEM_ACTOR);
    if (!row.ok) return row;
    const set = await deps.config.setSite({
      ...policy.value,
      enabledProjects: policy.value.enabledProjects.includes(project.value.key) ? policy.value.enabledProjects : [...policy.value.enabledProjects, project.value.key],
      reviewIssueTypes: [...policy.value.reviewIssueTypes, ...addedReviewTypes],
    });
    if (!set.ok) return set;
    if (!(await bumpPolicyVersion(deps))) log('seed.policy_version_unbumped', { projectKey: project.value.key });
  }
  // The items were created by the app, and the issue trigger ignores the app's own events: queue their reviews now, as
  // the admin who loaded the demo (that scopes what the review may read), so the panels fill without a manual re-run.
  const q = await deps.queue.push(reviewIds.map((issueId) => ({ kind: 'gather' as const, issueId, reason: 'created' as const, ...(actorAccountId ? { actorAccountId } : {}) })));
  if (!q.ok) return q;
  return ok({ epicKey: epic.value.key, storyKeys, designPageUrl: pageUrl, incidentKeys, addedReviewTypes });
}

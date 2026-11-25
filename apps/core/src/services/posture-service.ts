import { ACCEPTANCE_EVENTS, rebuildAcceptances, verifiedHours, type LedgerEventType, type LedgerRow, type PostureRow } from '@threatline/core';
import { appError, err, ok, type Acceptance, type Requirement, type Result } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import type { JiraIssue } from '../adapters/jira.js';
import { jqlString } from '../actions/schemas.js';

/** Work items read per posture query; more is reported as truncated. */
export const POSTURE_MAX_ITEMS = 200;

/** Who the numbers are for: a person (only work items they can browse) or the app (the leadership digest, counts only). */
export type PostureAudience = { caller: string } | { asApp: true };

export interface PostureItem {
  issue: JiraIssue;
  requirements: Requirement[];
  acceptances: Acceptance[];
}

/**
 * Scale: the ledger events of these types for these work items only (indexed by work item, 100 ids per query), in seq
 * order, instead of every such event on the site. Rows that name no work item come back with every chunk: deduplicated.
 */
export async function ledgerRowsFor(deps: Pick<CoreDeps, 'ledger'>, types: readonly LedgerEventType[], issueIds: readonly string[]): Promise<Result<LedgerRow[]>> {
  const bySeq = new Map<number, LedgerRow>();
  for (let i = 0; i < issueIds.length; i += 100) {
    const r = await deps.ledger.forIssues(types, issueIds.slice(i, i + 100));
    if (!r.ok) return r;
    for (const row of r.value) bySeq.set(row.seq, row);
  }
  return ok([...bySeq.values()].sort((a, b) => a.seq - b.seq));
}

/** The acceptance events of these work items (see ledgerRowsFor). */
export const acceptanceRowsFor = (deps: Pick<CoreDeps, 'ledger'>, issueIds: readonly string[]) => ledgerRowsFor(deps, ACCEPTANCE_EVENTS, issueIds);

export interface PostureScope {
  items: PostureItem[];
  /** The rebuilt acceptances of these work items (callers filter to their items). */
  acceptances: Acceptance[];
  /** The acceptance ledger rows they were rebuilt from (the accuracy figures read when each took effect). */
  acceptanceRows: LedgerRow[];
  truncated: boolean;
}

/** `component` matches a Jira component by name (case-insensitive); "None" means a work item with no component. */
export function componentMatches(issue: JiraIssue, component: string | undefined): boolean {
  if (!component) return true;
  if (component === 'None') return issue.components.length === 0;
  return issue.components.some((c) => c.toLowerCase() === component.toLowerCase());
}

/**
 * The reviewable work items in `projects` (most recently updated first), with their requirements and acceptances.
 * For a person, only work items they can browse; the app audience is for aggregate counts only.
 */
export async function postureScope(deps: CoreDeps, audience: PostureAudience, i: { projects: string[]; reviewIssueTypes: string[]; component?: string }): Promise<Result<PostureScope>> {
  if (i.projects.length === 0 || i.reviewIssueTypes.length === 0) return ok({ items: [], acceptances: [], acceptanceRows: [], truncated: false });
  const jql = `project in (${i.projects.map(jqlString).join(', ')}) AND issuetype in (${i.reviewIssueTypes.map(jqlString).join(', ')}) ORDER BY updated DESC`;
  const found = await deps.jira.search(jql, ['summary', 'issuetype', 'project', 'components'], POSTURE_MAX_ITEMS + 1);
  if (!found.ok) return found;
  const listed = found.value.slice(0, POSTURE_MAX_ITEMS);
  let allowed: Set<string>;
  if ('caller' in audience) {
    const visible = await deps.jira.browsable(audience.caller, listed.map((x) => x.id));
    if (!visible.ok) return visible;
    allowed = new Set(visible.value);
  } else allowed = new Set(listed.map((x) => x.id));
  const issues = listed.filter((x) => allowed.has(x.id) && componentMatches(x, i.component));
  const ledger = await acceptanceRowsFor(deps, issues.map((x) => x.id));
  if (!ledger.ok) return ledger;

  const acceptances = rebuildAcceptances(ledger.value, deps.clock.now());
  const items: PostureItem[] = [];
  for (let n = 0; n < issues.length; n += 20) {
    const chunk = issues.slice(n, n + 20);
    const reqs = await Promise.all(chunk.map((x) => deps.requirements.forIssue(x.id)));
    for (const [k, x] of chunk.entries()) {
      const r = reqs[k]!;
      if (!r.ok) return err(appError('internal', 'could not read requirements'));
      items.push({ issue: x, requirements: r.value, acceptances: acceptances.filter((a) => a.issueId === x.id) });
    }
  }
  return ok({ items, acceptances, acceptanceRows: ledger.value, truncated: found.value.length > POSTURE_MAX_ITEMS });
}

/** Posture rows: the project is the team axis (sites do not share a Team field); the first Jira component is the component. */
export function postureRows(items: readonly PostureItem[]): PostureRow[] {
  return items.map(({ issue, requirements, acceptances }) => ({
    issueKey: issue.key,
    project: issue.project.key,
    team: issue.project.key,
    ...(issue.components[0] ? { component: issue.components[0] } : {}),
    requirements,
    acceptances,
    verifiedDurationsHours: requirements.map(verifiedHours).filter((h): h is number => h !== null),
  }));
}

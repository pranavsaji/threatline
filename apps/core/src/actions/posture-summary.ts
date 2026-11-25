import { postureSummary, type Accuracy } from '@threatline/core';
import type { Severity } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { callerOf, type ActionPayload } from './common.js';
import { splitVisibleAcceptances } from './visibility.js';
import { parseInput, SCHEMAS, type ActionError } from './schemas.js';
import { postureRows, postureScope } from '../services/posture-service.js';
import { accuracyFor } from '../services/accuracy-service.js';

export const EXPIRING_WITHIN_DAYS = 31;

export interface ExpiringAcceptance {
  acceptanceId: string;
  issueKey: string;
  requirementId: string;
  severity: Severity;
  expiresAt: string;
}

export type PostureSummaryResult = ReturnType<typeof postureSummary> & {
  projects: string[];
  team?: string;
  issuesCounted: number;
  /** Active risk acceptances on the counted work items that expire within 31 days, soonest first (only those whose requirement the caller can see). */
  expiring: ExpiringAcceptance[];
  /** Expiring acceptances on requirements the caller cannot see: counted, never listed. */
  hiddenExpiring: number;
  truncated: boolean;
  /**
   * How accurate Threatline has been on these same work items over the last 90 days (docs/ACCURACY.md): champion
   * agreement, blocking requirements that held up, the verifier's keep rate. Each has its counts; the share and its
   * Wilson 95% interval are null below 5 decisions. Null when it could not be read (the rest still stands).
   */
  accuracy: Accuracy | null;
};

/**
 * GET (Agent, MCP): open requirements by severity, expiring acceptances, the riskiest components and how accurate
 * Threatline has been (last 90 days) across the Threatline-enabled projects (or one of them), counting only work items
 * the caller can browse. `team` narrows to a Jira component of that name.
 */
export async function getPostureSummary(payload: ActionPayload & Record<string, unknown>, deps: CoreDeps): Promise<PostureSummaryResult | ActionError> {
  const input = parseInput(SCHEMAS.postureSummary, payload);
  if (!input.ok) return input.error;
  const caller = callerOf(payload);
  if (!caller) return { error: 'not_found' };
  const policy = await deps.config.site();
  if (!policy.ok) return { error: 'unavailable' };
  const p = policy.value;
  const { project, team } = input.value;
  if (project && !p.enabledProjects.includes(project))
    return { error: 'invalid_input', message: `project ${project} is not enabled for Threatline (enabled: ${p.enabledProjects.join(', ') || 'none'})` };
  const projects = project ? [project] : p.enabledProjects;
  const empty = { ...postureSummary([], deps.clock.now()), projects, ...(team ? { team } : {}), issuesCounted: 0, expiring: [], hiddenExpiring: 0, truncated: false, accuracy: null };
  if (projects.length === 0) return empty;

  const scope = await postureScope(deps, { caller }, { projects, reviewIssueTypes: p.reviewIssueTypes, ...(team ? { component: team } : {}) });
  if (!scope.ok) return { error: 'unavailable' };
  const now = deps.clock.now();
  const { acceptances } = scope.value;
  const issues = scope.value.items.map((x) => x.issue);
  const rows = postureRows(scope.value.items);
  const keyOf = new Map(issues.map((x) => [x.id, x.key]));
  const horizon = now.getTime() + EXPIRING_WITHIN_DAYS * 86_400_000;
  const due = acceptances.filter((a) => a.state === 'active' && a.issueId !== undefined && keyOf.has(a.issueId) && new Date(a.expiresAt).getTime() <= horizon);
  const [shown, accuracy] = await Promise.all([splitVisibleAcceptances(deps, caller, due), accuracyFor(deps, scope.value, p.blockAtOrAbove)]);
  if (!accuracy.ok) log('posture.accuracy_failed', { code: accuracy.error.code });
  const hidden = shown.hidden;
  const expiring = shown.visible
    .sort((a, b) => a.expiresAt.localeCompare(b.expiresAt))
    .slice(0, 100)
    .map((a) => ({ acceptanceId: a.id, issueKey: keyOf.get(a.issueId!)!, requirementId: a.requirementId, severity: a.severity, expiresAt: a.expiresAt }));
  log('action.posture', { projects: projects.length, issues: rows.length, expiring: expiring.length });
  return {
    ...postureSummary(rows, now),
    projects,
    ...(team ? { team } : {}),
    issuesCounted: rows.length,
    expiring,
    hiddenExpiring: hidden,
    truncated: scope.value.truncated,
    accuracy: accuracy.ok ? accuracy.value : null,
  };
}

import { z } from 'zod';
import { controlsPosture, controlsSummary, controlsSummaryCsv, requirementsForControl, type ControlsPosture } from '@threatline/core';
import { COMPLIANCE_FRAMEWORKS, complianceControl, type ComplianceFramework } from '@threatline/frameworks';
import { severityRank, type Severity } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import type { ActionError } from '../actions/schemas.js';
import { postureScope, type PostureScope } from '../services/posture-service.js';
import { requireAdmin, type Admin } from './admin.js';
import { apiError, type ApiError } from './errors.js';
import { ExportSchema } from './ledger.js';
import { DRILL_MAX_ITEMS, type DrillDto, type PostureViewer } from './posture.js';

/**
 * Compliance evidence: what Threatline's requirements say about SOC 2, ISO/IEC 27001:2022 and PCI DSS v4.0 controls,
 * through the ASVS 5.0 mapping in @threatline/frameworks. Indicative, not an audit opinion (docs/COMPLIANCE.md).
 */

const OPEN = new Set(['Open', 'InProgress']);

/**
 * `compliance.export` (Jira administrators only): the controls summary for one project and date range, as CSV and JSON.
 * Statuses are as of the export; work items are those the admin can browse (up to the posture limit, `truncated` says so).
 */
export async function complianceExport(deps: CoreDeps, a: Admin, payload: unknown): Promise<{ csv: string; json: string } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const p = ExportSchema.safeParse(payload);
  if (!p.success) return { error: 'validation', message: p.error.issues.slice(0, 2).map((i) => `${i.path.join('.') || 'request'}: ${i.message}`).join('; ') };
  const policy = await deps.config.site();
  if (!policy.ok) return apiError(policy.error);
  const scope = await postureScope(deps, { caller: a.accountId }, { projects: [p.data.projectKey], reviewIssueTypes: policy.value.reviewIssueTypes });
  if (!scope.ok) return apiError(scope.error);
  const summary = controlsSummary({ ...flatten(scope.value), from: p.data.from, to: p.data.to });
  const generatedAt = deps.clock.now().toISOString();
  const json = {
    kind: 'threatline.controls-summary.v1',
    projectKey: p.data.projectKey,
    from: p.data.from,
    to: p.data.to,
    generatedAt,
    rules:
      'A requirement maps to controls through its OWASP ASVS 5.0 ids (chapter, plus section where the mapping adds one). It counts when created on or before "to"; its status is as of generatedAt. Evidence is listed when verified in the range; acceptances when their lifetime overlaps it.',
    truncated: scope.value.truncated,
    ...summary,
  };
  return { csv: controlsSummaryCsv(summary), json: JSON.stringify(json, null, 2) };
}

function flatten(scope: PostureScope) {
  return { requirements: scope.items.flatMap((x) => x.requirements), acceptances: scope.items.flatMap((x) => x.acceptances) };
}

/** Enabled projects, or the one asked for (it must be enabled). Shared by the two posture calls. */
async function scopeFor(deps: CoreDeps, v: PostureViewer, project: unknown): Promise<{ scope: PostureScope; projects: string[] } | ActionError> {
  if (!v.accountId) return { error: 'not_found' };
  const policy = await deps.config.site();
  if (!policy.ok) return { error: 'unavailable' };
  const p = policy.value;
  const wanted = typeof project === 'string' ? project.trim() : '';
  if (wanted && !p.enabledProjects.includes(wanted)) return { error: 'invalid_input', message: `project ${wanted.slice(0, 40)} is not enabled for Threatline (enabled: ${p.enabledProjects.join(', ') || 'none'})` };
  const projects = wanted ? [wanted] : p.enabledProjects;
  const scope = await postureScope(deps, { caller: v.accountId }, { projects, reviewIssueTypes: p.reviewIssueTypes });
  if (!scope.ok) return { error: 'unavailable' };
  return { scope: scope.value, projects };
}

export type ControlsPostureDto = ControlsPosture & { projects: string[]; issuesCounted: number; truncated: boolean };

/**
 * `posture.controls`: per framework, each control with requirements behind it, red (open), amber (accepted risk) or
 * green (all verified). Counts only; work items the viewer cannot browse are not counted, and no requirement text is
 * returned (it may come from a page the viewer cannot read).
 */
export async function postureControls(deps: CoreDeps, v: PostureViewer, payload: { project?: unknown }): Promise<ControlsPostureDto | ActionError> {
  const s = await scopeFor(deps, v, payload.project);
  if ('error' in s) return s;
  const summary = controlsSummary({ requirements: s.scope.items.flatMap((x) => x.requirements), acceptances: [] });
  return { ...controlsPosture(summary), projects: s.projects, issuesCounted: s.scope.items.length, truncated: s.scope.truncated };
}

const ControlDrillSchema = z
  .object({
    framework: z.enum(COMPLIANCE_FRAMEWORKS, { message: `framework must be one of ${COMPLIANCE_FRAMEWORKS.join(', ')}` }),
    control: z.string().trim().min(1).max(20),
    project: z.string().trim().max(255).optional(),
  })
  .strip()
  .refine((q) => complianceControl(q.framework, q.control) !== undefined, { message: 'not a control in the mapping', path: ['control'] });

/**
 * `posture.controlDrill`: the work items whose requirements map to one control, worst open severity first (a work item
 * with nothing open is listed by its highest mapped severity). Same shape as `posture.drill`.
 */
export async function postureControlDrill(deps: CoreDeps, v: PostureViewer, payload: Record<string, unknown>): Promise<DrillDto | ActionError> {
  if (!v.accountId) return { error: 'not_found' };
  const input = ControlDrillSchema.safeParse(payload ?? {});
  if (!input.success) return { error: 'invalid_input', message: input.error.issues.map((i) => i.message).join('; ') };
  const { framework, control, project } = input.data;
  const s = await scopeFor(deps, v, project);
  if ('error' in s) return s;
  const site = await deps.siteUrl();
  const matched: Array<DrillDto['issues'][number] & { open: boolean }> = [];
  for (const { issue, requirements } of s.scope.items) {
    const mapped = requirementsForControl(requirements, framework as ComplianceFramework, control);
    if (mapped.length === 0) continue;
    const open = mapped.filter((r) => OPEN.has(r.status));
    const pool = open.length ? open : mapped;
    const max = pool.reduce<Severity>((m, r) => (severityRank(r.severity) > severityRank(m) ? r.severity : m), pool[0]!.severity);
    matched.push({ key: issue.key, summary: issue.summary, maxOpenSeverity: max, url: `${site}/browse/${issue.key}`, open: open.length > 0 });
  }
  matched.sort((a, b) => Number(b.open) - Number(a.open) || severityRank(b.maxOpenSeverity) - severityRank(a.maxOpenSeverity) || a.key.localeCompare(b.key, 'en', { numeric: true }));
  const issues = matched.slice(0, DRILL_MAX_ITEMS).map(({ open: _open, ...i }) => i);
  const jql = issues.length ? `key in (${issues.map((i) => i.key).join(', ')}) ORDER BY key ASC` : null;
  return { jql, searchUrl: jql ? `${site}/issues/?jql=${encodeURIComponent(jql)}` : null, issues, truncated: s.scope.truncated || matched.length > DRILL_MAX_ITEMS };
}

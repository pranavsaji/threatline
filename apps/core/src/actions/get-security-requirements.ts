import { fixBy, dueDate, severityRank, testScaffold, type Requirement, type Severity, type TestLanguage } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { panelGet, type FixCheckDto } from '../resolvers/panel.js';
import type { ActionPayload } from './common.js';
import { callerOnIssue, fitJson, issueUrl, parseInput, SCHEMAS, type ActionError } from './schemas.js';

export interface RequirementDto {
  id: string;
  subtaskKey?: string;
  title: string;
  severity: Severity;
  status: Requirement['status'];
  acceptanceCriteria: string[];
  asvsIds: string[];
  fileHints: string[];
  /** When it should be fixed by (Critical 7 days, High 30, Medium 90 from creation); absent for Low or undated. */
  dueDate?: string;
  /** Whole days past dueDate while still open; 0 when not yet due. */
  overdueDays?: number;
  /** With testLanguage: a test skeleton with one failing test per Given/When/Then, to paste and fill in. */
  testSkeleton?: string;
  /**
   * Fix check (docs/FIX_CHECK.md): whether the latest pull request change CI sent fixes it, the added lines that do
   * (checked against the change), what is still missing and a suggested change; `holdsDone` when it waits for a champion.
   */
  fixCheck?: {
    verdict: 'fixed' | 'partial' | 'not_addressed' | 'unclear' | 'checking' | 'not_run';
    commit: string;
    reason?: string;
    evidence?: string[];
    missing?: string;
    suggestedChange?: string;
    holdsDone: boolean;
  };
}

export interface GetRequirementsResult {
  issueKey: string;
  panelUrl: string;
  requirements: RequirementDto[];
  hiddenRequirements: number;
  truncated: boolean;
}

export const toRequirementDto = (r: Requirement, o: { now?: Date; testLanguage?: TestLanguage } = {}): RequirementDto => ({
  id: r.id,
  ...(r.subtaskKey ? { subtaskKey: r.subtaskKey } : {}),
  title: r.title,
  severity: r.severity,
  status: r.status,
  acceptanceCriteria: r.criteria.map((c) => `Given ${c.given}, when ${c.when}, then ${c.then}`),
  asvsIds: r.asvsIds,
  fileHints: r.fileHints ?? [],
  ...(dueDate(r) ? { dueDate: dueDate(r)! } : {}),
  ...(o.now && fixBy(r, o.now) ? { overdueDays: fixBy(r, o.now)!.overdueDays } : {}),
  ...(o.testLanguage ? { testSkeleton: testScaffold(r, o.testLanguage) } : {}),
});

/** The fix check's word on one requirement, for an agent: absent when the latest change says nothing about it. */
export function fixCheckFor(fix: FixCheckDto | undefined, id: string): RequirementDto['fixCheck'] | undefined {
  if (!fix) return undefined;
  const hold = fix.holds[id];
  const f = fix.findings.find((x) => x.requirementId === id);
  const base = { commit: fix.commitSha.slice(0, 12), holdsDone: hold !== undefined };
  if (fix.status === 'pending') return f || hold ? { ...base, verdict: 'checking' } : undefined;
  if (fix.status === 'failed') return hold ? { ...base, verdict: 'not_run', ...(fix.failure ? { reason: fix.failure } : {}) } : undefined;
  if (!f) return undefined;
  return {
    ...base,
    verdict: f.verdict,
    reason: f.reason,
    ...(f.quotes.length > 0 ? { evidence: f.quotes.map((q) => `${q.path}:${q.line}: ${q.text}`) } : {}),
    ...(f.missing ? { missing: f.missing } : {}),
    ...(f.suggestion ? { suggestedChange: `${f.suggestion.summary}\n${f.suggestion.code}` } : {}),
  };
}

const OPEN_FIRST: Record<Requirement['status'], number> = { Open: 0, InProgress: 1, AcceptedRisk: 2, Verified: 3, NotApplicable: 4 };

/** GET (Agent, skill, MCP): the security requirements this caller may see, open and most severe first. */
export async function getSecurityRequirements(payload: ActionPayload & Record<string, unknown>, deps: CoreDeps): Promise<GetRequirementsResult | ActionError> {
  const input = parseInput(SCHEMAS.getSecurityRequirements, payload);
  if (!input.ok) return input.error;
  const who = await callerOnIssue(deps, payload, input.value.issueKey, 'browse');
  if (!who.ok) return who.error;
  const panel = await panelGet(deps, who.viewer);
  if ('error' in panel) return { error: panel.error };
  const status = input.value.status;
  const requirements = panel.requirements
    .filter((r) => !status || r.status === status)
    .sort((a, b) => OPEN_FIRST[a.status] - OPEN_FIRST[b.status] || severityRank(b.severity) - severityRank(a.severity) || a.title.localeCompare(b.title))
    .map((r) => {
      const dto = toRequirementDto(r, { now: deps.clock.now(), ...(input.value.testLanguage ? { testLanguage: input.value.testLanguage } : {}) });
      const fix = fixCheckFor(panel.fixCheck, r.id);
      return fix ? { ...dto, fixCheck: fix } : dto;
    });
  return fitJson({ issueKey: panel.issueKey, panelUrl: await issueUrl(deps, panel.issueKey), requirements, hiddenRequirements: panel.hiddenRequirements }, ['requirements']);
}

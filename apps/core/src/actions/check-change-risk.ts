import { DEFAULT_SITE_POLICY, GATE_CONFIG_PATHS, isSensitive, scoreDiff, type DiffSignal } from '@threatline/core';
import type { Requirement, Severity } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { panelGet } from '../resolvers/panel.js';
import type { ActionPayload } from './common.js';
import { callerOnIssue, fitJson, parseInput, SCHEMAS, type ActionError } from './schemas.js';

/** The Bitbucket merge check's default diff-score threshold (a repository can lower it in its Threatline settings). */
export const DEFAULT_DIFF_THRESHOLD = 40;

export interface ChangeRiskResult {
  issueKey: string;
  wouldPass: boolean;
  /** Whether the merge check will ask for a Threatline attestation for this change. */
  needsAttestation: boolean;
  diffScore: number;
  signals: DiffSignal[];
  sensitiveFiles: string[];
  touchedRequirements: Array<{ id: string; subtaskKey?: string; title: string; severity: Severity; status: Requirement['status']; paths: string[] }>;
  reasons: string[];
  truncated: boolean;
}

const OPEN = new Set<Requirement['status']>(['Open', 'InProgress']);

/**
 * GET (Agent, MCP): a preview of the merge check for a set of changed paths. Scores the paths the way the merge check
 * does (the gate's own configuration, site sensitive globs), lists the requirements whose file hints match, and says
 * whether the work item's verdict would let it through. The merge check also reads the repository's Threatline settings
 * and the destination branch's `.threatline/policy.yml`, which this cannot see and which can only add paths, so a pass
 * here is a prediction.
 */
export async function checkChangeRisk(payload: ActionPayload & Record<string, unknown>, deps: CoreDeps): Promise<ChangeRiskResult | ActionError> {
  const input = parseInput(SCHEMAS.checkChangeRisk, payload);
  if (!input.ok) return input.error;
  const who = await callerOnIssue(deps, payload, input.value.issueKey, 'browse');
  if (!who.ok) return who.error;
  const [panel, policy] = await Promise.all([panelGet(deps, who.viewer), deps.config.site()]);
  if ('error' in panel) return { error: panel.error };
  if (!policy.ok) return { error: 'unavailable' };

  const paths = input.value.changedPaths;
  // The same base set as the gate (packages/core merge-gate effectivePolicy): its own configuration is always sensitive.
  const sensitivePaths = [...new Set([...GATE_CONFIG_PATHS, ...DEFAULT_SITE_POLICY.sensitivePaths, ...policy.value.sensitivePaths])];
  const diff = scoreDiff(
    paths.map((path) => ({ path, status: 'modified' as const, linesAdded: 0 })),
    { sensitivePaths },
  );
  const needsAttestation = diff.sensitiveFiles.length > 0 || diff.score >= DEFAULT_DIFF_THRESHOLD;

  const touched = panel.requirements
    .map((r) => ({ r, hit: paths.filter((p) => (r.fileHints ?? []).length > 0 && isSensitive(p, r.fileHints ?? [])) }))
    .filter((x) => x.hit.length > 0)
    .map(({ r, hit }) => ({ id: r.id, ...(r.subtaskKey ? { subtaskKey: r.subtaskKey } : {}), title: r.title, severity: r.severity, status: r.status, paths: hit }));

  const v = panel.verdict;
  const reasons: string[] = [];
  let wouldPass: boolean;
  if (!needsAttestation) {
    wouldPass = true;
    reasons.push(
      'None of these paths is security-sensitive, so the merge check lets the change through without an attestation.',
      "This is a prediction: the repository's Threatline settings and the destination branch's .threatline/policy.yml can add sensitive paths (or lower the diff-score threshold), and the merge check uses them.",
    );
  } else {
    reasons.push(
      diff.sensitiveFiles.length > 0
        ? `Touches security-sensitive paths: ${[...new Set(diff.sensitiveFiles)].join(', ')}. The merge check needs a Threatline attestation for ${panel.issueKey}.`
        : `The change scores ${diff.score} (threshold ${DEFAULT_DIFF_THRESHOLD}), so the merge check needs a Threatline attestation for ${panel.issueKey}.`,
    );
    if (!v) {
      wouldPass = false;
      reasons.push(`${panel.issueKey} has no Threatline review yet, so no attestation can be issued. Start one with start-review.`);
    } else if (v.state === 'block') {
      wouldPass = false;
      reasons.push(...v.reasons.map((r) => r.message));
    } else {
      wouldPass = true;
      reasons.push(v.state === 'warn' ? `${panel.issueKey} is in warn-only mode: an attestation can be issued, and the merge check will show a warning.` : `${panel.issueKey} passes Threatline's gate: request an attestation with get-merge-attestation.`);
    }
  }
  for (const t of touched.filter((x) => OPEN.has(x.status)))
    reasons.push(`Requirement ${t.subtaskKey ?? t.id} (${t.severity}, ${t.status}) covers ${t.paths.join(', ')}: "${t.title}".`);

  log('action.change_risk', { issueId: who.viewer.issueId, paths: paths.length, score: diff.score, wouldPass, touched: touched.length });
  return fitJson(
    { issueKey: panel.issueKey, wouldPass, needsAttestation, diffScore: diff.score, signals: diff.signals, sensitiveFiles: [...new Set(diff.sensitiveFiles)], touchedRequirements: touched, reasons },
    ['touchedRequirements', 'sensitiveFiles', 'reasons'],
  );
}

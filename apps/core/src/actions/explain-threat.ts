import type { CoreDeps } from '../deps.js';
import { findThreat, scopedReview, threatExplain, type ThreatExplanation } from '../resolvers/panel.js';
import { seenBefore, type SeenKind } from '../services/memory-service.js';
import type { ActionPayload } from './common.js';
import { callerOnIssue, issueUrl, parseInput, SCHEMAS, type ActionError } from './schemas.js';

export interface ExplainThreatResult extends ThreatExplanation {
  issueKey: string;
  threatId: string;
  title: string;
  severity: string;
  panelUrl: string;
  /**
   * "Seen before" (docs/MEMORY.md): past incidents and the same threat on other work items, only those the caller may
   * open. `line` reads as the panel shows it: "INC-7 · Incident · Duplicate refunds after webhook retries (Sev-2, payments)".
   */
  seenBefore: Array<{ key: string; kind: SeenKind; line: string; reason: string; url: string; evidenceUrl?: string }>;
}

/**
 * GET (Agent, MCP): a plain-language attack story, fix patterns and references for one threat on the latest review,
 * and what happened before with threats like it on this site. Takes the threat id or the T-n ref get-review returned
 * (refs follow the panel's order, most severe first). Built from the review, the bundled framework data and Threatline's
 * own history: no model call.
 */
export async function explainThreat(payload: ActionPayload & Record<string, unknown>, deps: CoreDeps): Promise<ExplainThreatResult | ActionError> {
  const input = parseInput(SCHEMAS.explainThreat, payload);
  if (!input.ok) return input.error;
  const who = await callerOnIssue(deps, payload, input.value.issueKey, 'browse');
  if (!who.ok) return who.error;
  const latest = await deps.reviews.latest(who.viewer.issueId);
  if (!latest.ok) return { error: 'unavailable' };
  if (!latest.value) return { error: 'not_found' };
  const scoped = await scopedReview(deps, who.viewer, latest.value.id);
  if (!scoped) return { error: 'unavailable' };
  const threat = findThreat(scoped.threats, input.value.threatId);
  if (!threat) return { error: 'not_found' };
  const explained = await threatExplain(deps, who.viewer, { reviewId: latest.value.id, threatId: threat.id });
  if ('error' in explained) return { error: explained.error };
  // Security: the same per-viewer filter as the panel, as the calling user.
  const memory = await seenBefore(deps, who.viewer, who.issue, threat.id).catch(() => null);
  const items = memory?.threats[threat.id] ?? [];
  const seen = await Promise.all(
    items.map(async (s) => ({
      key: s.key,
      kind: s.kind,
      line: `${s.key} · ${s.text}`,
      reason: s.reason,
      url: await issueUrl(deps, s.key),
      ...(s.evidence ? { evidenceUrl: s.evidence.url } : {}),
    })),
  );
  return { issueKey: who.issue.key, threatId: threat.id, title: threat.title, severity: threat.severity, panelUrl: await issueUrl(deps, who.issue.key), ...explained, seenBefore: seen };
}

import { diagramText } from '@threatline/core';
import type { Review, Severity, Stride, Verdict } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { panelGet, threatRef } from '../resolvers/panel.js';
import type { ActionPayload } from './common.js';
import { callerOnIssue, fitJson, issueUrl, parseInput, SCHEMAS, type ActionError } from './schemas.js';

export interface ReviewThreatDto {
  /** Short ref for chat ("T-3"), in the panel's order (most severe first); explain-threat accepts it. */
  ref: string;
  id: string;
  title: string;
  stride: Stride;
  severity: Severity;
  state: string;
  component: string;
  plainLanguage: string;
  citations: Array<{ source: string; url: string; quote: string }>;
}

export interface GetReviewResult {
  issueKey: string;
  panelUrl: string;
  status: Review['status'] | 'not_reviewed';
  revision: number | null;
  riskScore: number | null;
  partial: boolean;
  verdict: { state: Verdict['state']; blockingCount: number; maxOpenSeverity: Severity | null; reasons: string[]; overridden?: true; validUntil?: string } | null;
  threats: ReviewThreatDto[];
  threatsTotal: number;
  hiddenThreats: number;
  /** The data-flow diagram as compact text (elements, numbered flows, trust boundaries), scoped like the threats. */
  dataFlowDiagram: string | null;
  truncated: boolean;
}

const DIAGRAM_CHARS = 6000;
const SKETCH_HIDDEN = 'Parts of the architecture come from sources you cannot open, so only the elements your visible threats name are shown.';

/** GET (Agent, MCP): the latest review as this caller may see it — verdict, risk score, partial flag, cited threats. */
export async function getReview(payload: ActionPayload & Record<string, unknown>, deps: CoreDeps): Promise<GetReviewResult | ActionError> {
  const input = parseInput(SCHEMAS.getReview, payload);
  if (!input.ok) return input.error;
  const who = await callerOnIssue(deps, payload, input.value.issueKey, 'browse');
  if (!who.ok) return who.error;
  const panel = await panelGet(deps, who.viewer);
  if ('error' in panel) return { error: panel.error };
  const facts = new Map(panel.facts.map((f) => [f.id, f]));
  const threats: ReviewThreatDto[] = panel.threats.map((t, i) => ({
    ref: threatRef(i),
    id: t.id,
    title: t.title,
    stride: t.stride,
    severity: t.severity,
    state: t.state,
    component: t.component,
    plainLanguage: t.plainLanguage,
    citations: t.citations.slice(0, 3).map((c) => ({ source: facts.get(c.factId)?.title ?? 'Work item', url: facts.get(c.factId)?.url ?? '', quote: c.quote })),
  }));
  const v = panel.verdict;
  const refs = new Map(threats.map((t) => [t.id, t.ref]));
  const d = panel.diagram;
  const dataFlowDiagram = d ? `${d.sketchHidden ? `${SKETCH_HIDDEN}\n` : ''}${diagramText(d, (id) => refs.get(id), DIAGRAM_CHARS)}` : null;
  log('action.get_review', { issueId: who.viewer.issueId, threats: threats.length });
  return fitJson(
    {
      issueKey: panel.issueKey,
      panelUrl: await issueUrl(deps, panel.issueKey),
      status: panel.review?.status ?? 'not_reviewed',
      revision: panel.review?.revision ?? null,
      riskScore: panel.review?.riskScore ?? null,
      partial: panel.review?.partial ?? false,
      verdict: v
        ? { state: v.state, blockingCount: v.blockingCount, maxOpenSeverity: v.maxOpenSeverity, reasons: v.reasons.map((r) => r.message), ...(v.overridden ? { overridden: true as const } : {}), ...(v.validUntil ? { validUntil: v.validUntil } : {}) }
        : null,
      threats,
      threatsTotal: panel.threatsTotal,
      hiddenThreats: panel.hiddenThreats,
      dataFlowDiagram,
    },
    ['threats'],
  ) as GetReviewResult;
}

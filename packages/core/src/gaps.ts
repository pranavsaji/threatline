import { appError, err, ok, type ContextBundle, type Result, type Review, type Threat } from '@threatline/shared';
import { gapPrompt, MAX_GAP_THREATS } from '@threatline/prompts';
import { gapCandidates, minorityThreats, reviewSignals } from './ingest.js';
import { agentSampleFromText, callText, type StageDeps, type Usage } from './pipeline.js';
import { buildReviewContext, renderReviewContext } from './review-context.js';
import type { Sample } from './ports.js';
import { severityOf } from './threats/severity.js';

/**
 * The past incidents in the review context (the gatherer adds those linked to the work item or on its components, and
 * only those the person who caused the review may open): their keys, for the gap check's incident step.
 */
export function pastIncidentKeys(bundle: Pick<ContextBundle, 'facts'>): string[] {
  const keys = bundle.facts.filter((f) => f.sourceType === 'incident').map((f) => /\b([A-Z][A-Z0-9_]{0,254}-\d{1,18}):/.exec(f.title)?.[1]);
  return [...new Set(keys.filter((k): k is string => !!k))];
}

/** Threats a reviewer sees on the review (what the gap check is told the first review agreed on). */
const shown = (t: Threat) => t.state === 'accepted' || t.state === 'needs_human';

/**
 * Threatline Engine, the gap check (after assembly, before the verifier): one deep-tier call reads the same nonce-fenced
 * review context the runs read, the threats they agreed on and the ones only one run raised, and names what the list
 * misses. Its answer becomes hidden candidates (gapCandidates); only the verifier's keep makes one active. The caller
 * skips it under suspected injection, as it skips the verifier. Returns the candidates, possibly none.
 */
export async function engineGapCheck(
  deps: Pick<StageDeps, 'llm' | 'policy' | 'budget'>,
  review: Review,
  bundle: ContextBundle,
  threats: readonly Threat[],
  samples: readonly Sample[],
  usage: Usage,
): Promise<Result<Threat[]>> {
  const context = renderReviewContext(buildReviewContext(bundle, { revision: review.revision }));
  const item = (t: { stride: string; title: string; scenario: string; likelihood: number; impact: number }, severity?: string) => ({
    stride: t.stride, title: t.title, scenario: t.scenario, severity: severity ?? severityOf(t.likelihood, t.impact),
  });
  const p = gapPrompt({
    issueKey: bundle.issueKey,
    context,
    found: threats.filter(shown).map((t) => item(t, t.severity)),
    minority: minorityThreats(samples).slice(0, 12).map((t) => item(t)),
    incidents: pastIncidentKeys(bundle),
  });
  const req = { ...p, purpose: 'gaps' as const, tier: 'deep' as const, maxOutputTokens: 2500 + 1500 * MAX_GAP_THREATS };
  const r = await callText(deps, usage, req);
  if (!r.ok) return r;
  // An empty list is a valid answer ("nothing missing"); anything that is not a threat model gets one repair call
  // (a strong model sometimes writes past the JSON or breaks it), then the check fails.
  let sample = agentSampleFromText(r.value, bundle.issueKey);
  if ('failed' in sample) {
    const again = await callText(deps, usage, { ...req, user: `${req.user}\n\nYour previous answer was not a valid threat model JSON object (${sample.failed}). Return only the corrected JSON object, with no other text.` });
    if (!again.ok) return again;
    sample = agentSampleFromText(again.value, bundle.issueKey);
  }
  if ('failed' in sample) return err(appError('schema', `gap check answer did not match the threat model format (${sample.failed})`));
  const llmFeatures = reviewSignals(bundle.facts, samples).llmFeatures;
  return ok(gapCandidates({ review, bundle, threats, sample, llmFeatures }));
}

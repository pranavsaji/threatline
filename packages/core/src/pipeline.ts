import { AgentThreatModelSchema, appError, err, ok, type AgentThreatModel, type ArchitectureSketch, type ContextBundle, type Result, type Review, type SitePolicy } from '@threatline/shared';
import {
  agentPrompt,
  automationPrompt,
  extractPrompt,
  ExtractFallbackSchema,
  ExtractOutputSchema,
  PROMPT_VERSION,
  ProposalFallbackSchema,
  ProposalSchema,
  fitProposal,
  proposePrompt,
  type EvidenceItem,
} from '@threatline/prompts';
import { z } from 'zod';
import { scanForInjection } from './context/injection.js';
import { assembleReview, extractAgentJson, fitAgentModel, parseFirstObject, type AssembleOutput } from './ingest.js';
import { buildReviewContext, renderReviewContext } from './review-context.js';
import type { ClockPort, FeedbackRepo, LlmPort, LlmPurpose, ModelTier, ReviewRepo, Sample } from './ports.js';

export interface PipelineDeps {
  llm: LlmPort;
  reviews: ReviewRepo;
  feedback: FeedbackRepo;
  clock: ClockPort;
  policy: SitePolicy;
}

/**
 * Optional atomic budget (Threatline Engine): reserve before each call, settle to the actual use after. Without it, the
 * per-review caps are checked against the running totals in `usage` (the eval path).
 */
export interface StageBudget {
  reserve(tokensIn: number, tokensOut: number): Promise<boolean>;
  settle(reserved: { tokensIn: number; tokensOut: number }, actual: { tokensIn: number; tokensOut: number }): Promise<void>;
}

/** What one engine stage needs: the model, where checkpoints live, and the per-review token budget. */
export type StageDeps = Pick<PipelineDeps, 'llm' | 'reviews' | 'policy'> & { budget?: StageBudget };

export interface Usage {
  tokensIn: number;
  tokensOut: number;
  modelIds: Set<string>;
}

const estimate = (system: string, user: string) => Math.ceil((system.length + user.length) / 4);

/** One model call within the per-review token budget (atomic reservation when `deps.budget` is set). */
export async function callText(
  deps: Pick<PipelineDeps, 'llm' | 'policy'> & { budget?: StageBudget },
  usage: Usage,
  req: { system: string; user: string; purpose: LlmPurpose; tier: ModelTier; maxOutputTokens: number },
): Promise<Result<string>> {
  const est = { tokensIn: estimate(req.system, req.user), tokensOut: req.maxOutputTokens };
  if (deps.budget) {
    if (!(await deps.budget.reserve(est.tokensIn, est.tokensOut))) return err(appError('budget', 'review token budget reached'));
  } else if (usage.tokensIn + est.tokensIn > deps.policy.budget.tokensInPerReview || usage.tokensOut >= deps.policy.budget.tokensOutPerReview) {
    return err(appError('budget', 'review token budget reached'));
  }
  const r = await deps.llm.complete(req);
  if (deps.budget) await deps.budget.settle(est, r.ok ? { tokensIn: r.value.tokensIn, tokensOut: r.value.tokensOut } : { tokensIn: 0, tokensOut: 0 });
  if (!r.ok) return r;
  usage.tokensIn += r.value.tokensIn;
  usage.tokensOut += r.value.tokensOut;
  usage.modelIds.add(r.value.modelId);
  return ok(r.value.text);
}

/**
 * Threatline Engine run: the Threatline agent prompt over the nonce-fenced review context, exactly what a Rovo agent run
 * sees (the path the eval measures best), on the deep tier. Its JSON becomes a sample like any agent run, so
 * consensus, verbatim-quote grounding, injection flags and the rule-based floor apply unchanged. An answer that is not a
 * valid threat model is a failed run; only the budget is an error.
 */
export async function engineAgentRun(deps: StageDeps, review: Review, bundle: ContextBundle, usage: Usage): Promise<Result<Sample>> {
  const ctx = renderReviewContext(buildReviewContext(bundle, { revision: review.revision }));
  const r = await callText(deps, usage, {
    system: agentPrompt(),
    user: `${automationPrompt(bundle.issueKey)}\n\nResult of get-review-context:\n${ctx}`,
    tier: 'deep',
    maxOutputTokens: 16000,
    purpose: 'propose',
  });
  if (!r.ok) return r.error.code === 'budget' ? r : ok({ failed: r.error.code });
  return ok(agentSampleFromText(r.value, bundle.issueKey));
}

/**
 * One run's reply as a sample, exactly as the Engine reads it (the offline eval uses this too): the strict contract
 * first; a strong model writes long, so on a schema miss its wording is fitted to the contract (quotes only shortened,
 * so still verbatim) and checked again.
 */
export function agentSampleFromText(text: string, issueKey: string): Sample {
  const m = extractAgentJson(text, issueKey);
  if (m.ok || m.error.code !== 'schema') return m.ok ? m.value : { failed: m.error.code };
  const fitted = AgentThreatModelSchema.safeParse(fitAgentModel(parseFirstObject(text)));
  if (fitted.success && fitted.data.issueKey.toLowerCase() === issueKey.toLowerCase()) return fitted.data;
  return { failed: m.error.code };
}

/** One stage call with the spec's failure ladder: validate → one repair with the validator error → smaller fallback schema → fail. */
export async function callStage<T>(
  deps: Pick<PipelineDeps, 'llm' | 'policy'> & { budget?: StageBudget },
  usage: Usage,
  req: { system: string; user: string; purpose: LlmPurpose; tier: ModelTier; maxOutputTokens: number },
  schema: z.ZodType<T>,
  fallback: { schema: z.ZodType<T>; instruction: string } | null,
): Promise<Result<T>> {
  const call = (system: string, user: string) => callText(deps, usage, { ...req, system, user });
  const validate = (text: string, s: z.ZodType<T>) => s.safeParse(parseFirstObject(text) ?? undefined);

  const first = await call(req.system, req.user);
  if (!first.ok) return first;
  let v = validate(first.value, schema);
  if (v.success) return ok(v.data);
  const issue = v.error.issues.slice(0, 3).map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ');
  const repair = await call(req.system, `${req.user}\n\nYour previous output failed validation: ${issue}. Return only the corrected JSON object.`);
  if (!repair.ok) return repair;
  v = validate(repair.value, schema);
  if (v.success) return ok(v.data);
  if (fallback) {
    const fb = await call(req.system, `${req.user}\n\n${fallback.instruction}`);
    if (!fb.ok) return fb;
    const fv = validate(fb.value, fallback.schema);
    if (fv.success) return ok(fv.data);
  }
  return err(appError('schema', `${req.purpose} output failed validation after repair and fallback`));
}

/** Every model-written sketch string is scanned; anything that reads like an instruction is dropped and flags injection. */
function sanitizeSketch(sketch: ArchitectureSketch): { sketch: ArchitectureSketch; flagged: boolean } {
  let flagged = false;
  const keep = (v: string) => {
    if (scanForInjection(v).suspected) {
      flagged = true;
      return false;
    }
    return true;
  };
  const clean: ArchitectureSketch = {
    ...sketch,
    components: sketch.components.filter(keep),
    dataStores: sketch.dataStores.filter(keep),
    externalServices: sketch.externalServices.filter(keep),
    trustBoundaries: sketch.trustBoundaries.filter(keep),
    flows: sketch.flows.filter((f) => keep(f.from) && keep(f.to) && keep(f.data)),
  };
  return { sketch: clean, flagged: flagged || sketch.injectionSuspected };
}

/** Evidence the extractor returned must reference a real fact, quote it, and carry no AI-directed text in its label. */
function cleanEvidence(items: EvidenceItem[], bundle: ContextBundle): EvidenceItem[] {
  const ids = new Set(bundle.facts.map((f) => f.id));
  return items.filter((e) => ids.has(e.factId) && !scanForInjection(e.about).suspected);
}

export interface Extracted {
  sketch: ArchitectureSketch;
  evidence: EvidenceItem[];
}

/**
 * Engine stage 2, quarantined extract: the only call that reads untrusted text. Checkpointed, so a redelivered job
 * reuses the saved result instead of paying for the call again.
 */
export async function engineExtract(deps: StageDeps, review: Review, bundle: ContextBundle, usage: Usage): Promise<Result<Extracted>> {
  const saved = await deps.reviews.stage(review.id, 'extract');
  if (!saved.ok) return saved;
  const checkpoint = saved.value?.status === 'done' ? (saved.value.checkpoint as Extracted | undefined) : undefined;
  if (checkpoint) return ok(checkpoint);
  await deps.reviews.saveStage(review.id, 'extract', 'running');
  const p = extractPrompt(bundle.facts);
  const r = await callStage(deps, usage, { ...p, purpose: 'extract', tier: 'balanced', maxOutputTokens: 6000 }, ExtractOutputSchema, {
    schema: ExtractFallbackSchema.transform((x) => ({ ...x, evidence: [] as EvidenceItem[] })) as unknown as z.ZodType<z.infer<typeof ExtractOutputSchema>>,
    instruction: 'Return only {"sketch": {...}} with no evidence list.',
  });
  if (!r.ok) {
    await deps.reviews.saveStage(review.id, 'extract', 'failed', undefined, r.error.code);
    return r;
  }
  const sanitized = sanitizeSketch(r.value.sketch);
  const out: Extracted = { sketch: { ...sanitized.sketch, injectionSuspected: sanitized.flagged }, evidence: cleanEvidence(r.value.evidence, bundle) };
  await deps.reviews.saveStage(review.id, 'extract', 'done', out);
  return ok(out);
}

/**
 * Engine stage 3, one independent proposal (lens n): sees only the typed sketch, evidence ids and trusted metadata,
 * never raw untrusted text. Returns a sample (a failed one when the output never validates), or an error for budget.
 */
export async function engineProposal(deps: StageDeps, review: Review, bundle: ContextBundle, extracted: Extracted, n: number, usage: Usage): Promise<Result<Sample>> {
  const { sketch, evidence } = extracted;
  const byId = new Map(evidence.map((e) => [e.id, e]));
  const trusted = bundle.facts.filter((f) => f.trustLevel === 'trusted');
  const p = proposePrompt(sketch, evidence, trusted, n);
  const r = await callStage(deps, usage, { ...p, purpose: 'propose', tier: 'deep', maxOutputTokens: 8000 }, z.preprocess(fitProposal, ProposalSchema) as unknown as z.ZodType<z.infer<typeof ProposalSchema>>, {
    schema: ProposalFallbackSchema.transform((x) => ({
      threats: x.threats.map((t) => ({ ...t, scenario: t.title, likelihood: 3, impact: 3 })),
    })) as unknown as z.ZodType<z.infer<typeof ProposalSchema>>,
    instruction: 'Return only {"threats": [{"stride","title","component","evidenceIds"}]} — titles only.',
  });
  if (!r.ok && r.error.code === 'budget') return r;
  const sample: Sample = r.ok
    ? ({
        schema: 'threatline.threatmodel.v1',
        issueKey: bundle.issueKey,
        sketch: { components: sketch.components, dataStores: sketch.dataStores, externalServices: sketch.externalServices, trustBoundaries: sketch.trustBoundaries, dataClasses: sketch.dataClasses, exposure: sketch.exposure, llmFeatures: sketch.llmFeatures },
        threats: r.value.threats.flatMap((t) => {
          const quotes = t.evidenceIds.map((id) => byId.get(id)?.quote).filter((q): q is string => !!q);
          if (quotes.length === 0) return [];
          const { evidenceIds: _ids, ...rest } = t;
          return [{ ...rest, evidence: quotes.slice(0, 3).map((quote) => ({ quote })) }];
        }),
      } satisfies AgentThreatModel)
    : { failed: r.error.code };
  await deps.reviews.saveStage(review.id, `propose:${n}`, 'failed' in sample ? 'failed' : 'done', sample);
  return ok(sample);
}

/**
 * The eval/dev review path (Claude Code or Forge LLMs): quarantined extract → N proposals over typed evidence ids →
 * deterministic assembly. Checkpoints after every stage so a retry resumes rather than restarts. In the product the
 * same stages run as separate queue jobs (Threatline Engine) so each fits a function timeout.
 */
export async function runPipeline(
  deps: PipelineDeps,
  review: Review,
  bundle: ContextBundle,
  opts: { samples: number; resumeFrom?: 'extract' | 'propose' | 'assemble' },
): Promise<Result<AssembleOutput>> {
  const usage: Usage = { tokensIn: review.tokensIn, tokensOut: review.tokensOut, modelIds: new Set(review.modelIds) };
  const resume = opts.resumeFrom ?? 'extract';
  if (resume === 'extract') {
    const s = await deps.reviews.stage(review.id, 'extract');
    if (s.ok && s.value?.status === 'done') await deps.reviews.saveStage(review.id, 'extract', 'running');
  }
  const extracted = await engineExtract(deps, review, bundle, usage);
  if (!extracted.ok) return extracted;
  const { sketch } = extracted.value;

  const samples: Sample[] = [];
  for (let n = 0; n < opts.samples; n++) {
    if (resume === 'assemble') {
      const s = await deps.reviews.stage(review.id, `propose:${n}`);
      if (s.ok && s.value?.status === 'done') {
        samples.push(s.value.checkpoint as Sample);
        continue;
      }
    }
    const r = await engineProposal(deps, review, bundle, extracted.value, n, usage);
    if (!r.ok) return r;
    samples.push(r.value);
  }
  if (samples.every((s) => 'failed' in s)) return err(appError('schema', 'every proposal sample failed validation'));

  // Stages 4–6: deterministic consensus, grounding, mapping, scoring.
  // Dismissal lookups use only trusted Jira components, never names the model produced.
  const dismissals = await Promise.all((bundle.components ?? []).slice(0, 10).map((c) => deps.feedback.dismissedFor(c)));
  const priorDismissed = dismissals.flatMap((d) => (d.ok ? d.value : []));
  const out = assembleReview({
    review, bundle, samples, samplesExpected: opts.samples, priorDismissed, policy: deps.policy, promptVersion: PROMPT_VERSION, now: deps.clock.now(),
    injectionSuspected: sketch.injectionSuspected,
  });
  await deps.reviews.saveThreats(review.id, out.threats, out.discarded);
  await deps.reviews.update(review.id, {
    status: out.status,
    riskScore: out.riskScore,
    tokensIn: usage.tokensIn,
    tokensOut: usage.tokensOut,
    modelIds: [...usage.modelIds],
    samplesReceived: samples.length,
    promptVersion: PROMPT_VERSION,
    updatedAt: deps.clock.now().toISOString(),
  });
  return ok(out);
}

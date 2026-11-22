import { agentPrompt, automationPrompt, PROMPT_VERSION } from '@threatline/prompts';
import { appError, err, ok, severityRank, type AgentThreatModel, type ContextBundle, type Result, type Review, type Threat } from '@threatline/shared';
import {
  applyVerification,
  assembleReview,
  engineVerify,
  riskScore,
  buildReviewContext,
  contextHash,
  DEFAULT_SITE_POLICY,
  agentSampleFromText,
  groundQuote,
  normalizeFact,
  renderReviewContext,
  runPipeline,
  type LlmPort,
  type Sample,
} from '@threatline/core';
import { CLEAN_CASES, POISONED_CASES, type CleanCase, type PoisonedCase } from '../fixtures/cases.js';
import { scoreCase, summarize, type CaseResult } from './metrics.js';
import { loadRecording, recordingLlm, replayLlm, saveRecording, type Recording } from './recorded.js';
import { JUDGE_VERSION, judgeExtras, parseJudge, type JudgeItem } from './judge.js';
import { memoryFeedbackRepo, memoryReviewRepo, fixedClock } from '../../packages/core/test/fakes/index.js';

/** `agent`: Rovo agent runs. `engine`: Threatline Engine (the same runs on the deep tier, then the verifier). `pipeline`: the earlier extract→propose design. */
export type EvalPath = 'agent' | 'engine' | 'pipeline';

export function bundleFor(c: CleanCase): ContextBundle {
  const key = `EVAL-${c.id.replace(/\D/g, '') || '1'}`;
  const facts = [
    normalizeFact({ sourceAri: `ari:eval:issue/${c.id}`, sourceType: 'jira_issue', title: `${key} ${c.summary}`, url: `https://eval/${c.id}`, text: c.summary, version: '1', trusted: false, origin: 'rest' }),
    normalizeFact({ sourceAri: `ari:eval:page/${c.id}`, sourceType: 'confluence_page', title: `Design: ${c.summary}`, url: `https://eval/${c.id}/design`, text: c.design, version: '1', trusted: false, origin: 'rest' }),
    normalizeFact({ sourceAri: `ari:eval:meta/${c.id}`, sourceType: 'jira_issue', title: `${key} metadata`, url: `https://eval/${c.id}`, text: `Type: Epic. Domain: ${c.domain}.`, version: '1', trusted: true, origin: 'rest' }),
  ];
  return { issueId: c.id, issueKey: key, facts, partial: false, partialReasons: [], contextHash: contextHash(facts), gatheredAt: '2026-11-15T00:00:00.000Z', components: [c.domain] };
}

const reviewFor = (b: ContextBundle, samples: number): Review => ({
  id: `rev_${b.issueId}`, issueId: b.issueId, issueKey: b.issueKey, revision: 1, status: 'awaiting_agent', contextHash: b.contextHash, riskScore: 0, partial: false,
  promptVersion: PROMPT_VERSION, modelIds: [], samplesExpected: samples, samplesReceived: 0, tokensIn: 0, tokensOut: 0, createdAt: 't', updatedAt: 't',
});

/** One agent run exactly as production: Threatline agent prompt + automation prompt + rendered get-review-context result. */
async function agentSample(llm: LlmPort, b: ContextBundle): Promise<{ sample: Sample; modelId?: string; tokensIn: number; tokensOut: number; quotes: string[] }> {
  const ctx = renderReviewContext(buildReviewContext(b, { revision: 1 }));
  const r = await llm.complete({ system: agentPrompt(), user: `${automationPrompt(b.issueKey)}\n\nResult of get-review-context:\n${ctx}`, tier: 'balanced', maxOutputTokens: 8000, purpose: 'propose' });
  if (!r.ok) return { sample: { failed: r.error.code }, tokensIn: 0, tokensOut: 0, quotes: [] };
  // Parsed exactly as the Engine parses a run (strict, then fitted to the contract), so the eval scores what ships.
  const sample = agentSampleFromText(r.value.text, b.issueKey);
  const quotes = 'threats' in sample ? sample.threats.flatMap((t) => t.evidence.map((e) => e.quote)) : [];
  return { sample, modelId: r.value.modelId, tokensIn: r.value.tokensIn, tokensOut: r.value.tokensOut, quotes };
}

export interface CaseRun {
  id: string;
  threats: Threat[];
  riskScore: number;
  injectionSuspected: boolean;
  blocking: number;
  quotes: string[];
  modelIds: string[];
  tokensIn: number;
  tokensOut: number;
}

const blockingOf = (threats: Threat[]) =>
  threats.filter((t) => (t.state === 'accepted' || t.state === 'needs_human') && severityRank(t.severity) >= severityRank(DEFAULT_SITE_POLICY.blockAtOrAbove)).length;

export async function runCase(c: CleanCase, llm: LlmPort | null, samples: number, path: EvalPath, coverage = true, verifier: LlmPort | null = null): Promise<Result<CaseRun>> {
  const b = bundleFor(c);
  const review = reviewFor(b, samples);
  if (llm && path === 'pipeline') {
    // Threatline Engine exactly as the product runs it: extract → proposals → assembly → verifier (skipped under injection).
    const reviews = memoryReviewRepo();
    await reviews.create(review);
    const r = await runPipeline({ llm, reviews, feedback: memoryFeedbackRepo(), clock: fixedClock('2026-11-15T00:00:00Z'), policy: DEFAULT_SITE_POLICY }, review, b, { samples });
    if (!r.ok) return err(r.error);
    let threats = r.value.threats;
    const tainted = new Set(b.facts.filter((f) => f.injectionSuspected).map((f) => f.id));
    if (!r.value.injectionSuspected) {
      const usage = { tokensIn: 0, tokensOut: 0, modelIds: new Set<string>() };
      const v = await engineVerify({ llm, policy: DEFAULT_SITE_POLICY }, threats, usage, `eval${c.id.replace(/\W/g, '')}`);
      if (v.ok) threats = applyVerification(threats, v.value, { injectionSuspected: false, taintedFacts: tainted, blockAtOrAbove: DEFAULT_SITE_POLICY.blockAtOrAbove }).threats;
    }
    const score = riskScore(threats, r.value.signals);
    const rev = await reviews.get(review.id);
    const models = rev.ok && rev.value ? rev.value.modelIds : [];
    return ok({ id: c.id, threats, riskScore: score, injectionSuspected: r.value.injectionSuspected, blocking: blockingOf(threats), quotes: threats.flatMap((t) => t.citations.map((x) => x.quote)), modelIds: models, tokensIn: rev.ok && rev.value ? rev.value.tokensIn : 0, tokensOut: rev.ok && rev.value ? rev.value.tokensOut : 0 });
  }
  const runs = llm
    ? await Promise.all(Array.from({ length: samples }, () => agentSample(llm, b)))
    : Array.from({ length: samples }, () => ({ sample: { schema: 'threatline.threatmodel.v1', issueKey: b.issueKey, threats: [] } as AgentThreatModel as Sample, tokensIn: 0, tokensOut: 0, quotes: [] as string[], modelId: 'baseline-only' }));
  // A rate limit or outage is not "the model found nothing": a case with no answer at all fails instead of scoring.
  if (llm && runs.every((x) => 'failed' in x.sample)) {
    const code = (runs[0]!.sample as { failed: string }).failed;
    return err(appError(code === 'timeout' ? 'timeout' : 'upstream', `every sample failed: ${runs.map((x) => (x.sample as { failed: string }).failed).join(', ')}`));
  }
  const out = assembleReview({ review, bundle: b, samples: runs.map((x) => x.sample), samplesExpected: samples, priorDismissed: [], policy: DEFAULT_SITE_POLICY, promptVersion: PROMPT_VERSION, now: new Date('2026-11-15T00:00:00Z'), coverage });
  // Threatline Engine: the verifier runs on the assembled review, exactly as in the product (skipped under injection).
  let threats = out.threats;
  let score = out.riskScore;
  if (path === 'engine' && verifier && !out.injectionSuspected) {
    const v = await engineVerify({ llm: verifier, policy: DEFAULT_SITE_POLICY }, threats, { tokensIn: 0, tokensOut: 0, modelIds: new Set() }, `eval${c.id.replace(/\W/g, '')}`);
    if (!v.ok) return err(v.error);
    const tainted = new Set(b.facts.filter((f) => f.injectionSuspected).map((f) => f.id));
    threats = applyVerification(threats, v.value, { injectionSuspected: false, taintedFacts: tainted, blockAtOrAbove: DEFAULT_SITE_POLICY.blockAtOrAbove }).threats;
    score = riskScore(threats, out.signals);
  }
  return ok({
    id: c.id,
    threats,
    riskScore: score,
    injectionSuspected: out.injectionSuspected,
    blocking: blockingOf(threats),
    quotes: [...runs.flatMap((x) => x.quotes), ...out.threats.filter((t) => t.origin === 'baseline').flatMap((t) => t.citations.map((q) => q.quote))],
    modelIds: [...new Set(runs.map((x) => x.modelId).filter((m): m is string => !!m))],
    tokensIn: runs.reduce((n, x) => n + x.tokensIn, 0),
    tokensOut: runs.reduce((n, x) => n + x.tokensOut, 0),
  });
}

/** Round-robin across domains so a subset still covers every domain; poisoned cases follow their clean twins. */
export function selectCases(subset: number | 'all'): { clean: CleanCase[]; poisoned: PoisonedCase[] } {
  if (subset === 'all') return { clean: CLEAN_CASES, poisoned: POISONED_CASES };
  const domains = ['web', 'api', 'mobile', 'data', 'ai'] as const;
  const byDomain = domains.map((d) => CLEAN_CASES.filter((c) => c.domain === d));
  const nClean = Math.ceil(subset * 0.8);
  const clean: CleanCase[] = [];
  for (let i = 0; clean.length < nClean && i < 8; i++) for (const list of byDomain) if (list[i] && clean.length < nClean) clean.push(list[i]!);
  const ids = new Set(clean.map((c) => c.id));
  const poisoned = POISONED_CASES.filter((p) => ids.has(p.twinOf)).slice(0, subset - clean.length);
  return { clean, poisoned };
}

export interface EvalReport {
  label: string;
  promptVersion: string;
  llm: string;
  path: EvalPath;
  modelIds: string[];
  cases: number;
  samples: number;
  date: string;
  summary: ReturnType<typeof summarize>;
  tokens: { in: number; out: number };
  failures: string[];
  perCase: Array<{ id: string; tp: number; fp: number; fn: number; riskScore: number; blocking: number; injectionHeld?: boolean; judgedValid?: number }>;
  /** Judged extras from each rule-based threat (by title): how often the judge rated the rule's threat valid. */
  baselineRules?: Array<{ title: string; extras: number; valid: number }>;
}

export interface EvalOptions {
  llm: LlmPort | null;
  llmName: string;
  subset: number | 'all';
  samples: number;
  path: EvalPath;
  concurrency?: number;
  onProgress?: (done: number, total: number) => void;
  /** Save each case's raw model replies here (evals/results/recorded) for the offline CI gate. */
  recordDir?: string;
  /** Per-case model, e.g. a replay of recorded replies; null means the case has no recording and fails. */
  llmFor?: (caseId: string) => LlmPort | null;
  /** With recordDir: replay cases already recorded in full; call the model (and re-record) only for the rest. */
  resume?: boolean;
  /**
   * Grade each reported threat that is not on the case's must-find list with a separate model call (offline eval only).
   * llmFor returns the judge for a case (null: no recording, the case is not judged); recordDir saves live replies.
   */
  judge?: {
    llmFor: (caseId: string) => LlmPort | null;
    recordDir?: string;
    /**
     * A case's judge recording. When it lists the items it rated, the recorded verdicts are matched to today's extras by
     * STRIDE and title, so removing some extras (for example, rule-based threats now covered) keeps the others judged.
     */
    recordingFor?: (caseId: string) => Recording | null;
    /** Write the rated items into recordings that lack them (run once with the review code that made the recording). */
    annotateDir?: string;
  };
  /** Off only to re-create how reviews looked before rule-based coverage existed (see judge.annotateDir). */
  coverage?: boolean;
  /** Path `engine`: the verifier per case (a replay, or a live model whose replies are saved to recordDir). */
  verify?: {
    llmFor: (caseId: string) => LlmPort | null;
    recordDir?: string;
    /** True for a case whose verifier replies are a replay: they are not saved again (that would relabel them). */
    replayed?: (caseId: string) => boolean;
  };
}

export async function runEval(opts: EvalOptions): Promise<Result<EvalReport>> {
  const { clean, poisoned } = selectCases(opts.subset);
  const total = clean.length + poisoned.length;
  let done = 0;
  const failures: string[] = [];
  const cleanRuns = new Map<string, CaseRun>();
  const results: CaseResult[] = [];
  const perCase: EvalReport['perCase'] = [];
  const modelIds = new Set<string>();
  let tin = 0;
  let tout = 0;
  const conc = Math.max(1, opts.concurrency ?? 1);

  const verifyRecorders = new Map<string, ReturnType<typeof recordingLlm>>();
  const verifierFor = (caseId: string): LlmPort | null => {
    const base = opts.verify?.llmFor(caseId) ?? null;
    if (!base || !opts.verify?.recordDir) return base;
    const rec = recordingLlm(base);
    verifyRecorders.set(caseId, rec);
    return rec.llm;
  };
  const runAll = async <T extends CleanCase>(list: T[], each: (c: T, r: CaseRun) => void) => {
    for (let i = 0; i < list.length; i += conc) {
      const batch = list.slice(i, i + conc);
      const outs = await Promise.all(
        batch.map(async (c) => {
          if (opts.llmFor) {
            const llm = opts.llmFor(c.id);
            return llm ? runCase(c, llm, opts.samples, opts.path, opts.coverage, verifierFor(c.id)) : err(appError('not_found', 'no recording'));
          }
          if (!opts.recordDir || !opts.llm) return runCase(c, opts.llm, opts.samples, opts.path, opts.coverage, verifierFor(c.id));
          const done = opts.resume ? loadRecording(opts.recordDir, c.id) : null;
          if (done && done.replies.length >= opts.samples) return runCase(c, replayLlm(done), opts.samples, opts.path, opts.coverage, verifierFor(c.id));
          const rec = recordingLlm(opts.llm);
          const r = await runCase(c, rec.llm, opts.samples, opts.path, opts.coverage, verifierFor(c.id));
          if (r.ok) saveRecording(opts.recordDir, { caseId: c.id, promptVersion: PROMPT_VERSION, replies: rec.replies() });
          return r;
        }),
      );
      outs.forEach((r, j) => {
        const c = batch[j]!;
        const vr = verifyRecorders.get(c.id);
        if (r.ok && vr && opts.verify?.recordDir && vr.replies().length > 0 && !opts.verify.replayed?.(c.id)) saveRecording(opts.verify.recordDir, { caseId: c.id, promptVersion: PROMPT_VERSION, replies: vr.replies() });
        done++;
        opts.onProgress?.(done, total);
        if (!r.ok) {
          failures.push(`${c.id}: ${r.error.code} (${r.error.message})`);
          return;
        }
        r.value.modelIds.forEach((m) => modelIds.add(m));
        tin += r.value.tokensIn;
        tout += r.value.tokensOut;
        each(c, r.value);
      });
    }
  };

  const groundedCount = (c: CleanCase, run: CaseRun) => {
    const facts = bundleFor(c).facts;
    return run.quotes.filter((q) => groundQuote(q, facts).grounding === 'supported').length;
  };

  const ruleStats = new Map<string, { extras: number; valid: number }>();
  const toJudge: Array<{ c: CleanCase; counted: JudgeItem[]; extras: JudgeItem[]; extraOrigins: Array<'agent' | 'baseline'>; split: NonNullable<CaseResult['judgedByOrigin']>; result: CaseResult; row: EvalReport['perCase'][number] }> = [];
  await runAll(clean, (c, run) => {
    cleanRuns.set(c.id, run);
    const predicted = run.threats.filter((t) => t.state === 'accepted' || t.state === 'needs_human');
    const s = scoreCase(predicted, c.expected);
    const { matchedIdx = [], extraIdx = [], ...score } = s;
    const result: CaseResult = { ...score, citationValid: groundedCount(c, run), citationTotal: run.quotes.length };
    const row = { id: c.id, tp: s.tp, fp: s.fp, fn: s.fn, riskScore: run.riskScore, blocking: run.blocking };
    results.push(result);
    perCase.push(row);
    const origin = (idx: number) => (predicted[idx]!.origin === 'baseline' ? 'baseline' : 'agent');
    const split = { agent: { tp: 0, extra: 0, valid: 0 }, baseline: { tp: 0, extra: 0, valid: 0 } };
    for (const i of matchedIdx) split[origin(i)].tp++;
    for (const i of extraIdx) split[origin(i)].extra++;
    const asItem = (prefix: string) => (idx: number, n: number): JudgeItem => {
      const t = predicted[idx]!;
      return { id: `${prefix}${n + 1}`, stride: t.stride, severity: t.severity, title: t.title, scenario: t.scenario };
    };
    toJudge.push({ c, counted: matchedIdx.map(asItem('c')), extras: extraIdx.map(asItem('x')), extraOrigins: extraIdx.map(origin), split, result, row });
  });
  if (opts.judge) {
    const judge = opts.judge;
    for (let i = 0; i < toJudge.length; i += conc) {
      await Promise.all(
        toJudge.slice(i, i + conc).map(async ({ c, counted, extras, extraOrigins, split, result, row }) => {
          if (extras.length === 0) {
            result.judgedValid = row.judgedValid = 0;
            result.judgedByOrigin = split;
            return;
          }
          const rec0 = judge.recordingFor?.(c.id) ?? null;
          const key = (x: { stride: string; title: string }) => `${x.stride}|${x.title}`;
          if (rec0?.items && rec0.replies[0]) {
            const parsed = parseJudge(rec0.replies[0].text, rec0.items.map((x) => x.id));
            if (parsed.ok) {
              const byKey = new Map(rec0.items.map((it) => [key(it), parsed.value.find((v) => v.id === it.id)?.valid ?? false] as const));
              if (extras.every((e) => byKey.has(key(e)))) {
                const valid = extras.map((e) => byKey.get(key(e))!);
                result.judgedValid = row.judgedValid = valid.filter(Boolean).length;
                valid.forEach((v, k) => {
                  if (v) split[extraOrigins[k]!].valid++;
                  if (extraOrigins[k] === 'baseline') {
                    const r = ruleStats.get(extras[k]!.title) ?? { extras: 0, valid: 0 };
                    ruleStats.set(extras[k]!.title, { extras: r.extras + 1, valid: r.valid + (v ? 1 : 0) });
                  }
                });
                result.judgedByOrigin = split;
                return;
              }
            }
          }
          const base = judge.llmFor(c.id);
          if (!base) {
            failures.push(`judge ${c.id}: not_found (no recorded judge reply)`);
            return;
          }
          const rec = judge.recordDir ? recordingLlm(base) : null;
          const v = await judgeExtras(rec?.llm ?? base, c, counted, extras);
          if (!v.ok) {
            const why = String((v.error.details as { stderr?: string } | undefined)?.stderr ?? '').trim().slice(0, 160);
            failures.push(`judge ${c.id}: ${v.error.code} (${v.error.message}${why ? `: ${why}` : ''})`);
            return;
          }
          const items = extras.map((e) => ({ id: e.id, stride: e.stride, title: e.title }));
          if (rec && judge.recordDir) saveRecording(judge.recordDir, { caseId: c.id, promptVersion: JUDGE_VERSION, replies: rec.replies(), items });
          else if (judge.annotateDir && rec0 && !rec0.items) saveRecording(judge.annotateDir, { ...rec0, items });
          result.judgedValid = row.judgedValid = v.value.filter((x) => x.valid).length;
          v.value.forEach((x, k) => {
            if (x.valid) split[extraOrigins[k]!].valid++;
            if (extraOrigins[k] === 'baseline') {
              const t = extras[k]!.title;
              const r = ruleStats.get(t) ?? { extras: 0, valid: 0 };
              ruleStats.set(t, { extras: r.extras + 1, valid: r.valid + (x.valid ? 1 : 0) });
            }
          });
          result.judgedByOrigin = split;
        }),
      );
    }
  }
  await runAll(poisoned, (c, run) => {
    const twin = cleanRuns.get((c as PoisonedCase).twinOf);
    const held = !!twin && run.blocking >= twin.blocking && run.riskScore >= twin.riskScore && run.injectionSuspected;
    results.push({ tp: 0, fp: 0, fn: 0, highTp: 0, highTotal: 0, perStride: {}, citationValid: groundedCount(c, run), citationTotal: run.quotes.length, injectionHeld: held });
    perCase.push({ id: c.id, tp: 0, fp: 0, fn: 0, riskScore: run.riskScore, blocking: run.blocking, injectionHeld: held });
  });
  if (results.length === 0) return err(appError('upstream', 'every eval case failed', { failures }));
  const date = new Date().toISOString().slice(0, 10);
  const models = [...modelIds];
  return ok({
    label:
      opts.llmName === 'fake'
        ? `scored offline with the deterministic baseline only (no model), ${total} cases, ${date}`
        : opts.llmName === 'recorded'
          ? `replayed offline from recorded Claude Code outputs (${models.join(', ') || 'unknown model'}), ${total} cases, ${date}`
          : `scored offline with Claude Code on ${models.join(', ') || 'unknown model'}, ${total} cases, ${date}`,
    promptVersion: PROMPT_VERSION,
    llm: opts.llmName,
    path: opts.path,
    modelIds: models,
    cases: total,
    samples: opts.samples,
    date,
    summary: summarize(results),
    tokens: { in: tin, out: tout },
    failures,
    perCase,
    ...(ruleStats.size ? { baselineRules: [...ruleStats].map(([title, v]) => ({ title, ...v })).sort((a, b) => b.extras - a.extras || a.title.localeCompare(b.title)) } : {}),
  });
}

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;

export function reportMarkdown(r: EvalReport): string {
  const s = r.summary;
  const judgeFailed = r.failures.filter((f) => f.startsWith('judge ')).length;
  const rows = Object.entries(s.perStride).map(([k, v]) => `| ${k} | ${v.tp} | ${v.fp} | ${v.fn} | ${pct(v.precision)} | ${pct(v.recall)} | ${pct(v.f1)} |`).join('\n');
  return `# Threatline eval — ${r.date}

_${r.label}; prompt ${r.promptVersion}; path ${r.path}; ${r.samples} sample(s) per case._

| Metric | Value |
| --- | --- |
| Precision | ${pct(s.precision)} |
${s.judgedPrecision === undefined ? '' : `| Precision, judged | ${pct(s.judgedPrecision)} (must-find matches plus extras a separate Claude call rated valid; ${s.judgedCases} case${s.judgedCases === 1 ? '' : 's'}${judgeFailed ? `; incomplete: ${judgeFailed} not judged, see failures` : ''}) |\n`}${
    s.judgedByOrigin
      ? `| Precision, judged: model-proposed threats | ${pct(s.judgedByOrigin.agent.precision)} (${s.judgedByOrigin.agent.valid} of ${s.judgedByOrigin.agent.extras} extras valid) |\n| Precision, judged: rule-based floor | ${pct(s.judgedByOrigin.baseline.precision)} (${s.judgedByOrigin.baseline.valid} of ${s.judgedByOrigin.baseline.extras} extras valid; kept by design, the agent can never remove them) |\n`
      : ''
  }| Recall | ${pct(s.recall)} |
| F1 | ${pct(s.f1)} |
| High-severity recall | ${pct(s.highRecall)} |
| Citation grounding | ${pct(s.citationValidity)} |
| Injection resistance | ${s.poisonedScored === 0 ? 'no poisoned case scored' : `${pct(s.injectionResistance)} (${s.injectionHeld} of ${s.poisonedScored})`} |

| STRIDE | TP | FP | FN | Precision | Recall | F1 |
| --- | --- | --- | --- | --- | --- | --- |
${rows}
${
  r.baselineRules?.length
    ? `
Rule-based floor, judged (extras only; matches to must-find threats are not listed):

| Rule-based threat | Extras | Rated valid |
| --- | --- | --- |
${r.baselineRules.map((b) => `| ${b.title} | ${b.extras} | ${b.valid} (${pct(b.extras ? b.valid / b.extras : 0)}) |`).join('\n')}
`
    : ''
}
${r.failures.length ? `Failures: ${r.failures.join(', ')}\n` : ''}`;
}

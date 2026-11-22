import { applyVerification, engineAgentRun, engineExtract, engineVerify, requirementsFor, type Extracted, type Sample, type Usage } from '@threatline/core';
import { appError, err, ok, type ContextBundle, type Result, type Review } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import type { ReviewJob } from '../jobs/types.js';
import { monthOf } from './budget.js';
import { refreshVerdict } from './verdict-service.js';
import { storeSample } from './samples.js';

type EngineJob = Extract<ReviewJob, { kind: 'engine' }>;
const voidOk = (): Result<void> => ok(undefined);

/** The stored facts as the bundle the stages read (components come from Jira, never from the model). */
async function bundleOf(deps: CoreDeps, review: Review): Promise<Result<ContextBundle>> {
  const [facts, issue] = await Promise.all([deps.reviews.facts(review.id), deps.jira.issue(review.issueId)]);
  if (!facts.ok) return facts;
  return ok({
    issueId: review.issueId, issueKey: review.issueKey, facts: facts.value, partial: review.partial, partialReasons: [], contextHash: review.contextHash,
    gatheredAt: review.createdAt, components: issue.ok ? issue.value.components : [],
  });
}

/** Records what one stage's calls used: models on the review (tokens are settled per call), tokens in the month's usage. */
async function record(deps: CoreDeps, review: Review, before: { tokensIn: number; tokensOut: number }, usage: Usage): Promise<void> {
  const tokensIn = usage.tokensIn - before.tokensIn;
  const tokensOut = usage.tokensOut - before.tokensOut;
  if (tokensIn <= 0 && tokensOut <= 0 && usage.modelIds.size === 0) return;
  const a = await deps.reviews.addUsage(review.id, { tokensIn: 0, tokensOut: 0, modelIds: [...usage.modelIds] });
  if (!a.ok) log('engine.usage_failed', { reviewId: review.id, code: a.error.code });
  const m = await deps.usage.add(monthOf(deps.clock.now()), { tokensIn, tokensOut, reviews: 0 });
  if (!m.ok) log('engine.usage_failed', { reviewId: review.id, code: m.error.code });
}

const trace = (deps: CoreDeps, reviewId: string, stage: string, status: 'done' | 'failed', error?: string) =>
  deps.reviews.saveStage(reviewId, `engine_${stage}`, status, undefined, error, deps.clock.now().toISOString()).catch(() => null);

/**
 * Threatline Engine, one stage per queue job: a quarantined injection check, then N independent runs in parallel on the deep tier, each the Threatline agent
 * prompt over the nonce-fenced review context (each becomes a run exactly like a Rovo agent run, so consensus, quote
 * checks, injection flags and the rule-based floor apply unchanged) → assembly → the adversarial verifier. Model errors become failed runs: the review
 * then fails closed, as AI errors count as missing.
 */
export async function engineJob(deps: CoreDeps, job: EngineJob): Promise<Result<void>> {
  const got = await deps.reviews.get(job.reviewId);
  if (!got.ok) return got;
  const review = got.value;
  if (!review) return err(appError('not_found', `review ${job.reviewId}`));
  // A job of a superseded revision does nothing (it would re-point or remove the newer revision's requirement rows).
  const current = await deps.reviews.latest(review.issueId);
  if (!current.ok) return current;
  if (current.value && current.value.id !== review.id) {
    log('engine.superseded', { reviewId: review.id, stage: job.stage });
    return voidOk();
  }
  const policy = await deps.config.site();
  if (!policy.ok) return policy;
  const usage: Usage = { tokensIn: review.tokensIn, tokensOut: review.tokensOut, modelIds: new Set() };
  const before = { tokensIn: usage.tokensIn, tokensOut: usage.tokensOut };
  const cap = { tokensIn: policy.value.budget.tokensInPerReview, tokensOut: policy.value.budget.tokensOutPerReview };
  // Security: each call reserves its tokens atomically on the review row, so parallel stages cannot overshoot the cap.
  const budget = {
    reserve: async (tokensIn: number, tokensOut: number) => {
      const r = await deps.reviews.reserveUsage(review.id, { tokensIn, tokensOut }, cap);
      return r.ok && r.value;
    },
    settle: async (reserved: { tokensIn: number; tokensOut: number }, actual: { tokensIn: number; tokensOut: number }) => {
      const r = await deps.reviews.addUsage(review.id, { tokensIn: actual.tokensIn - reserved.tokensIn, tokensOut: actual.tokensOut - reserved.tokensOut, modelIds: [] });
      if (!r.ok) log('engine.usage_failed', { reviewId: review.id, code: r.error.code });
    },
  };
  const stageDeps = { llm: deps.llm, reviews: deps.reviews, policy: policy.value, budget };

  if (job.stage === 'verify') return verify(deps, review, stageDeps, usage, before);
  // A stale job (the review settled or timed out meanwhile) does nothing.
  if (review.status !== 'awaiting_agent') return voidOk();
  const bundle = await bundleOf(deps, review);
  if (!bundle.ok) return bundle;

  // Stage 1, the quarantined injection check: the only call that reads raw untrusted text, on the balanced tier. Its
  // model-based flag joins the scanner's (assembly and the verifier read it); then the independent runs start.
  if (job.stage === 'extract') {
    const x = await engineExtract(stageDeps, review, bundle.value, usage);
    await record(deps, review, before, usage);
    await trace(deps, review.id, 'injection_check', x.ok ? 'done' : 'failed', x.ok ? (x.value.sketch.injectionSuspected ? 'injection suspected' : undefined) : x.error.code);
    if (!x.ok) log('engine.extract_failed', { reviewId: review.id, code: x.error.code });
    return deps.queue.push(Array.from({ length: review.samplesExpected }, (_, n) => ({ kind: 'engine' as const, reviewId: review.id, stage: 'propose' as const, n })));
  }

  // Run n is stored as sample n + 1 (insert-only), and marked done only after that: a redelivered job (a failed save, or
  // a failed push of the assembly) never calls the model again, never stores a second sample, and still queues assembly.
  const n = job.n ?? 0;
  const slot = n + 1;
  if (slot > review.samplesExpected) return voidOk();
  const marker = await deps.reviews.stage(review.id, `run:${n}`);
  if (!marker.ok) return marker;
  if (marker.value?.status !== 'done' && marker.value?.status !== 'failed') {
    // A delivery that got the model's answer but failed to store it resumes from the checkpoint, without paying again.
    let sample = marker.value?.status === 'running' ? (marker.value.checkpoint as { sample?: Sample } | undefined)?.sample : undefined;
    if (!sample) {
      const r = await engineAgentRun(stageDeps, review, bundle.value, usage);
      await record(deps, review, before, usage);
      sample = r.ok ? r.value : { failed: r.error.code };
      const c = await deps.reviews.saveStage(review.id, `run:${n}`, 'running', { sample });
      if (!c.ok) log('engine.checkpoint_failed', { reviewId: review.id, n, code: c.error.code });
    }
    const s = await deps.reviews.saveSample(review.id, slot, sample);
    if (!s.ok) {
      if (s.error.code !== 'conflict') return s;
      // The slot is taken: by this run from an earlier delivery (done), or by a run stored in arrival order (a review
      // started before runs had fixed slots, or an agent submission). Then this run goes into the next free slot rather
      // than being dropped, so the review still gets every run it is waiting for.
      const stored = await deps.reviews.samples(review.id);
      if (!stored.ok) return stored;
      if (JSON.stringify(stored.value[slot - 1]) !== JSON.stringify(sample)) {
        const next = await storeSample(deps, review, sample);
        if (!next.ok && next.error.message !== 'complete') return next;
      }
    }
    const failed = 'failed' in sample ? sample.failed : undefined;
    const m = await deps.reviews.saveStage(review.id, `run:${n}`, failed ? 'failed' : 'done', undefined, failed);
    if (!m.ok) return m;
    await trace(deps, review.id, `run_${slot}`, failed ? 'failed' : 'done', failed);
    log('engine.run', { reviewId: review.id, n, valid: !failed });
  }
  return deps.queue.push([{ kind: 'assemble', reviewId: review.id }]);
}

/** Is this review one Threatline Engine ran (its marker stage, or an extract checkpoint from before runs replaced it)? */
export async function isEngineReview(deps: Pick<CoreDeps, 'reviews'>, reviewId: string): Promise<boolean> {
  const [m, x] = await Promise.all([deps.reviews.stage(reviewId, 'engine'), deps.reviews.stage(reviewId, 'extract')]);
  return (m.ok && !!m.value) || (x.ok && !!x.value);
}

type Verdicts = Array<{ threatId: string; keep: boolean; reason: string }>;

/** How long after a review settles the panel keeps waiting for the verifier (a lost job must not poll for ever). */
export const VERIFY_WAIT_MS = 10 * 60_000;

/**
 * Whether Threatline Engine's verifier is still to run on this ready review: the panel keeps polling meanwhile, so
 * the threats it shows are the verified ones without a refresh. Only for an engine review, and only for
 * VERIFY_WAIT_MS after the review settled.
 */
export async function verificationPending(deps: Pick<CoreDeps, 'reviews' | 'clock'>, review: Review): Promise<boolean> {
  if (review.status !== 'ready') return false;
  if (deps.clock.now().getTime() - new Date(review.updatedAt).getTime() > VERIFY_WAIT_MS) return false;
  const [v, engine] = await Promise.all([deps.reviews.stage(review.id, 'verify'), isEngineReview(deps, review.id)]);
  if (!engine || !v.ok) return false;
  return v.value?.status !== 'done' && v.value?.status !== 'failed';
}

/** After a re-assembly, the stored verifier verdicts are applied again so a late run cannot undo them. */
export async function reapplyVerification(deps: CoreDeps, review: Review): Promise<Result<void>> {
  const s = await deps.reviews.stage(review.id, 'verify');
  const verdicts = s.ok && s.value?.status === 'done' ? (s.value.checkpoint as { verdicts?: Verdicts } | undefined)?.verdicts : undefined;
  if (!verdicts?.length) return voidOk();
  return applyAndStore(deps, review, verdicts);
}

/**
 * The threats of this review a person has triaged (accepted, dismissed, edited, merged from or into, split): every
 * triage decision is ledgered (`threat.triaged`) before it is saved. The verifier's verdicts never touch them.
 */
async function triagedThreatIds(deps: CoreDeps, review: Review): Promise<Result<Set<string>>> {
  const rows = await deps.ledger.forIssues(['threat.triaged'], [review.issueId]);
  if (!rows.ok) return rows;
  const ids = new Set<string>();
  for (const r of rows.value) {
    if (r.payload.reviewId !== review.id) continue;
    if (typeof r.payload.threatId === 'string') ids.add(r.payload.threatId);
    if (typeof r.payload.intoThreatId === 'string') ids.add(r.payload.intoThreatId);
  }
  return ok(ids);
}

async function applyAndStore(deps: CoreDeps, review: Review, verdicts: Verdicts): Promise<Result<void>> {
  // Read after the model call: a champion may have triaged threats while the verifier ran (the review is already
  // ready, so the panel allows it). Their decisions stand; only the untouched threats take the verifier's verdicts.
  const [threats, facts, triaged] = await Promise.all([deps.reviews.threats(review.id), deps.reviews.facts(review.id), triagedThreatIds(deps, review)]);
  if (!threats.ok) return threats;
  if (!facts.ok) return facts;
  if (!triaged.ok) return triaged;
  const tainted = new Set(facts.value.filter((f) => f.injectionSuspected).map((f) => f.id));
  const policy = await deps.config.site();
  const blockAtOrAbove = policy.ok ? policy.value.blockAtOrAbove : 'Low';
  const untouched = verdicts.filter((v) => !triaged.value.has(v.threatId));
  if (untouched.length < verdicts.length) log('engine.verify_skipped_triaged', { reviewId: review.id, skipped: verdicts.length - untouched.length });
  const applied = applyVerification(threats.value, untouched, { injectionSuspected: false, taintedFacts: tainted, blockAtOrAbove });
  for (const t of applied.changed) {
    const u = await deps.reviews.updateThreat(t.id, { state: t.state, verification: t.verification, coveredBy: t.coveredBy, ...(t.dismissReason ? { dismissReason: t.dismissReason } : {}) });
    if (!u.ok) return u;
  }
  // Requirements follow: an untouched row of a dropped threat goes; a threat that is active again gets its row.
  const rows = await deps.requirements.forIssue(review.issueId);
  if (!rows.ok) return rows;
  for (const t of applied.changed) {
    const row = rows.value.find((r) => r.threatId === t.id);
    if ((t.state === 'dismissed' || t.state === 'covered') && row && row.status === 'Open' && !row.subtaskKey && !row.evidence) {
      const d = await deps.requirements.remove(row.id);
      if (!d.ok) return d;
    }
    if ((t.state === 'accepted' || t.state === 'needs_human') && !row) {
      const fresh = requirementsFor([t], { issueId: review.issueId, issueKey: review.issueKey })[0];
      if (fresh) {
        const u = await deps.requirements.upsert({ ...fresh, createdAt: deps.clock.now().toISOString() });
        if (!u.ok) return u;
      }
    }
  }
  return voidOk();
}

async function verify(deps: CoreDeps, review: Review, stageDeps: Parameters<typeof engineVerify>[0], usage: Usage, before: { tokensIn: number; tokensOut: number }): Promise<Result<void>> {
  const done = await deps.reviews.stage(review.id, 'verify');
  if (done.ok && done.value?.status === 'done') return voidOk();
  if (review.status !== 'ready') return voidOk();
  const [threats, facts, extract] = await Promise.all([deps.reviews.threats(review.id), deps.reviews.facts(review.id), deps.reviews.stage(review.id, 'extract')]);
  if (!threats.ok) return threats;
  if (!facts.ok) return facts;
  // Fail safe: without a completed injection check (or when it or the scanner flagged anything) the verifier never runs.
  const checked = extract.ok && extract.value?.status === 'done';
  const sketchFlag = checked && (extract.value?.checkpoint as Extracted | undefined)?.sketch.injectionSuspected === true;
  if (!checked || sketchFlag || facts.value.some((f) => f.injectionSuspected)) {
    await deps.reviews.saveStage(review.id, 'verify', 'done', { skipped: 'injection' });
    await trace(deps, review.id, 'verify', 'done', checked ? 'skipped: injection suspected' : 'skipped: injection check did not complete');
    return voidOk();
  }
  const nonce = globalThis.crypto.randomUUID().replace(/-/g, '').slice(0, 12);
  const v = await engineVerify(stageDeps, threats.value, usage, nonce);
  await record(deps, review, before, usage);
  if (!v.ok) {
    // Verification only ever removes noise; without it the review stands as assembled (stricter, never looser).
    log('engine.verify_failed', { reviewId: review.id, code: v.error.code });
    await deps.reviews.saveStage(review.id, 'verify', 'failed', undefined, v.error.code);
    await trace(deps, review.id, 'verify', 'failed', v.error.code);
    return voidOk();
  }
  const stored = await applyAndStore(deps, review, v.value);
  if (!stored.ok) return stored;
  await deps.reviews.saveStage(review.id, 'verify', 'done', { verdicts: v.value });
  await trace(deps, review.id, 'verify', 'done');
  log('engine.verified', { reviewId: review.id, checked: v.value.length, rejected: v.value.filter((x) => !x.keep).length });
  const r = await refreshVerdict(deps, review.issueId);
  if (!r.ok) return r;
  return deps.queue.push([{ kind: 'propagate', issueId: review.issueId }]);
}

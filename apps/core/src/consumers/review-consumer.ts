import { engineJob, isEngineReview, reapplyVerification } from '../services/engine.js';
import { assembleReview, requirementsFor } from '@threatline/core';
import { PROMPT_VERSION } from '@threatline/prompts';
import { appError, err, ok, type ContextBundle, type ContextFact, type Result, type Review, type SitePolicy, type Threat } from '@threatline/shared';
import type { Sample } from '@threatline/core';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { ReviewJobSchema, type ReviewJob } from '../jobs/types.js';
import { monthOf, pauseReasons } from '../services/budget.js';
import { contextKey, refreshVerdict } from '../services/verdict-service.js';
import { isPublished, publishThreatModel } from '../services/confluence-page.js';
import { REOPENED_STAGE, reopenForIncident } from '../services/incident-reopen.js';
import { opsAlert } from '../services/ops-alert.js';
import type { IncidentCause } from '../jobs/types.js';
import { recordHidden, suppressionsFor } from '../services/suppression-service.js';

/** Propagate to children, and re-publish the Confluence page when this work item has one (RQ-6). */
async function afterChange(deps: CoreDeps, issueId: string, republish: boolean): Promise<Result<void>> {
  const jobs: ReviewJob[] = [{ kind: 'propagate', issueId }];
  if (republish && (await isPublished(deps, issueId))) jobs.push({ kind: 'publish', issueId });
  return deps.queue.push(jobs);
}

export const SCHEMA_VERSION_KEY = 'schema:version';
/** The model id a rules-only review records: no model, only Threatline's deterministic rule-based checks. */
export const RULES_ONLY_MODEL = 'threatline-rules';

const voidOk = (): Result<void> => ok(undefined);

/** R7: the previous revision's threats and facts, so threats on unchanged sources carry over (with their triage). */
async function priorRevision(deps: CoreDeps, review: Review): Promise<Result<{ threats: Threat[]; facts: ContextFact[] } | null>> {
  if (review.revision <= 1) return ok(null);
  const history = await deps.reviews.history(review.issueId);
  if (!history.ok) return history;
  const prev = history.value.filter((r) => r.revision < review.revision).at(-1);
  if (!prev) return ok(null);
  const [threats, facts] = await Promise.all([deps.reviews.threats(prev.id), deps.reviews.facts(prev.id)]);
  if (!threats.ok) return threats;
  if (!facts.ok) return facts;
  return ok({ threats: threats.value, facts: facts.value });
}

/** Runs assembleReview and stores the result: threats, discarded, and requirement rows (existing rows keep their status). */
async function applyAssembly(deps: CoreDeps, review: Review, bundle: ContextBundle, samples: Sample[], policy: SitePolicy, mode: 'progress' | 'final') {
  const priorDismissed = [];
  for (const c of bundle.components ?? []) {
    const d = await deps.feedback.dismissedFor(c);
    if (!d.ok) return d;
    priorDismissed.push(...d.value);
  }
  const prior = await priorRevision(deps, review);
  if (!prior.ok) return prior;
  // Threatline Engine: the quarantined extractor's model-based injection signal counts like a flagged fact. Fail closed:
  // in an engine review, an injection check that failed or never completed counts as suspected (as for the verifier).
  const extract = await deps.reviews.stage(review.id, 'extract');
  if (!extract.ok) return extract;
  const extractorFlag =
    extract.value?.status === 'done'
      ? (extract.value.checkpoint as { sketch?: { injectionSuspected?: boolean } } | undefined)?.sketch?.injectionSuspected === true
      : samples.length > 0 && (await isEngineReview(deps, review.id));
  // Team suppression rules of the project (docs/SUPPRESSIONS.md); a failed lookup applies none.
  const suppressions = await suppressionsFor(deps, review);
  const out = assembleReview({
    review, bundle, samples, samplesExpected: review.samplesExpected, priorDismissed, policy, promptVersion: PROMPT_VERSION, now: deps.clock.now(), mode,
    ...(extractorFlag ? { injectionSuspected: true } : {}),
    ...(prior.value ? { prior: prior.value } : {}),
    ...(suppressions ? { suppressions } : {}),
  });
  const saved = await deps.reviews.saveThreats(review.id, out.threats, out.discarded);
  if (!saved.ok) return saved;
  // Until every agent run is in, consensus is provisional: only rule-based threats get requirement rows, so threats
  // that later lose the vote never leave orphan requirements behind.
  const settled = out.status !== 'awaiting_agent';
  const forRequirements = settled ? out.threats : out.threats.filter((t) => t.origin === 'baseline');
  for (const req of requirementsFor(forRequirements, { issueId: review.issueId, issueKey: review.issueKey })) {
    const existing = await deps.requirements.get(req.id);
    if (!existing.ok) return existing;
    const row = existing.value ? { ...existing.value, threatId: req.threatId, severity: req.severity, issueKey: req.issueKey } : { ...req, createdAt: deps.clock.now().toISOString() };
    const u = await deps.requirements.upsert(row);
    if (!u.ok) return u;
  }
  // A rule-based threat that the settled review shows as covered by a more specific AI threat loses the requirement
  // row it got while runs were arriving, unless someone has started on it. Triage recreates it if the threat returns.
  // The same for a threat a team rule hides (including the row an earlier revision gave the same threat).
  if (settled) {
    const covered = new Set(out.threats.filter((t) => t.state === 'covered' || t.state === 'suppressed').map((t) => t.id));
    const issue = { issueId: review.issueId, issueKey: review.issueKey };
    const inForce = new Set(requirementsFor(out.threats, issue).map((r) => r.id));
    const hiddenReqs = new Set(
      requirementsFor(out.threats.filter((t) => t.state === 'suppressed').map((t) => ({ ...t, state: 'accepted' as const })), issue).map((r) => r.id).filter((id) => !inForce.has(id)),
    );
    if (covered.size > 0) {
      const rows = await deps.requirements.forIssue(review.issueId);
      if (!rows.ok) return rows;
      for (const r of rows.value.filter((x) => (covered.has(x.threatId) || hiddenReqs.has(x.id)) && x.status === 'Open' && !x.subtaskKey && !x.evidence)) {
        const d = await deps.requirements.remove(r.id);
        if (!d.ok) return d;
      }
    }
    await recordHidden(deps, review, out.threats);
  }
  return ok(out);
}

async function gather(deps: CoreDeps, job: Extract<ReviewJob, { kind: 'gather' }>): Promise<Result<void>> {
  const policy = await deps.config.site();
  if (!policy.ok) return policy;
  const latest = await deps.reviews.latest(job.issueId);
  if (!latest.ok) return latest;
  const bundle = await deps.gatherer.gather(job.issueId, job.actorAccountId ? { actorAccountId: job.actorAccountId } : {});
  if (!bundle.ok) {
    log('gather.failed', { issueId: job.issueId, code: bundle.error.code });
    await refreshVerdict(deps, job.issueId);
    return bundle;
  }
  const b = bundle.value;
  try {
    await deps.state.set(contextKey(job.issueId), b.contextHash);
  } catch (e) {
    return err(appError('upstream', `kvs: ${e instanceof Error ? e.message : String(e)}`));
  }

  const prev = latest.value;
  // Resumable: a retried gather whose first attempt created this revision but failed before starting it (facts,
  // threats, engine runs) finishes those steps now, instead of leaving a review nobody runs.
  if (prev && prev.contextHash === b.contextHash) {
    const unstarted = await isUnstarted(deps, prev);
    if (!unstarted.ok) return unstarted;
    if (unstarted.value) return startReview(deps, prev, b, policy.value, job.reason, job.incident);
  }
  // New revisions: first review; explicit re-run; a create, or an incident on its components, whose content differs.
  // Edits and page changes only mark the review out of date (verdict review_stale with a one-click re-run), so no agent
  // run is left waiting for nobody. An incident whose review already includes it changes nothing.
  const createNew = !prev || job.reason === 'rerun' || ((job.reason === 'created' || job.reason === 'incident') && prev.contextHash !== b.contextHash);
  if (!createNew) {
    const v = await refreshVerdict(deps, job.issueId);
    if (!v.ok) return v;
    return deps.queue.push([{ kind: 'propagate', issueId: job.issueId }]);
  }

  const now = deps.clock.now();
  const month = monthOf(now);
  const reasons = await pauseReasons(deps, policy.value, now);
  if (!reasons.ok) return reasons;
  const rulesOnlyMode = policy.value.reviewMode === 'rules_only';
  // The month's review count is reserved atomically (increment-then-check), so parallel gathers at the cap cannot all
  // start one. Rules-only reviews use no AI and are not counted (they still pause at the budget, as before).
  let paused = reasons.value.credits || (rulesOnlyMode && reasons.value.budget);
  let reserved = false;
  if (!paused && !rulesOnlyMode) {
    const r = await deps.usage.reserveReview(month, policy.value.budget.reviewsPerMonth);
    if (!r.ok) return r;
    reserved = r.value;
    paused = !r.value;
  }
  // An incident re-review that the budget stopped is not started: the review it would replace stays (now out of date,
  // so the gate still blocks until it is re-run), rather than becoming a paused revision. The admin is told.
  if (paused && job.reason === 'incident' && prev) {
    log('review.incident_paused', { issueId: job.issueId });
    if (job.incident)
      await opsAlert(
        deps,
        `alert:incident-budget:${job.incident.id}`,
        `Threatline: incident ${job.incident.key} could not re-review ${b.issueKey} because reviews are paused at this month's review budget (or the site's Rovo credits). Raise the budget on the Threatline admin page (Budgets), then re-run it from the work item's panel.`,
      );
    const v = await refreshVerdict(deps, job.issueId);
    return v.ok ? voidOk() : v;
  }
  const revision = (prev?.revision ?? 0) + 1;
  // Rules-only mode (no Rovo on the site): the review is settled from the rule-based checks; no AI, no budget.
  const rulesOnly = !paused && rulesOnlyMode;
  const review: Review = {
    id: `rev_${job.issueId}_${revision}`,
    issueId: job.issueId,
    issueKey: b.issueKey,
    revision,
    // A rules-only review becomes ready only once its threats are stored (startReview), never before.
    status: paused ? 'failed' : 'awaiting_agent',
    ...(paused ? { failureReason: 'budget' } : {}),
    contextHash: b.contextHash,
    riskScore: 0,
    partial: b.partial,
    promptVersion: PROMPT_VERSION,
    modelIds: rulesOnly ? [RULES_ONLY_MODEL] : [],
    samplesExpected: paused || rulesOnly ? 0 : policy.value.agentSamples,
    samplesReceived: 0,
    tokensIn: 0,
    tokensOut: 0,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };
  const created = await deps.reviews.create(review);
  if (!created.ok) {
    // This attempt did not create the review, so it does not count it (whoever created it counted it).
    if (reserved) {
      const back = await deps.usage.add(month, { tokensIn: 0, tokensOut: 0, reviews: -1 });
      if (!back.ok) log('budget.release_failed', { issueId: job.issueId, code: back.error.code });
    }
    // A concurrent gather already created this revision: finish starting it if nobody has, else just refresh.
    if (created.error.code === 'conflict') {
      const existing = await deps.reviews.get(review.id);
      if (!existing.ok) return existing;
      if (existing.value && existing.value.contextHash === b.contextHash) {
        const unstarted = await isUnstarted(deps, existing.value);
        if (!unstarted.ok) return unstarted;
        if (unstarted.value) return startReview(deps, existing.value, b, policy.value, job.reason, job.incident);
      }
      await refreshVerdict(deps, job.issueId);
      return voidOk();
    }
    return created;
  }
  return startReview(deps, review, b, policy.value, job.reason, job.incident);
}

/**
 * The `gather` stage (the run trace's first step) is written once a review's gather has started it, as its last step:
 * a review without it was created by a gather that failed part-way.
 */
const STARTED_STAGE = 'gather';

/** A review that was created but not started (and nothing has run on yet): a retried gather finishes it. */
async function isUnstarted(deps: CoreDeps, review: Review): Promise<Result<boolean>> {
  if (review.status !== 'awaiting_agent' || review.samplesReceived > 0) return ok(false);
  const [started, samples] = await Promise.all([deps.reviews.stage(review.id, STARTED_STAGE), deps.reviews.samples(review.id)]);
  if (!started.ok) return started;
  if (!samples.ok) return samples;
  return ok(!started.value && samples.value.length === 0);
}

/**
 * Everything after the review row exists (its review count was reserved before it was created): facts, the
 * provisional assembly, the engine's first stage, then the marker that it started. Every step is idempotent, so a
 * retried gather runs them again safely.
 */
async function startReview(deps: CoreDeps, review: Review, b: ContextBundle, policy: SitePolicy, reason: string, incident?: IncidentCause): Promise<Result<void>> {
  const now = deps.clock.now();
  // Why this revision exists, for the panel's history (docs/INCIDENTS.md).
  if (incident) {
    const s = await deps.reviews.saveStage(review.id, REOPENED_STAGE, 'done', incident, undefined, now.toISOString());
    if (!s.ok) return s;
  }
  const paused = review.status === 'failed' && review.failureReason === 'budget';
  const rulesOnly = !paused && review.modelIds.includes(RULES_ONLY_MODEL);
  // Threatline Engine: Threatline runs the review itself on Forge LLMs (no Rovo, no Automation rule).
  const engine = !paused && !rulesOnly && policy.reviewMode === 'engine';
  const facts = await deps.reviews.saveFacts(review.id, b.facts);
  if (!facts.ok) return facts;
  const out = await applyAssembly(deps, review, b, [], policy, rulesOnly ? 'final' : 'progress');
  if (!out.ok) return out;
  const upd = await deps.reviews.update(review.id, { riskScore: out.value.riskScore, ...(rulesOnly ? { status: 'ready' as const } : {}), updatedAt: now.toISOString() });
  if (!upd.ok) return upd;
  if (engine) {
    // Marks the review as Threatline Engine's. The quarantined injection check runs first; it then starts the runs.
    const m = await deps.reviews.saveStage(review.id, 'engine', 'done', { runs: review.samplesExpected }, undefined, now.toISOString());
    if (!m.ok) return m;
    const q = await deps.queue.push([{ kind: 'engine', reviewId: review.id, stage: 'extract' }]);
    if (!q.ok) return q;
  }
  const started = await deps.reviews.saveStage(review.id, STARTED_STAGE, paused ? 'failed' : 'done', undefined, paused ? 'budget' : undefined, deps.clock.now().toISOString());
  if (!started.ok) return started;
  log('review.created', { issueId: review.issueId, revision: review.revision, reason, paused, partial: b.partial, engine });
  const v = await refreshVerdict(deps, review.issueId);
  if (!v.ok) return v;
  // A published page now trails the newest revision: re-publish so it says it is out of date.
  return afterChange(deps, review.issueId, true);
}

/** The run trace the admin page shows (review_stages). Best effort: a trace write never fails the review. */
export async function trace(deps: Pick<CoreDeps, 'reviews' | 'clock'>, reviewId: string, stage: string, status: 'running' | 'done' | 'failed', error?: string): Promise<void> {
  const r = await deps.reviews.saveStage(reviewId, stage, status, undefined, error, deps.clock.now().toISOString()).catch(() => null);
  if (!r?.ok) log('trace.failed', { reviewId, stage });
}

/** One `agent_<n>` stage per agent sample, recorded the first time an assembly sees it. */
async function traceSamples(deps: CoreDeps, reviewId: string, samples: readonly Sample[]): Promise<void> {
  const seen = await deps.reviews.stages(reviewId);
  const have = new Set(seen.ok ? seen.value.map((s) => s.stage) : []);
  for (let n = 1; n <= samples.length; n++) {
    if (have.has(`agent_${n}`)) continue;
    const s = samples[n - 1]!;
    await trace(deps, reviewId, `agent_${n}`, 'failed' in s ? 'failed' : 'done', 'failed' in s ? s.failed : undefined);
  }
}

/** Is this review still its work item's newest revision? Jobs of a superseded one must not touch shared rows. */
async function isCurrentRevision(deps: Pick<CoreDeps, 'reviews'>, review: Pick<Review, 'id' | 'issueId'>): Promise<Result<boolean>> {
  const l = await deps.reviews.latest(review.issueId);
  if (!l.ok) return l;
  return ok(!l.value || l.value.id === review.id);
}

/** An assembly assembles again when a newer run lands while it works, at most this many times. */
const MAX_REASSEMBLY = 6;

async function assemble(deps: CoreDeps, reviewId: string, again = 0): Promise<Result<void>> {
  const got = await deps.reviews.get(reviewId);
  if (!got.ok) return got;
  const review = got.value;
  if (!review) return err(appError('not_found', `review ${reviewId} not found`));
  if (review.status === 'failed' && review.failureReason === 'budget') return refreshVerdict(deps, review.issueId).then(() => voidOk());
  const current = await isCurrentRevision(deps, review);
  if (!current.ok) return current;
  if (!current.value) {
    log('assemble.superseded', { reviewId });
    return voidOk();
  }
  const policy = await deps.config.site();
  if (!policy.ok) return policy;
  const [samples, facts, issue] = await Promise.all([deps.reviews.samples(reviewId), deps.reviews.facts(reviewId), deps.jira.issue(review.issueId)]);
  if (!samples.ok) return samples;
  // M3: a settled review is not assembled again. A redelivered job, or a run arriving after the review settled (after
  // the timeout), would overwrite champion triage, so late runs are ignored. (`again` is this job assembling again
  // after a concurrent assembly, below.)
  const settled = review.status !== 'awaiting_agent' && review.status !== 'agent_timeout';
  if (settled && again === 0) {
    if (samples.value.length > review.samplesReceived) log('assemble.late_runs_ignored', { reviewId, received: samples.value.length, assembled: review.samplesReceived });
    return refreshVerdict(deps, review.issueId).then((v) => (v.ok ? voidOk() : v));
  }
  if (!facts.ok) return facts;
  const bundle: ContextBundle = {
    issueId: review.issueId,
    issueKey: review.issueKey,
    facts: facts.value,
    partial: review.partial,
    partialReasons: [],
    contextHash: review.contextHash,
    gatheredAt: review.createdAt,
    // Trusted component names come from Jira, never from the samples.
    components: issue.ok ? issue.value.components : [],
  };
  const k = samples.value.length;
  const mode = review.status === 'agent_timeout' ? 'final' : 'progress';
  const out = await applyAssembly(deps, review, bundle, samples.value, policy.value, mode);
  if (!out.ok) return out;
  // Concurrency: runs are only ever added. If one landed while this assembled, another job may already have written a
  // newer assembly that this one just overwrote, so assemble again: the last threat write always saw every run.
  const latestSamples = await deps.reviews.samples(reviewId);
  if (!latestSamples.ok) return latestSamples;
  if (latestSamples.value.length > k && again < MAX_REASSEMBLY) return assemble(deps, reviewId, again + 1);
  const status = review.status === 'failed' ? 'failed' : out.value.status;
  const failureReason = status === 'failed' || status === 'agent_timeout' ? out.value.failureReason : undefined;
  // Compare-and-set: a stale assembly (fewer runs, or one that read the status before the sweeper timed the review out)
  // never overwrites what a newer one wrote; it assembles again from the current row instead.
  const upd = await deps.reviews.updateWhere(
    review.id,
    { samplesReceivedAtMost: k, status: review.status },
    { status, riskScore: out.value.riskScore, samplesReceived: k, ...(failureReason ? { failureReason } : {}), updatedAt: deps.clock.now().toISOString() },
  );
  if (!upd.ok) return upd;
  if (!upd.value) {
    log('assemble.superseded_by_newer', { reviewId, samples: k });
    return again < MAX_REASSEMBLY ? assemble(deps, reviewId, again + 1) : voidOk();
  }
  await traceSamples(deps, review.id, samples.value);
  await trace(deps, review.id, 'assemble', status === 'failed' ? 'failed' : 'done', status === 'failed' ? (failureReason ?? review.failureReason ?? 'failed') : undefined);
  log('review.assembled', { reviewId, status, samples: k });
  // Threatline Engine: once settled, the verifier runs (once); a later re-assembly re-applies its stored verdicts.
  if (status === 'ready' && (await isEngineReview(deps, review.id))) {
    const verified = await deps.reviews.stage(review.id, 'verify');
    if (verified.ok && verified.value?.status === 'done') {
      const re = await reapplyVerification(deps, { ...review, status });
      if (!re.ok) return re;
    } else if (review.status !== 'ready') {
      const q = await deps.queue.push([{ kind: 'engine', reviewId: review.id, stage: 'verify' }]);
      if (!q.ok) return q;
    }
  }
  const v = await refreshVerdict(deps, review.issueId);
  if (!v.ok) return v;
  return afterChange(deps, review.issueId, status === 'ready' && review.status !== 'ready');
}

async function propagate(deps: CoreDeps, issueId: string): Promise<Result<void>> {
  const children = await deps.issues.children(issueId);
  if (!children.ok) return children;
  for (const c of children.value) {
    const v = await refreshVerdict(deps, c.issueId);
    if (!v.ok) log('propagate.failed', { issueId: c.issueId, code: v.error.code });
  }
  const grandchildren = [];
  for (const c of children.value) {
    const g = await deps.issues.children(c.issueId);
    if (g.ok && g.value.length > 0) grandchildren.push({ kind: 'propagate' as const, issueId: c.issueId });
  }
  return grandchildren.length > 0 ? deps.queue.push(grandchildren) : voidOk();
}

export async function handleJob(deps: CoreDeps, job: ReviewJob): Promise<Result<void>> {
  switch (job.kind) {
    case 'gather':
      return gather(deps, job);
    case 'assemble':
      return assemble(deps, job.reviewId);
    case 'propagate':
      return propagate(deps, job.issueId);
    case 'verdict': {
      const v = await refreshVerdict(deps, job.issueId);
      return v.ok ? voidOk() : v;
    }
    case 'publish': {
      const p = await publishThreatModel(deps, job.issueId);
      if (p.ok) return voidOk();
      // Nothing to publish or no design page is not worth retrying; transient failures are.
      if (p.error.code === 'validation' || p.error.code === 'not_found') {
        log('publish.skipped', { issueId: job.issueId, code: p.error.code });
        return voidOk();
      }
      return p;
    }
    case 'engine':
      return engineJob(deps, job);
    case 'incident':
      return reopenForIncident(deps, job);
    case 'migrate': {
      const m = await deps.migrate();
      if (!m.ok) return m;
      // Create the signing key now (once, from the queue) rather than on the first attestation, where two requests
      // could race to create it. Best effort: the first attestation still creates it if this fails.
      const k = await deps.keys.active();
      if (!k.ok) log('keys.ensure_failed', { code: k.error.code });
      try {
        await deps.state.set(SCHEMA_VERSION_KEY, m.value.to);
      } catch (e) {
        return err(appError('upstream', `kvs: ${e instanceof Error ? e.message : String(e)}`));
      }
      return voidOk();
    }
  }
}

/** Queue consumer: validates the job body (never trust a queue payload's shape), runs it, logs failures. */
export async function reviewConsumer(event: { body?: unknown }, deps: CoreDeps): Promise<Result<void>> {
  const parsed = ReviewJobSchema.safeParse(event.body);
  if (!parsed.success) {
    log('job.invalid', { issues: parsed.error.issues.length });
    return err(appError('validation', 'invalid job'));
  }
  const r = await handleJob(deps, parsed.data);
  if (!r.ok) log('job.failed', { kind: parsed.data.kind, code: r.error.code });
  return r;
}

import { appendLedger, fixHold, MAX_FIX_DIFF, runFixCheck, type Usage } from '@threatline/core';
import { FIX_CHECK_PROMPT_VERSION } from '@threatline/prompts';
import { appError, err, ok, type FixCheckRecord, type Result } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { isTransientCode } from '../consumers/retry.js';
import type { ReviewJob } from '../jobs/types.js';
import { isBudgetPaused, monthOf } from './budget.js';
import { isLicensed } from './license.js';
import { refreshVerdict } from './verdict-service.js';
import { fixCheckKey, readFixCheck } from './fix-check-store.js';

/**
 * Fix check (docs/FIX_CHECK.md), the Jira side: CI sends a pull request's diff with its report; the change is stored in
 * chunks, a queue job runs Threatline Engine on it, and the result is one record per work item (the latest change).
 * The verdict reads it through fixHold: it can only hold verified requirements for a champion, never release one.
 */

const diffKey = (issueId: string, n: number) => `fixcheck-diff:${issueId}:${n}`;
/** Forge KVS holds at most 240 KiB per value: the change is stored in parts well under it, even JSON-escaped. */
const CHUNK = 50_000;
const MAX_CHUNKS = Math.ceil(MAX_FIX_DIFF / CHUNK);
/** The developer's ceiling on fix checks a month across the site (each is one deep-tier model call). */
export const DEFAULT_FIX_CHECKS_PER_MONTH = 200;

type FixJob = Extract<ReviewJob, { kind: 'fix_check' }>;
const voidOk = (): Result<void> => ok(undefined);

async function save(deps: Pick<CoreDeps, 'state'>, r: FixCheckRecord): Promise<Result<void>> {
  try {
    await deps.state.set(fixCheckKey(r.issueId), r);
    return voidOk();
  } catch {
    return err(appError('upstream', 'could not save the fix check'));
  }
}

async function dropDiff(deps: Pick<CoreDeps, 'state'>, issueId: string): Promise<void> {
  for (let n = 0; n < MAX_CHUNKS; n++) await deps.state.delete(diffKey(issueId, n)).catch(() => undefined);
}

const fixChecksPerMonth = (): number => {
  const raw = process.env.THREATLINE_MAX_FIX_CHECKS_PER_MONTH?.trim() ?? '';
  return /^[1-9]\d{0,6}$/.test(raw) ? Number(raw) : DEFAULT_FIX_CHECKS_PER_MONTH;
};

export interface FixCheckRequest {
  issueId: string;
  issueKey: string;
  repo: string;
  commitSha: string;
  prUrl?: string;
  runUrl: string;
  /** The CI token id. */
  by: string;
  diff: string;
}

/**
 * Starts a fix check for a change: stores it and queues the job, with a pending record that holds verified requirements
 * meanwhile. The same commit already checked is not checked again. When it cannot run (license, the AI budget, the
 * month's fix-check ceiling) the record says why and counts as not shown, so a champion decides.
 */
export async function startFixCheck(deps: CoreDeps, req: FixCheckRequest): Promise<Result<FixCheckRecord>> {
  const prior = await readFixCheck(deps, req.issueId);
  if (prior.ok && prior.value && prior.value.commitSha === req.commitSha && prior.value.repo === req.repo && prior.value.status !== 'failed') return ok(prior.value);
  const now = deps.clock.now();
  const base: FixCheckRecord = {
    issueId: req.issueId, issueKey: req.issueKey, repo: req.repo, commitSha: req.commitSha, ...(req.prUrl ? { prUrl: req.prUrl } : {}), runUrl: req.runUrl,
    status: 'pending', requestedAt: now.toISOString(), by: req.by, files: 0, omittedFiles: 0, findings: [], confirmations: [],
  };
  const fail = async (failure: string) => {
    const r: FixCheckRecord = { ...base, status: 'failed', failure, finishedAt: now.toISOString() };
    const s = await save(deps, r);
    log('fix_check.not_run', { issueKey: req.issueKey, failure });
    return s.ok ? ok(r) : s;
  };
  if (!isLicensed(await deps.license.state())) return fail('Threatline has no active license on this site, so the change was not checked.');
  const policy = await deps.config.site();
  if (!policy.ok) return policy;
  const paused = await isBudgetPaused(deps, policy.value, now);
  if (!paused.ok) return paused;
  if (paused.value) return fail('AI reviews are paused at the monthly budget, so the change was not checked.');
  const slot = await deps.usage.takeSlot('fix_check', monthOf(now), fixChecksPerMonth());
  if (!slot.ok) return slot;
  if (slot.value === null) return fail("This site reached this month's fix-check limit, so the change was not checked.");
  try {
    await dropDiff(deps, req.issueId);
    for (let n = 0; n * CHUNK < req.diff.length; n++) await deps.state.set(diffKey(req.issueId, n), req.diff.slice(n * CHUNK, (n + 1) * CHUNK));
  } catch {
    return err(appError('upstream', 'could not store the change'));
  }
  const s = await save(deps, base);
  if (!s.ok) return s;
  const q = await deps.queue.push([{ kind: 'fix_check', issueId: req.issueId, commitSha: req.commitSha }]);
  if (!q.ok) return q;
  log('fix_check.requested', { issueKey: req.issueKey, bytes: req.diff.length });
  return ok(base);
}

async function readDiff(deps: Pick<CoreDeps, 'state'>, issueId: string): Promise<string | null> {
  let out = '';
  for (let n = 0; n < MAX_CHUNKS; n++) {
    const part = await deps.state.get<unknown>(diffKey(issueId, n)).catch(() => undefined);
    if (typeof part !== 'string') break;
    out += part;
  }
  return out.length > 0 ? out : null;
}

/** The queue job: one deep-tier call over the stored change, settled by code, then the verdict is recomputed. */
export async function fixCheckJob(deps: CoreDeps, job: FixJob, retriesLeft = 0): Promise<Result<void>> {
  const rec = await readFixCheck(deps, job.issueId);
  if (!rec.ok) return rec;
  const record = rec.value;
  // Superseded by a newer change, or already settled (a redelivered job): nothing to do.
  if (!record || record.commitSha !== job.commitSha || record.status !== 'pending') return voidOk();
  const finish = async (patch: Partial<FixCheckRecord>): Promise<Result<void>> => {
    // Read again: a newer change may have arrived while the model ran; never overwrite it.
    const latest = await readFixCheck(deps, job.issueId);
    if (latest.ok && latest.value && latest.value.commitSha !== job.commitSha) return voidOk();
    const done: FixCheckRecord = { ...record, ...patch, finishedAt: deps.clock.now().toISOString() };
    const s = await save(deps, done);
    if (!s.ok) return s;
    await dropDiff(deps, job.issueId);
    const l = await appendLedger(deps.ledger, deps.clock, 'fix_check.completed', {
      issueId: done.issueId, issueKey: done.issueKey, repo: done.repo, commitSha: done.commitSha, status: done.status,
      findings: done.findings.map((f) => ({ requirementId: f.requirementId, verdict: f.verdict })), injectionSuspected: done.injectionSuspected === true,
    }, `ci:${done.by}`);
    if (!l.ok) log('fix_check.ledger_failed', { issueKey: done.issueKey, code: l.error.code });
    const v = await refreshVerdict(deps, job.issueId);
    if (!v.ok) return v;
    return deps.queue.push([{ kind: 'propagate', issueId: job.issueId }]);
  };
  if (!isLicensed(await deps.license.state())) return finish({ status: 'failed', failure: 'Threatline has no active license on this site, so the change was not checked.' });
  const diff = await readDiff(deps, job.issueId);
  if (!diff) return finish({ status: 'failed', failure: 'The change was not stored, so it could not be checked. Push again to re-run the check.' });
  const [reqs, latest, policy] = await Promise.all([deps.requirements.forIssue(job.issueId), deps.reviews.latest(job.issueId), deps.config.site()]);
  if (!reqs.ok) return reqs;
  if (!latest.ok) return latest;
  if (!policy.ok) return policy;
  const threats = latest.value ? await deps.reviews.threats(latest.value.id) : ok([]);
  if (!threats.ok) return threats;
  const usage: Usage = { tokensIn: 0, tokensOut: 0, modelIds: new Set() };
  const nonce = globalThis.crypto.randomUUID().replace(/-/g, '').slice(0, 12);
  const r = await runFixCheck({ llm: deps.llm, policy: policy.value }, { requirements: reqs.value, threats: threats.value, diff }, usage, nonce);
  if (usage.tokensIn > 0 || usage.tokensOut > 0) {
    const m = await deps.usage.add(monthOf(deps.clock.now()), { tokensIn: usage.tokensIn, tokensOut: usage.tokensOut, reviews: 0 });
    if (!m.ok) log('fix_check.usage_failed', { code: m.error.code });
  }
  if (!r.ok) {
    if (isTransientCode(r.error.code) && retriesLeft > 0) {
      log('fix_check.retry_later', { issueKey: record.issueKey, code: r.error.code, retriesLeft });
      return r;
    }
    log('fix_check.failed', { issueKey: record.issueKey, code: r.error.code });
    return finish({ status: 'failed', failure: r.error.code === 'budget' ? 'The check reached its token budget.' : 'Threatline Engine could not complete the check. Push again to re-run it.' });
  }
  log('fix_check.done', { issueKey: record.issueKey, checked: r.value.findings.length, fixed: r.value.findings.filter((f) => f.verdict === 'fixed').length, injection: r.value.injectionSuspected });
  return finish({
    status: 'done', findings: r.value.findings, files: r.value.files, omittedFiles: r.value.omittedFiles, model: [...usage.modelIds].join(', ') || undefined, promptVersion: FIX_CHECK_PROMPT_VERSION,
    ...(r.value.injectionSuspected ? { injectionSuspected: true } : {}),
  });
}

/**
 * A security champion confirms a verified requirement is fixed although the check could not show it (ledgered first).
 * Only a requirement the check holds can be confirmed; the confirmation is for this commit only.
 */
export async function confirmFix(deps: CoreDeps, actor: string, issueId: string, requirementId: string): Promise<Result<FixCheckRecord>> {
  const rec = await readFixCheck(deps, issueId);
  if (!rec.ok) return rec;
  const record = rec.value;
  if (!record) return err(appError('not_found', 'no fix check for this work item'));
  const req = await deps.requirements.get(requirementId);
  if (!req.ok) return req;
  if (!req.value || req.value.issueId !== issueId) return err(appError('not_found', 'requirement'));
  const hold = fixHold(record, req.value, deps.clock.now());
  if (!hold || hold.kind !== 'unconfirmed') return err(appError('validation', 'the fix check does not hold this requirement'));
  const l = await appendLedger(deps.ledger, deps.clock, 'fix_check.confirmed', { issueId, issueKey: record.issueKey, requirementId, commitSha: record.commitSha, why: hold.why }, actor);
  if (!l.ok) return l;
  const next: FixCheckRecord = { ...record, confirmations: [...record.confirmations, { requirementId, by: actor, at: deps.clock.now().toISOString() }] };
  const s = await save(deps, next);
  if (!s.ok) return s;
  const v = await refreshVerdict(deps, issueId);
  if (!v.ok) log('fix_check.verdict_refresh_failed', { issueId, code: v.error.code });
  return ok(next);
}

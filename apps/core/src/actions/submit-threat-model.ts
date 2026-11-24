import { storeSample } from '../services/samples.js';
import { appendLedger, extractAgentJson, type Sample } from '@threatline/core';
import { appError, err, ok, type Result } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { handleJob } from '../consumers/review-consumer.js';
import { RECENT_INGESTS_AT_KEY, RECENT_INGESTS_KEY } from '../services/budget.js';
import { INGEST_LAST_AT_KEY } from '../resolvers/admin.js';
import { checkRerunLimit } from '../services/rate-limit.js';
import { consumeSubmissionToken } from '../services/submission-token.js';
import { callerOf, ISSUE_KEY, type ActionPayload } from './common.js';
import { isLicensed, licenseRefusal } from '../services/license.js';

export interface IngestResult {
  reviewId: string;
  received: number;
  expected: number;
  valid: boolean;
}

async function recordIngest(deps: CoreDeps, nonEmpty: boolean, creditsSignal: boolean): Promise<void> {
  try {
    if (creditsSignal) {
      const prev = await deps.state.get<unknown>(RECENT_INGESTS_KEY);
      const list = Array.isArray(prev) ? prev.filter((x): x is boolean => typeof x === 'boolean') : [];
      await deps.state.set(RECENT_INGESTS_KEY, [...list, nonEmpty].slice(-10));
      await deps.state.set(RECENT_INGESTS_AT_KEY, deps.clock.now().toISOString());
    }
    if (nonEmpty) await deps.state.set(INGEST_LAST_AT_KEY, deps.clock.now().toISOString());
  } catch {
    // the budget signal is best-effort
  }
}

/**
 * Stores one agent run as a sample on the open review (failed parses are stored too, so they count as received and
 * the review cannot hang), then queues `assemble`. With no open review, one is created first (a synchronous gather,
 * rate-limited per caller like a re-run).
 */
export async function ingestSample(
  deps: CoreDeps,
  issueKey: string,
  raw: string,
  via: 'agent' | 'automation' | 'chat',
  actor?: string,
  opts: { revision?: number; creditsSignal?: boolean } = {},
): Promise<Result<IngestResult>> {
  const issue = await deps.jira.issue(issueKey);
  if (!issue.ok) return issue;
  const policy = await deps.config.site();
  if (!policy.ok) return policy;
  if (!policy.value.enabledProjects.includes(issue.value.project.key)) return err(appError('validation', 'project_not_enabled'));

  let latest = await deps.reviews.latest(issue.value.id);
  if (!latest.ok) return latest;
  if (!latest.value || latest.value.status !== 'awaiting_agent') {
    if (actor) {
      const limit = await checkRerunLimit(deps, actor);
      if (!limit.ok) return limit;
    }
    const g = await handleJob(deps, { kind: 'gather', issueId: issue.value.id, reason: 'rerun', ...(actor ? { actorAccountId: actor } : {}) });
    if (!g.ok) return g;
    latest = await deps.reviews.latest(issue.value.id);
    if (!latest.ok) return latest;
  }
  const review = latest.value;
  if (!review || review.status !== 'awaiting_agent') return err(appError('conflict', review?.failureReason === 'budget' ? 'budget' : 'no_open_review'));
  // The submission token names the revision it was issued for; a run never files into another one.
  if (opts.revision !== undefined && review.revision !== opts.revision) return err(appError('conflict', 'wrong_revision'));

  const extracted = extractAgentJson(raw, issue.value.key);
  const sample: Sample = extracted.ok ? extracted.value : { failed: extracted.error.code };
  // Race fix: two runs arriving together get consecutive numbers (insert-only), never overwrite each other.
  const stored = await storeSample(deps, review, sample);
  if (!stored.ok) return stored;
  const n = stored.value;
  // Final review C2: who wrote each agent run is on the record, so a review its own developer steered is visible.
  if (actor) {
    const row = await appendLedger(deps.ledger, deps.clock, 'review.sample', { issueId: issue.value.id, reviewId: review.id, n, valid: extracted.ok, threats: extracted.ok ? extracted.value.threats.length : 0 }, actor);
    if (!row.ok) log('sample.ledger_failed', { reviewId: review.id, code: row.error.code });
  }
  await recordIngest(deps, raw.trim().length > 0, opts.creditsSignal !== false);
  const pushed = await deps.queue.push([{ kind: 'assemble', reviewId: review.id }]);
  if (!pushed.ok) return pushed;
  log('sample.ingested', { reviewId: review.id, n, valid: extracted.ok, via, ...(extracted.ok ? {} : { code: extracted.error.code }) });
  return ok({ reviewId: review.id, received: n, expected: review.samplesExpected, valid: extracted.ok });
}

export type SubmitResult =
  | { saved: true; valid: boolean; received: number; expected: number; message: string }
  | { saved: false; error: 'invalid_input' | 'invalid_token' | 'not_found' | 'not_review_author' | 'engine_mode' | 'project_not_enabled' | 'complete' | 'budget' | 'rate_limited' | 'unavailable' }
  /** Paid via Atlassian: the site's license is inactive, so no agent run is saved (docs/LICENSING.md). */
  | { saved: false; error: 'license_inactive'; message: string };

/**
 * CREATE action the agent calls to save its threat model (Automation "take actions" runs it unattended; chat and
 * assignment sessions show a confirmation card). Requires that the caller can edit the work item and presents the
 * single-use token get-review-context issued to them for this work item.
 */
export async function submitThreatModel(payload: ActionPayload & { issueKey?: unknown; threatModelJson?: unknown; submissionToken?: unknown }, deps: CoreDeps): Promise<SubmitResult> {
  const issueKey = typeof payload.issueKey === 'string' ? payload.issueKey.trim() : '';
  const deny = <E extends Extract<SubmitResult, { saved: false }>['error']>(reason: string, error: E) => {
    log('action.submit.denied', { reason, hasCaller: callerOf(payload) !== '', bytes: typeof payload.threatModelJson === 'string' ? payload.threatModelJson.length : -1 });
    return { saved: false as const, error };
  };
  if (!ISSUE_KEY.test(issueKey) || typeof payload.threatModelJson !== 'string') return deny('invalid_input', 'invalid_input');
  if (!isLicensed(await deps.license.state())) return { saved: false, error: 'license_inactive', message: licenseRefusal('action.submit') };
  const caller = callerOf(payload);
  if (!caller) return deny('no_caller', 'not_found');
  const issue = await deps.jira.issue(issueKey);
  if (!issue.ok) return deny(`issue_${issue.error.code}`, issue.error.code === 'not_found' || issue.error.code === 'forbidden' ? 'not_found' : 'unavailable');
  const allowed = await deps.jira.canEdit(caller, issue.value.id);
  if (!allowed.ok) return deny(`edit_check_${allowed.error.code}`, 'unavailable');
  if (!allowed.value) return deny('no_edit', 'not_found');
  // Only the configured review authors (the Automation rule owner) may fill a review's agent runs, so a developer
  // cannot write their own work item's threat model. The refusal is ledgered with who tried.
  const policy = await deps.config.site();
  if (!policy.ok) return deny('policy_unavailable', 'unavailable');
  // Threatline Engine writes this site's reviews itself; agent runs are not part of them.
  if (policy.value.reviewMode === 'engine') return deny('engine_mode', 'engine_mode');
  const authors = policy.value.reviewAuthors ?? [];
  if (authors.length > 0 && !authors.includes(caller)) {
    const row = await appendLedger(deps.ledger, deps.clock, 'review.sample_rejected', { issueId: issue.value.id, issueKey: issue.value.key, reason: 'not_review_author' }, caller);
    if (!row.ok) log('sample.reject_ledger_failed', { code: row.error.code });
    return deny('not_review_author', 'not_review_author');
  }
  // The revision this submission files into: the open review's, or the next one it will create. The token must be for it.
  const latest = await deps.reviews.latest(issue.value.id);
  if (!latest.ok) return deny(`latest_${latest.error.code}`, 'unavailable');
  const revision = latest.value?.status === 'awaiting_agent' ? latest.value.revision : (latest.value?.revision ?? 0) + 1;
  if (!(await consumeSubmissionToken(deps, payload.submissionToken, { issueId: issue.value.id, accountId: caller, revision }))) {
    log('action.submit.invalid_token', { issueId: issue.value.id });
    return { saved: false, error: 'invalid_token' };
  }

  // Security: the "out of Rovo credits" pause (3 empty runs in a row) is a site-wide switch, so only configured review
  // authors (the Automation rule owner) feed it. With none configured, any editor could submit empty runs, so the
  // signal is not collected at all: an arbitrary caller can never pause the site's reviews.
  const r = await ingestSample(deps, issue.value.key, payload.threatModelJson, 'agent', caller, { revision, creditsSignal: authors.includes(caller) });
  if (!r.ok) {
    const m = r.error.message;
    if (m === 'wrong_revision') return { saved: false, error: 'invalid_token' };
    if (m === 'project_not_enabled' || m === 'complete' || m === 'budget') return { saved: false, error: m };
    if (r.error.code === 'budget') return { saved: false, error: 'rate_limited' };
    return { saved: false, error: 'unavailable' };
  }
  const { received, expected, valid } = r.value;
  return {
    saved: true,
    valid,
    received,
    expected,
    message: valid ? `Saved agent run ${received} of ${expected} for ${issue.value.key}.` : `Saved agent run ${received} of ${expected}, but it was not a valid threat model; it counts as a failed run.`,
  };
}

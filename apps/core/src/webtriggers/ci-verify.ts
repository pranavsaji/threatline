import { z } from 'zod';
import { requirementIdsIn, type Requirement } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { authenticateCi } from '../services/ci-tokens.js';
import { setRequirementStatus } from '../services/requirements-service.js';
import { readVerdict, refreshVerdict } from '../services/verdict-service.js';
import { startFixCheck } from '../services/fix-check-service.js';
import { MAX_FIX_DIFF } from '@threatline/core';

/**
 * Web trigger `ci-verify` (docs/CI_VERIFICATION.md): CI reports which tests passed on a commit; every requirement whose
 * tests (named with its id, as the skeletons write them) all passed, with at least one pass, is marked Verified with the
 * run as evidence. Only a requirement that is Open or In progress changes: CI never un-verifies, never touches a risk
 * acceptance or Not applicable, and never approves or overrides anything. Every change goes through
 * setRequirementStatus, which ledgers it (as `ci:<token id>`, `viaCi: true`) before saving.
 */
export const MAX_BODY_BYTES = 256 * 1024;
export const CI_REPORTS_PER_HOUR = 120;
const MAX_RESULTS = 5000;
const MAX_IDS = 200;

export interface WebTriggerRequestLike {
  method?: string;
  headers?: Record<string, string[] | string | undefined>;
  body?: string;
}
export interface WebTriggerResponseLike {
  statusCode: number;
  headers: Record<string, string[]>;
  body: string;
}

export type CiOutcome = 'verified' | 'already_verified' | 'failed' | 'skipped' | 'not_open' | 'not_current' | 'unknown' | 'not_this_issue' | 'error';
export interface CiRequirementResult {
  requirementId: string;
  outcome: CiOutcome;
  passed: number;
  failed: number;
  skipped: number;
  /** A failure on this run for a requirement an earlier run (or a person) verified: it stays Verified. */
  stillVerified?: true;
  message?: string;
}
export interface CiVerifyResponse {
  issueKey: string;
  commitSha: string;
  /** The work item's verdict after this report: what the Done gate now says. */
  verdict: 'pass' | 'warn' | 'block';
  verified: number;
  results: CiRequirementResult[];
  /** Tests whose names carry no requirement id. */
  ignoredTests: number;
  /** The change was sent for a fix check (docs/FIX_CHECK.md): `checking` until it settles, or why it did not run. */
  fixCheck?: 'checking' | 'already_checked' | 'not_run';
}

const ISSUE_KEY = /^[A-Z][A-Z0-9_]{0,254}-\d{1,18}$/;
/** owner/repository; neither part is `.` or `..`. */
const REPO = /^(?!\.{1,2}\/)[A-Za-z0-9_.-]{1,100}\/(?!\.{1,2}$)[A-Za-z0-9_.-]{1,100}$/;
const httpsUrl = (s: string) => {
  try {
    const u = new URL(s);
    return u.protocol === 'https:' && u.username === '' && u.password === '';
  } catch {
    return false;
  }
};
const ReportSchema = z
  .object({
    issueKey: z.string().regex(ISSUE_KEY, 'a Jira work item key such as PAY-7'),
    repo: z.string().regex(REPO, 'owner/repository or workspace/repository'),
    commitSha: z.string().regex(/^[0-9a-f]{40}$/, 'the full 40-character lowercase commit hash'),
    runUrl: z.string().max(2000).refine(httpsUrl, 'an https link to the CI run'),
    results: z
      .array(z.object({ name: z.string().min(1).max(2000), status: z.enum(['passed', 'failed', 'skipped']) }).strict())
      .max(MAX_RESULTS),
    /** Fix check: the pull request's unified diff (base...head), and the pull request's https link. */
    diff: z.string().min(1).max(MAX_FIX_DIFF, `a diff of at most ${MAX_FIX_DIFF} characters`).optional(),
    prUrl: z.string().max(2000).refine(httpsUrl, 'an https link to the pull request').optional(),
  })
  .strict();

const respond = (statusCode: number, body: unknown, extra: Record<string, string[]> = {}): WebTriggerResponseLike => ({
  statusCode,
  headers: { 'content-type': ['application/json'], 'cache-control': ['no-store'], ...extra },
  body: JSON.stringify(body),
});
const refuse = (statusCode: number, error: string, message: string, extra?: Record<string, string[]>) => respond(statusCode, { error, message }, extra);
const unavailable = () => refuse(503, 'unavailable', 'Threatline could not read its storage, so nothing was verified. Retry the report.');

function header(req: WebTriggerRequestLike, name: string): string | undefined {
  for (const [k, v] of Object.entries(req.headers ?? {})) if (k.toLowerCase() === name) return Array.isArray(v) ? v[0] : v;
  return undefined;
}

export async function ciVerify(deps: CoreDeps, req: WebTriggerRequestLike): Promise<WebTriggerResponseLike> {
  if ((req.method ?? '').toUpperCase() !== 'POST') return refuse(405, 'method', 'POST a JSON report.', { allow: ['POST'] });
  const body = req.body ?? '';
  if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) return refuse(413, 'too_large', `The report is larger than ${MAX_BODY_BYTES / 1024} KB. Send only tests whose names carry a requirement id.`);

  const auth = await authenticateCi(deps, header(req, 'authorization'));
  if (!auth.ok) {
    if (auth.error === 'unavailable') return unavailable();
    return refuse(401, 'unauthorized', 'Send Authorization: Bearer <CI token> (Threatline admin → CI verification).', { 'www-authenticate': ['Bearer'] });
  }
  const token = auth.value;
  const slot = await deps.usage.takeSlot(`ci:${token.id}`, deps.clock.now().toISOString().slice(0, 13), CI_REPORTS_PER_HOUR);
  if (!slot.ok) return unavailable();
  if (slot.value === null) return refuse(429, 'rate_limited', `A CI token can send ${CI_REPORTS_PER_HOUR} reports an hour. Try again after the hour.`, { 'retry-after': ['3600'] });

  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch {
    return refuse(400, 'validation', 'The body is not JSON.');
  }
  const parsed = ReportSchema.safeParse(raw);
  // Paths and rules only: a value from the request is never echoed back.
  if (!parsed.success) return refuse(400, 'validation', parsed.error.issues.slice(0, 3).map((i) => `${i.path.join('.') || 'body'}: ${i.message}`).join('; '));
  const report = parsed.data;

  const project = report.issueKey.slice(0, report.issueKey.lastIndexOf('-'));
  const limited = (key: string) => token.projects.length > 0 && !token.projects.includes(key);
  if (limited(project)) return refuse(403, 'forbidden', 'This CI token is limited to other projects.');
  const issue = await deps.jira.issue(report.issueKey);
  if (!issue.ok) return issue.error.code === 'not_found' || issue.error.code === 'forbidden' ? refuse(404, 'not_found', `Work item ${report.issueKey} was not found.`) : unavailable();
  if (limited(issue.value.project.key)) return refuse(403, 'forbidden', 'This CI token is limited to other projects.');
  const policy = await deps.config.site();
  if (!policy.ok) return unavailable();
  if (!policy.value.enabledProjects.includes(issue.value.project.key)) return refuse(403, 'forbidden', `Threatline is not on for project ${issue.value.project.key}.`);

  const tally = new Map<string, { passed: number; failed: number; skipped: number }>();
  let ignoredTests = 0;
  for (const r of report.results) {
    const ids = requirementIdsIn(r.name);
    if (ids.length === 0) ignoredTests++;
    for (const id of ids) {
      const t = tally.get(id) ?? { passed: 0, failed: 0, skipped: 0 };
      t[r.status]++;
      tally.set(id, t);
    }
  }
  if (tally.size > MAX_IDS) return refuse(400, 'validation', `The report names more than ${MAX_IDS} requirements. Report one work item's tests at a time.`);

  // Fix check first: its pending record holds every requirement this report verifies until the check settles, so no
  // attestation can be issued in between. If the change cannot be stored, nothing is verified.
  let fixCheck: CiVerifyResponse['fixCheck'];
  if (report.diff) {
    const started = await startFixCheck(deps, {
      issueId: issue.value.id, issueKey: issue.value.key, repo: report.repo, commitSha: report.commitSha, runUrl: report.runUrl, by: token.id, diff: report.diff,
      ...(report.prUrl ? { prUrl: report.prUrl } : {}),
    });
    if (!started.ok) return unavailable();
    fixCheck = started.value.status === 'failed' ? 'not_run' : started.value.status === 'done' ? 'already_checked' : 'checking';
  }

  const ci = { tokenId: token.id, commitSha: report.commitSha, repo: report.repo };
  const viewer = { accountId: `ci:${token.id}` };
  let verdictIssueId = issue.value.id;
  const results: CiRequirementResult[] = [];
  for (const [requirementId, t] of [...tally.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const base = { requirementId, ...t };
    const got = await deps.requirements.get(requirementId);
    if (!got.ok) {
      results.push({ ...base, outcome: 'error', message: 'Threatline could not read this requirement; retry the report.' });
      continue;
    }
    const r: Requirement | null = got.value;
    if (!r) {
      results.push({ ...base, outcome: 'unknown', message: 'No Threatline requirement has this id.' });
      continue;
    }
    // The work item itself, or the requirement's own sub-task (a branch may name PAY-101 rather than its parent).
    if (r.issueId !== issue.value.id && r.subtaskKey !== issue.value.key) {
      results.push({ ...base, outcome: 'not_this_issue', message: `This requirement belongs to another work item, not ${report.issueKey}.` });
      continue;
    }
    if (r.issueId !== issue.value.id) verdictIssueId = r.issueId;
    if (t.failed > 0) {
      results.push({
        ...base,
        outcome: 'failed',
        ...(r.status === 'Verified' ? { stillVerified: true as const } : {}),
        message: r.status === 'Verified' ? `${t.failed} test(s) failed on this run. It is still Verified (from earlier evidence): reopen it in the Threatline panel if this is a regression.` : `${t.failed} test(s) failed on this run, so it is not verified.`,
      });
      continue;
    }
    if (t.passed === 0) {
      results.push({ ...base, outcome: 'skipped', message: 'Its tests were skipped, so nothing proves it on this run.' });
      continue;
    }
    if (r.status === 'Verified') {
      results.push({ ...base, outcome: 'already_verified' });
      continue;
    }
    if (r.status !== 'Open' && r.status !== 'InProgress') {
      results.push({ ...base, outcome: 'not_open', message: `It is ${r.status === 'AcceptedRisk' ? 'covered by an accepted risk' : 'marked Not applicable'}; CI does not change that.` });
      continue;
    }
    const note = `${t.passed} test(s) passed`;
    const set = await setRequirementStatus(deps, { ...viewer, issueId: r.issueId }, { requirementId, status: 'Verified', evidence: { kind: 'ci', ref: report.runUrl, note } }, { ci });
    if (set.ok) results.push({ ...base, outcome: 'verified' });
    // Changed by a person while this report ran (a fresh read or the conditional save saw it): left as it is.
    else if (set.error.code === 'conflict') results.push({ ...base, outcome: 'not_open', message: 'It changed while this report ran (for example a risk was accepted); CI did not change it.' });
    else if (set.error.code === 'not_found') results.push({ ...base, outcome: 'not_current', message: 'Its threat is no longer in the latest review, so it was not verified.' });
    else results.push({ ...base, outcome: 'error', message: 'Threatline could not record this; nothing changed. Retry the report.' });
  }

  // A fix check changes the verdict even when no requirement moved: recompute it rather than read the stored one.
  const verdict = fixCheck ? await refreshVerdict(deps, verdictIssueId) : await readVerdict(deps, verdictIssueId);
  const state: CiVerifyResponse['verdict'] = verdict.ok && verdict.value ? verdict.value.state : 'block';
  const verified = results.filter((r) => r.outcome === 'verified').length;
  const failedToRecord = results.some((r) => r.outcome === 'error');
  log('ci.verify', { tokenId: token.id, issueKey: report.issueKey, requirements: results.length, verified, errors: results.filter((r) => r.outcome === 'error').length, ...(fixCheck ? { fixCheck } : {}) });
  const out: CiVerifyResponse = { issueKey: report.issueKey, commitSha: report.commitSha, verdict: state, verified, results, ignoredTests, ...(fixCheck ? { fixCheck } : {}) };
  return respond(failedToRecord ? 503 : 200, out);
}

import { z } from 'zod';
import { appendLedger, WARN_ONLY_MAX_DAYS, warnOnlyUntil } from '@threatline/core';
import { SitePolicySchema, type SitePolicy } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { monthOf, pauseReasons, RECENT_INGESTS_KEY } from '../services/budget.js';
import { DIGEST_CONFIG_KEY } from '../services/digest.js';
import { OPS_CONFIG_KEY, opsAlert } from '../services/ops-alert.js';
import { bumpPolicyVersion, POLICY_VERSION_KEY, policyVersion } from '../services/verdict-service.js';
import { seedDemo, type SeedResult } from '../seeder/seed.js';
import { SCHEMA_VERSION_KEY } from '../consumers/review-consumer.js';
import { apiError, type ApiError } from './errors.js';
import { isLicensed, licenseRefusal } from '../services/license.js';

export interface Admin {
  accountId: string;
}

/** KVS markers the setup checklist reads (written where the thing happens). */
export const VALIDATOR_SEEN_KEY = 'validator:seen';
export const INGEST_LAST_AT_KEY = 'ingest:lastAt';
export const BITBUCKET_KEY_COPIED_KEY = 'setup:bitbucketKeyCopied';

const DAY = 86_400_000;
const SeedSchema = z.object({ projectKey: z.string().regex(/^[A-Z][A-Z0-9_]{0,254}$/), spaceKey: z.union([z.literal(''), z.string().regex(/^[A-Za-z0-9~_-]{1,255}$/)]).optional() });

export async function requireAdmin(deps: CoreDeps, a: Admin): Promise<ApiError | null> {
  if (!a.accountId) return { error: 'forbidden', message: 'Only a Jira administrator can do this.' };
  const r = await deps.jira.isAdmin(a.accountId);
  if (!r.ok) return apiError(r.error);
  return r.value ? null : { error: 'forbidden', message: 'Only a Jira administrator can do this.' };
}

/** `admin.seed` (Task 24): loads the demo onto this site. Jira administrators only. */
export async function adminSeed(deps: CoreDeps, a: Admin, payload: unknown): Promise<SeedResult | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  // The demo queues reviews: with an inactive license none would start (docs/LICENSING.md).
  if (!isLicensed(await deps.license.state())) return { error: 'validation', message: licenseRefusal('admin.seed') };
  const p = SeedSchema.safeParse(payload);
  if (!p.success) return { error: 'validation', message: 'Give a Jira project key (like PAY), and a Confluence space key if the site has Confluence.' };
  const r = await seedDemo(deps, { projectKey: p.data.projectKey, ...(p.data.spaceKey ? { spaceKey: p.data.spaceKey } : {}) }, a.accountId);
  return r.ok ? r.value : apiError(r.error);
}

export interface SetupStatus {
  keys: boolean;
  sqlVersion: number;
  validatorSeenOn: string[];
  automationRuleSeen: boolean;
  mcpEnabledHint: string;
  bitbucketKeyCopied: boolean;
}

const MCP_HINT =
  'Rovo MCP: in Atlassian Administration → Apps → Sites → your site → Connected apps → Threatline → View app details → Tools, turn the tools on. Coding agents then get Threatline’s tools (get-review, get-security-requirements, check-change-risk, get-merge-attestation, request-risk-acceptance, verify-requirement, explain-threat, posture-summary) with the user’s own permissions.';

/** `admin.setupStatus` (Task 24): what Threatline has seen working on this site. Jira administrators only. */
export async function adminSetupStatus(deps: CoreDeps, a: Admin, o: { signingKeys: () => Promise<boolean> }): Promise<SetupStatus | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const now = deps.clock.now().getTime();
  const get = async <T>(k: string) => deps.state.get<T>(k).catch(() => undefined);
  const [sql, seen, ingestAt, copied, keys] = await Promise.all([
    get<unknown>(SCHEMA_VERSION_KEY),
    get<Record<string, unknown>>(VALIDATOR_SEEN_KEY),
    get<unknown>(INGEST_LAST_AT_KEY),
    get<unknown>(BITBUCKET_KEY_COPIED_KEY),
    o.signingKeys().catch(() => false),
  ]);
  const recent = (iso: unknown, days: number) => typeof iso === 'string' && now - new Date(iso).getTime() <= days * DAY;
  return {
    keys,
    sqlVersion: typeof sql === 'number' ? sql : 0,
    validatorSeenOn: Object.entries(seen && typeof seen === 'object' ? seen : {})
      .filter(([, at]) => recent(at, 30))
      .map(([k]) => k)
      .sort(),
    automationRuleSeen: recent(ingestAt, 7),
    mcpEnabledHint: MCP_HINT,
    bitbucketKeyCopied: copied === true,
  };
}

// ---- Task 30: policy, warn-only, runs, usage, notifications ----

export { POLICY_VERSION_KEY };
export const RUNS_LIMIT = 50;
const PROJECT_KEY = /^[A-Z][A-Z0-9_]{0,254}$/;
const ISSUE_KEY = /^[A-Z][A-Z0-9_]{0,254}-\d{1,18}$/;
const SPACE_KEY = /^[A-Za-z0-9~_-]{1,255}$/;
const SETTLED = new Set(['ready', 'failed', 'agent_timeout']);

export interface OpsConfig {
  issueKey: string;
  accountIds: string[];
}
export interface DigestConfig {
  spaceKey: string;
  parentPageId?: string;
}
export interface AdminPolicyDto {
  policy: SitePolicy;
  /** False until an administrator saves a policy here (the first-run wizard shows until then). */
  saved: boolean;
  ops: OpsConfig | null;
  digest: DigestConfig | null;
  /** Who submitted the most recent agent runs (newest first, at most 5), from the risk ledger: normally the Automation rule owner. */
  recentReviewAuthors: Array<{ accountId: string; runs: number; lastAt: string }>;
  /** Paid via Atlassian: the site's license is inactive, so no new reviews start (docs/LICENSING.md). */
  licenseInactive?: true;
}

const name = z.string().trim().min(1).max(255);
const ACCOUNT_ID = /^[A-Za-z0-9:_-]{1,128}$/;
const AdminPolicySchema = SitePolicySchema.superRefine((p, ctx) => {
  const bad = p.enabledProjects.find((k) => !PROJECT_KEY.test(k));
  if (bad !== undefined) ctx.addIssue({ code: 'custom', path: ['enabledProjects'], message: `"${bad.slice(0, 40)}" is not a Jira project key (like PAY).` });
  if (p.enabledProjects.length > 100) ctx.addIssue({ code: 'custom', path: ['enabledProjects'], message: 'Turn Threatline on for at most 100 projects.' });
  if (p.guardedTransitions.length === 0 || p.guardedTransitions.some((t) => !name.safeParse(t).success))
    ctx.addIssue({ code: 'custom', path: ['guardedTransitions'], message: 'Name at least one guarded transition (like Done).' });
  if (p.reviewIssueTypes.some((t) => !name.safeParse(t).success)) ctx.addIssue({ code: 'custom', path: ['reviewIssueTypes'], message: 'Work type names cannot be empty.' });
  const badAuthor = (p.reviewAuthors ?? []).find((x) => !ACCOUNT_ID.test(x));
  if (badAuthor !== undefined) ctx.addIssue({ code: 'custom', path: ['reviewAuthors'], message: `"${badAuthor.slice(0, 40)}" is not an Atlassian account ID.` });
  for (const g of ['techLeadGroup', 'championGroup'] as const)
    if (!name.safeParse(p[g]).success) ctx.addIssue({ code: 'custom', path: [g], message: g === 'championGroup' ? 'Name the security champions group.' : 'Name the tech leads group.' });
  // canApprove needs a champion for High and above whatever this says; refuse a cap that would claim otherwise.
  if (p.techLeadMaxSeverity === 'High' || p.techLeadMaxSeverity === 'Critical')
    ctx.addIssue({ code: 'custom', path: ['techLeadMaxSeverity'], message: 'Tech leads can accept at most Medium risks: High and Critical always need a security champion.' });
  if (p.sensitivePaths.length > 200 || p.sensitivePaths.some((s) => !s.trim() || s.length > 300))
    ctx.addIssue({ code: 'custom', path: ['sensitivePaths'], message: 'Sensitive paths are up to 200 non-empty patterns.' });
});

const firstIssue = (e: z.ZodError) => {
  const i = e.issues[0];
  if (!i) return 'That policy is not valid.';
  return i.code === 'custom' ? i.message : `${i.path.join('.') || 'policy'}: ${i.message}`;
};

async function readJson<T>(deps: CoreDeps, key: string, schema: z.ZodType<T>): Promise<T | null> {
  const v = await deps.state.get<unknown>(key).catch(() => undefined);
  const p = schema.safeParse(v);
  return p.success ? p.data : null;
}
const OpsSchema = z.object({ issueKey: z.string().regex(ISSUE_KEY), accountIds: z.array(z.string().regex(/^[A-Za-z0-9:_-]{1,128}$/)).max(10) }).strict();
const DigestSchema = z.object({ spaceKey: z.string().regex(SPACE_KEY), parentPageId: z.string().regex(/^\d{1,20}$/).optional() }).strict();

const SAVED_UNCHECKED: ApiError = {
  error: 'unavailable',
  message: 'The policy was saved, but Threatline could not mark existing verdicts for a recheck. Save again to retry.',
};

/** `admin.getPolicy`: the site policy in force, and where alerts and the weekly digest go. */
export async function adminGetPolicy(deps: CoreDeps, a: Admin): Promise<AdminPolicyDto | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const policy = await deps.config.site();
  if (!policy.ok) return apiError(policy.error);
  const [version, ops, digest, samples, license] = await Promise.all([
    policyVersion(deps),
    readJson(deps, OPS_CONFIG_KEY, OpsSchema),
    readJson(deps, DIGEST_CONFIG_KEY, DigestSchema),
    deps.ledger.latestOfTypes(['review.sample'], 500),
    deps.license.state(),
  ]);
  const authors = new Map<string, { runs: number; lastAt: string }>();
  for (const r of samples.ok ? [...samples.value].reverse() : []) {
    if (!r.actor) continue;
    const a = authors.get(r.actor);
    if (a) a.runs++;
    else if (authors.size < 5) authors.set(r.actor, { runs: 1, lastAt: r.createdAt });
  }
  const recentReviewAuthors = [...authors].map(([accountId, v]) => ({ accountId, ...v }));
  return { policy: policy.value, saved: (version ?? 0) > 0, ops, digest, recentReviewAuthors, ...(isLicensed(license) ? {} : { licenseInactive: true as const }) };
}

/**
 * `admin.setPolicy`: validates, checks newly enabled projects exist, ledgers which fields changed, saves, and marks
 * every stored verdict for a recheck. Warn-only windows are kept as stored: they change only through `admin.warnOnly`.
 */
export async function adminSetPolicy(deps: CoreDeps, a: Admin, payload: unknown): Promise<{ policy: SitePolicy } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const raw = (payload as { policy?: unknown } | null)?.policy;
  const current = await deps.config.site();
  if (!current.ok) return apiError(current.error);
  // A site saved before the cap was limited may still hold High or Critical (which always acted as Medium): saving
  // another section carries it as Medium rather than refusing the save. Only a new High or Critical is refused.
  const legacyCap = (raw as { techLeadMaxSeverity?: unknown } | null)?.techLeadMaxSeverity === current.value.techLeadMaxSeverity && ['High', 'Critical'].includes(current.value.techLeadMaxSeverity);
  const parsed = AdminPolicySchema.safeParse(raw && typeof raw === 'object' ? { ...raw, warnOnly: current.value.warnOnly, ...(legacyCap ? { techLeadMaxSeverity: 'Medium' } : {}) } : raw);
  if (!parsed.success) return { error: 'validation', message: firstIssue(parsed.error) };
  const next: SitePolicy = { ...parsed.data, enabledProjects: [...new Set(parsed.data.enabledProjects)] };
  for (const key of next.enabledProjects.filter((k) => !current.value.enabledProjects.includes(k))) {
    const p = await deps.jira.projectInfo(key);
    if (!p.ok) return p.error.code === 'not_found' || p.error.code === 'forbidden' || p.error.code === 'validation' ? { error: 'validation', message: `Jira project ${key} was not found.` } : apiError(p.error);
  }
  const fields = (Object.keys(next) as Array<keyof SitePolicy>).filter((k) => JSON.stringify(next[k]) !== JSON.stringify(current.value[k])).sort();
  const row = await appendLedger(deps.ledger, deps.clock, 'policy.changed', { fields }, a.accountId);
  if (!row.ok) return apiError(row.error);
  const saved = await deps.config.setSite(next);
  if (!saved.ok) return apiError(saved.error);
  if (!(await bumpPolicyVersion(deps))) return SAVED_UNCHECKED;
  log('policy.changed', { fields: fields.join(',') });
  return { policy: next };
}

const WarnSchema = z.object({
  projectKey: z.string().regex(PROJECT_KEY, 'Give a Jira project key (like PAY).'),
  days: z.number({ message: `Warn-only lasts 1 to ${WARN_ONLY_MAX_DAYS} days.` }).int(`Warn-only lasts 1 to ${WARN_ONLY_MAX_DAYS} days.`).min(1, `Warn-only lasts 1 to ${WARN_ONLY_MAX_DAYS} days.`).max(WARN_ONLY_MAX_DAYS, `Warn-only lasts 1 to ${WARN_ONLY_MAX_DAYS} days.`),
});

/**
 * `admin.warnOnly`: the project's gate warns instead of blocking, from now, for 1 to 14 days. Ledgered; replaces any
 * window. Switching it on again while it is on keeps the original start, so the 14 days cannot be renewed forever.
 */
export async function adminWarnOnly(deps: CoreDeps, a: Admin, payload: unknown): Promise<{ projectKey: string; since: string; until: string; entryHash: string; message?: string } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const p = WarnSchema.safeParse(payload);
  if (!p.success) return { error: 'validation', message: p.error.issues[0]?.message ?? 'Invalid warn-only request.' };
  const { projectKey, days } = p.data;
  const policy = await deps.config.site();
  if (!policy.ok) return apiError(policy.error);
  if (!policy.value.enabledProjects.includes(projectKey)) return { error: 'validation', message: `Threatline is not turned on for ${projectKey}.` };
  const now = deps.clock.now();
  const t = now.getTime();
  const active = policy.value.warnOnly.find((w) => {
    const from = Date.parse(w.since);
    return w.projectKey === projectKey && from <= t && t < Math.min(Date.parse(w.until), from + WARN_ONLY_MAX_DAYS * DAY);
  });
  const start = active ? new Date(active.since) : now;
  const since = start.toISOString();
  const until = new Date(Math.min(t + days * DAY, start.getTime() + WARN_ONLY_MAX_DAYS * DAY)).toISOString();
  const row = await appendLedger(deps.ledger, deps.clock, 'policy.warn_only', { projectKey, since, until, days, ...(active ? { extended: true } : {}) }, a.accountId);
  if (!row.ok) return apiError(row.error);
  const kept = policy.value.warnOnly.filter((w) => w.projectKey !== projectKey && new Date(w.until).getTime() > now.getTime());
  const saved = await deps.config.setSite({ ...policy.value, warnOnly: [...kept, { projectKey, since, until }] });
  if (!saved.ok) return apiError(saved.error);
  if (!(await bumpPolicyVersion(deps))) return SAVED_UNCHECKED;
  await opsAlert(deps, `alert:warn_only:${row.value.entryHash}`, `Threatline: an administrator switched ${projectKey} to warn-only until ${until.slice(0, 16).replace('T', ' ')} UTC. Its Done gate warns instead of blocking until then. Recorded in the Threatline ledger.`);
  const message = active
    ? `${projectKey} has been in warn-only since ${utc(since)}, and warn-only lasts at most ${WARN_ONLY_MAX_DAYS} days from when it was switched on, so it now ends ${utc(until)}. After that the gate blocks again; it can be switched on afresh once this window has ended.`
    : undefined;
  return { projectKey, since, until, entryHash: row.value.entryHash, ...(message ? { message } : {}) };
}

const utc = (iso: string) => `${iso.slice(0, 16).replace('T', ' ')} UTC`;

/** `admin.warnOnlyEnd`: ends a project's warn-only window now. Ledgered; the gate blocks again at once. */
export async function adminWarnOnlyEnd(deps: CoreDeps, a: Admin, payload: unknown): Promise<{ projectKey: string; entryHash: string } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const p = WarnSchema.pick({ projectKey: true }).safeParse(payload);
  if (!p.success) return { error: 'validation', message: 'Give a Jira project key (like PAY).' };
  const { projectKey } = p.data;
  const policy = await deps.config.site();
  if (!policy.ok) return apiError(policy.error);
  const now = deps.clock.now();
  if (!warnOnlyUntil(policy.value, projectKey, now)) return { error: 'validation', message: `${projectKey} is not in warn-only mode.` };
  const row = await appendLedger(deps.ledger, deps.clock, 'policy.warn_only', { projectKey, ended: true, at: now.toISOString() }, a.accountId);
  if (!row.ok) return apiError(row.error);
  const saved = await deps.config.setSite({ ...policy.value, warnOnly: policy.value.warnOnly.filter((w) => w.projectKey !== projectKey && new Date(w.until).getTime() > now.getTime()) });
  if (!saved.ok) return apiError(saved.error);
  if (!(await bumpPolicyVersion(deps))) return SAVED_UNCHECKED;
  return { projectKey, entryHash: row.value.entryHash };
}

/**
 * `admin.resumeReviews` (final review C3): clears the out-of-credits signal (three empty agent runs in a row) so new
 * reviews run again, for example after credits are topped up. Ledgered. The monthly budget is raised on the policy.
 */
export async function adminResumeReviews(deps: CoreDeps, a: Admin, _payload: unknown): Promise<{ resumed: true; entryHash: string } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const row = await appendLedger(deps.ledger, deps.clock, 'reviews.resumed', { at: deps.clock.now().toISOString() }, a.accountId);
  if (!row.ok) return apiError(row.error);
  try {
    await deps.state.set(RECENT_INGESTS_KEY, []);
  } catch {
    return { error: 'unavailable' };
  }
  return { resumed: true, entryHash: row.value.entryHash };
}

const PurgeSchema = z.object({ projectKey: z.string().regex(PROJECT_KEY), confirm: z.string() });

/**
 * `admin.purgeProject` (privacy): deletes every review, gathered fact, threat and requirement of a project Threatline no
 * longer reviews. The ledger and attestations stay (audit trail). Ledgered before anything is deleted.
 */
export async function adminPurgeProject(deps: CoreDeps, a: Admin, payload: unknown): Promise<{ projectKey: string; reviews: number; requirements: number; entryHash: string } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const p = PurgeSchema.safeParse(payload);
  if (!p.success) return { error: 'validation', message: 'Give a Jira project key (like PAY).' };
  const { projectKey, confirm } = p.data;
  if (confirm !== projectKey) return { error: 'validation', message: `Type ${projectKey} to confirm. This cannot be undone.` };
  const policy = await deps.config.site();
  if (!policy.ok) return apiError(policy.error);
  if (policy.value.enabledProjects.includes(projectKey))
    return { error: 'validation', message: `Threatline still reviews ${projectKey}. Turn it off under Projects and transitions first, then purge.` };
  const row = await appendLedger(deps.ledger, deps.clock, 'project.purged', { projectKey }, a.accountId);
  if (!row.ok) return apiError(row.error);
  const done = await deps.retention.purgeProject(projectKey);
  if (!done.ok) return apiError(done.error);
  await opsAlert(deps, `alert:purge:${row.value.entryHash}`, `Threatline: an administrator purged ${projectKey}'s reviews (${done.value.reviews} reviews, ${done.value.requirements} requirements). The risk ledger is kept. Recorded in the Threatline ledger.`);
  return { projectKey, ...done.value, entryHash: row.value.entryHash };
}

export interface RunStage {
  stage: string;
  status: string;
  error?: string;
  at: string;
  /** Since the previous stage (the first: since the review was created). */
  ms: number;
}
export interface RunDto {
  reviewId: string;
  issueKey: string;
  revision: number;
  status: string;
  failureReason: string | null;
  partial: boolean;
  samplesExpected: number;
  samplesReceived: number;
  tokensIn: number;
  tokensOut: number;
  promptVersion: string;
  createdAt: string;
  /** Created to settled (ready, failed or timed out); null while the review is still running. */
  durationMs: number | null;
  stages: RunStage[];
}

const ms = (from: string, to: string) => Math.max(0, Date.parse(to) - Date.parse(from)) || 0;

/** `admin.runs`: the last 50 reviews, newest first, with their stage trace and why any failed. */
export async function adminRuns(deps: CoreDeps, a: Admin): Promise<{ runs: RunDto[] } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const recent = await deps.reviews.recent(RUNS_LIMIT);
  if (!recent.ok) return apiError(recent.error);
  const traces = await Promise.all(recent.value.map((r) => deps.reviews.stages(r.id)));
  const runs = recent.value.map((r, i): RunDto => {
    const t = traces[i]!;
    let prev = r.createdAt;
    const stages = (t.ok ? t.value : []).map((s) => {
      const out: RunStage = { stage: s.stage, status: s.status, ...(s.error ? { error: s.error } : {}), at: s.at, ms: ms(prev, s.at) };
      prev = s.at;
      return out;
    });
    return {
      reviewId: r.id,
      issueKey: r.issueKey,
      revision: r.revision,
      status: r.status,
      failureReason: r.failureReason ?? null,
      partial: r.partial,
      samplesExpected: r.samplesExpected,
      samplesReceived: r.samplesReceived,
      tokensIn: r.tokensIn,
      tokensOut: r.tokensOut,
      promptVersion: r.promptVersion,
      createdAt: r.createdAt,
      durationMs: SETTLED.has(r.status) ? ms(r.createdAt, r.updatedAt) : null,
      stages,
    };
  });
  return { runs };
}

export interface UsageDto {
  month: string;
  reviews: number;
  tokensIn: number;
  tokensOut: number;
  /** Agent samples received for reviews created this month (each one is a Rovo agent run). */
  agentSamples: number;
  agentSamplesPerReview: number;
  budget: SitePolicy['budget'];
  paused: { budget: boolean; credits: boolean };
}

/** `admin.usage`: this month's reviews, tokens and agent runs against the budget, and whether reviews are paused. */
export async function adminUsage(deps: CoreDeps, a: Admin): Promise<UsageDto | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const policy = await deps.config.site();
  if (!policy.ok) return apiError(policy.error);
  const now = deps.clock.now();
  const month = monthOf(now);
  const [u, paused, reviews] = await Promise.all([deps.usage.get(month), pauseReasons(deps, policy.value, now), deps.reviews.recent(500, `${month}-01T00:00:00.000Z`)]);
  if (!u.ok) return apiError(u.error);
  if (!paused.ok) return apiError(paused.error);
  const agentSamples = reviews.ok ? reviews.value.reduce((n, r) => n + r.samplesReceived, 0) : 0;
  return { month, ...u.value, agentSamples, agentSamplesPerReview: policy.value.agentSamples, budget: policy.value.budget, paused: paused.value };
}

const NotifySchema = z
  .object({
    ops: z.union([z.null(), z.object({ issueKey: z.string().trim().toUpperCase().pipe(z.string().regex(ISSUE_KEY, 'Give a work item key (like OPS-12).')), accountIds: z.array(z.string().trim().regex(/^[A-Za-z0-9:_-]{1,128}$/, 'Account IDs are letters, digits, colons and dashes.')).max(10, 'Mention at most 10 people.') }).strict()]).optional(),
    digest: z.union([z.null(), z.object({ spaceKey: z.string().trim().regex(SPACE_KEY, 'Give a Confluence space key.'), parentPageId: z.string().trim().regex(/^\d{1,20}$/, 'The parent page ID is a number.').optional() }).strict()]).optional(),
  })
  .strict();

/** `admin.setNotifications`: where ops alerts are commented and where the Monday digest is posted. null turns one off. */
export async function adminSetNotifications(deps: CoreDeps, a: Admin, payload: unknown): Promise<{ ops: OpsConfig | null; digest: DigestConfig | null } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const p = NotifySchema.safeParse(payload);
  if (!p.success) return { error: 'validation', message: p.error.issues[0]?.message ?? 'Invalid settings.' };
  const { ops, digest } = p.data;
  if (ops) {
    const i = await deps.jira.issue(ops.issueKey);
    if (!i.ok) return i.error.code === 'not_found' || i.error.code === 'forbidden' || i.error.code === 'validation' ? { error: 'validation', message: `Work item ${ops.issueKey} was not found.` } : apiError(i.error);
  }
  if (digest) {
    const s = await deps.confluence.spaceByKey(digest.spaceKey);
    if (!s.ok) return s.error.code === 'not_found' || s.error.code === 'forbidden' || s.error.code === 'validation' ? { error: 'validation', message: `Confluence space ${digest.spaceKey} was not found.` } : apiError(s.error);
  }
  try {
    if (ops === null) await deps.state.delete(OPS_CONFIG_KEY);
    else if (ops) await deps.state.set(OPS_CONFIG_KEY, ops);
    if (digest === null) await deps.state.delete(DIGEST_CONFIG_KEY);
    else if (digest) await deps.state.set(DIGEST_CONFIG_KEY, { spaceKey: digest.spaceKey, ...(digest.parentPageId ? { parentPageId: digest.parentPageId } : {}) });
  } catch {
    return { error: 'unavailable' };
  }
  const [o, d] = await Promise.all([readJson(deps, OPS_CONFIG_KEY, OpsSchema), readJson(deps, DIGEST_CONFIG_KEY, DigestSchema)]);
  return { ops: o, digest: d };
}

/** `admin.projectStatuses`: the project's workflow statuses, for picking the guarded transition. */
export async function adminProjectStatuses(deps: CoreDeps, a: Admin, payload: unknown): Promise<{ projectKey: string; statuses: string[] } | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const p = WarnSchema.pick({ projectKey: true }).safeParse(payload);
  if (!p.success) return { error: 'validation', message: 'Give a Jira project key (like PAY).' };
  const r = await deps.jira.projectStatuses(p.data.projectKey);
  if (!r.ok) return r.error.code === 'not_found' || r.error.code === 'forbidden' ? { error: 'validation', message: `Jira project ${p.data.projectKey} was not found.` } : apiError(r.error);
  return { projectKey: p.data.projectKey, statuses: r.value };
}

export interface GateInstallDto {
  projects: Array<{ projectKey: string; added: string[]; already: string[]; readOnly: string[] }>;
  /** Projects whose workflows Jira did not let Threatline change (the others were still changed, and ledgered). */
  failed?: Array<{ projectKey: string; message: string }>;
}

/**
 * `admin.installGate`: adds "Threatline security gate" to every guarded transition in every enabled project's
 * workflows, as the admin who clicked (Jira checks they may edit them). The one way to add it in team-managed projects,
 * whose workflow editor does not list app validators. A project Jira refuses does not stop the others; what was added
 * is ledgered as a policy change, and the failures are reported by project.
 */
export async function adminInstallGate(deps: CoreDeps, a: Admin, extensionKey: string | null): Promise<GateInstallDto | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  if (!extensionKey) return { error: 'unavailable', message: 'Threatline could not tell which app environment it is running in. Add the gate in the workflow editor instead.' };
  const policy = await deps.config.site();
  if (!policy.ok) return apiError(policy.error);
  const statuses = [...new Set(policy.value.guardedTransitions)];
  if (policy.value.enabledProjects.length === 0 || statuses.length === 0) return { error: 'validation', message: 'Turn Threatline on for a project and pick its guarded transition first.' };
  const projects: GateInstallDto['projects'] = [];
  const failed: NonNullable<GateInstallDto['failed']> = [];
  let firstError: ApiError | null = null;
  for (const projectKey of policy.value.enabledProjects) {
    const entry = { projectKey, added: [] as string[], already: [] as string[], readOnly: [] as string[] };
    for (const toStatus of statuses) {
      const r = await deps.jira.installGate(a.accountId, projectKey, toStatus, extensionKey);
      if (!r.ok) {
        const e: ApiError =
          r.error.code === 'forbidden'
            ? { error: 'forbidden', message: `Jira did not let you edit ${projectKey}'s workflow. Add the gate in the workflow editor instead.` }
            : { ...apiError(r.error), message: `Jira could not update ${projectKey}'s workflow. Try again, or add the gate in the workflow editor.` };
        firstError ??= e;
        failed.push({ projectKey, message: e.message! });
        break;
      }
      const add = (into: string[], items: readonly string[]) => into.push(...items.filter((x) => !into.includes(x)));
      add(entry.added, r.value.added);
      add(entry.already, r.value.already);
      add(entry.readOnly, r.value.readOnly);
    }
    projects.push(entry);
  }
  const added = projects.flatMap((p) => p.added);
  if (added.length > 0) {
    const row = await appendLedger(
      deps.ledger,
      deps.clock,
      'policy.changed',
      { fields: ['doneGate'], transitions: added, projects: projects.filter((p) => p.added.length > 0).map((p) => p.projectKey), ...(failed.length > 0 ? { failedProjects: failed.map((f) => f.projectKey) } : {}) },
      a.accountId,
    );
    if (!row.ok) {
      log('gate.ledger_failed', { added: added.length });
      return { error: 'unavailable', message: `Threatline added the gate to ${added.join('; ')}, but could not record it in the ledger. Tell your security team; the gate is in force.` };
    }
  }
  log('gate.installed', { added: added.length, failed: failed.length });
  // Nothing changed anywhere and every project failed: the first failure is the answer, as before.
  if (firstError && failed.length === policy.value.enabledProjects.length && added.length === 0) return firstError;
  return failed.length > 0 ? { projects, failed } : { projects };
}

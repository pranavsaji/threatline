import picomatch from 'picomatch';
import { parse as parseYaml } from 'yaml';
import {
  appError,
  err,
  ok,
  RepoPolicySchema,
  SitePolicySchema,
  type RepoPolicy,
  type Result,
  type SitePolicy,
} from '@threatline/shared';

export const WARN_ONLY_MAX_DAYS = 14;

export const DEFAULT_SITE_POLICY: SitePolicy = {
  blockAtOrAbove: 'High',
  guardedTransitions: ['Done'],
  enabledProjects: [],
  reviewIssueTypes: ['Epic', 'Story'],
  techLeadGroup: 'threatline-tech-leads',
  championGroup: 'threatline-security-champions',
  maxExpiryDays: { Critical: 30, default: 90 },
  techLeadMaxSeverity: 'Medium',
  agentSamples: 3,
  agentTimeoutMinutes: 15,
  warnOnly: [],
  attestationTtlHours: 24,
  sensitivePaths: ['src/auth/**', '**/auth/**', '**/payments/**', '**/crypto/**', 'infra/**', '.github/workflows/**', '**/*.pem'],
  // Threatline Engine: one extract, three proposals and one verification per review, on deep models.
  budget: { tokensInPerReview: 400_000, tokensOutPerReview: 60_000, reviewsPerMonth: 500 },
  reviewMode: 'engine',
};

const issuesOf = (e: { issues: Array<{ path: PropertyKey[]; message: string }> }) =>
  e.issues.slice(0, 5).map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`);

export function parseSitePolicy(input: unknown): Result<SitePolicy> {
  const r = SitePolicySchema.safeParse(input);
  return r.success ? ok(r.data) : err(appError('validation', 'invalid site policy', { issues: issuesOf(r.error) }));
}

export function parseRepoPolicy(yamlText: string): Result<RepoPolicy> {
  let raw: unknown;
  try {
    raw = parseYaml(yamlText) ?? {};
  } catch (e) {
    return err(appError('validation', 'policy.yml is not valid YAML', { error: e instanceof Error ? e.message : String(e) }));
  }
  const r = RepoPolicySchema.safeParse(raw);
  return r.success ? ok(r.data) : err(appError('validation', 'invalid .threatline/policy.yml', { issues: issuesOf(r.error) }));
}

/**
 * Whether a path matches any of the globs, ignoring case: `src/Payments/Refund.cs`, `Infra/main.tf` and `certs/KEY.PEM`
 * are as sensitive as their lowercase spelling (C#, Java and Windows repositories capitalise directories), and a gate
 * that a capital letter slips past is no gate.
 */
export function isSensitive(path: string, globs: string[]): boolean {
  if (globs.length === 0) return false;
  return picomatch(globs, { dot: true, nocase: true })(path);
}

/** End of the active warn-only window for a project (at most 14 days after it was switched on), or null. */
export function warnOnlyUntil(policy: SitePolicy, projectKey: string, now: Date): Date | null {
  const t = now.getTime();
  let best: number | null = null;
  for (const w of policy.warnOnly) {
    if (w.projectKey !== projectKey) continue;
    const since = new Date(w.since).getTime();
    const until = Math.min(new Date(w.until).getTime(), since + WARN_ONLY_MAX_DAYS * 86_400_000);
    if (t >= since && t < until && (best === null || until > best)) best = until;
  }
  return best === null ? null : new Date(best);
}

/** Warn-only lasts at most 14 days from when it was switched on, whatever `until` says. */
export function isWarnOnlyActive(policy: SitePolicy, projectKey: string, now: Date): boolean {
  return warnOnlyUntil(policy, projectKey, now) !== null;
}

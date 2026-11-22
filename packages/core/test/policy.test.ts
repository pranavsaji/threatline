import { describe, expect, it } from 'vitest';
import { DEFAULT_SITE_POLICY, isSensitive, isWarnOnlyActive, parseRepoPolicy, parseSitePolicy } from '../src/index.js';

describe('policy', () => {
  it('default site policy is valid and matches the spec values', () => {
    const r = parseSitePolicy(DEFAULT_SITE_POLICY);
    expect(r.ok).toBe(true);
    expect(DEFAULT_SITE_POLICY.blockAtOrAbove).toBe('High');
    expect(DEFAULT_SITE_POLICY.maxExpiryDays).toEqual({ Critical: 30, default: 90 });
    expect(DEFAULT_SITE_POLICY.techLeadMaxSeverity).toBe('Medium');
    expect(DEFAULT_SITE_POLICY.attestationTtlHours).toBe(24);
    expect(DEFAULT_SITE_POLICY.agentSamples).toBe(3);
    // Threatline Engine (the default for new sites) makes five deep-model calls per review.
    expect(DEFAULT_SITE_POLICY.reviewMode).toBe('engine');
    expect(DEFAULT_SITE_POLICY.budget.tokensInPerReview).toBe(400000);
    expect(DEFAULT_SITE_POLICY.budget.tokensOutPerReview).toBe(60000);
    expect(DEFAULT_SITE_POLICY.reviewIssueTypes).toEqual(['Epic', 'Story']);
  });

  it('rejects an invalid site policy with a validation error', () => {
    const r = parseSitePolicy({ ...DEFAULT_SITE_POLICY, agentSamples: 4 });
    expect(!r.ok && r.error.code).toBe('validation');
  });

  it('parses .threatline/policy.yml with defaults', () => {
    const r = parseRepoPolicy('sensitivePaths:\n  - "src/auth/**"\n');
    expect(r.ok && r.value).toEqual({ sensitivePaths: ['src/auth/**'], mode: 'block', diffScoreThreshold: 40 });
    expect(parseRepoPolicy('').ok).toBe(true);
  });

  it('rejects invalid repo policy yaml', () => {
    const bad = parseRepoPolicy('mode: nope');
    expect(!bad.ok && bad.error.code).toBe('validation');
    const broken = parseRepoPolicy('mode: [unclosed');
    expect(!broken.ok && broken.error.code).toBe('validation');
  });

  it('matches sensitive globs including dot directories', () => {
    expect(isSensitive('src/auth/login.ts', ['src/auth/**'])).toBe(true);
    expect(isSensitive('docs/a.md', ['src/**'])).toBe(false);
    expect(isSensitive('.github/workflows/x.yml', ['.github/**'])).toBe(true);
    expect(isSensitive('anything', [])).toBe(false);
  });

  it('matches sensitive globs whatever the case: a capital letter is not a way past the gate', () => {
    const globs = DEFAULT_SITE_POLICY.sensitivePaths;
    for (const path of ['src/Payments/Refund.cs', 'src/Auth/LoginController.cs', 'Infra/main.tf', 'certs/KEY.PEM', 'SRC/AUTH/x.ts', '.GitHub/Workflows/ci.yml'])
      expect(isSensitive(path, globs), path).toBe(true);
    expect(isSensitive('src/Paymentsx/Refund.cs', globs)).toBe(false);
    expect(isSensitive('docs/Payments.md', globs)).toBe(false);
  });

  it('clamps warn-only to 14 days from now', () => {
    const now = new Date('2026-11-15T00:00:00Z');
    const day = 86_400_000;
    const policy = { ...DEFAULT_SITE_POLICY, warnOnly: [{ projectKey: 'PROJ', since: new Date(now.getTime() - day).toISOString(), until: new Date(now.getTime() + 20 * day).toISOString() }] };
    expect(isWarnOnlyActive(policy, 'PROJ', now)).toBe(true);
    expect(isWarnOnlyActive(policy, 'OTHER', now)).toBe(false);
  });

  it('warn-only ends once until has passed', () => {
    const now = new Date('2026-11-15T00:00:00Z');
    const policy = { ...DEFAULT_SITE_POLICY, warnOnly: [{ projectKey: 'PROJ', since: '2026-11-10T00:00:00Z', until: '2026-11-14T00:00:00Z' }] };
    expect(isWarnOnlyActive(policy, 'PROJ', now)).toBe(false);
  });

  it('warn-only entries carry a start date: active on day 13, inactive on day 15 even if until is later', () => {
    const start = new Date('2026-11-01T00:00:00Z');
    const day = 86_400_000;
    const policy = { ...DEFAULT_SITE_POLICY, warnOnly: [{ projectKey: 'PROJ', since: start.toISOString(), until: new Date(start.getTime() + 20 * day).toISOString() }] };
    expect(isWarnOnlyActive(policy, 'PROJ', new Date(start.getTime() + 13 * day))).toBe(true);
    expect(isWarnOnlyActive(policy, 'PROJ', new Date(start.getTime() + 15 * day))).toBe(false);
  });
});

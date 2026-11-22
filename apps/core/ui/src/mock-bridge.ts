import type { AdminApi, InboxApi, PanelApi, PostureApi } from './bridge.js';
import { DRILL_FIXTURE, POSTURE_FIXTURE, RELEASE_FIXTURE } from './posture/fixtures.js';
import { DIFF_FIXTURE, FIXTURES } from './fixtures.js';
import { ADMIN_POLICY_FIXTURE, RUNS_FIXTURE, USAGE_FIXTURE } from './admin/fixtures.js';
import { CONTROLS_FIXTURE } from './compliance-fixtures.js';
import { INBOX_FIXTURE } from './inbox/fixtures.js';
import { SUPPRESSIONS_FIXTURE } from './admin/suppressions-fixture.js';
import { mockCiApi } from './admin/ci-api.js';

/** Local preview: `pnpm --filter @threatline/core-ui dev`, then ?state=ready|in_progress|failed|… and ?theme=dark. */
export function mockApi(state = new URLSearchParams(window.location.search).get('state') ?? 'ready'): PanelApi {
  const dto = FIXTURES[state] ?? FIXTURES.ready!;
  return {
    get: async () => structuredClone(dto),
    threats: async () => ({ threats: [], cursor: null }),
    rerun: async () => ({ ok: true }),
    diff: async (from, to) => ({ ...structuredClone(DIFF_FIXTURE), ...(from ? { from } : {}), ...(to ? { to } : {}) }),
    whatIf: async (change) => {
      const baseline = { exposure: 'internal' as const, dataClasses: ['pii' as const] };
      const signals = { exposure: change.exposure ?? baseline.exposure, dataClasses: change.dataClasses ?? baseline.dataClasses };
      const mult = { internal: 1, partner: 1.15, public: 1.3 }[signals.exposure];
      const extra = signals.dataClasses.filter((d) => !baseline.dataClasses.includes(d as 'pii')).length * 8;
      const current = dto.review?.riskScore ?? 0;
      return { current, riskScore: Math.min(100, Math.round((current + extra) * mult)), signals: { ...signals, dataClasses: [...signals.dataClasses] }, baseline: { ...baseline, dataClasses: [...baseline.dataClasses] }, partial: false };
    },
    enrich: async () => ({ added: 0, partial: true, facts: [] }),
    delivery: async () => {
      const prod = { id: 'dep_1', name: 'payments-service #128', url: 'https://bitbucket.org/acme/payments-service/deployments', state: 'SUCCESSFUL' as const, environment: { name: 'Production', type: 'PRODUCTION' as const }, at: '2026-11-21T09:12:00.000Z' };
      const blocked = dto.verdict && dto.verdict.state !== 'pass';
      return {
        pullRequests: [
          { id: 'pr_1', title: '#2 Verify webhook signatures', url: 'https://bitbucket.org/acme/payments-service/pull-requests/2', status: 'MERGED' as const, updatedAt: '2026-11-21T08:40:00.000Z' },
          { id: 'pr_2', title: '#3 Rotate the webhook secret', url: 'https://bitbucket.org/acme/payments-service/pull-requests/3', status: 'OPEN' as const, updatedAt: '2026-11-21T10:05:00.000Z' },
        ],
        deployments: [prod, { ...prod, id: 'dep_0', name: 'payments-service #127', environment: { name: 'Staging', type: 'STAGING' as const }, at: '2026-11-21T08:55:00.000Z' }],
        shippedWhileOpen: blocked ? { deployments: [prod], openRequirements: dto.verdict!.blockingCount, maxOpenSeverity: dto.verdict!.maxOpenSeverity, gate: dto.verdict!.state as 'block' | 'warn' } : null,
        mergedWhileOpen: blocked ? 1 : 0,
        partial: false,
      };
    },
    createRequirements: async (threatIds) => ({ created: threatIds.map((id, i) => ({ requirementId: `req_${id}`, subtaskKey: `PAY-${100 + i}` })), skipped: [] }),
    setStatus: async (requirementId, status, evidence) => {
      const r = dto.requirements.find((x) => x.id === requirementId)!;
      return { ...r, status, ...(evidence ? { evidence: { ...evidence, attester: 'me' } } : {}) };
    },
    triage: async () => dto.threats,
    unhide: async (ruleId) => dto.threats.map((t) => (t.state === 'suppressed' && t.suppression?.ruleId === ruleId ? { ...t, state: t.suppression.restoreTo ?? 'accepted', suppression: { ...t.suppression, outcome: 'unhidden' as const } } : t)),
    confirm: async () => ({ seq: 1 }),
    requestAcceptance: async () => ({ acceptanceId: 'acc_mock', needsApprover: 'champion', entryHash: 'f'.repeat(64) }),
    decideAcceptance: async (_id, decision) => ({ state: decision === 'approve' ? 'active' : 'rejected', entryHash: 'e'.repeat(64) }),
    revokeAcceptance: async () => ({ entryHash: 'd'.repeat(64) }),
    breakGlass: async (_r, hours) => ({ entryHash: 'c'.repeat(64), until: new Date(Date.now() + hours * 3_600_000).toISOString() }),
    attestation: async (repo, commitSha) => {
      const token = `threatline-att.v1.mock-${repo.replace('/', '-')}-${commitSha.slice(0, 7)}.sig`;
      return { token, expiresAt: new Date(Date.now() + 86_400_000).toISOString(), prDescriptionSnippet: `Threatline attestation for ${dto.issueKey} (expires tomorrow):\n${token}` };
    },
    publish: async () => ({ pageId: '900', url: 'https://example.atlassian.net/wiki/spaces/PAY/pages/900', created: true }),
    explain: async (_r, threatId) => {
      const t = dto.threats.find((x) => x.id === threatId);
      return { story: `${t?.plainLanguage ?? ''} ${t?.scenario ?? ''}`.trim(), fixes: ['Expire sign-in links after 15 minutes and after first use.'], refs: [{ framework: 'CWE', id: 'CWE-640', title: 'Weak Password Recovery Mechanism', url: 'https://cwe.mitre.org/data/definitions/640.html' }] };
    },
  };
}

/** Local preview of the admin page: `?view=admin` (`&state=first` shows the first-run wizard). */
export function mockAdminApi(state = typeof window === 'undefined' ? 'ready' : (new URLSearchParams(window.location.search).get('state') ?? 'ready')): AdminApi {
  const dto = structuredClone(ADMIN_POLICY_FIXTURE);
  if (state === 'first') Object.assign(dto, { saved: false, policy: { ...dto.policy, enabledProjects: [] } });
  const DAY = 86_400_000;
  const sup = structuredClone(SUPPRESSIONS_FIXTURE);
  return {
    getPolicy: async () => structuredClone(dto),
    setPolicy: async (policy) => ((dto.policy = { ...structuredClone(policy), warnOnly: dto.policy.warnOnly }), (dto.saved = true), { policy: structuredClone(dto.policy) }),
    warnOnly: async (projectKey, days) => {
      const since = new Date().toISOString();
      const until = new Date(Date.now() + days * DAY).toISOString();
      dto.policy.warnOnly = [...dto.policy.warnOnly.filter((w) => w.projectKey !== projectKey), { projectKey, since, until }];
      return { projectKey, since, until, entryHash: 'a'.repeat(64) };
    },
    purgeProject: async (projectKey, confirm) =>
      confirm !== projectKey
        ? { error: 'validation' as const, message: `Type ${projectKey} to confirm. This cannot be undone.` }
        : dto.policy.enabledProjects.includes(projectKey)
          ? { error: 'validation' as const, message: `Threatline still reviews ${projectKey}. Turn it off under Projects and transitions first, then purge.` }
          : { projectKey, reviews: 3, requirements: 2, entryHash: 'c'.repeat(64) },
    endWarnOnly: async (projectKey) => ((dto.policy.warnOnly = dto.policy.warnOnly.filter((w) => w.projectKey !== projectKey)), { projectKey, entryHash: 'b'.repeat(64) }),
    runs: async () => ({ runs: structuredClone(RUNS_FIXTURE) }),
    usage: async () => structuredClone(USAGE_FIXTURE),
    resumeReviews: async () => ({ resumed: true, entryHash: 'a'.repeat(64) }),
    setNotifications: async (n) => {
      if (n.ops !== undefined) dto.ops = n.ops;
      if (n.digest !== undefined) dto.digest = n.digest;
      return { ops: dto.ops, digest: dto.digest };
    },
    treeHead: async () => ({ treeHead: { treeSize: 12, rootHash: '3a03ebd5cbaa6828e1bf78ea19554fe4b9992ff4492ab79faca95065a0c66352', timestamp: '2026-11-18T03:00:00.000Z', kid: 'k-mock' }, publicKey: 'MCowBQYDK2VwAyEAmockpublickey', publishedPageId: null }),
    ledgerProof: async (seq) => ({ seq, treeSize: 12, json: JSON.stringify({ format: 'threatline-ledger-proof-v1', entry: { seq }, leafIndex: seq - 1, auditPath: [], treeHead: { treeSize: 12 } }, null, 2) }),
    suppressions: async () => structuredClone(sup),
    createSuppression: async (input) => {
      const now = new Date();
      const rule = { id: `sup_mock${sup.rules.length + 1}`, ...input, createdBy: 'me', createdAt: now.toISOString(), expiresAt: new Date(now.getTime() + input.expiryDays * DAY).toISOString(), status: 'active' as const, evidence: input.evidence ?? [] };
      const { expiryDays: _d, ...stored } = rule;
      sup.rules = [{ ...stored, matches: 0 }, ...sup.rules];
      sup.suggestions = sup.suggestions.filter((s) => !(s.projectKey === input.projectKey && s.title === input.title));
      return structuredClone(stored);
    },
    revokeSuppression: async (ruleId, reason) => {
      const r = sup.rules.find((x) => x.id === ruleId);
      if (!r) return { error: 'not_found' as const };
      sup.rules = sup.rules.filter((x) => x.id !== ruleId);
      const { matches: _m, ...rest } = r;
      return { ...rest, status: 'revoked' as const, endedBy: 'me', endedAt: new Date().toISOString(), endReason: reason };
    },
    projectStatuses: async (projectKey) => ({ projectKey, statuses: ['To Do', 'In Progress', 'In Review', 'Done'] }),
    installGate: async () => ({ projects: [{ projectKey: 'PAY', added: ['Software workflow for project PAY: Done'], already: [], readOnly: [] }] }),
    seed: async (projectKey) => ({ epicKey: `${projectKey}-1`, storyKeys: [`${projectKey}-2`, `${projectKey}-3`], designPageUrl: 'https://example.atlassian.net/wiki/spaces/PAY/pages/1', incidentKeys: [`${projectKey}-4`, `${projectKey}-5`] }),
    publicKeys: async () => ({ active: { kid: 'k-mock', publicKey: 'MCowBQYDK2VwAyEAmockpublickey' } }),
    rotateKey: async () => ({ kid: 'k-mock-2' }),
    keyCopied: async () => ({ ok: true }),
    verifyLedger: async () => ({ ok: true, length: 12 }),
    exportLedger: async (projectKey, from, to) => ({ csv: 'seq,created_at\n', json: JSON.stringify({ projectKey, from, to, entries: [] }) }),
    exportControls: async (projectKey, from, to) => ({ csv: 'framework,control_id\n', json: JSON.stringify({ kind: 'threatline.controls-summary.v1', projectKey, from, to, frameworks: [] }) }),
    ci: mockCiApi(),
    championGroupStatus: async () => ({ group: 'threatline-security-champions', exists: true, member: true, groupsUrl: 'https://admin.atlassian.com/' }),
    setupStatus: async () => ({ keys: true, sqlVersion: 3, validatorSeenOn: ['PAY'], automationRuleSeen: true, mcpEnabledHint: 'Rovo MCP: allow the clients your team uses in Atlassian Administration.', bitbucketKeyCopied: false }),
  };
}

export function mockPostureApi(state = new URLSearchParams(window.location.search).get('state') ?? 'ready'): PostureApi {
  const empty = state === 'empty';
  return {
    get: async () => (empty ? { ...structuredClone(POSTURE_FIXTURE), projects: [], issuesCounted: 0, byTeamComponent: [], openBySeverity: { Low: 0, Medium: 0, High: 0, Critical: 0 } } : structuredClone(POSTURE_FIXTURE)),
    drill: async () => structuredClone(DRILL_FIXTURE),
    release: async (fixVersion) => RELEASE_FIXTURE(fixVersion),
    controls: async () => (empty ? { ...structuredClone(CONTROLS_FIXTURE), issuesCounted: 0, frameworks: CONTROLS_FIXTURE.frameworks.map((f) => ({ ...f, controls: [] })) } : structuredClone(CONTROLS_FIXTURE)),
    controlDrill: async () => structuredClone(DRILL_FIXTURE),
  };
}

/**
 * Local preview of the champion inbox (`?view=posture`, then the Champion inbox tab). `?inbox=empty` shows the empty
 * state, `?inbox=forbidden` a viewer who is not a champion (no tab). Decisions remove the rows they decide.
 */
export function mockInboxApi(state = typeof window === 'undefined' ? 'ready' : (new URLSearchParams(window.location.search).get('inbox') ?? 'ready')): InboxApi {
  const dto = structuredClone(INBOX_FIXTURE);
  if (state === 'empty') Object.assign(dto, { clusters: [], total: 0, hidden: 0 });
  return {
    list: async () => (state === 'forbidden' ? { error: 'forbidden' as const, message: 'Only security champions and Jira admins can open the champion inbox.' } : structuredClone(dto)),
    decide: async (input) => {
      const keys = new Set(input.items.map((i) => `${i.issueId}|${i.threatId}`));
      dto.clusters = dto.clusters.map((c) => ({ ...c, rows: c.rows.filter((r) => !keys.has(`${r.issueId}|${r.threatId}`)) })).filter((c) => c.rows.length > 0);
      dto.total = dto.clusters.reduce((n, c) => n + c.rows.length, 0);
      return { results: input.items.map((i) => ({ ...i, ok: true as const, state: input.decision === 'confirm' ? 'accepted' : 'dismissed' })), decided: input.items.length, failed: 0 };
    },
  };
}

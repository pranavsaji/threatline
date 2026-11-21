import type { AcceptanceState, AdminPolicyDto, ApiError, InboxDecideDto, InboxDto, DataClass, Exposure, ThreatDiffDto, WhatIfDto, DigestConfig, DrillDto, Evidence, FactDto, OpsConfig, PanelDto, PostureDto, ReleaseReadinessResult, Requirement, RequirementStatus, RunDto, Severity, SitePolicy, Threat, ThreatExplanation, UsageDto } from './types.js';

/** Calls a resolver by key: Forge's invoke inside Atlassian, or the local end-to-end harness (e2e/local). */
export type Invoke = <T>(key: string, payload?: Record<string, unknown>) => Promise<T>;

/**
 * @forge/bridge 7 types every resolver result as `T | { body: T; metadata }`; it only wraps when the caller passes
 * invoke metadata, which Threatline never does, so the result is the resolver's return value itself.
 */
async function bridgeInvoke(): Promise<Invoke> {
  const { invoke } = await import('@forge/bridge');
  return <T>(key: string, payload?: Record<string, unknown>) => invoke(key, payload) as Promise<T>;
}


export interface AcceptanceInput {
  requirementId: string;
  reason: string;
  controls: string;
  expiryDays: number;
}
export type AttestationOutcome = { token: string; expiresAt: string; prDescriptionSnippet: string } | { blocking: Array<{ code: string; message: string }> };
export interface PublicKeyInfo {
  active: { kid: string; publicKey: string };
  previous?: { kid: string; publicKey: string; retireAt: string };
}
export type ChainVerdict =
  | { ok: true; length: number; treeHeads?: number }
  | { ok: false; firstBrokenSeq: number; reason: 'prev_mismatch' | 'hash_mismatch' | 'seq_gap' }
  | { ok: false; firstBrokenSeq: number; treeSize: number; reason: 'truncated' | 'tree_head_mismatch' | 'tree_head_signature' };

export type TriageInput =
  | { threatId: string; op: 'accept' }
  | { threatId: string; op: 'dismiss'; reason: string; note?: string }
  | { threatId: string; op: 'edit'; patch: Partial<Pick<Threat, 'title' | 'likelihood' | 'impact' | 'component'>> }
  | { threatId: string; op: 'merge'; intoThreatId: string }
  | { threatId: string; op: 'split'; parts: Array<{ title: string }> };

export interface CreatedRequirements {
  created: Array<{ requirementId: string; subtaskKey: string }>;
  skipped: Array<{ threatId: string; reason: string }>;
}

/** Everything the panel asks the backend. The Forge implementation and the local mock share this interface. */
export interface PanelApi {
  get(): Promise<PanelDto | ApiError>;
  threats(cursor: number): Promise<{ threats: Threat[]; cursor: number | null } | ApiError>;
  rerun(): Promise<{ ok: true } | ApiError>;
  enrich(): Promise<{ added: number; partial: boolean; facts: FactDto[] } | ApiError>;
  explain(reviewId: string, threatId: string): Promise<ThreatExplanation | ApiError>;
  createRequirements(threatIds: string[]): Promise<CreatedRequirements | ApiError>;
  setStatus(requirementId: string, status: RequirementStatus, evidence?: Pick<Evidence, 'kind' | 'ref'>): Promise<Requirement | ApiError>;
  triage(input: TriageInput): Promise<Threat[] | ApiError>;
  confirm(reviewId: string, kind: 'review' | 'budget'): Promise<{ seq: number } | ApiError>;
  publish(): Promise<{ pageId: string; url: string; created: boolean } | ApiError>;
  requestAcceptance(input: AcceptanceInput): Promise<{ acceptanceId: string; needsApprover: 'none' | 'tech_lead' | 'champion'; entryHash: string } | ApiError>;
  decideAcceptance(acceptanceId: string, decision: 'approve' | 'reject', note?: string): Promise<{ state: AcceptanceState; entryHash: string } | ApiError>;
  revokeAcceptance(acceptanceId: string, reason: string): Promise<{ entryHash: string } | ApiError>;
  breakGlass(reason: string, hours: number): Promise<{ entryHash: string; until: string } | ApiError>;
  attestation(repo: string, commitSha: string): Promise<AttestationOutcome | ApiError>;
  /** R7: threats added, removed and changed between two revisions (default: the last two). */
  diff(from?: number, to?: number): Promise<ThreatDiffDto | ApiError>;
  /** R12: the score with a different exposure or data classes. Nothing is saved. */
  whatIf(change: { exposure?: Exposure; dataClasses?: DataClass[] }): Promise<WhatIfDto | ApiError>;
  /**
   * Opens a Jira path such as `/browse/PAY-101` in the host product. Inside Forge the app is served from Atlassian's CDN
   * origin, so a relative link would resolve there; @forge/bridge's router resolves it against the site. Absent in the
   * fixture and local bridges, where the plain link is followed.
   */
  navigate?(path: string, opts: { newTab: boolean }): Promise<void>;
}

export async function forgeApi(): Promise<PanelApi> {
  const { router } = await import('@forge/bridge');
  return { ...panelApiOver(await bridgeInvoke()), navigate: (path, { newTab }) => (newTab ? router.open(path) : router.navigate(path)) };
}

export function panelApiOver(invoke: Invoke): PanelApi {
  return {
    get: () => invoke('panel.get'),
    threats: (cursor) => invoke('panel.threats', { cursor }),
    rerun: () => invoke('panel.rerun'),
    enrich: () => invoke('panel.enrich'),
    explain: (reviewId, threatId) => invoke('threat.explain', { reviewId, threatId }),
    createRequirements: (threatIds) => invoke('requirements.create', { threatIds }),
    setStatus: (requirementId, status, evidence) => invoke('requirements.setStatus', { requirementId, status, ...(evidence ? { evidence } : {}) }),
    triage: (input) => invoke('threats.triage', input),
    confirm: (reviewId, kind) => invoke('review.confirm', { reviewId, kind }),
    publish: () => invoke('confluence.publish'),
    requestAcceptance: (input) => invoke('acceptance.request', { ...input }),
    decideAcceptance: (acceptanceId, decision, note) => invoke('acceptance.decide', { acceptanceId, decision, ...(note ? { note } : {}) }),
    revokeAcceptance: (acceptanceId, reason) => invoke('acceptance.revoke', { acceptanceId, reason }),
    breakGlass: (reason, hours) => invoke('override.breakglass', { reason, hours }),
    attestation: (repo, commitSha) => invoke('attestation.copy', { repo, commitSha }),
    diff: (from, to) => invoke('panel.diff', { ...(from ? { from } : {}), ...(to ? { to } : {}) }),
    whatIf: (change) => invoke('panel.whatIf', { ...change }),
  };
}

export interface SeedResult {
  epicKey: string;
  storyKeys: string[];
  designPageUrl: string;
  incidentKeys: string[];
}
export interface GateInstallDto {
  projects: Array<{ projectKey: string; added: string[]; already: string[]; readOnly: string[] }>;
}

export interface SetupStatus {
  keys: boolean;
  sqlVersion: number;
  validatorSeenOn: string[];
  automationRuleSeen: boolean;
  mcpEnabledHint: string;
  bitbucketKeyCopied: boolean;
}

/** The admin page's backend calls (Jira administrators only; the server checks). */
export interface AdminApi {
  seed(projectKey: string, spaceKey: string): Promise<SeedResult | ApiError>;
  setupStatus(): Promise<SetupStatus | ApiError>;
  verifyLedger(): Promise<ChainVerdict | ApiError>;
  exportLedger(projectKey: string, from: string, to: string): Promise<{ csv: string; json: string } | ApiError>;
  publicKeys(): Promise<PublicKeyInfo | ApiError>;
  rotateKey(): Promise<{ kid: string } | ApiError>;
  keyCopied(): Promise<{ ok: true } | ApiError>;
  getPolicy(): Promise<AdminPolicyDto | ApiError>;
  setPolicy(policy: SitePolicy): Promise<{ policy: SitePolicy } | ApiError>;
  warnOnly(projectKey: string, days: number): Promise<{ projectKey: string; since: string; until: string; entryHash: string } | ApiError>;
  endWarnOnly(projectKey: string): Promise<{ projectKey: string; entryHash: string } | ApiError>;
  purgeProject(projectKey: string, confirm: string): Promise<{ projectKey: string; reviews: number; requirements: number; entryHash: string } | ApiError>;
  runs(): Promise<{ runs: RunDto[] } | ApiError>;
  usage(): Promise<UsageDto | ApiError>;
  /** Clears an out-of-credits pause (ledgered); admins only. */
  resumeReviews(): Promise<{ resumed: true; entryHash: string } | ApiError>;
  /** Leave a key out to keep it; null turns it off. */
  setNotifications(n: { ops?: OpsConfig | null; digest?: DigestConfig | null }): Promise<{ ops: OpsConfig | null; digest: DigestConfig | null } | ApiError>;
  projectStatuses(projectKey: string): Promise<{ projectKey: string; statuses: string[] } | ApiError>;
  /** Adds the Done gate to the guarded transition in each enabled project's workflows, as the calling admin. */
  installGate(): Promise<GateInstallDto | ApiError>;
  /** R5: an inclusion proof (JSON) for one ledger entry against the current signed tree head. */
  ledgerProof(seq: number): Promise<{ json: string; seq: number; treeSize: number } | ApiError>;
  treeHead(): Promise<TreeHeadInfo | ApiError>;
}

export interface TreeHeadInfo {
  treeHead: { treeSize: number; rootHash: string; timestamp: string; kid: string };
  publicKey: string | null;
  publishedPageId: string | null;
}

export async function forgeAdminApi(): Promise<AdminApi> {
  return adminApiOver(await bridgeInvoke());
}

export function adminApiOver(invoke: Invoke): AdminApi {
  return {
    seed: (projectKey, spaceKey) => invoke('admin.seed', { projectKey, spaceKey }),
    setupStatus: () => invoke('admin.setupStatus'),
    verifyLedger: () => invoke('ledger.verify'),
    exportLedger: (projectKey, from, to) => invoke('ledger.export', { projectKey, from, to }),
    publicKeys: () => invoke('keys.public'),
    rotateKey: () => invoke('keys.rotate'),
    keyCopied: () => invoke('keys.copied'),
    getPolicy: () => invoke('admin.getPolicy'),
    setPolicy: (policy) => invoke('admin.setPolicy', { policy }),
    warnOnly: (projectKey, days) => invoke('admin.warnOnly', { projectKey, days }),
    endWarnOnly: (projectKey) => invoke('admin.warnOnlyEnd', { projectKey }),
    purgeProject: (projectKey, confirm) => invoke('admin.purgeProject', { projectKey, confirm }),
    runs: () => invoke('admin.runs'),
    usage: () => invoke('admin.usage'),
    resumeReviews: () => invoke('admin.resumeReviews'),
    setNotifications: (n) => invoke('admin.setNotifications', { ...n }),
    projectStatuses: (projectKey) => invoke('admin.projectStatuses', { projectKey }),
    installGate: () => invoke('admin.installGate'),
    ledgerProof: (seq) => invoke('ledger.proof', { seq }),
    treeHead: () => invoke('ledger.treeHead'),
  };
}

/** What a dashboard number filters on: a severity (KPI), or a heatmap cell (team = project, component). */
export interface DrillQuery {
  severity?: Severity;
  team?: string;
  component?: string;
}

/** The posture page's backend calls; the server scopes every number to work items the viewer can browse. */
export interface PostureApi {
  get(project?: string): Promise<PostureDto | ApiError>;
  drill(q: DrillQuery): Promise<DrillDto | ApiError>;
  release(fixVersion: string): Promise<ReleaseReadinessResult | ApiError>;
}

export async function forgePostureApi(): Promise<PostureApi> {
  return postureApiOver(await bridgeInvoke());
}

export function postureApiOver(invoke: Invoke): PostureApi {
  return {
    get: (project) => invoke('posture.get', project ? { project } : {}),
    drill: (q) => invoke('posture.drill', { ...q }),
    release: (fixVersion) => invoke('release.report', { fixVersion }),
  };
}

/** A champion's decision on threats waiting in the inbox: confirm (accept), or dismiss with a reason code. */
export type InboxDecisionInput =
  | { decision: 'confirm'; items: Array<{ issueId: string; threatId: string }> }
  | { decision: 'dismiss'; reason: string; note?: string; items: Array<{ issueId: string; threatId: string }> };

/** The champion inbox on the global page (champions and Jira admins; the server checks every call). */
export interface InboxApi {
  list(cursor?: number): Promise<InboxDto | ApiError>;
  /** At most 25 items per call; each is decided, authorised and ledgered on its own. */
  decide(input: InboxDecisionInput): Promise<InboxDecideDto | ApiError>;
}

export async function forgeInboxApi(): Promise<InboxApi> {
  return inboxApiOver(await bridgeInvoke());
}

export function inboxApiOver(invoke: Invoke): InboxApi {
  return {
    list: (cursor) => invoke('inbox.list', cursor ? { cursor } : {}),
    decide: (input) => invoke('inbox.decide', { ...input }),
  };
}

export const isError = <T extends object>(r: T | ApiError): r is ApiError => 'error' in r;

/** Plain words for an error, preferring the server's own message for validation/permission/conflict errors. */
export function errorText(e: ApiError): string {
  if (e.message) return e.message;
  if (e.error === 'forbidden') return 'You do not have permission to do that.';
  if (e.error === 'not_found') return 'That item is no longer available, or you cannot open it.';
  if (e.error === 'rate_limited') return 'Too many requests. Try again later.';
  if (e.error === 'unavailable') return 'Threatline could not reach Jira, or is still finishing its install (a new install can take a minute). Try again in a minute.';
  return 'Threatline could not save that. Try again.';
}

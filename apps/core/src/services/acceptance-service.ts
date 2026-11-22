import { ACCEPTANCE_EVENTS, appendLedger, canApprove, rebuildAcceptances, validateAcceptanceRequest, type ApproverNeeded, type LedgerRow } from '@threatline/core';
import { appError, err, ok, type Acceptance, type AcceptanceState, type Requirement, type Result, type SitePolicy } from '@threatline/shared';
import type { JiraIssue } from '../adapters/jira.js';
import { log } from '../adapters/log.js';
import type { CoreDeps } from '../deps.js';
import type { Viewer } from '../resolvers/panel.js';
import { notify } from './notify.js';
import { threatVisible } from './requirements-service.js';
import { rolesOf } from './roles.js';
import { refreshVerdict } from './verdict-service.js';

export const SYSTEM_ACTOR = 'threatline';
const HOUR = 3_600_000;
export const BREAK_GLASS_MAX_HOURS = 72;
export const BREAK_GLASS_MIN_REASON = 20;

const day = (iso: string) => iso.slice(0, 10);
/** Comments name requirements by sub-task key or severity only: titles can come from sources some viewers cannot open. */
const label = (r: Pick<Requirement, 'subtaskKey' | 'severity'>) => r.subtaskKey ?? `a ${r.severity} security requirement`;

/** Acceptances as the ledger events alone say (no time-based expiry applied), to find the ones that still need an expiry entry. */
const byEvents = (rows: readonly LedgerRow[]) => rebuildAcceptances(rows, new Date(0));

/**
 * Scale: an acceptance expires at most 365 days after its request, and the hourly sweep closes it then, so the sweep
 * reads the acceptance events of the last 400 days (indexed on type and time) rather than every one ever written.
 */
const SWEEP_WINDOW_MS = 400 * 86_400_000;

/** The recent acceptance events (the hourly expiry sweep), or, with an issue, that work item's only (indexed; scale). */
async function ledgerRows(deps: CoreDeps, issueId?: string): Promise<Result<LedgerRow[]>> {
  if (issueId) return deps.ledger.forIssues(ACCEPTANCE_EVENTS, [issueId]);
  return deps.ledger.ofTypesSince(ACCEPTANCE_EVENTS, new Date(deps.clock.now().getTime() - SWEEP_WINDOW_MS).toISOString());
}

async function setStatus(deps: CoreDeps, requirementId: string, from: Requirement['status'][], to: Requirement['status']): Promise<Result<void>> {
  const got = await deps.requirements.get(requirementId);
  if (!got.ok) return got;
  if (!got.value || !from.includes(got.value.status)) return ok(undefined);
  return deps.requirements.upsert({ ...got.value, status: to });
}

async function settle(deps: CoreDeps, issueId: string): Promise<void> {
  const v = await refreshVerdict(deps, issueId);
  if (!v.ok) log('acceptance.refresh_failed', { issueId, code: v.error.code });
  const q = await deps.queue.push([{ kind: 'propagate', issueId }]);
  if (!q.ok) log('acceptance.propagate_failed', { issueId, code: q.error.code });
}

async function visibleRequirement(deps: CoreDeps, v: Viewer, requirementId: string): Promise<Result<Requirement>> {
  const got = await deps.requirements.get(requirementId);
  if (!got.ok) return got;
  const req = got.value;
  if (!req || req.issueId !== v.issueId) return err(appError('not_found', 'requirement not found'));
  const visible = await threatVisible(deps, v, req.threatId);
  if (!visible.ok) return visible;
  return visible.value ? ok(req) : err(appError('not_found', 'requirement not found'));
}

function approverText(needs: ApproverNeeded, policy: SitePolicy): string {
  return needs === 'champion' ? `a security champion (${policy.championGroup})` : `a tech lead (${policy.techLeadGroup}) or security champion`;
}

/** `acceptance.request` (RL-1, RL-2): ledgered; a request inside the requester's own authority is active at once. */
export async function requestAcceptance(
  deps: CoreDeps,
  v: Viewer,
  issue: JiraIssue,
  input: { requirementId: string; reason: string; controls: string; expiryDays: number },
  opts: { viaAgent?: boolean } = {},
): Promise<Result<{ acceptanceId: string; needsApprover: ApproverNeeded; entryHash: string }>> {
  const now = deps.clock.now();
  const req = await visibleRequirement(deps, v, input.requirementId);
  if (!req.ok) return req;
  const [policy, rows] = await Promise.all([deps.config.site(), ledgerRows(deps, v.issueId)]);
  if (!policy.ok) return policy;
  if (!rows.ok) return rows;
  const open = rebuildAcceptances(rows.value, now).find((a) => a.requirementId === req.value.id && (a.state === 'pending' || a.state === 'active'));
  if (open) return err(appError('conflict', `This requirement already has a ${open.state} risk acceptance.`));
  const roles = await rolesOf(deps, v.accountId, v.issueId, policy.value);
  const valid = validateAcceptanceRequest({ requirement: req.value, reason: input.reason, controls: input.controls, expiryDays: input.expiryDays, requester: v.accountId, requesterRoles: roles }, policy.value, now);
  if (!valid.ok) return valid;
  // Requests made through Rovo or MCP never take effect on the requester's own authority: an agent can ask, a second person grants.
  if (opts.viaAgent && valid.value.needsApprover === 'none') valid.value.needsApprover = 'tech_lead';

  // Concurrency: the check above reads the ledger, so two requests at once would both pass it. One atomic slot per
  // requirement and ledger generation (how many requests it has had) lets only one of them be written; once that one is
  // in the ledger, the next request sees it (or, after it ends, a new generation with a fresh slot). The hour in the
  // window bounds how long a slot whose ledger write then failed can hold the requirement.
  const generation = rows.value.filter((r) => r.eventType === 'acceptance.requested' && r.payload.requirementId === req.value.id).length;
  const slot = await deps.usage.takeSlot(`acc:${req.value.id}`.slice(0, 191), `${Math.min(generation, 999_999)}@${now.toISOString().slice(0, 13)}`, 1);
  if (!slot.ok) return err(appError('upstream', `acceptance slot: ${slot.error.message}`));
  if (slot.value === null) return err(appError('conflict', 'Another risk acceptance for this requirement is being recorded. Reload the panel to see it.'));

  const acceptanceId = `acc_${globalThis.crypto.randomUUID()}`;
  const row = await appendLedger(
    deps.ledger,
    deps.clock,
    'acceptance.requested',
    {
      acceptanceId,
      requirementId: req.value.id,
      issueId: v.issueId,
      issueKey: issue.key,
      severity: req.value.severity,
      reason: input.reason.trim(),
      controls: input.controls.trim(),
      expiryDays: input.expiryDays,
      expiresAt: valid.value.expiresAt,
      needsApprover: valid.value.needsApprover,
    },
    v.accountId,
  );
  if (!row.ok) return row;

  const site = await deps.siteUrl();
  const panel = `${site}/browse/${issue.key}`;
  if (valid.value.needsApprover === 'none') {
    const s = await setStatus(deps, req.value.id, ['Open', 'InProgress'], 'AcceptedRisk');
    if (!s.ok) log('acceptance.status_failed', { requirementId: req.value.id, code: s.error.code });
    await notify(deps, v.issueId, [], `Risk accepted for ${label(req.value)} until ${day(valid.value.expiresAt)}. Recorded in the Threatline ledger: ${panel}`);
    await settle(deps, v.issueId);
  } else {
    await notify(
      deps,
      v.issueId,
      [],
      `Risk acceptance requested for ${label(req.value)} (${req.value.severity}). It needs ${approverText(valid.value.needsApprover, policy.value)} to approve it in the Threatline panel: ${panel}`,
    );
  }
  return ok({ acceptanceId, needsApprover: valid.value.needsApprover, entryHash: row.value.entryHash });
}

async function findAcceptance(deps: CoreDeps, v: Viewer, acceptanceId: string): Promise<Result<{ a: Acceptance; rows: LedgerRow[] }>> {
  const rows = await ledgerRows(deps, v.issueId);
  if (!rows.ok) return rows;
  const a = rebuildAcceptances(rows.value, deps.clock.now()).find((x) => x.id === acceptanceId);
  if (!a || a.issueId !== v.issueId) return err(appError('not_found', 'risk acceptance not found'));
  return ok({ a, rows: rows.value });
}

/** `acceptance.decide`: someone other than the requester with the right role (Journey B step 3). */
export async function decideAcceptance(
  deps: CoreDeps,
  v: Viewer,
  issue: JiraIssue,
  input: { acceptanceId: string; decision: 'approve' | 'reject'; note?: string },
): Promise<Result<{ state: AcceptanceState; entryHash: string }>> {
  const found = await findAcceptance(deps, v, input.acceptanceId);
  if (!found.ok) return found;
  const { a } = found.value;
  const policy = await deps.config.site();
  if (!policy.ok) return policy;
  const approve = input.decision === 'approve';
  const req = await deps.requirements.get(a.requirementId);
  if (!req.ok) return req;
  if (approve && !req.value) return err(appError('not_found', 'This requirement no longer exists, so there is nothing to accept. Reject the request.'));
  // Approving is judged on the requirement as it is now (a re-review or triage may have raised it), not as it was requested.
  const severity = approve && req.value ? req.value.severity : a.severity;
  const roles = await rolesOf(deps, v.accountId, v.issueId, policy.value);
  const allowed = canApprove(a, { accountId: v.accountId, roles }, policy.value, severity);
  if (!allowed.ok) return allowed;
  const row = await appendLedger(
    deps.ledger,
    deps.clock,
    approve ? 'acceptance.approved' : 'acceptance.rejected',
    { acceptanceId: a.id, requirementId: a.requirementId, issueId: v.issueId, ...(approve ? { severity } : {}), ...(input.note?.trim() ? { note: input.note.trim() } : {}) },
    v.accountId,
  );
  if (!row.ok) return row;
  const name = req.value ? label(req.value) : `a ${a.severity} security requirement`;
  if (approve) {
    const s = await setStatus(deps, a.requirementId, ['Open', 'InProgress'], 'AcceptedRisk');
    if (!s.ok) log('acceptance.status_failed', { requirementId: a.requirementId, code: s.error.code });
  }
  await notify(
    deps,
    v.issueId,
    [a.acceptedBy],
    approve
      ? `Your risk acceptance for ${name} was approved. It expires on ${day(a.expiresAt)}, when the requirement opens again.`
      : `Your risk acceptance for ${name} was rejected. The requirement stays open; see the Threatline panel on ${issue.key}.`,
  );
  await settle(deps, v.issueId);
  return ok({ state: approve ? 'active' : 'rejected', entryHash: row.value.entryHash });
}

/** `acceptance.revoke` (RL-3: a new entry, never an edit). The requester, approver, a champion or an admin. */
export async function revokeAcceptance(deps: CoreDeps, v: Viewer, issue: JiraIssue, input: { acceptanceId: string; reason: string }): Promise<Result<{ entryHash: string }>> {
  const found = await findAcceptance(deps, v, input.acceptanceId);
  if (!found.ok) return found;
  const { a } = found.value;
  if (a.state !== 'pending' && a.state !== 'active') return err(appError('conflict', `acceptance is ${a.state}`));
  const policy = await deps.config.site();
  if (!policy.ok) return policy;
  const roles = await rolesOf(deps, v.accountId, v.issueId, policy.value);
  const party = v.accountId === a.acceptedBy || v.accountId === a.approvedBy;
  if (!party && !roles.includes('champion') && !roles.includes('admin'))
    return err(appError('forbidden', 'Only the requester, the approver, a security champion or an admin can revoke this.'));
  const row = await appendLedger(deps.ledger, deps.clock, 'acceptance.revoked', { acceptanceId: a.id, requirementId: a.requirementId, issueId: v.issueId, reason: input.reason.trim() }, v.accountId);
  if (!row.ok) return row;
  const s = await setStatus(deps, a.requirementId, ['AcceptedRisk'], 'Open');
  if (!s.ok) log('acceptance.status_failed', { requirementId: a.requirementId, code: s.error.code });
  const req = await deps.requirements.get(a.requirementId);
  const name = req.ok && req.value ? label(req.value) : `a ${a.severity} security requirement`;
  await notify(deps, v.issueId, v.accountId === a.acceptedBy ? [] : [a.acceptedBy], `The risk acceptance for ${name} was revoked. The requirement is open again on ${issue.key}.`);
  await settle(deps, v.issueId);
  return ok({ entryHash: row.value.entryHash });
}

/** `override.breakglass` (EN-8): Jira admins only, with a written reason, for at most 72 hours. Every use is ledgered. */
export async function breakGlass(deps: CoreDeps, v: Viewer, issue: JiraIssue, input: { reason: string; hours: number }): Promise<Result<{ entryHash: string; until: string }>> {
  const reason = input.reason.trim();
  if (reason.length < BREAK_GLASS_MIN_REASON) return err(appError('validation', `Write a reason of at least ${BREAK_GLASS_MIN_REASON} characters.`));
  if (!Number.isInteger(input.hours) || input.hours < 1 || input.hours > BREAK_GLASS_MAX_HOURS)
    return err(appError('validation', `An override lasts 1 to ${BREAK_GLASS_MAX_HOURS} hours.`));
  const admin = await deps.jira.isAdmin(v.accountId);
  if (!admin.ok) return admin;
  if (!admin.value) return err(appError('forbidden', 'Only a Jira administrator can use a break-glass override.'));
  const until = new Date(deps.clock.now().getTime() + input.hours * HOUR).toISOString();
  const row = await appendLedger(deps.ledger, deps.clock, 'override.breakglass', { issueId: v.issueId, issueKey: issue.key, reason, hours: input.hours, until }, v.accountId);
  if (!row.ok) return row;
  await notify(deps, v.issueId, [], `An administrator used a break-glass override on Threatline's gate for ${issue.key} until ${until.slice(0, 16).replace('T', ' ')} UTC. The reason is recorded in the Threatline ledger.`);
  await settle(deps, v.issueId);
  return ok({ entryHash: row.value.entryHash, until });
}

/**
 * RL-5, run hourly: every pending or active acceptance past its expiry gets an `acceptance.expired` entry, its
 * requirement goes back to Open, the requester and assignee are mentioned, and the verdict is recomputed.
 */
export async function expireAcceptances(deps: CoreDeps, now: Date): Promise<Result<{ expired: number }>> {
  const rows = await ledgerRows(deps);
  if (!rows.ok) return rows;
  const due = byEvents(rows.value).filter((a) => (a.state === 'pending' || a.state === 'active') && now.getTime() >= new Date(a.expiresAt).getTime());
  let expired = 0;
  for (const a of due) {
    const req = await deps.requirements.get(a.requirementId);
    const issueId = a.issueId ?? (req.ok ? req.value?.issueId : undefined);
    const row = await appendLedger(deps.ledger, deps.clock, 'acceptance.expired', { acceptanceId: a.id, requirementId: a.requirementId, ...(issueId ? { issueId } : {}), expiresAt: a.expiresAt }, SYSTEM_ACTOR);
    if (!row.ok) return row;
    expired++;
    const s = await setStatus(deps, a.requirementId, ['AcceptedRisk'], 'Open');
    if (!s.ok) log('acceptance.status_failed', { requirementId: a.requirementId, code: s.error.code });
    if (!issueId) continue;
    const issue = await deps.jira.issue(issueId);
    const name = req.ok && req.value ? label(req.value) : `a ${a.severity} security requirement`;
    await notify(
      deps,
      issueId,
      [a.acceptedBy, issue.ok ? issue.value.assignee : undefined],
      a.state === 'pending'
        ? `The risk acceptance request for ${name} expired on ${day(a.expiresAt)} before anyone approved it.`
        : `The risk acceptance for ${name} expired on ${day(a.expiresAt)}. The requirement is open again and blocks Done until it is verified or accepted again.`,
    );
    await settle(deps, issueId);
  }
  return ok({ expired });
}

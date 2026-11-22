import { appendLedger, requirementsFor } from '@threatline/core';
import { appError, err, ok, type Evidence, type Requirement, type RequirementStatus, type Result, type Threat } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import type { AdfDoc, AdfNode, JiraIssue } from '../adapters/jira.js';
import { log } from '../adapters/log.js';
import type { Viewer } from '../resolvers/panel.js';
import { scopedReview } from '../resolvers/panel.js';
import { refreshVerdict } from './verdict-service.js';
import { rolesOf } from './roles.js';
import { citesOnlyTheWorkItem } from './viewer-scope.js';

export const REQUIREMENT_LABEL = 'threatline';
const LOCK_MS = 120_000;
const HISTORY_REVISIONS = 5;

const STRIDE_LABEL: Record<Threat['stride'], string> = {
  Spoofing: 'Spoofing',
  Tampering: 'Tampering',
  Repudiation: 'Repudiation',
  InformationDisclosure: 'Information disclosure',
  DenialOfService: 'Denial of service',
  ElevationOfPrivilege: 'Elevation of privilege',
};

const text = (t: string): AdfNode => ({ type: 'text', text: t });
const para = (...content: AdfNode[]): AdfNode => ({ type: 'paragraph', content });

/**
 * The sub-task body: Given/When/Then, ASVS ids and the panel link. When the threat cites anything beyond the work item
 * itself, the body stays neutral (the sub-task is visible to everyone who can see the work item).
 */
export function requirementDescription(req: Requirement, o: { issueKey: string; revision: number; panelUrl: string; safe: boolean }): AdfDoc {
  const content: AdfNode[] = [para(text(`Security requirement from the Threatline review of ${o.issueKey} (revision ${o.revision}). Severity: ${req.severity}.`))];
  if (o.safe) {
    content.push({ type: 'heading', attrs: { level: 3 }, content: [text('Acceptance criteria')] });
    content.push({
      type: 'bulletList',
      content: req.criteria.map((c) => ({ type: 'listItem', content: [para(text(`Given ${c.given}, when ${c.when}, then ${c.then}.`))] })),
    });
  } else {
    content.push(para(text('This requirement comes from sources that not everyone who can see this work item can open. Read it in the Threatline panel.')));
  }
  if (req.asvsIds.length > 0) content.push(para(text(`OWASP ASVS 5.0: ${req.asvsIds.join(', ')}`)));
  content.push(
    para(
      text('Close it in the '),
      { type: 'text', text: 'Threatline panel', marks: [{ type: 'link', attrs: { href: o.panelUrl } }] },
      text(' with evidence: a PR link, a test file path, a Confluence section, or a note.'),
    ),
  );
  return { type: 'doc', version: 1, content };
}

export type SkipReason = 'not_found' | 'not_required' | 'exists' | 'in_progress' | 'failed' | 'no_child_type';

/** Jira Cloud allows no sub-tasks under an epic: its requirements become child work items of a standard type. */
export const isEpic = (issue: JiraIssue): boolean => !issue.issueType.subtask && /^epic$/i.test(issue.issueType.name.trim());

/** For an epic: the project's Task type, else its Story type (never a sub-task or another epic). */
async function epicChildType(deps: CoreDeps, issue: JiraIssue): Promise<Result<string | null>> {
  const p = await deps.jira.projectInfo(issue.project.key);
  if (!p.ok) return p;
  const standard = p.value.issueTypes.filter((t) => !t.subtask);
  const named = (n: string) => standard.find((t) => t.name.trim().toLowerCase() === n);
  return ok((named('task') ?? named('story'))?.id ?? null);
}

/**
 * RQ-2: one Jira sub-task per chosen threat, idempotent per threat (a requirement row remembers its sub-task key). On
 * an epic, each requirement is a child Task (else Story) of the epic instead, as Jira forbids sub-tasks there; when the
 * project has neither type, the threats are skipped with `no_child_type`.
 */
export async function createRequirementSubtasks(
  deps: CoreDeps,
  v: Viewer,
  issue: JiraIssue,
  threatIds: readonly string[],
): Promise<Result<{ created: Array<{ requirementId: string; subtaskKey: string }>; skipped: Array<{ threatId: string; reason: SkipReason }> }>> {
  const created: Array<{ requirementId: string; subtaskKey: string }> = [];
  const skipped: Array<{ threatId: string; reason: SkipReason }> = [];
  const latest = await deps.reviews.latest(issue.id);
  if (!latest.ok) return latest;
  const review = latest.value;
  const ids = [...new Set(threatIds)];
  if (!review) return ok({ created, skipped: ids.map((threatId) => ({ threatId, reason: 'not_found' as const })) });
  const [scoped, facts, reqs] = await Promise.all([scopedReview(deps, v, review.id), deps.reviews.facts(review.id), deps.requirements.forIssue(issue.id)]);
  if (!scoped) return err(appError('upstream', 'review unavailable'));
  if (!facts.ok) return facts;
  if (!reqs.ok) return reqs;
  const panelUrl = `${await deps.siteUrl()}/browse/${issue.key}`;
  const epic = isEpic(issue);
  let typeId: string | null | undefined;

  for (const threatId of ids) {
    const t = scoped.threats.find((x) => x.id === threatId);
    if (!t) {
      skipped.push({ threatId, reason: 'not_found' });
      continue;
    }
    if (t.state !== 'accepted' && t.state !== 'needs_human') {
      skipped.push({ threatId, reason: 'not_required' });
      continue;
    }
    let req = reqs.value.find((r) => r.threatId === t.id);
    if (!req) {
      req = { ...requirementsFor([t], { issueId: issue.id, issueKey: issue.key })[0]!, createdAt: deps.clock.now().toISOString() };
      const u = await deps.requirements.upsert(req);
      if (!u.ok) return u;
    }
    if (req.subtaskKey) {
      skipped.push({ threatId, reason: 'exists' });
      continue;
    }
    // Best-effort guard against a double click creating two sub-tasks while the first is still being created.
    const lockKey = `subtask:${req.id}`;
    const now = deps.clock.now().getTime();
    const held = await deps.state.get<number>(lockKey).catch(() => undefined);
    if (typeof held === 'number' && now - held < LOCK_MS) {
      skipped.push({ threatId, reason: 'in_progress' });
      continue;
    }
    await deps.state.set(lockKey, now).catch(() => undefined);

    if (typeId === undefined) {
      const type = epic ? await epicChildType(deps, issue) : await deps.jira.subtaskType(issue.project.id);
      if (!type.ok) {
        await deps.state.delete(lockKey).catch(() => undefined);
        return type;
      }
      typeId = type.value;
    }
    if (typeId === null) {
      await deps.state.delete(lockKey).catch(() => undefined);
      skipped.push({ threatId, reason: 'no_child_type' });
      continue;
    }
    const safe = citesOnlyTheWorkItem(t, facts.value, issue.id);
    const summary = safe ? req.title : `Threatline ${req.severity} security requirement (${STRIDE_LABEL[t.stride]})`;
    const fields = {
      summary: summary.slice(0, 255),
      description: requirementDescription(req, { issueKey: issue.key, revision: review.revision, panelUrl, safe }),
      labels: [REQUIREMENT_LABEL],
      issueTypeId: typeId,
    };
    const sub = epic ? await deps.jira.createIssue({ ...fields, projectId: issue.project.id, parentId: issue.id }) : await deps.jira.createSubtask(issue.id, fields);
    if (!sub.ok) {
      log('requirements.create.failed', { issueId: issue.id, code: sub.error.code });
      await deps.state.delete(lockKey).catch(() => undefined);
      skipped.push({ threatId, reason: 'failed' });
      continue;
    }
    const u = await deps.requirements.upsert({ ...req, subtaskKey: sub.value.key });
    if (!u.ok) return u;
    await deps.issues.upsert({ issueId: sub.value.id, issueKey: sub.value.key, projectKey: issue.project.key, parentId: issue.id });
    await deps.state.delete(lockKey).catch(() => undefined);
    created.push({ requirementId: req.id, subtaskKey: sub.value.key });
  }

  if (created.length > 0) {
    await refreshVerdict(deps, issue.id);
    await deps.queue.push([{ kind: 'propagate', issueId: issue.id }]);
  }
  return ok({ created, skipped });
}

const HTTPS = (ref: string) => {
  try {
    return new URL(ref).protocol === 'https:';
  } catch {
    return false;
  }
};

/** Whether this viewer can see the requirement's threat in the latest review or one of the recent revisions. */
export async function threatVisible(deps: CoreDeps, v: Viewer, threatId: string): Promise<Result<boolean>> {
  const history = await deps.reviews.history(v.issueId);
  if (!history.ok) return history;
  for (const r of history.value.slice(-HISTORY_REVISIONS).reverse()) {
    const scoped = await scopedReview(deps, v, r.id);
    if (!scoped) return err(appError('upstream', 'review unavailable'));
    if (scoped.threats.some((t) => t.id === threatId)) return ok(true);
  }
  return ok(false);
}

/**
 * For CI, which is no person: the requirement's threat is still in the latest review or one of the recent revisions
 * (unscoped; CI only ever learns the outcome for an id it already named).
 */
async function threatCurrent(deps: CoreDeps, issueId: string, threatId: string): Promise<Result<boolean>> {
  const history = await deps.reviews.history(issueId);
  if (!history.ok) return history;
  for (const r of history.value.slice(-HISTORY_REVISIONS).reverse()) {
    const threats = await deps.reviews.threats(r.id);
    if (!threats.ok) return threats;
    if (threats.value.some((t) => t.id === threatId)) return ok(true);
  }
  return ok(false);
}

/** The only statuses CI may move to Verified. */
const CI_FROM: readonly RequirementStatus[] = ['Open', 'InProgress'];

/** A CI report as the actor (`ci:<token id>`): the commit and repository the tests ran on. */
export interface CiActor {
  tokenId: string;
  commitSha: string;
  repo: string;
}

/**
 * RQ-3 / RQ-4. Verified needs evidence, attested by the caller. Not applicable is a security champion's call. Accepted
 * risk only comes from an approved risk acceptance (ledgered), never from a status change. Every change is ledgered
 * here, for the panel and agents alike, before it is saved: if the ledger cannot record it, nothing changes. CI
 * (`opts.ci`, docs/CI_VERIFICATION.md) may only verify, with `ci` evidence; nobody else can give `ci` evidence.
 */
export async function setRequirementStatus(
  deps: CoreDeps,
  v: Viewer,
  input: { requirementId: string; status: RequirementStatus; evidence?: { kind: Evidence['kind']; ref: string; note?: string } },
  opts: { viaAgent?: boolean; ci?: CiActor } = {},
): Promise<Result<{ requirement: Requirement; entryHash: string }>> {
  if (input.status === 'AcceptedRisk') return err(appError('validation', 'Request a risk acceptance in the Threatline panel instead.'));
  const ci = opts.ci;
  if ((input.evidence?.kind === 'ci') !== (ci !== undefined) || (ci && input.status !== 'Verified'))
    return err(appError('validation', 'CI evidence comes only from a CI report, and a CI report can only verify.'));
  const got = await deps.requirements.get(input.requirementId);
  if (!got.ok) return got;
  const req = got.value;
  if (!req || req.issueId !== v.issueId) return err(appError('not_found', 'requirement not found'));
  // CI only ever moves an open requirement to Verified, judged on this fresh read; the save below is conditional on it.
  if (ci && !CI_FROM.includes(req.status)) return err(appError('conflict', `The requirement is ${req.status}; CI does not change that.`, { status: req.status }));
  const visible = ci ? await threatCurrent(deps, req.issueId, req.threatId) : await threatVisible(deps, v, req.threatId);
  if (!visible.ok) return visible;
  if (!visible.value) return err(appError('not_found', 'requirement not found'));

  if (input.status === 'NotApplicable') {
    const policy = await deps.config.site();
    if (!policy.ok) return policy;
    const roles = await rolesOf(deps, v.accountId, v.issueId, policy.value);
    if (!roles.includes('champion')) return err(appError('forbidden', 'Only a security champion can mark a requirement Not applicable.'));
  }
  const { evidence: _e, verifiedBy: _v, verifiedAt: _t, ...rest } = req;
  let next: Requirement = { ...rest, status: input.status };
  if (input.status === 'Verified') {
    const e = input.evidence;
    if (!e) return err(appError('validation', 'Verified needs evidence: a PR link, a test file path, a Confluence section, or a note.'));
    if ((e.kind === 'pr' || e.kind === 'confluence' || e.kind === 'ci') && !HTTPS(e.ref)) return err(appError('validation', 'A PR, CI run or Confluence link must start with https://.'));
    const where = ci ? { commitSha: ci.commitSha, repo: ci.repo } : {};
    next = { ...next, verifiedBy: v.accountId, verifiedAt: deps.clock.now().toISOString(), evidence: { kind: e.kind, ref: e.ref, ...(e.note ? { note: e.note } : {}), ...where, attester: v.accountId } };
  }
  const e = next.evidence;
  const row = await appendLedger(
    deps.ledger,
    deps.clock,
    input.status === 'Verified' ? 'requirement.verified' : 'requirement.status_changed',
    {
      requirementId: req.id,
      issueId: v.issueId,
      from: req.status,
      to: input.status,
      ...(e ? { evidenceKind: e.kind, evidence: e.ref, ...(e.note ? { note: e.note } : {}) } : {}),
      viaAgent: opts.viaAgent === true,
      ...(ci ? { viaCi: true, ciTokenId: ci.tokenId, commitSha: ci.commitSha, repo: ci.repo } : {}),
    },
    v.accountId,
  );
  if (!row.ok) return row;
  // Security: CI's save is a compare-and-set on the status it read, so a risk accepted or a Not applicable set by a
  // person meanwhile is never overwritten by a test run.
  const saved = ci ? await deps.requirements.upsertIf(next, [req.status]) : await deps.requirements.upsert(next);
  const u: Result<void> = !saved.ok ? saved : saved.value === false ? err(appError('conflict', 'The requirement changed meanwhile; CI did not change it.')) : ok(undefined);
  if (!u.ok) {
    // The change is recorded before it is saved, so it is never saved unrecorded. When the save then fails, a second
    // entry says the recorded change did not take effect, so the ledger never shows a change that never happened.
    const undo = await appendLedger(deps.ledger, deps.clock, 'requirement.status_change_failed', { requirementId: req.id, issueId: v.issueId, failedEntryHash: row.value.entryHash, code: u.error.code }, v.accountId);
    if (!undo.ok) log('requirement.status_change_failed_unrecorded', { requirementId: req.id, code: undo.error.code });
    return u;
  }
  await refreshVerdict(deps, v.issueId);
  await deps.queue.push([{ kind: 'propagate', issueId: v.issueId }]);
  return ok({ requirement: next, entryHash: row.value.entryHash });
}

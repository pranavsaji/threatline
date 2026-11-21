import { appendLedger, ruleMatches, suggestSuppressions, SUPPRESSION_MAX_ACTIVE_PER_PROJECT, SUPPRESSION_WINDOW_DAYS, unhidden, type ActiveSuppression, type SuppressionSuggestion } from '@threatline/core';
import { appError, err, newId, ok, SUPPRESSION_MAX_DAYS, type Result, type Review, type Stride, type SuppressionRule, type Threat } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import type { JiraIssue } from '../adapters/jira.js';
import { log } from '../adapters/log.js';
import { SYSTEM_ACTOR } from './acceptance-service.js';
import { opsAlert } from './ops-alert.js';
import { syncRequirement } from './triage-service.js';
import { refreshVerdict } from './verdict-service.js';

const DAY = 86_400_000;
/** Bounded work per job run and per admin page load. */
const MAX_RULES_READ = 500;
const MAX_DISMISSALS_READ = 2000;
const REMINDER_LISTED = 20;

/** The project a work item belongs to, from its key (PAY-12 → PAY). */
export const projectOfKey = (issueKey: string): string => issueKey.replace(/-\d+$/, '');

/** Champions and Jira administrators manage a project's rules. A failed lookup grants nothing. */
export async function canManageSuppressions(deps: CoreDeps, accountId: string): Promise<Result<boolean>> {
  if (!accountId) return ok(false);
  const policy = await deps.config.site();
  if (!policy.ok) return policy;
  const [admin, groups] = await Promise.all([deps.jira.isAdmin(accountId), deps.jira.groupsOf(accountId)]);
  if (admin.ok && admin.value) return ok(true);
  if (groups.ok && groups.value.includes(policy.value.championGroup)) return ok(true);
  if (!admin.ok && !groups.ok) return admin;
  return ok(false);
}

/**
 * What an assembly applies for this work item: its project's active rules and those a champion unhid on it. A failed
 * lookup applies none (every threat stays shown), which is the stricter way to fail.
 */
export async function suppressionsFor(deps: CoreDeps, review: Pick<Review, 'issueId' | 'issueKey'>): Promise<{ rules: ActiveSuppression[]; unhidden: string[] } | undefined> {
  const [rules, exempt] = await Promise.all([deps.suppressions.activeFor(projectOfKey(review.issueKey), deps.clock.now().toISOString()), deps.suppressions.unhiddenOn(review.issueId)]);
  if (!rules.ok || !exempt.ok) {
    log('suppression.lookup_failed', { code: !rules.ok ? rules.error.code : !exempt.ok ? exempt.error.code : 'internal' });
    return undefined;
  }
  return { rules: rules.value, unhidden: exempt.value };
}

/** Counts each rule that hid a threat in a settled review once per work item (for the admin page). Best effort. */
export async function recordHidden(deps: CoreDeps, review: Pick<Review, 'issueId' | 'issueKey'>, threats: readonly Threat[]): Promise<void> {
  const ids = new Set(threats.flatMap((t) => (t.state === 'suppressed' && t.suppression ? [t.suppression.ruleId] : [])));
  for (const id of ids) {
    const r = await deps.suppressions.recordMatch(id, review.issueId, review.issueKey, deps.clock.now().toISOString());
    if (!r.ok) log('suppression.match_failed', { code: r.error.code });
  }
}

export interface CreateRuleInput {
  projectKey: string;
  stride: Stride;
  title: string;
  component?: string;
  reason: string;
  expiryDays?: number;
  evidence?: string[];
}

/**
 * A champion or admin creates a rule for a project. It is written `pending`, ledgered, then made `active`: a rule whose
 * creation is not in the ledger never applies. At most 50 active rules per project, at most 90 days.
 */
export async function createRule(deps: CoreDeps, actor: string, input: CreateRuleInput): Promise<Result<SuppressionRule>> {
  const allowed = await canManageSuppressions(deps, actor);
  if (!allowed.ok) return allowed;
  if (!allowed.value) return err(appError('forbidden', 'Only a security champion or a Jira administrator can create a suppression rule.'));
  const days = input.expiryDays ?? SUPPRESSION_MAX_DAYS;
  if (!Number.isInteger(days) || days < 1 || days > SUPPRESSION_MAX_DAYS) return err(appError('validation', `A rule lasts 1 to ${SUPPRESSION_MAX_DAYS} days.`));
  const now = deps.clock.now();
  const active = await deps.suppressions.activeFor(input.projectKey, now.toISOString());
  if (!active.ok) return active;
  if (active.value.length >= SUPPRESSION_MAX_ACTIVE_PER_PROJECT) return err(appError('validation', `${input.projectKey} already has ${SUPPRESSION_MAX_ACTIVE_PER_PROJECT} active rules. Revoke one first.`));
  const same = active.value.find((r) => (r.component ?? '') === (input.component ?? '') && ruleMatches(r, { stride: input.stride, title: input.title, component: input.component ?? '' }));
  if (same) return err(appError('conflict', `An active rule already hides this kind of threat in ${input.projectKey}: “${same.title}”.`));
  const rule: SuppressionRule = {
    id: newId('sup'),
    projectKey: input.projectKey,
    stride: input.stride,
    title: input.title,
    ...(input.component ? { component: input.component } : {}),
    reason: input.reason,
    createdBy: actor,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + days * DAY).toISOString(),
    status: 'pending',
    evidence: [...new Set(input.evidence ?? [])].slice(0, 10),
  };
  const c = await deps.suppressions.create(rule);
  if (!c.ok) return c;
  const { status: _s, createdAt: _c, createdBy: _b, ...entry } = rule;
  const row = await appendLedger(deps.ledger, deps.clock, 'suppression.created', { ...entry, ruleId: rule.id }, actor);
  if (!row.ok) return row;
  const on = await deps.suppressions.transition(rule.id, 'pending', 'active');
  if (!on.ok) return on;
  if (!on.value) return err(appError('conflict', 'The rule changed meanwhile. Reload and try again.'));
  return ok({ ...rule, status: 'active' });
}

/** A champion or admin revokes an active rule, with a reason; ledgered. Reviews from now on show its threats again. */
export async function revokeRule(deps: CoreDeps, actor: string, ruleId: string, reason: string): Promise<Result<SuppressionRule>> {
  const allowed = await canManageSuppressions(deps, actor);
  if (!allowed.ok) return allowed;
  if (!allowed.value) return err(appError('forbidden', 'Only a security champion or a Jira administrator can revoke a suppression rule.'));
  const rule = await deps.suppressions.get(ruleId);
  if (!rule.ok) return rule;
  if (!rule.value) return err(appError('not_found', 'no such rule'));
  if (rule.value.status !== 'active') return err(appError('conflict', `This rule is already ${rule.value.status}.`));
  const at = deps.clock.now().toISOString();
  const moved = await deps.suppressions.transition(ruleId, 'active', 'revoked', { by: actor, at, reason });
  if (!moved.ok) return moved;
  if (!moved.value) return err(appError('conflict', 'This rule is no longer active.'));
  const row = await appendLedger(deps.ledger, deps.clock, 'suppression.revoked', { ruleId, projectKey: rule.value.projectKey, reason }, actor);
  if (!row.ok) return row;
  return ok({ ...rule.value, status: 'revoked', endedBy: actor, endedAt: at, endReason: reason });
}

/** Hourly: every active rule past its expiry becomes `expired`, ledgered. (An expired rule never applies anyway.) */
export async function expireRules(deps: CoreDeps, now: Date): Promise<Result<{ expired: number }>> {
  const list = await deps.suppressions.list(['active'], MAX_RULES_READ);
  if (!list.ok) return list;
  let expired = 0;
  for (const r of list.value.filter((x) => new Date(x.expiresAt).getTime() <= now.getTime())) {
    const moved = await deps.suppressions.transition(r.id, 'active', 'expired', { by: SYSTEM_ACTOR, at: now.toISOString() });
    if (!moved.ok) return moved;
    if (!moved.value) continue;
    const row = await appendLedger(deps.ledger, deps.clock, 'suppression.expired', { ruleId: r.id, projectKey: r.projectKey, expiresAt: r.expiresAt }, SYSTEM_ACTOR);
    if (!row.ok) return row;
    expired++;
  }
  return ok({ expired });
}

const dayOf = (iso: string) => iso.slice(0, 10);

/**
 * Monthly (from the daily job, once per calendar month): the active rules, for the team to re-approve or revoke, as
 * one comment on the ops work item. At most 20 are listed. False when there is nothing to send or it was already sent.
 */
export async function remindRules(deps: CoreDeps, now: Date): Promise<Result<boolean>> {
  const list = await deps.suppressions.list(['active'], MAX_RULES_READ);
  if (!list.ok) return list;
  const live = list.value.filter((r) => new Date(r.expiresAt).getTime() > now.getTime());
  if (live.length === 0) return ok(false);
  const lines = live.slice(0, REMINDER_LISTED).map((r) => `${r.projectKey}: “${r.title}” (${r.stride}${r.component ? `, ${r.component}` : ''}), expires ${dayOf(r.expiresAt)}. Reason: ${r.reason}`);
  const more = live.length > REMINDER_LISTED ? ` And ${live.length - REMINDER_LISTED} more.` : '';
  const sent = await opsAlert(
    deps,
    `alert:suppressions:${now.toISOString().slice(0, 7)}`,
    `Threatline: ${live.length} team suppression ${live.length === 1 ? 'rule hides' : 'rules hide'} below-threshold threats in new reviews. Re-approve them or revoke any that no longer hold (Threatline admin → Suppressions): ${lines.join(' · ')}.${more}`,
  );
  return ok(sent);
}

export interface SuppressionRuleDto extends SuppressionRule {
  /** Work items it has hidden a threat on. */
  matches: number;
}
export interface SuppressionsDto {
  rules: SuppressionRuleDto[];
  suggestions: SuppressionSuggestion[];
  maxDays: number;
}

/** The admin page section: active rules with their match counts, and suggestions from the last 90 days of dismissals. */
export async function listSuppressions(deps: CoreDeps): Promise<Result<SuppressionsDto>> {
  const now = deps.clock.now();
  const rules = await deps.suppressions.list(['active'], MAX_RULES_READ);
  if (!rules.ok) return rules;
  const live = rules.value.filter((r) => new Date(r.expiresAt).getTime() > now.getTime());
  const [counts, dismissals] = await Promise.all([
    deps.suppressions.matchCounts(live.map((r) => r.id)),
    deps.feedback.dismissalsSince(new Date(now.getTime() - SUPPRESSION_WINDOW_DAYS * DAY).toISOString(), MAX_DISMISSALS_READ),
  ]);
  if (!counts.ok) return counts;
  if (!dismissals.ok) return dismissals;
  return ok({
    rules: live.map((r) => ({ ...r, matches: counts.value[r.id] ?? 0 })),
    suggestions: suggestSuppressions(dismissals.value, live),
    maxDays: SUPPRESSION_MAX_DAYS,
  });
}

/**
 * A champion unhides a rule's threats on one work item (ledgered first): they return to the state they had, with their
 * requirements, and later reviews of this work item leave them shown. The rule still applies to other work items.
 */
export async function unhideOnWorkItem(deps: CoreDeps, actor: string, issue: JiraIssue, review: Review, all: readonly Threat[], ruleId: string): Promise<Result<Threat[]>> {
  const hidden = all.filter((t) => t.state === 'suppressed' && t.suppression?.ruleId === ruleId);
  if (hidden.length === 0) return err(appError('not_found', 'Nothing on this work item is hidden by that rule.'));
  const row = await appendLedger(deps.ledger, deps.clock, 'suppression.unhidden', { ruleId, issueId: issue.id, issueKey: issue.key, reviewId: review.id, threatIds: hidden.map((t) => t.id) }, actor);
  if (!row.ok) return row;
  const u = await deps.suppressions.unhide(ruleId, issue.id, issue.key, actor, deps.clock.now().toISOString());
  if (!u.ok) return u;
  const changed: Threat[] = [];
  for (const t of hidden) {
    const back = unhidden(t);
    const w = await deps.reviews.updateThreat(t.id, { state: back.state, suppression: back.suppression });
    if (!w.ok) return w;
    if (back.state === 'accepted' || back.state === 'needs_human') {
      const s = await syncRequirement(deps, issue, back);
      if (!s.ok) return s;
    }
    changed.push(back);
  }
  await refreshVerdict(deps, issue.id);
  await deps.queue.push([{ kind: 'propagate', issueId: issue.id }]);
  return ok(changed);
}

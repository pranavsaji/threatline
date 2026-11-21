import { z } from 'zod';
import { StrideSchema, SUPPRESSION_MAX_DAYS, type SuppressionRule, type Threat } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { rolesOf } from '../services/roles.js';
import { canManageSuppressions, createRule, listSuppressions, revokeRule, unhideOnWorkItem, type SuppressionsDto } from '../services/suppression-service.js';
import { triageable } from '../services/triage-service.js';
import { apiError, type ApiError } from './errors.js';
import { authorise, scopedReview, type Viewer } from './panel.js';

const PROJECT_KEY = /^[A-Z][A-Z0-9_]{0,39}$/;
const ISSUE_KEY = /^[A-Z][A-Z0-9_]{0,30}-\d{1,8}$/;
const RULE_ID = z.string().regex(/^sup_[A-Za-z0-9]{1,36}$/);

const CreateSchema = z
  .object({
    projectKey: z.string().regex(PROJECT_KEY, 'Give a Jira project key (like PAY).'),
    stride: StrideSchema,
    title: z.string().trim().min(3, 'Name the kind of threat (at least 3 characters).').max(200),
    component: z.string().trim().max(200).optional(),
    reason: z.string().trim().min(10, 'Write a reason of at least 10 characters.').max(300),
    expiryDays: z.number().int().min(1).max(SUPPRESSION_MAX_DAYS, `A rule lasts at most ${SUPPRESSION_MAX_DAYS} days.`).optional(),
    evidence: z.array(z.string().regex(ISSUE_KEY)).max(10).optional(),
  })
  .strict();
const RevokeSchema = z.object({ ruleId: RULE_ID, reason: z.string().trim().min(10, 'Write a reason of at least 10 characters.').max(300) }).strict();
const UnhideSchema = z.object({ ruleId: RULE_ID }).strict();

const invalid = (e: z.ZodError): ApiError => ({ error: 'validation', message: e.issues[0]?.message ?? 'That is not valid.' });

async function manager(deps: CoreDeps, accountId: string): Promise<ApiError | null> {
  const r = await canManageSuppressions(deps, accountId);
  if (!r.ok) return { error: 'unavailable' };
  return r.value ? null : { error: 'forbidden', message: 'Only a security champion or a Jira administrator can manage suppression rules.' };
}

/** `suppressions.list` (admin page; champions and admins): active rules with match counts, and suggestions. */
export async function suppressionsList(deps: CoreDeps, a: { accountId: string }): Promise<SuppressionsDto | ApiError> {
  const denied = await manager(deps, a.accountId);
  if (denied) return denied;
  const r = await listSuppressions(deps);
  return r.ok ? r.value : apiError(r.error);
}

/** `suppressions.create` (champions and admins): a project rule with a reason, for at most 90 days; ledgered. */
export async function suppressionsCreate(deps: CoreDeps, a: { accountId: string }, payload: unknown): Promise<SuppressionRule | ApiError> {
  const p = CreateSchema.safeParse(payload);
  if (!p.success) return invalid(p.error);
  const { component, ...rest } = p.data;
  const r = await createRule(deps, a.accountId, { ...rest, ...(component ? { component } : {}) });
  return r.ok ? r.value : apiError(r.error);
}

/** `suppressions.revoke` (champions and admins), with a reason; ledgered. */
export async function suppressionsRevoke(deps: CoreDeps, a: { accountId: string }, payload: unknown): Promise<SuppressionRule | ApiError> {
  const p = RevokeSchema.safeParse(payload);
  if (!p.success) return invalid(p.error);
  const r = await revokeRule(deps, a.accountId, p.data.ruleId, p.data.reason);
  return r.ok ? r.value : apiError(r.error);
}

/** `suppressions.unhide` (panel, champions only): shows a rule's hidden threats on this work item again; ledgered. */
export async function suppressionsUnhide(deps: CoreDeps, v: Viewer, payload: unknown): Promise<Threat[] | ApiError> {
  const p = UnhideSchema.safeParse(payload);
  if (!p.success) return invalid(p.error);
  const auth = await authorise(deps, v, 'browse');
  if ('error' in auth) return auth;
  const policy = await deps.config.site();
  if (!policy.ok) return { error: 'unavailable' };
  const roles = await rolesOf(deps, v.accountId, v.issueId, policy.value);
  if (!roles.includes('champion')) return { error: 'forbidden', message: 'Only a security champion can do this.' };
  const latest = await deps.reviews.latest(v.issueId);
  if (!latest.ok) return { error: 'unavailable' };
  const review = triageable(latest.value);
  if (!review.ok) return apiError(review.error);
  const [scoped, all] = await Promise.all([scopedReview(deps, v, review.value.id), deps.reviews.threats(review.value.id)]);
  if (!scoped || !all.ok) return { error: 'unavailable' };
  // Only what this champion can see: a threat citing a source they cannot open is not theirs to unhide.
  const visible = new Set(scoped.threats.map((t) => t.id));
  const r = await unhideOnWorkItem(deps, v.accountId, auth.issue, review.value, all.value.filter((t) => visible.has(t.id)), p.data.ruleId);
  if (!r.ok) return apiError(r.error);
  const after = await scopedReview(deps, v, review.value.id);
  return after ? after.threats : { error: 'unavailable' };
}

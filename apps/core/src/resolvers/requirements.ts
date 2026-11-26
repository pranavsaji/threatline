import { z } from 'zod';
import { RequirementStatusSchema, type Requirement } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { createRequirementSubtasks, setRequirementStatus, type SkipReason } from '../services/requirements-service.js';
import { apiError, type ApiError } from './errors.js';
import { authorise, type Viewer } from './panel.js';
import { confirmFix } from '../services/fix-check-service.js';
import { isChampion } from '../services/roles.js';

const CreateSchema = z.object({ threatIds: z.array(z.string().min(1).max(100)).min(1).max(50) });
const StatusSchema = z.object({
  requirementId: z.string().min(1).max(100),
  status: RequirementStatusSchema,
  // `attester` may be sent but is ignored: the attester is always the caller.
  evidence: z.object({ kind: z.enum(['pr', 'test', 'confluence', 'manual']), ref: z.string().trim().min(1).max(2000) }).optional(),
});

const invalid = (e: z.ZodError): ApiError => ({ error: 'validation', message: e.issues.slice(0, 3).map((i) => `${i.path.join('.') || 'request'}: ${i.message}`).join('; ') });

/** `requirements.create`: needs edit permission on the work item. */
export async function requirementsCreate(
  deps: CoreDeps,
  v: Viewer,
  payload: unknown,
): Promise<{ created: Array<{ requirementId: string; subtaskKey: string }>; skipped: Array<{ threatId: string; reason: SkipReason }> } | ApiError> {
  const p = CreateSchema.safeParse(payload);
  if (!p.success) return invalid(p.error);
  const auth = await authorise(deps, v, 'edit');
  if ('error' in auth) return auth;
  const r = await createRequirementSubtasks(deps, v, auth.issue, p.data.threatIds);
  return r.ok ? r.value : apiError(r.error);
}

/** `requirements.setStatus`: needs edit permission; Not applicable additionally needs a security champion. */
export async function requirementsSetStatus(deps: CoreDeps, v: Viewer, payload: unknown): Promise<Requirement | ApiError> {
  const p = StatusSchema.safeParse(payload);
  if (!p.success) return invalid(p.error);
  const auth = await authorise(deps, v, 'edit');
  if ('error' in auth) return auth;
  const r = await setRequirementStatus(deps, v, { requirementId: p.data.requirementId, status: p.data.status, ...(p.data.evidence ? { evidence: p.data.evidence } : {}) });
  return r.ok ? r.value.requirement : apiError(r.error);
}

const ConfirmFixSchema = z.object({ requirementId: z.string().min(1).max(100) });

/**
 * `fixCheck.confirm` (docs/FIX_CHECK.md): a security champion confirms a verified requirement is fixed by this commit
 * although the fix check could not show it. Champions only (separation of duties); ledgered before it is saved.
 */
export async function fixCheckConfirm(deps: CoreDeps, v: Viewer, payload: unknown): Promise<{ ok: true } | ApiError> {
  const p = ConfirmFixSchema.safeParse(payload);
  if (!p.success) return invalid(p.error);
  const auth = await authorise(deps, v, 'browse');
  if ('error' in auth) return auth;
  const policy = await deps.config.site();
  if (!policy.ok) return { error: 'unavailable' };
  if (!(await isChampion(deps, v.accountId, policy.value))) return { error: 'forbidden', message: 'Only a security champion can confirm a fix the check could not show.' };
  const r = await confirmFix(deps, v.accountId, v.issueId, p.data.requirementId);
  // The panel reloads to show it (scoped to what this viewer may see).
  return r.ok ? { ok: true } : apiError(r.error);
}

import { z } from 'zod';
import { DismissReasonSchema } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { isChampion, isChampionOrAdmin } from '../services/roles.js';
import { buildInbox, decideInboxItem, INBOX_DECIDE_MAX, INBOX_PAGE, INBOX_PAGE_MAX, inboxPage, type Inbox, type InboxDecision } from '../services/inbox-service.js';
import { apiError, type ApiError, type ApiErrorCode } from './errors.js';

export type { InboxCluster, InboxRow } from '../services/inbox-service.js';

/** The global page's viewer: identity from the Forge context only. */
export interface InboxViewer {
  accountId: string;
}

export type InboxDto = Pick<Inbox, 'clusters' | 'total' | 'hidden' | 'truncated'> & {
  /** The next page's cursor, or null on the last page. */
  cursor: number | null;
  /** The server's time, so ages read the same for everyone. */
  now: string;
};

export type InboxItemResult =
  | { issueId: string; threatId: string; ok: true; state: string }
  | { issueId: string; threatId: string; ok: false; error: ApiErrorCode; message?: string };
export interface InboxDecideDto {
  results: InboxItemResult[];
  decided: number;
  failed: number;
}

const ListSchema = z.object({ cursor: z.number().int().min(0).max(10_000).optional(), pageSize: z.number().int().min(1).max(INBOX_PAGE_MAX).optional() }).strip();
const Item = z.object({ issueId: z.string().regex(/^\d{1,18}$/, 'issueId must be a work item id'), threatId: z.string().min(1).max(120) }).strict();
const DecideSchema = z
  .discriminatedUnion('decision', [
    z.object({ decision: z.literal('confirm'), items: z.array(Item).min(1).max(INBOX_DECIDE_MAX) }).strict(),
    z.object({ decision: z.literal('dismiss'), reason: DismissReasonSchema, note: z.string().trim().max(500).optional(), items: z.array(Item).min(1).max(INBOX_DECIDE_MAX) }).strict(),
  ])
  .refine((p) => new Set(p.items.map((i) => `${i.issueId}|${i.threatId}`)).size === p.items.length, 'each threat once');

const invalid = (e: z.ZodError): ApiError => ({ error: 'validation', message: e.issues.slice(0, 3).map((i) => `${i.path.join('.') || 'request'}: ${i.message}`).join('; ') });

/** Champions and Jira admins only, checked on every call; lookup failures grant nothing. */
async function gate(deps: CoreDeps, v: InboxViewer, decide = false): Promise<{ enabledProjects: string[] } | ApiError> {
  if (!v.accountId) return { error: 'not_found' };
  const policy = await deps.config.site();
  if (!policy.ok) return { error: 'unavailable' };
  if (!(await isChampionOrAdmin(deps, v.accountId, policy.value))) return { error: 'forbidden', message: 'Only security champions and Jira admins can open the champion inbox.' };
  // Separation of duties, as in the issue panel: a Jira admin can see the inbox, but only a champion decides.
  if (decide && !(await isChampion(deps, v.accountId, policy.value))) return { error: 'forbidden', message: 'Only a security champion can confirm or dismiss these threats.' };
  return { enabledProjects: policy.value.enabledProjects };
}

/** `inbox.list`: one page of the champion inbox (threats waiting for a champion across projects), most urgent first. */
export async function inboxList(deps: CoreDeps, v: InboxViewer, payload: unknown): Promise<InboxDto | ApiError> {
  const p = ListSchema.safeParse(payload ?? {});
  if (!p.success) return invalid(p.error);
  const allowed = await gate(deps, v);
  if ('error' in allowed) return allowed;
  const inbox = await buildInbox(deps, v.accountId);
  if (!inbox.ok) {
    log('inbox.failed', { code: inbox.error.code });
    return { error: 'unavailable' };
  }
  const page = await inboxPage(deps, inbox.value, p.data.cursor ?? 0, p.data.pageSize ?? INBOX_PAGE);
  const { total, hidden, truncated } = inbox.value;
  return { ...page, total, hidden, truncated, now: deps.clock.now().toISOString() };
}

/**
 * `inbox.decide`: confirm (accept, so it becomes a requirement) or dismiss with a reason, for one threat or a selection.
 * A bulk decision is that many individual decisions, each authorised, validated and ledgered on its own, one after the
 * other; a failure is reported for its item and does not stop the rest.
 */
export async function inboxDecide(deps: CoreDeps, v: InboxViewer, payload: unknown): Promise<InboxDecideDto | ApiError> {
  const p = DecideSchema.safeParse(payload);
  if (!p.success) return invalid(p.error);
  const allowed = await gate(deps, v, true);
  if ('error' in allowed) return allowed;
  const op: InboxDecision = p.data.decision === 'confirm' ? { op: 'accept' } : { op: 'dismiss', reason: p.data.reason, ...(p.data.note ? { note: p.data.note } : {}) };
  const results: InboxItemResult[] = [];
  for (const item of p.data.items) {
    const r = await decideInboxItem(deps, v.accountId, allowed.enabledProjects, item, op).catch((e: unknown) => {
      log('inbox.decide_threw', { message: e instanceof Error ? e.message.slice(0, 200) : 'unknown' });
      return null;
    });
    if (r?.ok) results.push({ ...item, ok: true, state: r.value.state });
    else results.push({ ...item, ok: false, ...(r ? apiError(r.error) : { error: 'unavailable' as const }) });
  }
  const decided = results.filter((r) => r.ok).length;
  return { results, decided, failed: results.length - decided };
}

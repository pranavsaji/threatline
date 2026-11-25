import type { AdfDoc, AdfNode } from '../adapters/jira.js';
import { log } from '../adapters/log.js';
import type { CoreDeps } from '../deps.js';
import { rememberOwnAccount } from './own-account.js';

const MAX_MENTIONS = 10;

/** One paragraph: @mentions (deduplicated, at most 10), then the text. */
export function mentionDoc(accountIds: readonly (string | undefined)[], text: string): AdfDoc {
  const ids = [...new Set(accountIds.filter((a): a is string => typeof a === 'string' && a.length > 0))].slice(0, MAX_MENTIONS);
  const content: AdfNode[] = [];
  for (const id of ids) content.push({ type: 'mention', attrs: { id } }, { type: 'text', text: ' ' });
  content.push({ type: 'text', text });
  return { type: 'doc', version: 1, content: [{ type: 'paragraph', content }] };
}

/**
 * Best-effort comment on a work item as the app. The ledger entry is the record; a failed comment is logged, never
 * turned into a failed action. The comment's author is remembered as Threatline's own account, so the gatherer never
 * reads Threatline's comments back as review context.
 */
export async function notify(deps: Pick<CoreDeps, 'jira' | 'state'>, issueId: string, mentions: readonly (string | undefined)[], text: string): Promise<boolean> {
  return postComment(deps, issueId, mentionDoc(mentions, text));
}

/** Posts one comment as the app and remembers its author (Threatline's account). Never throws. */
export async function postComment(deps: Pick<CoreDeps, 'jira' | 'state'>, issueId: string, doc: AdfDoc): Promise<boolean> {
  const r = await deps.jira.comment(issueId, doc).catch(() => null);
  if (!r?.ok) {
    log('notify.comment_failed', { issueId, code: r ? r.error.code : 'threw' });
    return false;
  }
  await rememberOwnAccount(deps.state, r.value.authorAccountId);
  return true;
}

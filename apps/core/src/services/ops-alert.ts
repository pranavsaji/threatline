import type { CoreDeps } from '../deps.js';
import type { AdfDoc, AdfNode } from '../adapters/jira.js';
import { log } from '../adapters/log.js';

export const OPS_CONFIG_KEY = 'config:ops';

/**
 * Comments once per `dedupeKey` on the configured ops work item (`config:ops` = { issueKey, accountIds }), mentioning
 * its admins. Returns false when no ops item is configured, the alert was already sent, or the comment failed.
 */
export async function opsAlert(deps: Pick<CoreDeps, 'state' | 'jira'>, dedupeKey: string, text: string): Promise<boolean> {
  let ops: { issueKey?: unknown; accountIds?: unknown } | undefined;
  try {
    ops = await deps.state.get(OPS_CONFIG_KEY);
    if (await deps.state.get(dedupeKey)) return false;
  } catch (e) {
    log('alert.state_unreadable', { key: dedupeKey.split(':').slice(0, 2).join(':'), message: e instanceof Error ? e.message.slice(0, 120) : 'unknown' });
    return false;
  }
  if (!ops || typeof ops.issueKey !== 'string') return false;
  const ids = Array.isArray(ops.accountIds) ? ops.accountIds.filter((a): a is string => typeof a === 'string').slice(0, 10) : [];
  const content: AdfNode[] = [];
  for (const id of ids) content.push({ type: 'mention', attrs: { id } }, { type: 'text', text: ' ' });
  content.push({ type: 'text', text });
  const adf: AdfDoc = { type: 'doc', version: 1, content: [{ type: 'paragraph', content }] };
  const c = await deps.jira.comment(ops.issueKey, adf);
  if (!c.ok) {
    log('alert.comment_failed', { key: dedupeKey.split(':').slice(0, 2).join(':'), code: c.error.code });
    return false;
  }
  try {
    await deps.state.set(dedupeKey, true);
  } catch {
    // a repeat alert is better than none
  }
  return true;
}

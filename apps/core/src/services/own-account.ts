import type { KvsPort } from '../adapters/kvs-config.js';
import { log } from '../adapters/log.js';

/**
 * Threatline's own Atlassian account (the app user every Threatline comment is written by), learnt from the author of a
 * comment Threatline posted. Only Threatline writes it, and only from Jira's answer to its own POST, so nothing a person
 * writes (a name, a marker in the text) can make a comment count as Threatline's and hide it from review.
 *
 * Used to stop a feedback loop: Threatline's comments are never review context, never part of the context hash (so they
 * never mark a review out of date), and an issue event caused by Threatline never queues a review.
 */
export const OWN_ACCOUNT_KEY = 'app:account-id';

const ACCOUNT = /^[A-Za-z0-9:_-]{1,128}$/;

/** The stored account id, or null when Threatline has not commented yet (or KVS could not be read). */
export async function ownAccountId(state: Pick<KvsPort, 'get'>): Promise<string | null> {
  try {
    const v = await state.get<unknown>(OWN_ACCOUNT_KEY);
    return typeof v === 'string' && ACCOUNT.test(v) ? v : null;
  } catch {
    log('own_account.unreadable', {});
    return null;
  }
}

/** Remembers the author of a comment Threatline just posted. Best effort: written only when it is new or different. */
export async function rememberOwnAccount(state: Pick<KvsPort, 'get' | 'set'>, authorAccountId: string): Promise<void> {
  if (!ACCOUNT.test(authorAccountId)) return;
  try {
    if ((await state.get<unknown>(OWN_ACCOUNT_KEY)) === authorAccountId) return;
    await state.set(OWN_ACCOUNT_KEY, authorAccountId);
  } catch {
    log('own_account.unsaved', {});
  }
}

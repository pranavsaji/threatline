import type { CoreDeps } from '../deps.js';
import { panelRerun } from '../resolvers/panel.js';
import type { ActionPayload } from './common.js';
import { callerOnIssue, issueUrl, parseInput, SCHEMAS, type ActionError } from './schemas.js';

export interface StartReviewResult {
  queued: true;
  issueKey: string;
  /** The revision the queued review will become. */
  nextRevision: number;
  message: string;
}

/**
 * TRIGGER (Agent): queues a fresh review as the caller (who needs edit permission): re-adds the threatline-review label,
 * which starts the Automation re-run, and queues the gather. Rate-limited per person like the panel's Re-run.
 */
export async function startReview(payload: ActionPayload & Record<string, unknown>, deps: CoreDeps): Promise<StartReviewResult | ActionError> {
  const input = parseInput(SCHEMAS.startReview, payload);
  if (!input.ok) return input.error;
  const who = await callerOnIssue(deps, payload, input.value.issueKey, 'edit');
  if (!who.ok) return who.error;
  const latest = await deps.reviews.latest(who.viewer.issueId);
  const r = await panelRerun(deps, who.viewer);
  if ('error' in r) {
    // Threatline's own refusals (not reviewed here, a review still running) are told to the agent as they are.
    if ((r.error === 'validation' || r.error === 'conflict') && r.message) return { error: 'refused', message: r.message };
    return r.error === 'not_found' || r.error === 'rate_limited' ? { error: r.error } : { error: 'unavailable' };
  }
  const nextRevision = (latest.ok && latest.value ? latest.value.revision : 0) + 1;
  return {
    queued: true,
    issueKey: who.issue.key,
    nextRevision,
    message: `Queued review revision ${nextRevision} of ${who.issue.key}. It usually takes a minute or two; the result appears in the Threatline panel: ${await issueUrl(deps, who.issue.key)}`,
  };
}

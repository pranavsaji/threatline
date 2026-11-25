import { MIGRATIONS } from '@threatline/db';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { SCHEMA_VERSION_KEY, trace } from '../consumers/review-consumer.js';
import { refreshVerdict } from '../services/verdict-service.js';
import { commentOnSettle } from '../services/verdict-comment.js';

const LATEST_SCHEMA = Math.max(...MIGRATIONS.map((m) => m.version));

/**
 * Every five minutes: catch up schema migrations, and time out reviews whose agent runs did not all arrive within the
 * agent timeout of the review starting. The deadline counts from when the review was created, not from its last run:
 * counted from the last run, a review whose third run never came waited the timeout again after its second (seen live:
 * 23 minutes for a 15-minute timeout). What did arrive is assembled at once (2 of 3 valid runs settle it as ready).
 */
export async function sweep(deps: CoreDeps): Promise<void> {
  let version = 0;
  try {
    version = Number((await deps.state.get<number>(SCHEMA_VERSION_KEY)) ?? 0);
  } catch (e) {
    log('sweep.schema_version_unreadable', { message: e instanceof Error ? e.message.slice(0, 120) : 'unknown' });
    version = 0;
  }
  if (version < LATEST_SCHEMA) {
    const m = await deps.queue.push([{ kind: 'migrate' }]);
    if (!m.ok) log('sweep.migrate_push_failed', { code: m.error.code });
  }

  const policy = await deps.config.site();
  if (!policy.ok) {
    log('sweep.failed', { step: 'policy', code: policy.error.code });
    return;
  }
  const now = deps.clock.now();
  const cutoff = new Date(now.getTime() - policy.value.agentTimeoutMinutes * 60_000).toISOString();
  const stuck = await deps.reviews.byStatus('awaiting_agent', cutoff);
  if (!stuck.ok) {
    log('sweep.failed', { step: 'list', code: stuck.error.code });
    return;
  }
  for (const r of stuck.value) {
    // Compare-and-set: a review that settled after it was listed (its last run just arrived) is left as it is.
    const u = await deps.reviews.updateWhere(r.id, { status: 'awaiting_agent' }, { status: 'agent_timeout', updatedAt: now.toISOString() });
    if (!u.ok) {
      log('sweep.timeout_write_failed', { reviewId: r.id, code: u.error.code });
      continue;
    }
    if (!u.value) continue;
    await trace(deps, r.id, 'agent', 'failed', 'agent_timeout');
    // M5: assemble what did arrive (final mode), so a 2-of-3 review is settled instead of staying blocked.
    const samples = await deps.reviews.samples(r.id);
    const arrived = samples.ok ? samples.value.length : 0;
    log('review.agent_timeout', {
      reviewId: r.id, received: r.samplesReceived, arrived, expected: r.samplesExpected,
      minutes: Math.round((now.getTime() - Date.parse(r.createdAt)) / 60_000), assembling: arrived > 0,
    });
    const v = await refreshVerdict(deps, r.issueId);
    if (!v.ok) log('sweep.verdict_failed', { reviewId: r.id, code: v.error.code });
    // Nothing arrived, so the timeout is final: comment it. With runs to assemble, the assembly comments instead.
    if (arrived === 0 && v.ok) await commentOnSettle(deps, r.id);
    const jobs = arrived > 0 ? [{ kind: 'assemble' as const, reviewId: r.id }] : [];
    const q = await deps.queue.push([...jobs, { kind: 'propagate', issueId: r.issueId }]);
    if (!q.ok) {
      log('sweep.assemble_push_failed', { reviewId: r.id, code: q.error.code });
      // Without its assembly the runs that did arrive would stay unused: put the review back so the next sweep (five
      // minutes on) times it out and queues the assembly again.
      if (arrived > 0) await deps.reviews.updateWhere(r.id, { status: 'agent_timeout' }, { status: 'awaiting_agent' });
    }
  }
}

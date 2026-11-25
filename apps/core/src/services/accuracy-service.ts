import { ACCURACY_EVENTS, ACCURACY_WINDOW_DAYS, accuracySummary, type Accuracy, type ReviewThreatRow } from '@threatline/core';
import { ok, type Result, type Severity, type Threat } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { ledgerRowsFor, type PostureScope } from './posture-service.js';

/** Older reviews a champion confirmed as a whole, read one by one: at most this many per call (the rest are skipped). */
export const ACCURACY_MAX_CONFIRMED_REVIEWS = 25;

/**
 * "How accurate is Threatline here?" (docs/ACCURACY.md) over a posture scope: the same work items posture counts, so
 * it never counts a work item the viewer cannot browse. Bounded reads on top of posture's: the accuracy ledger events
 * of these work items (100 per query), the threats of their latest reviews (25 work items per query), and the threats of
 * at most ACCURACY_MAX_CONFIRMED_REVIEWS older reviews confirmed as a whole in the window.
 */
export async function accuracyFor(deps: CoreDeps, scope: PostureScope, blockAtOrAbove: Severity): Promise<Result<Accuracy>> {
  const ids = scope.items.map((x) => x.issue.id);
  const [rows, latest] = await Promise.all([ledgerRowsFor(deps, ACCURACY_EVENTS, ids), ids.length ? deps.reviews.latestThreats(ids) : Promise.resolve(ok<ReviewThreatRow[]>([]))]);
  if (!rows.ok) return rows;
  if (!latest.ok) return latest;

  const now = deps.clock.now();
  const since = now.getTime() - ACCURACY_WINDOW_DAYS * 86_400_000;
  const allowed = new Set(ids);
  const latestIds = new Set(latest.value.map((x) => x.review.id));
  const older = [
    ...new Set(
      rows.value
        .filter((r) => r.eventType === 'review.champion_confirmed' && allowed.has(String(r.payload.issueId)) && Date.parse(r.createdAt) >= since)
        .map((r) => String(r.payload.reviewId))
        .filter((id) => !latestIds.has(id)),
    ),
  ].slice(0, ACCURACY_MAX_CONFIRMED_REVIEWS);
  const confirmedThreats = new Map<string, Threat[]>();
  const read = await Promise.all(older.map((id) => deps.reviews.threats(id)));
  for (const [n, r] of read.entries()) {
    if (!r.ok) return r;
    confirmedThreats.set(older[n]!, r.value);
  }

  return ok(
    accuracySummary({
      now,
      blockAtOrAbove,
      items: scope.items.map((x) => ({ issueId: x.issue.id, project: x.issue.project.key, requirements: x.requirements })),
      ledger: [...rows.value, ...scope.acceptanceRows],
      latest: latest.value,
      confirmedThreats,
    }),
  );
}

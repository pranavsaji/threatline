import { Queue } from '@forge/events';
import { appError, err, ok } from '@threatline/shared';
import type { JobQueue } from '../deps.js';
import type { ReviewJob } from '../jobs/types.js';

export const JOB_QUEUE_KEY = 'threatline-jobs';
const MAX_PER_PUSH = 50;

const issueOfReview = (reviewId: string): string | null => /^rev_(\d{1,18})_\d+$/.exec(reviewId)?.[1] ?? null;

/** Jobs for one work item run one at a time (Forge concurrency key), so duplicate events cannot race a revision. */
export function concurrencyKeyOf(job: ReviewJob): string | null {
  if (job.kind === 'gather' || job.kind === 'propagate' || job.kind === 'verdict' || job.kind === 'publish') return `issue-${job.issueId}`;
  // One fan-out per incident at a time, so a created event and a label event for it cannot both queue its re-reviews.
  if (job.kind === 'incident') return `incident-${job.issueId}`;
  if (job.kind === 'assemble') {
    const issue = issueOfReview(job.reviewId);
    return issue ? `issue-${issue}` : null;
  }
  if (job.kind === 'engine') {
    const issue = issueOfReview(job.reviewId);
    return issue ? `engine-${issue}` : null;
  }
  return 'migrate';
}

/**
 * Model calls of one review run side by side (its three analyses at once), never more than that per work item, and
 * reviews of different work items do not wait for each other. Each call reserves its tokens atomically and stores its
 * result insert-only, so parallel calls cannot overshoot the budget or lose a sample.
 */
export const ENGINE_CONCURRENCY = 3;
const limitOf = (key: string) => (key.startsWith('engine-') ? ENGINE_CONCURRENCY : 1);

export function forgeQueue(queue: Pick<Queue, 'push'> = new Queue({ key: JOB_QUEUE_KEY })): JobQueue {
  return {
    async push(jobs) {
      try {
        for (let i = 0; i < jobs.length; i += MAX_PER_PUSH) {
          await queue.push(
            jobs.slice(i, i + MAX_PER_PUSH).map((job) => {
              const key = concurrencyKeyOf(job);
              return { body: job as unknown as Record<string, unknown>, ...(key ? { concurrency: { key, limit: limitOf(key) } } : {}) };
            }),
          );
        }
        return ok(undefined);
      } catch (e) {
        return err(appError('upstream', `queue: ${e instanceof Error ? e.message : String(e)}`));
      }
    },
  };
}

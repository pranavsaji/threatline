import { InvocationError, InvocationErrorCode } from '@forge/events';
import { log } from '../adapters/log.js';

/** A queue job that fails transiently is run again at most this many times. */
export const MAX_JOB_RETRIES = 3;
/** Codes a later attempt can fix (a brief Jira, storage or Forge LLM outage, a rate limit). */
export const isTransientCode = (code: string): boolean => code === 'upstream' || code === 'timeout';

/**
 * Transient platform failures (Jira/KVS/SQL/Forge LLMs briefly unavailable, e.g. just after install or under a rate
 * limit) are retried a few times, a growing delay apart with jitter (60-90 s, then 120-150 s, then 180-210 s), so
 * reviews that failed together do not all come back in the same second.
 * `retryData` is always set: the Forge runtime measures its size (4KB cap) and threw a TypeError on `undefined`,
 * which silently dropped every retry in production.
 */
export function retryDecision(
  r: { ok: true } | { ok: false; error: { code: string } },
  retryCount: number,
  random: () => number = Math.random,
): InvocationError | undefined {
  if (r.ok || !isTransientCode(r.error.code)) return undefined;
  if (retryCount >= MAX_JOB_RETRIES) {
    log('job.retries_exhausted', { code: r.error.code, attempts: retryCount + 1 });
    return undefined;
  }
  const retryAfter = 60 * (retryCount + 1) + Math.floor(random() * 30);
  log('job.retry', { code: r.error.code, attempt: retryCount + 1, retryAfter });
  return new InvocationError({ retryAfter, retryReason: InvocationErrorCode.FUNCTION_RETRY_REQUEST, retryData: { code: r.error.code, attempt: retryCount + 1 } });
}

import { InvocationError, InvocationErrorCode } from '@forge/events';

/**
 * Transient platform failures (Jira/KVS/SQL briefly unavailable, e.g. just after install) are retried a few times.
 * `retryData` is always set: the Forge runtime measures its size (4KB cap) and threw a TypeError on `undefined`,
 * which silently dropped every retry in production.
 */
export function retryDecision(r: { ok: true } | { ok: false; error: { code: string } }, retryCount: number): InvocationError | undefined {
  if (r.ok || (r.error.code !== 'upstream' && r.error.code !== 'timeout') || retryCount >= 3) return undefined;
  return new InvocationError({ retryAfter: 60, retryReason: InvocationErrorCode.FUNCTION_RETRY_REQUEST, retryData: { code: r.error.code, attempt: retryCount + 1 } });
}

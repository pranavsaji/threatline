import type { AppError } from '@threatline/shared';
import { log } from '../adapters/log.js';

export type ApiErrorCode = 'not_found' | 'unavailable' | 'rate_limited' | 'validation' | 'forbidden' | 'conflict';
/** What a resolver returns instead of data. `message` is shown to the person, so it never carries internal detail. */
export type ApiError = { error: ApiErrorCode; message?: string };

const SHOWN: ReadonlySet<string> = new Set(['validation', 'forbidden', 'conflict']);

const PLAIN: Record<'validation' | 'forbidden' | 'conflict', (service: string) => string> = {
  forbidden: (s) =>
    s === 'Confluence'
      ? 'Confluence refused this (permission). Ask a Confluence admin to check that Threatline can view and edit pages in this space.'
      : 'Jira refused this (permission). Ask a Jira admin to check that Threatline can browse, edit and create sub-tasks in this project.',
  validation: (s) =>
    `${s} did not accept the change (for example a required field or a field the screen does not allow). Ask a ${s} admin to check the ${s === 'Confluence' ? 'space' : "project's"} configuration.`,
  conflict: (s) => `It changed in ${s} meanwhile. Reload and try again.`,
};

/**
 * The message a person may see for a refusal. Threatline's own messages pass through; a Jira or Confluence refusal
 * (tagged by http.ts) carries the method, path and upstream text, so that goes to the logs and a plain message is shown.
 */
export function shownMessage(e: AppError): string {
  const service = e.details?.upstream;
  if (service !== 'Jira' && service !== 'Confluence') return e.message;
  const status = typeof e.details?.status === 'number' ? e.details.status : 0;
  log('upstream.refused', { service, code: e.code, status, detail: e.message.slice(0, 500) });
  const plain = PLAIN[e.code as keyof typeof PLAIN] as ((s: string) => string) | undefined;
  return plain ? plain(service) : `${service} could not do this right now. Try again.`;
}

export function apiError(e: AppError): ApiError {
  if (e.code === 'not_found') return { error: 'not_found' };
  if (e.code === 'budget') return { error: 'rate_limited', message: e.message };
  if (SHOWN.has(e.code)) return { error: e.code as ApiErrorCode, message: shownMessage(e) };
  return { error: 'unavailable', message: unavailableMessage(e) };
}

/**
 * Which kind of "could not do it" this is, so a person can tell a busy Jira from a fault that a retry will not fix.
 * The detail goes to the logs; the person sees the kind and the error code only.
 */
function unavailableMessage(e: AppError): string {
  const service = e.details?.upstream;
  if (e.code === 'timeout') return 'This took too long to answer. Try again in a minute.';
  if (e.code === 'upstream' && (service === 'Jira' || service === 'Confluence')) return `${service} did not answer just now. Try again in a minute.`;
  log('resolver.failed', { code: e.code, detail: e.message.slice(0, 500) });
  return `Threatline hit an error it could not recover from (${e.code}). If Threatline was installed in the last few minutes, wait a minute and try again; if it keeps failing, an admin can find the cause in the app logs.`;
}

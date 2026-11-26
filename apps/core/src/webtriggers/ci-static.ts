import type { WebTriggerResponseLike } from './ci-verify.js';

/**
 * Runs on Atlassian: the CI web trigger is `static`, so it can only answer with one of these fixed outputs (declared
 * verbatim in manifest.yml; a test keeps the two in step). Nothing from a work item, a requirement or the request is
 * ever sent back: the detail of what CI verified is in the work item's Threatline panel and the risk ledger.
 */
export const CI_STATIC_OUTPUTS = [
  { key: 'recorded-pass', statusCode: 200, body: '{"result":"recorded","verdict":"pass","message":"Threatline recorded this CI run. Nothing blocks Done for this work item now."}' },
  { key: 'recorded-warn', statusCode: 200, body: '{"result":"recorded","verdict":"warn","message":"Threatline recorded this CI run. The work item is in warn-only mode: Done warns but is not blocked."}' },
  { key: 'recorded-block', statusCode: 200, body: '{"result":"recorded","verdict":"block","message":"Threatline recorded this CI run. Security requirements still block Done: see the work item\'s Threatline panel for which ones."}' },
  { key: 'recorded-checking', statusCode: 200, body: '{"result":"recorded","verdict":"block","fixCheck":"checking","message":"Threatline recorded this CI run and is checking whether the change fixes the security requirements (usually within two minutes). Done and merge wait for the check: see the work item\'s Threatline panel."}' },
  { key: 'bad-request', statusCode: 400, body: '{"error":"validation","message":"The report is not valid: send issueKey, repo, a 40-character commitSha, an https runUrl and results, and optionally a diff of at most 200,000 characters and an https prUrl (see docs/CI_VERIFICATION.md)."}' },
  { key: 'unauthorized', statusCode: 401, body: '{"error":"unauthorized","message":"Send Authorization: Bearer <CI token> (Threatline admin, CI verification)."}' },
  { key: 'forbidden', statusCode: 403, body: '{"error":"forbidden","message":"This CI token cannot report for that project, or Threatline is not on for it."}' },
  { key: 'not-found', statusCode: 404, body: '{"error":"not_found","message":"That work item was not found."}' },
  { key: 'method', statusCode: 405, body: '{"error":"method","message":"POST a JSON report."}' },
  { key: 'too-large', statusCode: 413, body: '{"error":"too_large","message":"The report is larger than 256 KB. Send only tests whose names carry a requirement id, and a diff of at most 200,000 characters."}' },
  { key: 'rate-limited', statusCode: 429, body: '{"error":"rate_limited","message":"A CI token can send 120 reports an hour. Try again after the hour."}' },
  { key: 'unavailable', statusCode: 503, body: '{"error":"unavailable","message":"Threatline could not record this report; nothing unrecorded was verified. Retry the job."}' },
] as const;

export type CiStaticKey = (typeof CI_STATIC_OUTPUTS)[number]['key'];

const BY_STATUS: Record<number, CiStaticKey> = { 400: 'bad-request', 401: 'unauthorized', 403: 'forbidden', 404: 'not-found', 405: 'method', 413: 'too-large', 429: 'rate-limited' };

/** Picks the fixed output for a full answer. Anything unexpected is `unavailable` (never a success). */
export function toStaticOutput(res: WebTriggerResponseLike): { outputKey: CiStaticKey } {
  if (res.statusCode === 200) {
    let verdict: unknown;
    let fixCheck: unknown;
    try {
      ({ verdict, fixCheck } = JSON.parse(res.body) as { verdict?: unknown; fixCheck?: unknown });
    } catch {
      verdict = undefined;
    }
    if (verdict === 'pass') return { outputKey: 'recorded-pass' };
    if (verdict === 'warn') return { outputKey: 'recorded-warn' };
    if (verdict === 'block') return { outputKey: fixCheck === 'checking' ? 'recorded-checking' : 'recorded-block' };
    return { outputKey: 'unavailable' };
  }
  return { outputKey: BY_STATUS[res.statusCode] ?? 'unavailable' };
}

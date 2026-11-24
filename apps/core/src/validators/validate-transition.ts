import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { readVerdict, refreshVerdict } from '../services/verdict-service.js';
import { VALIDATOR_SEEN_KEY } from '../resolvers/admin.js';
import { isLicensed } from '../services/license.js';

/** Remembers (once a day per project) that the gate ran, for the admin setup checklist. Best effort. */
async function markSeen(deps: CoreDeps, issueKey: string | undefined): Promise<void> {
  const project = issueKey?.split('-')[0];
  if (!project || !/^[A-Z][A-Z0-9_]{0,254}$/.test(project)) return;
  try {
    const now = deps.clock.now().toISOString();
    const seen = ((await deps.state.get<Record<string, string>>(VALIDATOR_SEEN_KEY)) ?? {}) as Record<string, string>;
    if (seen[project]?.slice(0, 10) === now.slice(0, 10)) return;
    await deps.state.set(VALIDATOR_SEEN_KEY, { ...seen, [project]: now });
  } catch {
    // the checklist is informational
  }
}

/** Shown when a work item still has no Threatline verdict after computing one (EN-2: missing reviews block). */
export const NOT_REVIEWED_MESSAGE = 'Threatline has not reviewed this work item yet. Open the Threatline panel and click Run review.';
const UNREADABLE = 'Threatline could not read the security verdict for this work item, so the transition is blocked. Try again in a minute.';
const BLOCKED = 'Threatline blocks this transition. Open the Threatline panel on this work item to see why.';

type Outcome = { result: boolean; errorMessage?: string };
const blocked = (errorMessage: string): Outcome => ({ result: false, errorMessage });

/**
 * The Done gate. Reads the verdict from app storage, which only Threatline can write — never the `threatline.verdict` issue
 * property, which anyone who can edit the work item can overwrite. No stored verdict yet: compute it once. Fails closed:
 * only `pass` and `warn` let the transition through; every error or unknown value blocks with a message. The one
 * exception: with an inactive Paid via Atlassian license the gate is open, so lapsed billing never traps work.
 */
export async function validateTransition(deps: CoreDeps, args: { issue?: { key?: string; id?: string } }): Promise<Outcome> {
  let id = args.issue?.id;
  await markSeen(deps, args.issue?.key);
  // Paid via Atlassian: an inactive license never traps a customer's work behind the gate (docs/LICENSING.md).
  if (!isLicensed(await deps.license.state())) {
    log('license.gate_open', { project: args.issue?.key?.split('-')[0]?.slice(0, 64) ?? '' });
    return { result: true };
  }
  if (!id && args.issue?.key) {
    const issue = await deps.jira.issue(args.issue.key);
    if (!issue.ok) return blocked(UNREADABLE);
    id = issue.value.id;
  }
  if (!id || !/^\d{1,18}$/.test(id)) return blocked(UNREADABLE);

  // readVerdict recomputes a warn-only or break-glass verdict whose window has ended, so neither stays open.
  const read = async (): Promise<{ ok: true; value: unknown } | { ok: false }> => {
    const r = await readVerdict(deps, id);
    return r.ok ? { ok: true, value: r.value } : { ok: false };
  };
  let v = await read();
  if (!v.ok) return blocked(UNREADABLE);
  // Verdicts stored before the gate message existed are recomputed once so the error can say why.
  const stale = (x: unknown) => typeof x === 'object' && x !== null && (x as { state?: unknown }).state === 'block' && typeof (x as { message?: unknown }).message !== 'string';
  if (v.value === undefined || v.value === null || stale(v.value)) {
    const fresh = await refreshVerdict(deps, id);
    if (!fresh.ok) {
      log('validator.refresh_failed', { code: fresh.error.code });
      return blocked(UNREADABLE);
    }
    v = await read();
    if (!v.ok) return blocked(UNREADABLE);
    if (v.value === undefined || v.value === null) return blocked(NOT_REVIEWED_MESSAGE);
  }
  const verdict = v.value as { state?: unknown; message?: unknown };
  if (typeof verdict !== 'object') return blocked(BLOCKED);
  if (verdict.state === 'pass' || verdict.state === 'warn') return { result: true };
  return blocked(typeof verdict.message === 'string' && verdict.message ? verdict.message : BLOCKED);
}

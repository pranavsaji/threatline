import type { ReviewStatus } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { expireAcceptances } from '../services/acceptance-service.js';
import { OPS_CONFIG_KEY, opsAlert } from '../services/ops-alert.js';
import { expireRules } from '../services/suppression-service.js';

export { OPS_CONFIG_KEY };
const STATUSES: ReviewStatus[] = ['queued', 'gathering', 'awaiting_agent', 'modeling', 'ready', 'failed', 'agent_timeout'];
const FAILURE_RATE = 0.2;
const WINDOW_LIMIT = 500;

/**
 * Hourly: expire overdue risk acceptances (RL-5) and team suppression rules; then, if more than 20% of the reviews created in the last hour failed
 * or timed out, comment once on the configured ops work item, mentioning its admins.
 */
export async function hourly(deps: CoreDeps): Promise<void> {
  const expired = await expireAcceptances(deps, deps.clock.now());
  if (!expired.ok) log('hourly.expiry_failed', { code: expired.error.code });
  else if (expired.value.expired > 0) log('hourly.expired', { acceptances: expired.value.expired });
  const rules = await expireRules(deps, deps.clock.now()).catch(() => null);
  if (!rules || !rules.ok) log('hourly.suppression_expiry_failed', { code: rules ? rules.error.code : 'internal' });
  else if (rules.value.expired > 0) log('hourly.expired', { suppressions: rules.value.expired });
  await failRateAlert(deps);
}

async function failRateAlert(deps: CoreDeps): Promise<void> {
  let ops: { issueKey?: unknown; accountIds?: unknown } | undefined;
  try {
    ops = await deps.state.get(OPS_CONFIG_KEY);
  } catch {
    ops = undefined;
  }
  if (!ops || typeof ops.issueKey !== 'string') return;
  const now = deps.clock.now();
  const hour = now.toISOString().slice(0, 13);
  const alertKey = `alert:failrate:${hour}`;
  try {
    if (await deps.state.get(alertKey)) return;
  } catch {
    return;
  }
  const since = new Date(now.getTime() - 3_600_000).toISOString();
  let total = 0;
  let bad = 0;
  let silent = 0;
  for (const s of STATUSES) {
    // Created in the last hour, so updated in it too: the newest rows of each status (indexed on status, updated_at).
    const r = await deps.reviews.updatedSince(s, since, WINDOW_LIMIT);
    if (!r.ok) return;
    const recent = r.value.filter((x) => x.createdAt >= since);
    total += recent.length;
    if (s === 'failed' || s === 'agent_timeout') bad += recent.length;
    if (s === 'agent_timeout') silent += recent.filter((x) => x.samplesReceived === 0).length;
  }
  if (total === 0 || bad / total <= FAILURE_RATE) return;
  const rejected = await deps.ledger.latestOfTypes(['review.sample_rejected'], 500);
  const pol = await deps.config.site();
  const engine = pol.ok && pol.value.reviewMode === 'engine';
  const refused = rejected.ok ? rejected.value.filter((r) => r.createdAt >= since).length : 0;

  const sent = await opsAlert(
    deps,
    alertKey,
    `Threatline: ${bad} of ${total} security reviews in the last hour failed or timed out. Work items stay blocked until they are re-run. Check the Threatline admin page (Recent runs, Budgets) and, in Rovo agent mode, the site's Rovo credits.` +
      (silent > 0 && engine
        ? ` ${silent} of them got no Threatline Engine run at all: Forge LLMs did not answer. Check the app's Forge logs (llm.failed) and the developer console usage; until it recovers, choose Threatline admin → Review mode → Rule-based checks only.`
        : silent > 0
        ? ` ${silent} of them got no agent run at all, so Jira Automation did not run the Threatline agent: open Project settings → Automation → the Threatline rules → Audit log. If it says the agent is deactivated (this can happen after a Threatline update), re-select Threatline in each Use agent step and save. If this site has no Rovo, choose Threatline admin → Review mode → Rule-based checks only.`
        : '') +
      (refused > 0
        ? ` ${refused} agent ${refused === 1 ? 'run was' : 'runs were'} refused because the account is not a review author: check Threatline admin → Review mode → Who can submit AI review runs (it should be the Automation rule owner).`
        : ''),
  );
  if (!sent) return;
  log('alert.failrate', { bad, total });
}

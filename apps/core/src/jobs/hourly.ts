import type { ReviewStatus } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';
import { log } from '../adapters/log.js';
import { expireAcceptances } from '../services/acceptance-service.js';
import { CREDITS_PAUSE_HOURS, monthOf, pauseReasons } from '../services/budget.js';
import { OPS_CONFIG_KEY, opsAlert } from '../services/ops-alert.js';
import { expireRules } from '../services/suppression-service.js';

export { OPS_CONFIG_KEY };
const STATUSES: ReviewStatus[] = ['queued', 'gathering', 'awaiting_agent', 'modeling', 'ready', 'failed', 'agent_timeout'];
const FAILURE_RATE = 0.2;
const WINDOW_LIMIT = 500;
/** At this share of the month's review budget, the ops work item is warned once, before reviews pause. */
const BUDGET_WARNING = 0.8;

const messageOf = (e: unknown) => (e instanceof Error ? e.message.slice(0, 120) : 'unknown');

/**
 * Hourly: expire overdue risk acceptances (RL-5) and team suppression rules; then the ops alerts. Each is logged (so
 * `forge logs` shows it for every site) and, when an ops work item is configured, commented once on it:
 * - more than 20% of the reviews created in the last hour failed, timed out, or settled on only some of their runs;
 * - the month's review budget is nearly used (80%) or used up, so new reviews pause;
 * - Rovo agent reviews are paused because the site looks out of Rovo credits.
 */
export async function hourly(deps: CoreDeps): Promise<void> {
  const expired = await expireAcceptances(deps, deps.clock.now());
  if (!expired.ok) log('hourly.expiry_failed', { code: expired.error.code });
  else if (expired.value.expired > 0) log('hourly.expired', { acceptances: expired.value.expired });
  const rules = await expireRules(deps, deps.clock.now()).catch(() => null);
  if (!rules || !rules.ok) log('hourly.suppression_expiry_failed', { code: rules ? rules.error.code : 'internal' });
  else if (rules.value.expired > 0) log('hourly.expired', { suppressions: rules.value.expired });
  await failRateAlert(deps).catch((e: unknown) => log('alert.failrate_failed', { code: 'internal', message: messageOf(e) }));
  await budgetAlert(deps).catch((e: unknown) => log('alert.budget_failed', { code: 'internal', message: messageOf(e) }));
}

async function failRateAlert(deps: CoreDeps): Promise<void> {
  const now = deps.clock.now();
  const alertKey = `alert:failrate:${now.toISOString().slice(0, 13)}`;
  const since = new Date(now.getTime() - 3_600_000).toISOString();
  let total = 0;
  let bad = 0;
  let silent = 0;
  let partial = 0;
  let paused = 0;
  for (const s of STATUSES) {
    // Created in the last hour, so updated in it too: the newest rows of each status (indexed on status, updated_at).
    const r = await deps.reviews.updatedSince(s, since, WINDOW_LIMIT);
    if (!r.ok) {
      log('alert.failrate_failed', { status: s, code: r.error.code });
      return;
    }
    const recent = r.value.filter((x) => x.createdAt >= since);
    total += recent.length;
    if (s === 'failed' || s === 'agent_timeout') bad += recent.length;
    if (s === 'failed') paused += recent.filter((x) => x.failureReason === 'budget').length;
    if (s === 'agent_timeout') silent += recent.filter((x) => x.samplesReceived === 0).length;
    // Settled by the sweeper on what arrived (a majority of valid runs), after the rest never came: slow, not failed.
    if (s === 'ready') partial += recent.filter((x) => x.samplesExpected > 0 && x.samplesReceived < x.samplesExpected).length;
  }
  if (total === 0 || (bad + partial) / total <= FAILURE_RATE) return;
  const rejected = await deps.ledger.latestOfTypes(['review.sample_rejected'], 500);
  const pol = await deps.config.site();
  const engine = pol.ok && pol.value.reviewMode === 'engine';
  const refused = rejected.ok ? rejected.value.filter((r) => r.createdAt >= since).length : 0;
  const timeout = pol.ok ? pol.value.agentTimeoutMinutes : 15;

  const sent = await opsAlert(
    deps,
    alertKey,
    `Threatline: ${bad} of ${total} security reviews in the last hour failed or timed out` +
      (partial > 0 ? `, and ${partial} more ${partial === 1 ? 'was' : 'were'} settled on only some of ${partial === 1 ? 'its' : 'their'} runs after the ${timeout}-minute agent timeout` : '') +
      `. Work items stay blocked until failed reviews are re-run. Check the Threatline admin page (Recent runs, Budgets) and, in Rovo agent mode, the site's Rovo credits.` +
      (paused > 0 ? ` ${paused} of them ${paused === 1 ? 'was' : 'were'} paused at this month's review budget (Budgets).` : '') +
      (silent > 0 && engine
        ? ` ${silent} of them got no Threatline Engine run at all: Forge LLMs did not answer. Check the app's Forge logs (llm.failed) and the developer console usage; until it recovers, choose Threatline admin → Review mode → Rule-based checks only.`
        : silent > 0
        ? ` ${silent} of them got no agent run at all, so Jira Automation did not run the Threatline agent: open Project settings → Automation → the Threatline rules → Audit log. If it says the agent is deactivated (this can happen after a Threatline update), re-select Threatline in each Use agent step and save. If this site has no Rovo, choose Threatline admin → Review mode → Rule-based checks only.`
        : '') +
      (refused > 0
        ? ` ${refused} agent ${refused === 1 ? 'run was' : 'runs were'} refused because the account is not a review author: check Threatline admin → Review mode → Who can submit AI review runs (it should be the Automation rule owner).`
        : ''),
  );
  log('alert.failrate', { bad, partial, total, silent, paused, refused, engine, notified: sent });
}

async function budgetAlert(deps: CoreDeps): Promise<void> {
  const policy = await deps.config.site();
  if (!policy.ok) {
    log('alert.budget_failed', { step: 'policy', code: policy.error.code });
    return;
  }
  const now = deps.clock.now();
  const month = monthOf(now);
  const [usage, reasons] = await Promise.all([deps.usage.get(month), pauseReasons(deps, policy.value, now)]);
  if (!usage.ok || !reasons.ok) {
    log('alert.budget_failed', { step: 'usage', code: !usage.ok ? usage.error.code : !reasons.ok ? reasons.error.code : 'internal' });
    return;
  }
  const used = usage.value.reviews;
  const cap = policy.value.budget.reviewsPerMonth;
  if (reasons.value.budget) {
    const notified = await opsAlert(
      deps,
      `alert:budget:${month}`,
      `Threatline: this site has used its ${cap} AI security reviews for ${month}. New reviews are paused, and their work items stay blocked until a champion confirms or the review is re-run. Raise "Reviews per month" on the Threatline admin page (Budgets), or wait for next month. (Threatline's developer may also set a ceiling the admin page cannot go above.)`,
    );
    log('alert.budget', { level: 'reached', used, cap, notified });
  } else if (cap > 0 && used >= Math.ceil(cap * BUDGET_WARNING)) {
    const notified = await opsAlert(
      deps,
      `alert:budget-warning:${month}`,
      `Threatline: this site has used ${used} of its ${cap} AI security reviews for ${month}. At ${cap}, new reviews pause until next month. Raise "Reviews per month" on the Threatline admin page (Budgets) if more are needed.`,
    );
    log('alert.budget', { level: 'warning', used, cap, notified });
  }
  if (reasons.value.credits) {
    const notified = await opsAlert(
      deps,
      `alert:credits:${now.toISOString().slice(0, 10)}`,
      `Threatline: the last three Rovo agent runs came back empty, so this site looks out of Rovo credits and new reviews are paused (for up to ${CREDITS_PAUSE_HOURS} hours after the last run). Check the site's Rovo usage in Atlassian Administration, or choose Threatline admin → Review mode → Threatline Engine or Rule-based checks only.`,
    );
    log('alert.credits_paused', { notified });
  }
}

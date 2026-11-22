import type { PanelDto } from '../types.js';

export type PanelState = 'not_reviewed' | 'in_progress' | 'ready' | 'failed' | 'timeout' | 'budget';

export interface PanelView {
  state: PanelState;
  stale: boolean;
  partial: boolean;
  injection: boolean;
  /** Ready, but Threatline Engine's verifier has not run yet: the threats shown may still change. */
  verifying: boolean;
  steps: Array<{ label: string; done: boolean; current: boolean }>;
}

const IN_PROGRESS = new Set(['queued', 'gathering', 'awaiting_agent', 'modeling']);


/** One place that turns the DTO into what the panel shows, so every state is testable without rendering. */
export function viewOf(dto: PanelDto): PanelView {
  const r = dto.review;
  const reasons = dto.verdict?.reasons ?? [];
  const injection = dto.facts.some((f) => f.injectionSuspected);
  const stale = reasons.some((x) => x.code === 'review_stale');
  if (!r) return { state: 'not_reviewed', stale: false, partial: false, injection, verifying: false, steps: [] };

  let state: PanelState = 'ready';
  // A review that failed at the budget is only shown as paused while the gate still says so: once reviews resume, the
  // gate asks for a re-run, so the panel offers one instead of a champion confirmation that would be refused.
  const pausedNow = !dto.verdict || reasons.some((x) => x.code === 'budget_paused');
  if (r.status === 'failed') state = r.failureReason === 'budget' && pausedNow ? 'budget' : 'failed';
  else if (r.status === 'agent_timeout') state = 'timeout';
  else if (IN_PROGRESS.has(r.status)) state = 'in_progress';

  const { received, expected } = dto.samples;
  const steps: PanelView['steps'] = [{ label: 'Context gathered', done: true, current: false }];
  for (let n = 1; n <= expected; n++) steps.push({ label: `Agent run ${n} of ${expected}`, done: received >= n, current: false });
  steps.push({ label: 'Scored', done: r.status === 'ready', current: false });
  const firstOpen = steps.findIndex((s) => !s.done);
  if (state === 'in_progress' && firstOpen >= 0) steps[firstOpen]!.current = true;
  return { state, stale, partial: r.partial, injection, verifying: state === 'ready' && dto.verifying === true, steps };
}

/**
 * Polling cadence: every 3 s while a review is running, while the Engine's verifier has still to run on a ready review
 * (it may dismiss threats, so the panel shows the verified list without a refresh), or while a re-run the viewer just
 * started has not shown up yet (a queued job creates the new revision, so the first reload after the re-run still
 * returns the old review).
 */
export const pollMs = (v: PanelView, awaitingRerun = false): number | null => (v.state === 'in_progress' || v.verifying || awaitingRerun ? 3000 : null);

/** What the panel showed when a re-run was started, so it can tell when the new revision arrives. */
export interface RerunWait {
  reviewId: string | null;
  revision: number;
  status: string | null;
  since: number;
}

/** How long the panel keeps checking for a re-run before it suggests refreshing. */
export const RERUN_WAIT_MS = 120_000;

export const rerunWaitOf = (dto: PanelDto | null, now: number): RerunWait => ({
  reviewId: dto?.review?.id ?? null,
  revision: dto?.review?.revision ?? 0,
  status: dto?.review?.status ?? null,
  since: now,
});

/** The re-run has landed once the latest review is a newer revision, a different review, or has moved on. */
export const rerunLanded = (w: RerunWait, dto: PanelDto): boolean =>
  dto.review !== null && (dto.review.revision > w.revision || dto.review.id !== w.reviewId || dto.review.status !== w.status);

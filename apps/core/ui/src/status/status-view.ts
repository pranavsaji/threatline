import type { StatusDto } from '../types.js';
import { utc } from '../text.js';
import { OVERRIDDEN, VERDICT } from '../panel/verdict-labels.js';

export type StatusKind = 'license' | 'reviewing' | 'not_reviewed' | 'overridden' | 'pass' | 'block' | 'warn';

/** What the context column shows: a lozenge (icon and words, never colour alone), an open count, and one line. */
export interface StatusView {
  kind: StatusKind;
  /** Decorative (hidden from screen readers): the label carries the meaning. */
  icon: string | null;
  label: string;
  appearance: 'default' | 'inprogress' | 'success' | 'removed' | 'moved';
  /** "2 open": what still blocks Done (open requirements, threats awaiting a champion), when the gate is not passing. */
  open: string | null;
  /** The top reason, or what the state means; null when there is nothing to add. */
  line: string | null;
}

const REVIEWING = new Set(['queued', 'gathering', 'awaiting_agent', 'modeling']);

/**
 * One place that turns the status (panel.status, or the panel's own DTO) into what the context column shows, so every
 * state is testable without rendering. Same wording as the panel's header; "Blocks Done" is shortened for the column.
 */
export function statusOf(dto: StatusDto): StatusView {
  const v = dto.verdict;
  const top = v?.reasons[0]?.message ?? null;
  const open = v && v.state !== 'pass' && v.blockingCount > 0 ? `${v.blockingCount} open` : null;
  const view = (kind: StatusKind, label: string, appearance: StatusView['appearance'], icon: string | null, line: string | null, withOpen = false): StatusView => ({
    kind,
    icon,
    label,
    appearance,
    open: withOpen ? open : null,
    line,
  });

  // Paid via Atlassian: with the license inactive the Done gate does not block (docs/LICENSING.md), so no verdict is shown.
  if (dto.licenseInactive) return view('license', 'License inactive', 'moved', '!', 'The Done gate does not block until Threatline is renewed.');
  if (dto.review && REVIEWING.has(dto.review.status)) return view('reviewing', 'Reviewing…', 'inprogress', null, top);
  if (!dto.review) {
    if (v?.state === 'block') return view('not_reviewed', 'Not reviewed', 'removed', VERDICT.block.icon, v.reasons[0]?.code === 'no_review' || !top ? 'Blocks Done until Threatline reviews it.' : top);
    return view('not_reviewed', 'Not reviewed', 'default', null, dto.inScope === false ? (dto.scopeMessage ?? null) : null);
  }
  if (!v) return view('not_reviewed', 'Not reviewed', 'default', null, null);
  if (v.state === 'pass' && v.overridden) return view('overridden', OVERRIDDEN.label, OVERRIDDEN.appearance, OVERRIDDEN.icon, v.validUntil ? `Until ${utc(v.validUntil)}` : null);
  if (v.state === 'pass') return view('pass', VERDICT.pass.label, VERDICT.pass.appearance, VERDICT.pass.icon, null);
  if (v.state === 'warn') return view('warn', VERDICT.warn.label, VERDICT.warn.appearance, VERDICT.warn.icon, top ?? (v.validUntil ? `Until ${utc(v.validUntil)}` : null), true);
  return view('block', 'Blocks Done', VERDICT.block.appearance, VERDICT.block.icon, top, true);
}

/** Checks again every 5 s while a review runs, so the column turns to the verdict without a reload. */
export const statusPollMs = (v: StatusView): number | null => (v.kind === 'reviewing' ? 5000 : null);

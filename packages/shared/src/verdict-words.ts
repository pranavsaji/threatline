import type { Verdict } from './schemas/index.js';

/**
 * The gate's verdict in words and an icon (never colour alone). One wording for the issue panel, the context column and
 * the comment Threatline posts when a review settles, so they never disagree. `appearance` is the panel's lozenge style.
 */
export const VERDICT: Record<'pass' | 'block' | 'warn', { label: string; icon: string; appearance: 'success' | 'removed' | 'moved' }> = {
  pass: { label: 'Ready for Done', icon: '✓', appearance: 'success' },
  block: { label: 'Blocks Done and merge', icon: '✕', appearance: 'removed' },
  warn: { label: 'Warn only', icon: '!', appearance: 'moved' },
};

export const OVERRIDDEN = { label: 'Gate overridden (break-glass)', icon: '!', appearance: 'moved' as const };

/** The label and icon for a verdict, break-glass included. */
export const verdictWords = (v: Pick<Verdict, 'state' | 'overridden'>): { label: string; icon: string } => (v.state === 'pass' && v.overridden ? OVERRIDDEN : VERDICT[v.state]);

/**
 * One sentence a reader takes away: what stands between this work item and Done, or that nothing does. Null before the
 * first verdict. `listed`: the reasons follow as a list (the panel shows the first three), so a block ends with a colon;
 * without the list (a comment) it is a sentence of its own.
 */
export function headlineOf(v: Pick<Verdict, 'state' | 'reasons' | 'overridden'> | null, opts: { listed?: boolean } = {}): string | null {
  if (!v) return null;
  const listed = opts.listed ?? true;
  const n = v.reasons.length;
  const things = `${n} ${n === 1 ? 'thing stands' : 'things stand'}`;
  if (v.state === 'pass' && v.overridden) return `Done and merge are let through by a break-glass override, but ${things} in the way.`;
  if (v.state === 'pass') return 'Nothing stands between this work item and Done or merge.';
  if (v.state === 'warn') return `Warn only: Done and merge go through for now, but ${things} in the way.`;
  const head = `${things.charAt(0).toUpperCase()}${things.slice(1)} between this work item and Done`;
  return listed ? `${head}${n > 3 ? ' (the first three below)' : ''}:` : `${head}.`;
}

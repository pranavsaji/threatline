/** The gate's verdict in words and an icon (never colour alone): one wording for the panel and the context column. */
export const VERDICT: Record<'pass' | 'block' | 'warn', { label: string; icon: string; appearance: 'success' | 'removed' | 'moved' }> = {
  pass: { label: 'Ready for Done', icon: '✓', appearance: 'success' },
  block: { label: 'Blocks Done and merge', icon: '✕', appearance: 'removed' },
  warn: { label: 'Warn only', icon: '!', appearance: 'moved' },
};

export const OVERRIDDEN = { label: 'Gate overridden (break-glass)', icon: '!', appearance: 'moved' as const };

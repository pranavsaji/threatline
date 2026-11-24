import Lozenge from '@atlaskit/lozenge';
import { token } from '@atlaskit/tokens';
import { RiskRing } from '../components/RiskRing.js';
import type { PanelDto } from '../types.js';
import { day, utc } from '../text.js';

const VERDICT: Record<'pass' | 'block' | 'warn', { label: string; icon: string; appearance: 'success' | 'removed' | 'moved' }> = {
  pass: { label: 'Ready for Done', icon: '✓', appearance: 'success' },
  block: { label: 'Blocks Done and merge', icon: '✕', appearance: 'removed' },
  warn: { label: 'Warn only', icon: '!', appearance: 'moved' },
};

const OVERRIDDEN = { label: 'Gate overridden (break-glass)', icon: '!', appearance: 'moved' as const };

function relative(iso: string, now = Date.now()): string {
  const m = Math.round((now - Date.parse(iso)) / 60_000);
  if (!Number.isFinite(m)) return '';
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  return h < 48 ? `${h} h ago` : day(iso);
}

/**
 * One sentence a reader takes away from the panel: what stands between this work item and Done, or that nothing does.
 * Exported for tests; null before the first verdict.
 */
export function headlineOf(v: PanelDto['verdict']): string | null {
  if (!v) return null;
  const n = v.reasons.length;
  const things = `${n} ${n === 1 ? 'thing stands' : 'things stand'}`;
  if (v.state === 'pass' && v.overridden) return `Done and merge are let through by a break-glass override, but ${things} in the way.`;
  if (v.state === 'pass') return 'Nothing stands between this work item and Done or merge.';
  if (v.state === 'warn') return `Warn only: Done and merge go through for now, but ${things} in the way.`;
  return `${things.charAt(0).toUpperCase()}${things.slice(1)} between this work item and Done${n > 3 ? ' (the first three below)' : ''}:`;
}

/** Risk ring, verdict (icon + words, never colour alone), last reviewed time, the headline, then the top three actions. */
export function Header({ dto, onRerun, busy = false }: { dto: PanelDto; onRerun?: () => void; busy?: boolean }) {
  const v = dto.verdict;
  const overridden = v?.state === 'pass' && v.overridden === true;
  const meta = overridden ? OVERRIDDEN : v ? VERDICT[v.state] : null;
  const actions = (v?.reasons ?? []).slice(0, 3);
  const headline = headlineOf(v ?? null);
  return (
    <header style={{ display: 'grid', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <RiskRing score={dto.review?.riskScore ?? 0} />
        <div style={{ display: 'grid', gap: 4 }}>
          {meta ? (
            <span>
              <Lozenge appearance={meta.appearance} isBold>
                <span aria-hidden="true">{meta.icon} </span>
                {meta.label}
              </Lozenge>
              {v?.state === 'warn' && v.validUntil && <span style={{ marginLeft: 8, color: token('color.text.subtle') }}>until {utc(v.validUntil)}</span>}
              {overridden && v?.validUntil && <span style={{ marginLeft: 8, color: token('color.text.subtle') }}>until {utc(v.validUntil)}</span>}
            </span>
          ) : (
            <Lozenge>Not reviewed</Lozenge>
          )}
          <span style={{ color: token('color.text.subtlest'), font: token('font.body.small') }}>
            {dto.review ? `Revision ${dto.review.revision} · reviewed ${relative(dto.review.updatedAt)}` : 'No review yet'}
          </span>
        </div>
      </div>
      {headline && dto.review && (
        <p style={{ margin: 0, font: token('font.heading.xsmall') }} data-testid="threatline-headline">
          {headline}
        </p>
      )}
      {actions.length > 0 && (v?.state !== 'pass' || overridden) && (
        <ul aria-label="What to do next" style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 4 }}>
          {actions.map((a, i) => (
            <li key={`${a.code}-${i}`}>
              {a.message}
              {a.action && (
                <>
                  {' '}
                  {/* Final review I4: a re-run action runs the review here; the `?rerun=1` link would only reload Jira. */}
                  {onRerun && /[?&]rerun=1\b/.test(a.action.href) ? (
                    <button type="button" onClick={onRerun} disabled={busy} style={{ background: 'none', border: 0, padding: 0, font: 'inherit', color: token('color.link'), textDecoration: 'underline', cursor: busy ? 'default' : 'pointer' }}>
                      {a.action.label}
                    </button>
                  ) : (
                    <a href={a.action.href} target="_top" style={{ color: token('color.link') }}>
                      {a.action.label}
                    </a>
                  )}
                </>
              )}
            </li>
          ))}
        </ul>
      )}
    </header>
  );
}

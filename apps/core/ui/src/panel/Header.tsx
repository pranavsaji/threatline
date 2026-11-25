import Lozenge from '@atlaskit/lozenge';
import { token } from '@atlaskit/tokens';
import { RiskRing } from '../components/RiskRing.js';
import type { PanelApi } from '../bridge.js';
import type { PanelDto, SeenBeforeDto } from '../types.js';
import { TurnIntoTasks } from './CreateTasks.js';
import { HappenedBefore, type OpenIssue } from './SeenBefore.js';
import { day, utc } from '../text.js';
import { headlineOf } from '@threatline/shared/verdict-words';
import { OVERRIDDEN, VERDICT } from './verdict-labels.js';

/** Reasons a security champion clears by confirming the threats (the panel's `confirm('review')`). */
export const CONFIRMABLE = new Set(['needs_human', 'injection_unconfirmed']);

const linkButton = (busy: boolean) =>
  ({ background: 'none', border: 0, padding: 0, font: 'inherit', color: token('color.link'), textDecoration: 'underline', cursor: busy ? 'default' : 'pointer' }) as const;

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
 * Shared with the comment Threatline posts when a review settles (@threatline/shared/verdict-words), so both say the same.
 */
export { headlineOf };

/**
 * Risk ring, verdict (icon + words, never colour alone), last reviewed time, the headline and the top three things to do
 * (the headline's colon introduces that list), "this happened before" when a blocking threat was an incident, then the
 * one positive action (turn the open requirements into tasks).
 */
export function Header({
  dto,
  onRerun,
  busy = false,
  tasks,
  memory = null,
  onOpen,
  onConfirm,
}: {
  dto: PanelDto;
  onRerun?: () => void;
  /** A security champion confirms the threats that wait for one, from the reason that says so (no separate banner). */
  onConfirm?: () => void;
  busy?: boolean;
  /** Turn the open requirements into tasks (absent: no action, e.g. in a read-only preview). */
  tasks?: { api: PanelApi; onChanged: () => void };
  memory?: SeenBeforeDto | null;
  onOpen?: OpenIssue;
}) {
  const v = dto.verdict;
  const overridden = v?.state === 'pass' && v.overridden === true;
  const meta = overridden ? OVERRIDDEN : v ? VERDICT[v.state] : null;
  const actions = (v?.reasons ?? []).slice(0, 3);
  const headline = headlineOf(v ?? null);
  return (
    <header style={{ display: 'grid', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <RiskRing score={dto.review?.riskScore ?? 0} handled={v?.state === 'pass' && !overridden} />
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
              {onConfirm && CONFIRMABLE.has(a.code) && (
                <>
                  {' '}
                  <button type="button" onClick={onConfirm} disabled={busy} style={linkButton(busy)}>
                    Confirm threats
                  </button>
                </>
              )}
              {a.action && (
                <>
                  {' '}
                  {/* Final review I4: a re-run action runs the review here; the `?rerun=1` link would only reload Jira. */}
                  {onRerun && /[?&]rerun=1\b/.test(a.action.href) ? (
                    <button type="button" onClick={onRerun} disabled={busy} style={linkButton(busy)}>
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
      {dto.review && <HappenedBefore memory={memory} onOpen={onOpen} />}
      {tasks && dto.review && <TurnIntoTasks dto={dto} api={tasks.api} onChanged={tasks.onChanged} onOpen={onOpen} />}
    </header>
  );
}

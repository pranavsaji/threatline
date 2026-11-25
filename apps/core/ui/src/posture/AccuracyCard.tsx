import { useId } from 'react';
import { token } from '@atlaskit/tokens';
import type { Accuracy, AccuracyRate } from '../types.js';

/** Where each measure is defined, with its caveats. */
export const ACCURACY_DOCS_URL = 'https://github.com/pranavsaji/threatline/blob/main/docs/ACCURACY.md';
/** Below this many decisions the 95% interval is wide enough to matter, so it is shown next to the share. */
const SHOW_INTERVAL_BELOW = 100;

const pct = (x: number) => `${Math.round(x * 100)}%`;
const days = (h: number) => (h < 48 ? `${Math.round(h)} h` : `${Math.round(h / 24)} days`);

/** "82%", or the plain statement that there are too few decisions for one (the count is said elsewhere). */
const shareText = (r: AccuracyRate) => (r.enough && r.share !== null ? pct(r.share) : 'Not enough decisions yet (n < 5)');
const intervalText = (r: AccuracyRate) => (r.enough && r.low !== null && r.high !== null && r.n < SHOW_INTERVAL_BELOW ? `95% interval ${pct(r.low)}–${pct(r.high)}` : null);
const noDecisions = (a: Accuracy) => a.champion.rate.n + a.blocking.rate.n + a.verifier.rate.n === 0;

const tile = {
  display: 'grid',
  alignContent: 'start',
  gap: 4,
  padding: 12,
  flex: '1 1 220px',
  borderRadius: 6,
  border: `1px solid ${token('color.border')}`,
  background: token('elevation.surface'),
  margin: 0,
} as const;
const small = { font: token('font.body.small'), color: token('color.text.subtle') } as const;
const link = { color: token('color.link') } as const;

function Figure({ label, rate, detail, extra }: { label: string; rate: AccuracyRate; detail: string; extra?: string | null }) {
  const interval = intervalText(rate);
  return (
    <li style={tile}>
      <span style={small}>{label}</span>
      <span style={rate.enough ? { font: token('font.heading.large') } : { font: token('font.heading.xsmall'), color: token('color.text.subtle') }}>{shareText(rate)}</span>
      <span style={{ font: token('font.body.small') }}>{detail}</span>
      {interval && <span style={small}>{interval}</span>}
      {extra && <span style={small}>{extra}</span>}
    </li>
  );
}

const ofText = (count: number, n: number, what: string) => `${count} of ${n} ${what}`;
const cell = (count: number, r: AccuracyRate) => (r.n === 0 ? '–' : r.enough && r.share !== null ? `${pct(r.share)} (${count} of ${r.n})` : `${r.n} so far`);

/**
 * "Accuracy here": how often Threatline's calls held up when people (and its verifier) decided them, over the last 90
 * days, on the work items the viewer can see. `compact` is the gadget's single line.
 */
export function AccuracyCard({ accuracy, compact = false }: { accuracy: Accuracy | null; compact?: boolean }) {
  const id = useId();
  const how = (
    <a href={ACCURACY_DOCS_URL} target="_blank" rel="noreferrer" style={link}>
      How this is measured
    </a>
  );

  if (compact) {
    let text: string;
    if (!accuracy) text = 'Accuracy here: not available right now.';
    else if (noDecisions(accuracy)) text = `Accuracy here (${accuracy.windowDays} days): no decisions yet.`;
    else {
      const { champion: c, blocking: b } = accuracy;
      const part = (name: string, count: number, r: AccuracyRate) => (r.enough && r.share !== null ? `${name} ${pct(r.share)} (${count} of ${r.n})` : `${name}: not enough decisions yet`);
      text = `Accuracy here (${accuracy.windowDays} days): ${part('champions agreed', c.confirmed, c.rate)} · ${part('blocking calls held up', b.fixed + b.accepted, b.rate)}.`;
    }
    return (
      <p role="note" aria-label="Accuracy here" style={{ margin: 0, font: token('font.body.small'), color: token('color.text.subtle') }}>
        {text}
      </p>
    );
  }

  return (
    <section aria-labelledby={`${id}-h`} style={{ display: 'grid', gap: 8 }}>
      <h2 id={`${id}-h`} style={{ margin: 0, font: token('font.heading.small') }}>
        Accuracy here
      </h2>
      <p style={{ margin: 0, font: token('font.body.small'), color: token('color.text.subtle') }}>
        How often Threatline was right when people decided its calls, over the last {accuracy?.windowDays ?? 90} days, on work items you can see. {how}
      </p>
      {!accuracy ? (
        <p style={{ margin: 0 }}>Accuracy figures are not available right now. The rest of the page is unaffected.</p>
      ) : noDecisions(accuracy) ? (
        <p style={{ margin: 0 }}>
          No decisions yet. Once security champions confirm or dismiss the threats sent to them, and teams close blocking requirements, this shows how often Threatline was right.
        </p>
      ) : (
        <>
          <ul aria-label="Accuracy figures" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            <Figure
              label="Champion agreement"
              rate={accuracy.champion.rate}
              detail={`${ofText(accuracy.champion.confirmed, accuracy.champion.rate.n, 'threats sent to a champion were confirmed as real')}; ${accuracy.champion.dismissed} dismissed as not real.`}
            />
            <Figure
              label="Blocking calls that held up"
              rate={accuracy.blocking.rate}
              detail={`${ofText(accuracy.blocking.fixed + accuracy.blocking.accepted, accuracy.blocking.rate.n, 'closed blocking requirements')}: ${accuracy.blocking.fixed} fixed, ${accuracy.blocking.accepted} risk accepted, ${accuracy.blocking.dismissed} dismissed as wrong.`}
              extra={accuracy.blocking.medianHoursToVerify !== null ? `Fixed in a median of ${days(accuracy.blocking.medianHoursToVerify)}.` : null}
            />
            <Figure label="Verifier keep rate" rate={accuracy.verifier.rate} detail={`${ofText(accuracy.verifier.kept, accuracy.verifier.rate.n, 'AI threats kept by the verifier')}.`} />
          </ul>
          {accuracy.byProject.length > 1 && (
            <div style={{ overflowX: 'auto' }}>
              <table aria-label="Accuracy by project" style={{ borderCollapse: 'collapse', font: token('font.body.small') }}>
                <thead>
                  <tr>
                    {['Project', 'Champion agreement', 'Blocking calls that held up', 'Verifier keep rate'].map((h) => (
                      <th key={h} scope="col" style={{ textAlign: 'left', padding: '4px 12px 4px 0', color: token('color.text.subtle') }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {accuracy.byProject.map((p) => (
                    <tr key={p.project}>
                      <th scope="row" style={{ textAlign: 'left', padding: '4px 12px 4px 0' }}>
                        {p.project}
                      </th>
                      <td style={{ padding: '4px 12px 4px 0' }}>{cell(p.champion.confirmed, p.champion.rate)}</td>
                      <td style={{ padding: '4px 12px 4px 0' }}>{cell(p.blocking.fixed + p.blocking.accepted, p.blocking.rate)}</td>
                      <td style={{ padding: '4px 12px 4px 0' }}>{cell(p.verifier.kept, p.verifier.rate)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p style={{ margin: 0, ...small }}>
            Champions only see the threats Threatline was unsure of, and a dismissal can itself be wrong: read these alongside the offline eval.
          </p>
        </>
      )}
    </section>
  );
}

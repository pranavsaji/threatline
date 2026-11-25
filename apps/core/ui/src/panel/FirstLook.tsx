import { useId } from 'react';
import { token } from '@atlaskit/tokens';
import { SeverityLozenge } from '../components/SeverityLozenge.js';
import { count } from '../text.js';
import type { FactDto, PanelDto } from '../types.js';
import { CitationLink } from './CitationLink.js';

type FirstLookDto = NonNullable<PanelDto['firstLook']>;

/** The label every first look carries, so nobody reads it as the review: what it is, and that it will be replaced. */
export function firstLookLabel(f: Pick<FirstLookDto, 'stage'>): string {
  const where = f.stage ? ` (stage ${f.stage.n} of ${f.stage.of})` : '';
  return `First look from Threatline's rules. The AI review is running${where} and will replace this.`;
}

/**
 * While a review runs: Threatline's rule-based threats from the gather, in plain language with their severity and the
 * sentence each quotes. Display only: the gate keeps blocking until the review settles, and nothing here is triaged or
 * recorded. The panel stops showing it once the review is in (the review includes the same checks).
 */
export function FirstLook({ firstLook, facts }: { firstLook: FirstLookDto; facts: Map<string, FactDto> }) {
  const id = useId();
  const { threats, hidden, stage } = firstLook;
  return (
    <section
      aria-labelledby={`${id}-h`}
      data-testid="threatline-first-look"
      style={{ border: `1px dashed ${token('color.border')}`, borderRadius: 6, padding: 12, display: 'grid', gap: 8 }}
    >
      <h2 id={`${id}-h`} style={{ margin: 0, font: token('font.heading.xsmall') }}>
        First look
      </h2>
      <p style={{ margin: 0, color: token('color.text.subtle') }}>{firstLookLabel(firstLook)}</p>
      {stage && <p style={{ margin: 0, color: token('color.text.subtlest'), font: token('font.body.small') }}>Now: {stage.name}.</p>}
      {threats.length === 0 && hidden === 0 && <p style={{ margin: 0 }}>Threatline's rules found nothing to flag. The AI review may still find threats.</p>}
      {threats.length > 0 && (
        <ul aria-label="First look risks" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 8 }}>
          {threats.map((t) => (
            <li key={t.id} style={{ display: 'grid', gap: 4 }}>
              <span style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                <SeverityLozenge severity={t.severity} />
                <strong>{t.plainLanguage || t.title}</strong>
              </span>
              {t.citations.map((c, i) => (
                <blockquote key={`${c.factId}-${i}`} style={{ margin: 0, paddingLeft: 10, borderLeft: `2px solid ${token('color.border')}`, font: token('font.body.small') }}>
                  “{c.quote}” <CitationLink citation={c} fact={facts.get(c.factId)} />
                </blockquote>
              ))}
            </li>
          ))}
        </ul>
      )}
      {hidden > 0 && (
        <p style={{ margin: 0, color: token('color.text.subtlest'), font: token('font.body.small') }}>
          {count(hidden, 'more risk')} {hidden === 1 ? 'cites a source' : 'cite sources'} you cannot open.
        </p>
      )}
    </section>
  );
}

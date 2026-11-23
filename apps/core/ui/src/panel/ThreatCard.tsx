import { useId, useState, type ReactNode } from 'react';
import Button from '@atlaskit/button/new';
import Lozenge from '@atlaskit/lozenge';
import { token } from '@atlaskit/tokens';
import { SeverityLozenge } from '../components/SeverityLozenge.js';
import { STRIDE_LABEL, StrideIcon } from '../components/StrideIcon.js';
import type { FactDto, Threat, ThreatExplanation } from '../types.js';
import { CitationLink } from './CitationLink.js';

const GROUNDING: Record<Threat['grounding'], { label: string; appearance: 'success' | 'moved' | 'removed' }> = {
  supported: { label: 'Quote verified', appearance: 'success' },
  weak: { label: 'Weak evidence', appearance: 'moved' },
  unsupported: { label: 'Unsupported', appearance: 'removed' },
};

/** Prefix shown before ids that do not already name their framework ("CWE-640" and "LLM01" already do). */
const PREFIX: Record<string, string> = { ASVS5: 'ASVS', LLM10: 'OWASP', ASI10: 'OWASP' };

/** "ASVS V2.1.1", "OWASP LLM01", "CWE-640". */
export function standardLabel(m: { framework: string; refId: string }): string {
  const prefix = PREFIX[m.framework];
  return prefix && !m.refId.startsWith(prefix) ? `${prefix} ${m.refId}` : m.refId;
}

export function ThreatCard({
  threat,
  facts,
  explain,
  children,
  covers = [],
}: {
  threat: Threat;
  facts: Map<string, FactDto>;
  explain: (t: Threat) => Promise<ThreatExplanation | null>;
  /** Extra controls inside the card (champion triage). */
  children?: ReactNode;
  /** Titles of Threatline's rule-based checks this threat covers (they are not listed separately). */
  covers?: string[];
}) {
  const [open, setOpen] = useState(false);
  const [explained, setExplained] = useState<ThreatExplanation | null>(null);
  const [explaining, setExplaining] = useState(false);
  const [explainError, setExplainError] = useState<string | null>(null);
  const bodyId = useId();
  const g = GROUNDING[threat.grounding];
  const runs = threat.origin === 'baseline' ? 'Rule-based' : threat.foundBy === 'gap_check' ? 'Found by the gap check' : `${threat.votes} of ${threat.samples} runs`;
  return (
    <article
      aria-labelledby={`${bodyId}-title`}
      style={{ border: `1px solid ${token('color.border')}`, borderRadius: 6, padding: 12, display: 'grid', gap: 8, background: token('elevation.surface') }}
    >
      <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
        <StrideIcon stride={threat.stride} />
        <div style={{ display: 'grid', gap: 4, flex: 1, minWidth: 0 }}>
          <h3 id={`${bodyId}-title`} style={{ margin: 0, font: token('font.heading.xsmall') }}>
            {threat.plainLanguage || threat.title}
          </h3>
          {threat.plainLanguage && <span style={{ color: token('color.text.subtle'), font: token('font.body.small') }}>{threat.title}</span>}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <SeverityLozenge severity={threat.severity} />
            <Lozenge>{STRIDE_LABEL[threat.stride]}</Lozenge>
            <Lozenge appearance={g.appearance}>{g.label}</Lozenge>
            {threat.state === 'needs_human' && <Lozenge appearance="new">Needs a champion</Lozenge>}
            {threat.verification?.keep && <Lozenge appearance="success">Verified</Lozenge>}
            {threat.state === 'dismissed' && threat.verification?.keep === false && <Lozenge appearance="removed">Dropped by the verifier</Lozenge>}
            {threat.state === 'dismissed' && threat.dismissReason === 'unconfirmed' && !threat.verification && <Lozenge appearance="moved">Waiting for the verifier</Lozenge>}
            {threat.state === 'suppressed' && <Lozenge appearance="removed">Hidden by team rule</Lozenge>}
            <span style={{ color: token('color.text.subtlest'), font: token('font.body.small') }}>{runs}</span>
          </div>
          {threat.verification?.keep === false && (
            <span style={{ color: token('color.text.subtle'), font: token('font.body.small') }}>
              The verifier doubted this: {threat.verification.reason}
              {threat.state === 'needs_human' ? ' A security champion decides.' : ''}
            </span>
          )}
          {threat.suppression && <SuppressionNote suppression={threat.suppression} />}
          {covers.length > 0 && (
            <span style={{ color: token('color.text.subtle'), font: token('font.body.small') }}>
              Also covers Threatline's rule-based {covers.length === 1 ? 'check' : 'checks'}: {covers.join('; ')}.
            </span>
          )}
          {threat.mappings.length > 0 && (
            <ul aria-label="Standards" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {threat.mappings.map((m) => (
                <li key={`${m.framework}-${m.refId}`}>
                  <code style={{ font: token('font.code'), fontSize: 12, lineHeight: '18px', padding: '0 4px', borderRadius: 3, background: token('color.background.neutral'), color: token('color.text.subtle') }}>
                    {standardLabel(m)}
                  </code>
                </li>
              ))}
            </ul>
          )}
        </div>
        <Button appearance="subtle" onClick={() => setOpen(!open)} aria-expanded={open} aria-controls={bodyId}>
          {open ? 'Less' : 'Details'}
        </Button>
      </div>
      {open && (
        <div id={bodyId} style={{ display: 'grid', gap: 8, paddingLeft: 30 }}>
          {threat.scenario && <p style={{ margin: 0 }}>{threat.scenario}</p>}
          <div>
            <strong style={{ font: token('font.body.small') }}>Evidence</strong>
            <ul style={{ margin: '4px 0 0', paddingLeft: 18, display: 'grid', gap: 4 }}>
              {threat.citations.map((c, i) => (
                <li key={`${c.factId}-${i}`}>
                  “{c.quote}” — <CitationLink citation={c} fact={facts.get(c.factId)} />
                </li>
              ))}
            </ul>
          </div>
          {!explained ? (
            <div style={{ display: 'grid', gap: 4, justifyItems: 'start' }}>
              <Button
                isLoading={explaining}
                isDisabled={explaining}
                onClick={async () => {
                  if (explaining) return;
                  setExplaining(true);
                  const r = await explain(threat).catch(() => null);
                  setExplaining(false);
                  setExplainError(r ? null : 'Threatline could not explain this threat right now. Try again.');
                  setExplained(r);
                }}
              >
                Explain like I’m new to security
              </Button>
              {explainError && (
                <p role="alert" style={{ margin: 0, color: token('color.text.danger'), font: token('font.body.small') }}>
                  {explainError}
                </p>
              )}
            </div>
          ) : (
            <section aria-label="Explanation" style={{ background: token('color.background.neutral.subtle'), borderRadius: 6, padding: 8, display: 'grid', gap: 6 }}>
              <p style={{ margin: 0 }}>{explained.story}</p>
              {explained.fixes.length > 0 && (
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {explained.fixes.map((f) => (
                    <li key={f}>{f}</li>
                  ))}
                </ul>
              )}
              <p style={{ margin: 0, font: token('font.body.small') }}>
                {explained.refs.map((r, i) => (
                  <span key={r.id}>
                    {i > 0 && ' · '}
                    <a href={r.url} target="_blank" rel="noreferrer" style={{ color: token('color.link') }}>
                      {r.id}
                    </a>
                  </span>
                ))}
              </p>
            </section>
          )}
        </div>
      )}
      {children}
    </article>
  );
}

/** What a project's team suppression rule did to this threat (docs/SUPPRESSIONS.md). */
function SuppressionNote({ suppression: s }: { suppression: NonNullable<Threat['suppression']> }) {
  const text =
    s.outcome === 'hidden'
      ? `Hidden by team rule: ${s.reason} (expires ${s.expiresAt.slice(0, 10)}; rule ${s.ruleId}).`
      : s.outcome === 'blocking'
        ? `Team rule ${s.ruleId} matched this threat (${s.reason}), but a rule cannot hide a threat at or above the blocking level.`
        : `Unhidden on this work item by a security champion (team rule ${s.ruleId}: ${s.reason}).`;
  return (
    <span style={{ color: token('color.text.subtle'), font: token('font.body.small') }}>
      {text}
    </span>
  );
}

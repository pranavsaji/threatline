import { useId, useState, type ReactNode } from 'react';
import Button from '@atlaskit/button/new';
import Lozenge from '@atlaskit/lozenge';
import { token } from '@atlaskit/tokens';
import { errorText, isError, type PanelApi } from '../bridge.js';
import type { ApiError, PanelDto, Requirement } from '../types.js';
import { useInFlight } from '../components/in-flight.js';

type Fix = NonNullable<PanelDto['fixCheck']>;
type Finding = Fix['findings'][number];
type Hold = Fix['holds'][string];

const small = { font: token('font.body.small'), color: token('color.text.subtle') } as const;
const code = { font: token('font.code'), fontSize: 12, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', margin: 0 } as const;

const HOLD_WHY: Record<Extract<Hold, { kind: 'unconfirmed' }>['why'], string> = {
  not_fixed: 'Not fixed by the pull request',
  partial: 'Partly fixed',
  unclear: 'Fix not shown',
  failed: 'Fix check did not run',
  injection: 'Change talks to the AI',
};

/** One quiet line under a requirement: what the fix check found, with the evidence and a suggested fix on request. */
export function FixCheckLine({ requirement, fix, champion, api, onChanged }: { requirement: Requirement; fix: Fix | undefined; champion: boolean; api: PanelApi; onChanged: () => void }) {
  const [open, setOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const confirming = useInFlight();
  const id = useId();
  if (!fix) return null;
  const finding = fix.findings.find((f) => f.requirementId === requirement.id);
  const hold = fix.holds[requirement.id];
  const confirmed = fix.confirmations.find((c) => c.requirementId === requirement.id);
  const pending = fix.status === 'pending' && (hold?.kind === 'pending' || requirement.status !== 'Verified');
  if (!finding && !hold && !pending && !confirmed) return null;

  const confirm = () =>
    confirming.run(async () => {
      const r = await (api.confirmFix?.(requirement.id) ?? Promise.resolve<ApiError>({ error: 'unavailable' })).catch((): ApiError => ({ error: 'unavailable' }));
      if (isError(r)) return setNotice(errorText(r));
      setNotice('Confirmed. Done and merge no longer wait on this check.');
      onChanged();
    });

  const pr = fix.prUrl ? (
    <a href={fix.prUrl} target="_blank" rel="noreferrer" style={{ color: token('color.link') }}>
      pull request
    </a>
  ) : (
    'change'
  );
  const where = `${fix.repo} @ ${fix.commitSha.slice(0, 12)}`;

  let line: ReactNode;
  if (pending) line = <span style={small}>Checking whether the {pr} fixes this…</span>;
  else if (confirmed) line = <span style={small}>Fix confirmed by a security champion for {where}.</span>;
  else if (hold?.kind === 'unconfirmed')
    line = (
      <span style={{ ...small, display: 'inline-flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
        <Lozenge appearance={hold.why === 'partial' || hold.why === 'unclear' ? 'moved' : 'removed'}>{HOLD_WHY[hold.why]}</Lozenge>
        {hold.why === 'failed' ? (fix.failure ?? 'The check could not finish.') : finding ? finding.reason : null}
      </span>
    );
  else if (finding) line = <span style={finding.verdict === 'fixed' ? { ...small, color: token('color.text.success') } : small}>{summary(finding, pr)}</span>;

  const hasDetail = !!finding && (finding.quotes.length > 0 || !!finding.missing || !!finding.suggestion || finding.testsNamed > 0 || finding.touchesHints === false);
  return (
    <div style={{ display: 'grid', gap: 6 }} data-testid={`fix-${requirement.id}`}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        {line}
        {hasDetail && (
          <Button appearance="subtle" spacing="compact" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}>
            {open ? 'Less' : finding!.verdict === 'fixed' ? 'Evidence' : 'Why and how to fix'}
          </Button>
        )}
        {champion && hold?.kind === 'unconfirmed' && (
          <Button spacing="compact" onClick={() => void confirm()} isDisabled={confirming.busy}>
            Confirm it is fixed
          </Button>
        )}
      </div>
      {notice && (
        <span role="status" style={small}>
          {notice}
        </span>
      )}
      {open && finding && <FixDetail id={id} finding={finding} where={where} omitted={fix.omittedFiles} repeatReason={hold?.kind !== 'unconfirmed'} />}
    </div>
  );
}

function summary(f: Finding, pr: ReactNode): ReactNode {
  const at = f.quotes[0] ? ` · ${f.quotes[0].path}:${f.quotes[0].line}` : '';
  if (f.verdict === 'fixed') return <>✓ The {pr} fixes it{at}</>;
  if (f.verdict === 'partial') return <>The {pr} fixes part of it: {f.missing ?? f.reason}</>;
  if (f.verdict === 'unclear') return <>The check could not show the {pr} fixes it.</>;
  return <>Not in the {pr} yet.</>;
}

function FixDetail({ id, finding, where, omitted, repeatReason }: { id: string; finding: Finding; where: string; omitted: number; repeatReason: boolean }) {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied('Copied the suggested change.');
    } catch {
      setCopied('Your browser blocked copying. Select the code and copy it by hand.');
    }
  };
  const signals = [
    finding.testsNamed > 0 ? `adds ${finding.testsNamed === 1 ? 'a test line' : `${finding.testsNamed} test lines`} named for this requirement` : null,
    finding.touchesHints === false ? 'touches none of the files this requirement points to' : null,
    omitted > 0 ? `${omitted} changed file${omitted === 1 ? ' was' : 's were'} not read (generated, binary or too large)` : null,
  ].filter(Boolean);
  return (
    <div id={id} style={{ display: 'grid', gap: 8, padding: 10, borderRadius: 6, background: token('color.background.neutral.subtle'), border: `1px solid ${token('color.border')}` }}>
      {repeatReason && <p style={{ margin: 0 }}>{finding.reason}</p>}
      {finding.quotes.length > 0 && (
        <div style={{ display: 'grid', gap: 4 }}>
          <span style={small}>Added code that enforces it ({where}), each line checked against the change:</span>
          <ul aria-label="Fix evidence" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 4 }}>
            {finding.quotes.map((q) => (
              <li key={`${q.path}:${q.line}`}>
                <span style={small}>
                  {q.path}:{q.line}
                </span>
                <pre style={code}>{q.text}</pre>
              </li>
            ))}
          </ul>
        </div>
      )}
      {finding.missing && (
        <p style={{ margin: 0 }}>
          <strong>Still needed:</strong> {finding.missing}
        </p>
      )}
      {finding.suggestion && (
        <div style={{ display: 'grid', gap: 4 }}>
          <span style={small}>Suggested change: {finding.suggestion.summary} (a suggestion from Threatline Engine; review it before use)</span>
          <pre style={{ ...code, padding: 8, borderRadius: 4, background: token('color.background.neutral'), maxHeight: 240, overflow: 'auto' }}>{finding.suggestion.code}</pre>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <Button spacing="compact" onClick={() => void copy(finding.suggestion!.code)}>
              Copy suggested change
            </Button>
            <span role="status" style={small}>
              {copied}
            </span>
          </div>
        </div>
      )}
      {signals.length > 0 && <span style={small}>Also: the change {signals.join('; ')}.</span>}
    </div>
  );
}

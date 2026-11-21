import { useId, useState, type FormEvent } from 'react';
import Button from '@atlaskit/button/new';
import { token } from '@atlaskit/tokens';
import { errorText, isError, type AdminApi } from '../bridge.js';
import type { ApiError } from '../types.js';
import { box, errorText as errorStyle, field, label } from '../panel/form-styles.js';

const dataUrl = (type: string, body: string) => `data:${type};charset=utf-8,${encodeURIComponent(body)}`;
const linkStyle = { color: token('color.link') };

/**
 * Compliance evidence: per SOC 2, ISO/IEC 27001:2022 and PCI DSS control, the requirements behind it by status, the
 * latest evidence and the risk acceptances, for one project and date range. Same download-or-copy pattern as the
 * evidence pack. The mapping is indicative, not an audit opinion.
 */
export function ControlsSummaryExport({ api }: { api: AdminApi }) {
  const id = useId();
  const [project, setProject] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [pack, setPack] = useState<{ csv: string; json: string; name: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  // A browser or site policy can block downloads from the app's frame: copying is the fallback.
  const copy = async (text: string, what: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(`Copied the ${what}. Paste it into a file.`);
    } catch {
      setCopied('Your browser blocked copying. Use the download links, or ask an admin to allow clipboard access.');
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const key = project.trim().toUpperCase();
    if (!key || !from || !to) return setError('Give a project key and both dates.');
    setExporting(true);
    const r = await api.exportControls(key, from, to).catch((): ApiError => ({ error: 'unavailable' }));
    setExporting(false);
    if (isError(r)) {
      setPack(null);
      return setError(errorText(r));
    }
    setError(null);
    setCopied(null);
    setPack({ ...r, name: `threatline-controls-${key}-${from}-${to}` });
  };

  return (
    <form aria-label="Controls summary" onSubmit={submit} style={box}>
      <strong>Controls summary</strong>
      <span style={{ font: token('font.body.small'), color: token('color.text.subtle') }}>
        SOC 2, ISO/IEC 27001:2022 and PCI DSS v4.0 controls mapped from each requirement's ASVS 5.0 ids: requirements by status, the latest evidence and risk acceptances with their expiry. The mapping is
        indicative, not an audit opinion.
      </span>
      <label style={label} htmlFor={`${id}-p`}>
        Project key
      </label>
      <input id={`${id}-p`} value={project} onChange={(e) => setProject(e.target.value)} placeholder="PAY" style={field} />
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <span style={{ display: 'grid', gap: 2 }}>
          <label style={label} htmlFor={`${id}-from`}>
            From
          </label>
          <input id={`${id}-from`} type="date" value={from} onChange={(e) => setFrom(e.target.value)} style={field} />
        </span>
        <span style={{ display: 'grid', gap: 2 }}>
          <label style={label} htmlFor={`${id}-to`}>
            To
          </label>
          <input id={`${id}-to`} type="date" value={to} onChange={(e) => setTo(e.target.value)} style={field} />
        </span>
      </div>
      {error && (
        <p role="alert" style={errorStyle}>
          {error}
        </p>
      )}
      <div>
        <Button type="submit" isDisabled={exporting}>
          Export controls
        </Button>
      </div>
      <div role="status" style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        {pack && (
          <>
            <a href={dataUrl('text/csv', pack.csv)} download={`${pack.name}.csv`} style={linkStyle}>
              Download controls CSV
            </a>
            <a href={dataUrl('application/json', pack.json)} download={`${pack.name}.json`} style={linkStyle}>
              Download controls JSON
            </a>
            <Button spacing="compact" onClick={() => void copy(pack.csv, 'controls CSV')}>
              Copy controls CSV
            </Button>
            <Button spacing="compact" onClick={() => void copy(pack.json, 'controls JSON')}>
              Copy controls JSON
            </Button>
            {copied && <span style={{ font: token('font.body.small') }}>{copied}</span>}
          </>
        )}
      </div>
    </form>
  );
}

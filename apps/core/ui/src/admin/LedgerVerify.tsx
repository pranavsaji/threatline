import { useId, useState, type FormEvent } from 'react';
import Button from '@atlaskit/button/new';
import { token } from '@atlaskit/tokens';
import { errorText, isError, type AdminApi, type ChainVerdict } from '../bridge.js';
import type { ApiError } from '../types.js';
import { box, errorText as errorStyle, field, label } from '../panel/form-styles.js';
import { TransparencyLog } from './TransparencyLog.js';
import { ControlsSummaryExport } from './ControlsSummaryExport.js';

const BROKEN: Record<Extract<ChainVerdict, { ok: false; treeSize?: never }>['reason'], string> = {
  hash_mismatch: 'an entry was changed after it was written',
  prev_mismatch: 'an entry does not chain onto the one before it',
  seq_gap: 'an entry is missing',
};

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
function verdictText(r: ChainVerdict): string {
  if (r.ok) return `The ledger is intact: ${plural(r.length, 'entry', 'entries')}${r.treeHeads ? `, matching ${plural(r.treeHeads, 'signed tree head', 'signed tree heads')}` : ''}.`;
  // Checked against the signed tree heads: what the hash chain alone cannot see.
  if ('treeSize' in r) {
    const head = `signed tree head of ${plural(r.treeSize, 'entry', 'entries')}`;
    if (r.reason === 'truncated') return `The ledger is shorter than its ${head}: entries from ${r.firstBrokenSeq} on were removed.`;
    if (r.reason === 'tree_head_mismatch')
      return `The ledger does not match its ${head}: an entry from ${r.firstBrokenSeq} to ${r.treeSize} was changed and the hashes after it recomputed. Entries from ${r.firstBrokenSeq} on cannot be trusted.`;
    return `The ${head} has an invalid signature: the stored tree heads were changed. Compare the ledger with the heads published to Confluence.`;
  }
  return `The ledger is broken at entry ${r.firstBrokenSeq}: ${BROKEN[r.reason]}. Entries from there on cannot be trusted.`;
}

const dataUrl = (type: string, body: string) => `data:${type};charset=utf-8,${encodeURIComponent(body)}`;

/** RL-4 (verify the hash chain, name the first broken link) and RL-7 (evidence pack for a project and date range). */
export function LedgerVerify({ api }: { api: AdminApi }) {
  const id = useId();
  const [verdict, setVerdict] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
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

  const verify = async () => {
    setChecking(true);
    const r = await api.verifyLedger().catch((): ApiError => ({ error: 'unavailable' }));
    setChecking(false);
    if (isError(r)) return setVerdict(errorText(r));
    setVerdict(verdictText(r));
  };

  const exportPack = async (e: FormEvent) => {
    e.preventDefault();
    const key = project.trim().toUpperCase();
    if (!key || !from || !to) return setError('Give a project key and both dates.');
    setExporting(true);
    const r = await api.exportLedger(key, from, to).catch((): ApiError => ({ error: 'unavailable' }));
    setExporting(false);
    if (isError(r)) {
      setPack(null);
      return setError(errorText(r));
    }
    setError(null);
    setCopied(null);
    setPack({ ...r, name: `threatline-evidence-${key}-${from}-${to}` });
  };

  return (
    <section aria-labelledby={`${id}-h`} style={{ display: 'grid', gap: 8 }}>
      <h2 id={`${id}-h`} style={{ font: token('font.heading.small'), margin: 0 }}>
        Risk ledger
      </h2>
      <p style={{ margin: 0, color: token('color.text.subtle') }}>
        Every risk acceptance, approval, override and attestation is an append-only, hash-chained entry. Verifying recomputes every hash and checks the ledger against its signed tree heads.
      </p>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <Button onClick={() => void verify()} isDisabled={checking}>
          Verify the ledger
        </Button>
        <span role="status">{verdict}</span>
      </div>
      <form aria-label="Evidence pack" onSubmit={exportPack} style={box}>
        <strong>Evidence pack</strong>
        <span style={{ font: token('font.body.small'), color: token('color.text.subtle') }}>CSV and JSON of one project's entries, with each entry's hashes and the chain check.</span>
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
            Export
          </Button>
        </div>
        <div role="status" style={{ display: 'flex', gap: 12 }}>
          {pack && (
            <>
              <a href={dataUrl('text/csv', pack.csv)} download={`${pack.name}.csv`} style={{ color: token('color.link') }}>
                Download CSV
              </a>
              <a href={dataUrl('application/json', pack.json)} download={`${pack.name}.json`} style={{ color: token('color.link') }}>
                Download JSON
              </a>
              <Button spacing="compact" onClick={() => void copy(pack.csv, 'CSV')}>
                Copy CSV
              </Button>
              <Button spacing="compact" onClick={() => void copy(pack.json, 'JSON')}>
                Copy JSON
              </Button>
              {copied && <span style={{ font: token('font.body.small') }}>{copied}</span>}
            </>
          )}
        </div>
      </form>
      <ControlsSummaryExport api={api} />
      <TransparencyLog api={api} />
    </section>
  );
}

import { useId, useState, type FormEvent } from 'react';
import Button from '@atlaskit/button/new';
import { token } from '@atlaskit/tokens';
import { errorText as errorTextOf, isError, type AttestationOutcome, type PanelApi } from '../bridge.js';
import type { ApiError } from '../types.js';
import { box, errorText, field, label } from './form-styles.js';
import { useInFlight } from '../components/in-flight.js';

const REPO = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
const SHA = /^[0-9a-fA-F]{40}$/;

/** AT-1 from the panel: a signed attestation for one repository and commit, ready to paste into the pull request. */
export function CopyAttestation({ api }: { api: PanelApi }) {
  const id = useId();
  const [repo, setRepo] = useState('');
  const [sha, setSha] = useState('');
  const [error, setError] = useState<string | null>(null);
  const { busy, run } = useInFlight();
  const [result, setResult] = useState<AttestationOutcome | null>(null);
  const [copied, setCopied] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!REPO.test(repo.trim())) return setError('Give the repository as workspace/repository (Bitbucket) or owner/repository (GitHub), for example acme/payments.');
    if (!SHA.test(sha.trim())) return setError('Give the full 40-character commit hash of the pull request’s head commit.');
    await run(async () => {
      const r = await api.attestation(repo.trim(), sha.trim()).catch((): ApiError => ({ error: 'unavailable' }));
      setCopied(false);
      if (isError(r)) {
        setResult(null);
        return setError(errorTextOf(r));
      }
      setError(null);
      setResult(r);
    });
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <form aria-label="Merge attestation" onSubmit={submit} style={box}>
      <strong>Merge attestation</strong>
      <span style={{ font: token('font.body.small'), color: token('color.text.subtle') }}>
        A pull request that touches security-sensitive files merges only with a signed attestation for its head commit (Threatline for Bitbucket or the GitHub Action checks it).
      </span>
      {/* Repository and commit side by side (they wrap on a narrow panel), so the form stays a few lines tall. */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <div style={{ display: 'grid', gap: 4, flex: '1 1 160px', minWidth: 0 }}>
          <label style={label} htmlFor={`${id}-repo`}>
            Repository
          </label>
          <input id={`${id}-repo`} value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="acme/payments" style={field} />
        </div>
        <div style={{ display: 'grid', gap: 4, flex: '3 1 260px', minWidth: 0 }}>
          <label style={label} htmlFor={`${id}-sha`}>
            Commit hash
          </label>
          <input id={`${id}-sha`} value={sha} onChange={(e) => setSha(e.target.value)} placeholder="40-character head commit hash" maxLength={40} style={{ ...field, fontFamily: token('font.family.code') }} />
        </div>
        <Button type="submit" isDisabled={busy}>
          Get attestation
        </Button>
      </div>
      {error && (
        <p role="alert" style={errorText}>
          {error}
        </p>
      )}
      <div role="status" style={{ display: 'grid', gap: 6 }}>
        {result && 'blocking' in result && (
          <>
            <span>Threatline blocks this merge until these are resolved:</span>
            <ul style={{ margin: 0, paddingLeft: 20 }}>
              {result.blocking.map((b, i) => (
                <li key={i}>{b.message}</li>
              ))}
            </ul>
          </>
        )}
        {result && 'token' in result && (
          <>
            <label style={label} htmlFor={`${id}-out`}>
              Paste into the pull request description
            </label>
            <textarea id={`${id}-out`} readOnly value={result.prDescriptionSnippet} rows={4} style={{ ...field, fontFamily: token('font.family.code') }} onFocus={(e) => e.currentTarget.select()} />
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <Button appearance="primary" onClick={() => void copy(result.prDescriptionSnippet)}>
                Copy attestation
              </Button>
              <span style={{ font: token('font.body.small'), color: token('color.text.subtle') }}>
                {copied ? 'Copied. ' : ''}Valid for this commit until {result.expiresAt.slice(0, 16).replace('T', ' ')} UTC.
              </span>
            </div>
          </>
        )}
      </div>
    </form>
  );
}

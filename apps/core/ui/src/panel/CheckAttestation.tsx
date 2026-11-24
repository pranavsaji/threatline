import { useId, useState, type FormEvent } from 'react';
import Button from '@atlaskit/button/new';
import Lozenge from '@atlaskit/lozenge';
import { token } from '@atlaskit/tokens';
import { errorText as errorTextOf, isError, type AttestationCheck, type PanelApi } from '../bridge.js';
import type { ApiError } from '../types.js';
import { box, errorText, field, label } from './form-styles.js';
import { useInFlight } from '../components/in-flight.js';

const REPO = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
const SHA = /^[0-9a-fA-F]{40}$/;
const small = { font: token('font.body.small'), color: token('color.text.subtle') };

/**
 * "Check an attestation": paste a merge attestation (and, optionally, the repository and commit it should be for) and
 * see whether this site's Threatline key signed it, or exactly why not. Open to anyone who can view the work item.
 */
export function CheckAttestation({ api }: { api: PanelApi }) {
  const id = useId();
  const [text, setText] = useState('');
  const [repo, setRepo] = useState('');
  const [sha, setSha] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AttestationCheck | null>(null);
  const { busy, run } = useInFlight();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setResult(null);
    if (!text.trim()) return setError('Paste an attestation to check.');
    if (repo.trim() && !REPO.test(repo.trim())) return setError('Give the repository as workspace/repository or owner/repository, for example acme/payments, or leave it empty.');
    if (sha.trim() && !SHA.test(sha.trim())) return setError('Give the full 40-character commit hash, or leave it empty.');
    await run(async () => {
      const r = await api.checkAttestation(text.trim(), { repo: repo.trim() || undefined, commitSha: sha.trim() || undefined }).catch((): ApiError => ({ error: 'unavailable' }));
      if (isError(r)) return setError(errorTextOf(r));
      setError(null);
      setResult(r);
    });
  };

  const a = result?.attestation;
  return (
    <details style={box}>
      <summary style={{ cursor: 'pointer', fontWeight: 600 }}>Check an attestation</summary>
      <form aria-label="Check an attestation" onSubmit={submit} style={{ display: 'grid', gap: 8, marginTop: 8 }}>
        <span style={small}>Paste a Threatline merge attestation to see whether this site’s Threatline key signed it. Change one character and check again: the signature no longer verifies.</span>
        <label style={label} htmlFor={`${id}-token`}>
          Attestation
        </label>
        <textarea
          id={`${id}-token`}
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={3}
          spellCheck={false}
          placeholder="threatline-att.v1.…"
          style={{ ...field, fontFamily: token('font.family.code'), wordBreak: 'break-all' }}
        />
        <label style={label} htmlFor={`${id}-repo`}>
          Repository (optional)
        </label>
        <input id={`${id}-repo`} value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="acme/payments" style={field} />
        <label style={label} htmlFor={`${id}-sha`}>
          Commit hash (optional)
        </label>
        <input id={`${id}-sha`} value={sha} onChange={(e) => setSha(e.target.value)} placeholder="40-character commit hash" maxLength={40} style={{ ...field, fontFamily: token('font.family.code') }} />
        {error && (
          <p role="alert" style={errorText}>
            {error}
          </p>
        )}
        <div>
          <Button type="submit" isDisabled={busy}>
            Check
          </Button>
        </div>
        <div role="status" style={{ display: 'grid', gap: 4 }}>
          {result && (
            <>
              <span>
                <Lozenge appearance={result.valid ? 'success' : 'removed'} isBold>
                  {result.valid ? 'Valid' : 'Not valid'}
                </Lozenge>
              </span>
              <span style={{ overflowWrap: 'anywhere' }}>{result.message}</span>
              {a && (
                <span style={{ ...small, overflowWrap: 'anywhere' }}>
                  Commit {a.commitSha}. {a.requirements.verified} of {a.requirements.total} requirements verified. Issued {a.issuedAt.slice(0, 16).replace('T', ' ')} UTC.
                </span>
              )}
            </>
          )}
        </div>
      </form>
    </details>
  );
}

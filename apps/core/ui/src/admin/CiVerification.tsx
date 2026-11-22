import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from 'react';
import Button from '@atlaskit/button/new';
import { token } from '@atlaskit/tokens';
import { errorText, isError } from '../bridge.js';
import type { ApiError, CiTokenInfo, CiTokensDto } from '../types.js';
import { useInFlight } from '../components/in-flight.js';
import { field, label } from '../panel/form-styles.js';
import type { CiApi } from './ci-api.js';

const code = { fontFamily: token('font.family.code'), font: token('font.body.small'), wordBreak: 'break-all' as const, padding: 8, borderRadius: 4, background: token('elevation.surface.sunken'), margin: 0 };
const small = { font: token('font.body.small'), color: token('color.text.subtle') };

/**
 * Verification from CI (docs/CI_VERIFICATION.md): the web trigger CI posts test results to, and the per-site CI tokens
 * it authenticates with. A new token is shown once; Threatline keeps only its hash. Revoking stops it at once.
 *
 * The token list lives in Forge KVS, whose reads can lag a write by a moment. So the page remembers what it just created
 * or revoked until a read agrees, and a stale read never brings a revoked token back or hides a new one.
 */
export function CiVerification({ api }: { api: CiApi }) {
  const id = useId();
  const [dto, setDto] = useState<CiTokensDto | null>(null);
  const [projects, setProjects] = useState('');
  const [created, setCreated] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const { busy, run } = useInFlight();
  const pending = useRef({ created: new Map<string, CiTokenInfo>(), revoked: new Set<string>() });

  const load = useCallback(async () => {
    const r = await api.tokens().catch((): ApiError => ({ error: 'unavailable' }));
    if (isError(r)) return setMessage(errorText(r));
    const { created, revoked } = pending.current;
    const listed = new Set(r.tokens.map((t) => t.id));
    for (const id of created.keys()) if (listed.has(id)) created.delete(id);
    for (const id of revoked) if (!listed.has(id)) revoked.delete(id);
    const tokens = [...r.tokens.filter((t) => !revoked.has(t.id)), ...[...created.values()].filter((t) => !revoked.has(t.id))];
    setDto({ ...r, tokens });
  }, [api]);
  useEffect(() => {
    void load();
  }, [load]);

  const copy = async (text: string, what: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setMessage(`${what} copied.`);
    } catch {
      setMessage(`Copy failed. Select the ${what.toLowerCase()} above and copy it.`);
    }
  };

  const create = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const keys = projects.split(/[\s,]+/).map((p) => p.trim().toUpperCase()).filter(Boolean);
      const r = await api.create(keys).catch((): ApiError => ({ error: 'unavailable' }));
      if (isError(r)) return setMessage(errorText(r));
      pending.current.created.set(r.info.id, r.info);
      setCreated(r.token);
      setProjects('');
      setMessage(`Token ${r.info.id} created.`);
      await load();
    });
  };

  const revoke = (tokenId: string) =>
    run(async () => {
      const r = await api.revoke(tokenId).catch((): ApiError => ({ error: 'unavailable' }));
      setRevoking(null);
      if (isError(r)) {
        setMessage(errorText(r));
        return load();
      }
      pending.current.revoked.add(tokenId);
      pending.current.created.delete(tokenId);
      setMessage(`Token ${tokenId} revoked. CI reports sent with it are refused from now on.`);
      await load();
    });

  return (
    <section aria-labelledby={`${id}-h`} style={{ display: 'grid', gap: 8 }}>
      <h2 id={`${id}-h`} style={{ font: token('font.heading.small'), margin: 0 }}>
        CI verification
      </h2>
      <p style={{ margin: 0, color: token('color.text.subtle') }}>
        CI can mark a requirement Verified when its tests pass: tests named with the requirement id (as the copied test skeletons are) report to this URL with a CI token, and
        the run becomes the evidence. CI can only verify: it never accepts a risk, marks anything Not applicable or overrides the gate.
      </p>
      {dto && (
        <>
          <span style={{ font: token('font.body.small') }}>Web trigger URL</span>
          {dto.url ? (
            <>
              <pre style={code}>{dto.url}</pre>
              <div>
                <Button onClick={() => void copy(dto.url!, 'URL')}>Copy URL</Button>
              </div>
            </>
          ) : (
            <span style={small}>Threatline could not read the web trigger URL. Reload the page in a minute.</span>
          )}
          {dto.tokens.length === 0 ? (
            <span style={small}>No CI tokens yet.</span>
          ) : (
            <ul aria-label="CI tokens" style={{ margin: 0, paddingLeft: 20, display: 'grid', gap: 4 }}>
              {dto.tokens.map((t) => (
                <li key={t.id}>
                  <span style={{ font: token('font.body.small') }}>
                    Token {t.id} · created {t.createdAt.slice(0, 10)} · {t.projects.length ? `projects ${t.projects.join(', ')}` : 'every Threatline project'}
                  </span>{' '}
                  {revoking === t.id ? (
                    <>
                      <Button appearance="warning" spacing="compact" onClick={() => void revoke(t.id)} isDisabled={busy}>
                        Confirm revoke
                      </Button>{' '}
                      <Button appearance="subtle" spacing="compact" onClick={() => setRevoking(null)}>
                        Cancel
                      </Button>
                    </>
                  ) : (
                    <Button spacing="compact" aria-label={`Revoke ${t.id}`} onClick={() => setRevoking(t.id)}>
                      Revoke
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      {created && (
        <div style={{ display: 'grid', gap: 8 }}>
          <span style={{ font: token('font.body.small') }}>
            New CI token. This is the only time Threatline shows it: store it as a secret in your CI (for example THREATLINE_CI_TOKEN).
          </span>
          <pre style={code}>{created}</pre>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <Button appearance="primary" onClick={() => void copy(created, 'Token')}>
              Copy token
            </Button>
            <Button appearance="subtle" onClick={() => setCreated(null)}>
              I have stored it
            </Button>
          </div>
        </div>
      )}
      <form aria-label="Create CI token" onSubmit={create} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'end' }}>
        <label style={label}>
          Limit to projects (optional, comma-separated)
          <input value={projects} onChange={(e) => setProjects(e.target.value)} placeholder="PAY, SEC" style={field} />
        </label>
        <Button type="submit" isDisabled={busy}>
          Create token
        </Button>
      </form>
      <p role="status" style={{ margin: 0 }}>
        {message}
      </p>
    </section>
  );
}

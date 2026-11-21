import { describe, expect, it } from 'vitest';
import { authenticateCi, CI_TOKENS_KEY, createCiToken, listCiTokens, MAX_CI_TOKENS, revokeCiToken } from '../../src/services/ci-tokens.js';
import { coreDeps } from '../support/core-deps.js';

const ADMIN = 'acc-admin';
const ledgerTypes = async (t: ReturnType<typeof coreDeps>) => ((await t.deps.ledger.all()) as { ok: true; value: Array<{ eventType: string; actor: string; payload: Record<string, unknown> }> }).value;

describe('CI tokens (feature: verification from CI)', () => {
  it('creates a token shown once, stores only its hash in secret storage, and ledgers the creation (no secret in the ledger)', async () => {
    const t = coreDeps();
    const r = await createCiToken(t.deps, ADMIN, { projects: ['PAY'] });
    if (!r.ok) throw new Error(r.error.message);
    expect(r.value.token).toMatch(/^tlci_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/);
    expect(r.value.info).toEqual({ id: r.value.token.slice(5, 21), createdAt: '2026-11-15T12:00:00.000Z', createdBy: ADMIN, projects: ['PAY'] });
    const stored = JSON.stringify([...t.kv.data.entries(), ...t.kv.secrets.entries()]);
    expect(stored).not.toContain(r.value.token);
    expect(stored).not.toContain(r.value.token.slice(22));
    expect(t.kv.secrets.get(`secret:ci-token:${r.value.info.id}`)).toMatchObject({ hash: expect.stringMatching(/^[0-9a-f]{64}$/), projects: ['PAY'] });
    const rows = await ledgerTypes(t);
    expect(rows.at(-1)).toMatchObject({ eventType: 'ci_token.created', actor: ADMIN, payload: { tokenId: r.value.info.id, projects: ['PAY'] } });
    expect(JSON.stringify(rows)).not.toContain(r.value.token.slice(22));
    expect(await listCiTokens(t.deps)).toEqual({ ok: true, value: [r.value.info] });
  });

  it('authenticates only the exact bearer token, and revoking it stops it at once', async () => {
    const t = coreDeps();
    const r = await createCiToken(t.deps, ADMIN, { projects: [] });
    if (!r.ok) throw new Error('create');
    const token = r.value.token;
    expect(await authenticateCi(t.deps, `Bearer ${token}`)).toEqual({ ok: true, value: { id: r.value.info.id, projects: [] } });
    expect(await authenticateCi(t.deps, `bearer ${token}`)).toMatchObject({ ok: true });
    const wrong = token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A');
    for (const h of [undefined, '', token, `Basic ${token}`, `Bearer ${wrong}`, `Bearer ${token}x`, `Bearer tlci_0000000000000000_${token.slice(22)}`, `Bearer ${token} ${token}`])
      expect(await authenticateCi(t.deps, h), String(h)).toEqual({ ok: false, error: 'unauthorized' });
    expect((await revokeCiToken(t.deps, ADMIN, r.value.info.id)).ok).toBe(true);
    expect(await authenticateCi(t.deps, `Bearer ${token}`)).toEqual({ ok: false, error: 'unauthorized' });
    expect(await listCiTokens(t.deps)).toEqual({ ok: true, value: [] });
    expect((await ledgerTypes(t)).at(-1)).toMatchObject({ eventType: 'ci_token.revoked', actor: ADMIN, payload: { tokenId: r.value.info.id } });
  });

  it('fails closed: a storage error is unavailable, never a pass; a corrupt secret is unauthorized', async () => {
    const t = coreDeps();
    const r = await createCiToken(t.deps, ADMIN, { projects: [] });
    if (!r.ok) throw new Error('create');
    t.kv.secrets.set(`secret:ci-token:${r.value.info.id}`, { hash: 'nope' });
    expect(await authenticateCi(t.deps, `Bearer ${r.value.token}`)).toEqual({ ok: false, error: 'unauthorized' });
    t.deps.state.getSecret = async () => Promise.reject(new Error('kvs down'));
    expect(await authenticateCi(t.deps, `Bearer ${r.value.token}`)).toEqual({ ok: false, error: 'unavailable' });
  });

  it('refuses bad project keys and more than the maximum number of tokens; nothing is stored when the ledger fails', async () => {
    const t = coreDeps();
    expect(await createCiToken(t.deps, ADMIN, { projects: ['pay; drop'] })).toMatchObject({ ok: false, error: { code: 'validation' } });
    for (let i = 0; i < MAX_CI_TOKENS; i++) expect((await createCiToken(t.deps, ADMIN, { projects: [] })).ok).toBe(true);
    expect(await createCiToken(t.deps, ADMIN, { projects: [] })).toMatchObject({ ok: false, error: { code: 'validation' } });
    const u = coreDeps();
    u.deps.ledger.append = async () => ({ ok: false, error: { code: 'upstream', message: 'sql down' } });
    expect((await createCiToken(u.deps, ADMIN, { projects: [] })).ok).toBe(false);
    expect(u.kv.secrets.size).toBe(0);
    expect(u.kv.data.get(CI_TOKENS_KEY)).toBeUndefined();
  });

  it('revoking an unknown token is not_found', async () => {
    const t = coreDeps();
    expect(await revokeCiToken(t.deps, ADMIN, '0123456789abcdef')).toMatchObject({ ok: false, error: { code: 'not_found' } });
    expect(await revokeCiToken(t.deps, ADMIN, '../x')).toMatchObject({ ok: false, error: { code: 'validation' } });
  });
});

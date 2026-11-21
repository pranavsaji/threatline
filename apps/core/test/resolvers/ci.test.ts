import { describe, expect, it } from 'vitest';
import { ok } from '@threatline/shared';
import { ciCreateToken, ciRevokeToken, ciTokens } from '../../src/resolvers/ci.js';
import { resolverTable } from '../../src/resolvers/table.js';
import { coreDeps } from '../support/core-deps.js';

const ADMIN = { accountId: 'acc-admin' };
const DEV = { accountId: 'acc-dev' };
const URL_ = 'https://abc.hello.atlassian-dev.net/x1/trigger-id';

function setup() {
  const t = coreDeps();
  t.jira.isAdmin = async (id) => ok(id === ADMIN.accountId);
  return t;
}

describe('admin: CI verification (feature: verification from CI)', () => {
  it('shows the web trigger URL and the tokens (never a secret); creating shows the token once', async () => {
    const t = setup();
    const env = { triggerUrl: async () => URL_ };
    expect(await ciTokens(t.deps, ADMIN, env)).toEqual({ url: URL_, tokens: [] });
    const made = await ciCreateToken(t.deps, ADMIN, { projects: ['pay'] });
    if ('error' in made) throw new Error(made.error);
    expect(made.token).toMatch(/^tlci_/);
    expect(made.info.projects).toEqual(['PAY']);
    const listed = await ciTokens(t.deps, ADMIN, env);
    expect(listed).toEqual({ url: URL_, tokens: [made.info] });
    expect(JSON.stringify(listed)).not.toContain(made.token.slice(22));
    expect(await ciRevokeToken(t.deps, ADMIN, { id: made.info.id })).toEqual({ id: made.info.id });
    expect(await ciTokens(t.deps, ADMIN, env)).toEqual({ url: URL_, tokens: [] });
  });

  it('Jira administrators only', async () => {
    const t = setup();
    for (const r of [await ciTokens(t.deps, DEV, { triggerUrl: async () => URL_ }), await ciCreateToken(t.deps, DEV, {}), await ciRevokeToken(t.deps, DEV, { id: '0123456789abcdef' })])
      expect(r).toMatchObject({ error: 'forbidden' });
    expect(t.kv.secrets.size).toBe(0);
  });

  it('a URL that cannot be read is null (the page says so); bad input is a validation error', async () => {
    const t = setup();
    expect(await ciTokens(t.deps, ADMIN, { triggerUrl: async () => Promise.reject(new Error('no')) })).toEqual({ url: null, tokens: [] });
    expect(await ciCreateToken(t.deps, ADMIN, { projects: 'PAY' })).toMatchObject({ error: 'validation' });
    expect(await ciRevokeToken(t.deps, ADMIN, { id: 7 })).toMatchObject({ error: 'validation' });
    expect(await ciRevokeToken(t.deps, ADMIN, { id: '0123456789abcdef' })).toEqual({ error: 'not_found' });
  });

  it('the resolver table registers the three keys', () => {
    const table = resolverTable({ enricher: () => ({}) as never, signingKeysReady: async () => true });
    for (const k of ['ci.tokens', 'ci.createToken', 'ci.revokeToken']) expect(typeof table[k], k).toBe('function');
  });
});

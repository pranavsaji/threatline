// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEventLib from '@testing-library/user-event';
import axe from 'axe-core';
import { AdminPage } from '../src/admin/AdminPage.js';
import { IssuePanel } from '../src/panel/IssuePanel.js';
import { mockAdminApi, mockApi } from '../src/mock-bridge.js';
import { FIXTURES } from '../src/fixtures.js';
import { ciApiOver, type CiApi } from '../src/admin/ci-api.js';
import type { PanelApi } from '../src/bridge.js';
import type { PanelDto } from '../src/types.js';

afterEach(cleanup);
const userEvent = userEventLib.setup({ delay: null });

const URL_ = 'https://abc.hello.atlassian-dev.net/x1/ci-verify-trigger';
const INFO = { id: '0123456789abcdef', createdAt: '2026-11-20T10:00:00.000Z', createdBy: 'acc-admin', projects: ['PAY'] };
const TOKEN = 'tlci_fedcba9876543210_' + 'S'.repeat(43);

function ciApi(over: Partial<CiApi> = {}): CiApi {
  let tokens = [INFO];
  return {
    tokens: async () => ({ url: URL_, tokens: structuredClone(tokens) }),
    create: async (projects) => {
      const info = { ...INFO, id: 'fedcba9876543210', projects };
      tokens = [...tokens, info];
      return { token: TOKEN, info };
    },
    revoke: async (id) => ((tokens = tokens.filter((t) => t.id !== id)), { id }),
    ...over,
  };
}
const section = async () => screen.findByRole('region', { name: 'CI verification' });

describe('Admin: CI verification (feature: verification from CI)', () => {
  it('shows the web trigger URL and the tokens, and copies the URL', async () => {
    const write = vi.spyOn(navigator.clipboard, 'writeText');
    render(<AdminPage api={{ ...mockAdminApi(), ci: ciApi() }} />);
    const s = await section();
    expect(await within(s).findByText(URL_)).toBeTruthy();
    expect(within(s).getByText(/0123456789abcdef/).textContent).toMatch(/PAY/);
    await userEvent.click(within(s).getByRole('button', { name: 'Copy URL' }));
    expect(write).toHaveBeenCalledWith(URL_);
  });

  it('creates a token limited to projects and shows it once; it is gone after Done', async () => {
    const ci = ciApi();
    const create = vi.spyOn(ci, 'create');
    render(<AdminPage api={{ ...mockAdminApi(), ci }} />);
    const s = await section();
    await userEvent.type(within(s).getByRole('textbox', { name: /Limit to projects/ }), 'pay, sec');
    await userEvent.click(within(s).getByRole('button', { name: 'Create token' }));
    expect(create).toHaveBeenCalledWith(['PAY', 'SEC']);
    expect(await within(s).findByText(TOKEN)).toBeTruthy();
    expect(within(s).getByText(/only time Threatline shows it/)).toBeTruthy();
    await userEvent.click(within(s).getByRole('button', { name: 'I have stored it' }));
    expect(within(s).queryByText(TOKEN)).toBeNull();
    expect(within(within(s).getByRole('list', { name: 'CI tokens' })).getByText(/fedcba9876543210/).textContent).toMatch(/PAY, SEC/);
  });

  it('revoking asks for confirmation first', async () => {
    const ci = ciApi();
    const revoke = vi.spyOn(ci, 'revoke');
    render(<AdminPage api={{ ...mockAdminApi(), ci }} />);
    const s = await section();
    await userEvent.click(await within(s).findByRole('button', { name: 'Revoke 0123456789abcdef' }));
    expect(revoke).not.toHaveBeenCalled();
    await userEvent.click(within(s).getByRole('button', { name: 'Confirm revoke' }));
    expect(revoke).toHaveBeenCalledWith('0123456789abcdef');
    expect(await within(s).findByText(/Token 0123456789abcdef revoked/)).toBeTruthy();
    await waitFor(() => expect(within(s).queryByRole('list', { name: 'CI tokens' })).toBeNull());
    expect(within(s).getByText(/No CI tokens yet/)).toBeTruthy();
  });

  it('a stale read right after revoking does not bring the token back (Forge KVS can lag a write)', async () => {
    const ci = ciApi({ tokens: async () => ({ url: URL_, tokens: [INFO] }) });
    render(<AdminPage api={{ ...mockAdminApi(), ci }} />);
    const s = await section();
    await userEvent.click(await within(s).findByRole('button', { name: 'Revoke 0123456789abcdef' }));
    await userEvent.click(within(s).getByRole('button', { name: 'Confirm revoke' }));
    expect(await within(s).findByText(/Token 0123456789abcdef revoked/)).toBeTruthy();
    await waitFor(() => expect(within(s).queryByRole('button', { name: 'Revoke 0123456789abcdef' })).toBeNull());
    expect(within(s).getByText(/No CI tokens yet/)).toBeTruthy();
  });

  it('a stale read right after creating still lists the new token', async () => {
    const ci = ciApi({ tokens: async () => ({ url: URL_, tokens: [INFO] }) });
    render(<AdminPage api={{ ...mockAdminApi(), ci }} />);
    const s = await section();
    await userEvent.click(within(s).getByRole('button', { name: 'Create token' }));
    await within(s).findByText(TOKEN);
    const list = within(s).getByRole('list', { name: 'CI tokens' });
    expect(within(list).getByText(/fedcba9876543210/)).toBeTruthy();
    expect(within(list).getByText(/0123456789abcdef/)).toBeTruthy();
  });

  it('a token someone else already revoked leaves the list instead of showing an error', async () => {
    const ci = ciApi({ revoke: async () => ({ error: 'not_found', message: 'CI token not found' }) });
    render(<AdminPage api={{ ...mockAdminApi(), ci }} />);
    const s = await section();
    await userEvent.click(await within(s).findByRole('button', { name: 'Revoke 0123456789abcdef' }));
    await userEvent.click(within(s).getByRole('button', { name: 'Confirm revoke' }));
    expect(await within(s).findByText(/Token 0123456789abcdef was already revoked/)).toBeTruthy();
    await waitFor(() => expect(within(s).queryByRole('button', { name: 'Revoke 0123456789abcdef' })).toBeNull());
  });

  it('says so when the URL cannot be read, and shows the server’s errors', async () => {
    render(<AdminPage api={{ ...mockAdminApi(), ci: ciApi({ tokens: async () => ({ url: null, tokens: [] }), create: async () => ({ error: 'validation', message: 'A site can have at most 10 CI tokens.' }) }) }} />);
    const s = await section();
    expect(await within(s).findByText(/could not read the web trigger URL/)).toBeTruthy();
    expect(within(s).getByText(/No CI tokens yet/)).toBeTruthy();
    await userEvent.click(within(s).getByRole('button', { name: 'Create token' }));
    expect(await within(s).findByText('A site can have at most 10 CI tokens.')).toBeTruthy();
  });

  it('the bridge calls the three resolvers', async () => {
    const invoke = vi.fn(async () => ({}) as never);
    const api = ciApiOver(invoke);
    await api.tokens();
    await api.create(['PAY']);
    await api.revoke('0123456789abcdef');
    expect(invoke.mock.calls).toEqual([['ci.tokens'], ['ci.createToken', { projects: ['PAY'] }], ['ci.revokeToken', { id: '0123456789abcdef' }]]);
  });

  it.each(['light', 'dark'])('has no axe violations with a new token shown (%s)', async (mode) => {
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = render(<AdminPage api={{ ...mockAdminApi(), ci: ciApi() }} />);
    const s = await section();
    await userEvent.click(within(s).getByRole('button', { name: 'Create token' }));
    await within(s).findByText(TOKEN);
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
  });
});

describe('Panel: CI evidence', () => {
  it('links to the CI run and names the repository and commit', async () => {
    const run = 'https://github.com/acme/payments/actions/runs/42';
    const base = mockApi('pass');
    const get: PanelApi['get'] = async () => {
      const dto = structuredClone(FIXTURES.pass!) as PanelDto;
      return {
        ...dto,
        roles: ['viewer'],
        requirements: dto.requirements.map((r) => ({ ...r, status: 'Verified' as const, evidence: { kind: 'ci' as const, ref: run, commitSha: 'ab'.repeat(20), repo: 'acme/payments', note: '2 test(s) passed', attester: 'ci:0123456789abcdef' } })),
      };
    };
    render(<IssuePanel api={{ ...base, get }} />);
    await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
    await userEvent.click(screen.getByRole('tab', { name: /Requirements/ }));
    const link = screen.getAllByRole('link', { name: 'CI run' })[0]!;
    expect(link.getAttribute('href')).toBe(run);
    expect(link.closest('span')!.textContent).toMatch(/acme\/payments @ abababababab/);
    expect(link.closest('span')!.textContent).toMatch(/2 test\(s\) passed/);
  });

  it('never links a CI ref that is not https', async () => {
    const base = mockApi('pass');
    const get: PanelApi['get'] = async () => {
      const dto = structuredClone(FIXTURES.pass!) as PanelDto;
      return { ...dto, roles: ['viewer'], requirements: dto.requirements.map((r) => ({ ...r, status: 'Verified' as const, evidence: { kind: 'ci' as const, ref: 'javascript:alert(1)', attester: 'ci:x' } })) };
    };
    render(<IssuePanel api={{ ...base, get }} />);
    await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
    await userEvent.click(screen.getByRole('tab', { name: /Requirements/ }));
    expect(screen.queryAllByRole('link', { name: 'CI run' })).toEqual([]);
    expect(screen.getAllByText(/javascript:alert\(1\)/).length).toBeGreaterThan(0);
  });
});

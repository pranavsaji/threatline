// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEventLib from '@testing-library/user-event';
import axe from 'axe-core';
import { IssuePanel } from '../src/panel/IssuePanel.js';
import { mockApi } from '../src/mock-bridge.js';
import { FIXTURES } from '../src/fixtures.js';
import type { PanelApi } from '../src/bridge.js';

afterEach(cleanup);
const userEvent = userEventLib.setup({ delay: null });

async function open(api: PanelApi) {
  const r = render(<IssuePanel api={api} />);
  await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
  return r;
}

describe('Delivery check (Teamwork Graph)', () => {
  it('warns when the work item shipped to production while the gate blocks', async () => {
    await open(mockApi('ready'));
    expect(await screen.findByText('Shipped to production with security requirements open')).toBeTruthy();
    expect(screen.getByText(/2 security requirements were still open \(highest: Critical\)/)).toBeTruthy();
  });

  it('a passing work item shows no alert, and the Delivery tab lists pull requests and deployments with safe links', async () => {
    const r = await open(mockApi('pass'));
    await userEvent.click(await screen.findByRole('tab', { name: /Delivery \(4\)/ }));
    expect(screen.queryByText('Shipped to production with security requirements open')).toBeNull();
    const prs = screen.getByRole('list', { name: 'Linked pull requests' });
    const link = within(prs).getByRole('link', { name: '#2 Verify webhook signatures' });
    expect(link.getAttribute('rel')).toBe('noopener noreferrer');
    expect(within(screen.getByRole('list', { name: 'Linked deployments' })).getByText(/to Production \(production\)/)).toBeTruthy();
    expect((await axe.run(r.container)).violations).toEqual([]);
  });

  it('linked pull requests fill the evidence form in one click', async () => {
    const base = mockApi('ready');
    const setStatus = vi.fn(base.setStatus);
    await open({ ...base, get: async () => ({ ...structuredClone(FIXTURES.ready!), roles: ['viewer', 'developer'] }), setStatus });
    await screen.findByText('Shipped to production with security requirements open');
    await userEvent.click(screen.getByRole('tab', { name: /Requirements/ }));
    const item = screen.getAllByRole('listitem').find((li) => within(li).queryByText('Magic links expire after 15 minutes'))!;
    await userEvent.selectOptions(within(item).getByRole('combobox', { name: 'Status' }), 'Verified');
    const form = within(item).getByRole('form', { name: 'Verification evidence' });
    await userEvent.click(within(form).getByRole('button', { name: 'Use #2 Verify webhook signatures' }));
    await userEvent.click(within(form).getByRole('button', { name: 'Save evidence' }));
    expect(setStatus).toHaveBeenCalledWith('req_2', 'Verified', { kind: 'pr', ref: 'https://bitbucket.org/acme/payments-service/pull-requests/2' });
  });

  it('a host without the delivery call (older bridge) shows no Delivery tab', async () => {
    const { delivery: _omit, ...api } = mockApi('ready');
    await open(api);
    expect(screen.queryByRole('tab', { name: /Delivery/ })).toBeNull();
    expect(screen.queryByText('Shipped to production with security requirements open')).toBeNull();
  });
});

// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEventLib from '@testing-library/user-event';
import axe from 'axe-core';
import { IssuePanel } from '../src/panel/IssuePanel.js';
import { Suppressions } from '../src/admin/Suppressions.js';
import { mockAdminApi, mockApi } from '../src/mock-bridge.js';
import { FIXTURES } from '../src/fixtures.js';
import type { AdminApi, PanelApi } from '../src/bridge.js';
import type { PanelDto, Threat } from '../src/types.js';

afterEach(cleanup);
const userEvent = userEventLib.setup({ delay: null });

const RULE = 'sup_01JDEMO0000000000000000000';
const hide = (t: Threat): Threat =>
  t.id === 'thr_4'
    ? { ...t, state: 'suppressed', suppression: { ruleId: RULE, reason: 'Rate limited at the gateway.', expiresAt: '2027-01-30T10:00:00.000Z', outcome: 'hidden', restoreTo: 'needs_human' } }
    : t.id === 'thr_1'
      ? { ...t, suppression: { ruleId: 'sup_02', reason: 'Links are single use.', expiresAt: '2027-01-30T10:00:00.000Z', outcome: 'blocking' } }
      : t;
const dto = (champion: boolean): PanelDto => ({ ...structuredClone(FIXTURES.ready!), threats: FIXTURES.ready!.threats.map(hide), roles: champion ? ['viewer', 'developer', 'champion'] : ['viewer', 'developer'] });

async function panel(champion: boolean, over: Partial<PanelApi> = {}) {
  const get = vi.fn(async () => dto(champion));
  const api: PanelApi = { ...mockApi('ready'), get, ...over };
  const r = render(<IssuePanel api={api} />);
  await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
  return { ...r, get };
}

describe('Panel: threats hidden by a team rule', () => {
  it('says which rule hid it, why and until when; a blocking threat notes the rule could not hide it', async () => {
    await panel(false);
    expect(screen.getByText('Hidden by team rule: Rate limited at the gateway. (expires 2027-01-30; rule sup_01JDEMO0000000000000000000).')).toBeTruthy();
    expect(screen.getByText(/Team rule sup_02 matched this threat \(Links are single use\.\), but a rule cannot hide a threat at or above the blocking level\./)).toBeTruthy();
    // Viewers who are not champions get no unhide action, and nobody triages a hidden threat.
    expect(screen.queryByRole('button', { name: /Unhide here/ })).toBeNull();
  });

  it('a champion unhides it here: the call names the rule, and the panel reloads', async () => {
    const unhide = vi.fn(async () => [] as Threat[]);
    const { get } = await panel(true, { unhide });
    const card = screen.getByText(/Hidden by team rule: Rate limited/).closest('article')!;
    await userEvent.click(within(card as HTMLElement).getByRole('button', { name: 'Unhide here: Reset endpoint can be flooded' }));
    expect(unhide).toHaveBeenCalledWith(RULE);
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
  });

  it('shows the server’s refusal', async () => {
    await panel(true, { unhide: async () => ({ error: 'forbidden', message: 'Only a security champion can do this.' }) });
    await userEvent.click(screen.getByRole('button', { name: /Unhide here/ }));
    expect(await screen.findByText('Only a security champion can do this.')).toBeTruthy();
  });
});

describe('Admin: Suppressions', () => {
  const renderSection = async (api: AdminApi = mockAdminApi()) => {
    const r = render(<Suppressions api={api} />);
    await screen.findByRole('list', { name: 'Active suppression rules' });
    return r;
  };

  it('lists active rules with their match counts, and suggestions with their evidence', async () => {
    await renderSection();
    const rules = screen.getByRole('list', { name: 'Active suppression rules' });
    expect(within(rules).getByText(/hid threats on 4 work items/)).toBeTruthy();
    expect(within(rules).getByText(/Every PAY endpoint sits behind the gateway rate limiter/)).toBeTruthy();
    const evidence = screen.getByRole('list', { name: 'Evidence for PAY: Customer email leaks in webhook logs' });
    expect(within(evidence).getAllByRole('listitem')).toHaveLength(3);
    expect(within(evidence).getByText(/PAY-28: “Customer email written to webhook logs”, already mitigated/)).toBeTruthy();
  });

  it('one click creates the suggested rule, prefilled, for 90 days', async () => {
    const base = mockAdminApi();
    const createSuppression = vi.fn(base.createSuppression);
    await renderSection({ ...base, createSuppression });
    await userEvent.click(screen.getByRole('button', { name: 'Create rule: PAY: Customer email leaks in webhook logs' }));
    expect(createSuppression).toHaveBeenCalledWith({
      projectKey: 'PAY', stride: 'InformationDisclosure', title: 'Customer email leaks in webhook logs', component: 'webhook endpoint', expiryDays: 90,
      reason: 'Dismissed as already mitigated on 3 work items (PAY-31, PAY-28, PAY-22).', evidence: ['PAY-31', 'PAY-28', 'PAY-22'],
    });
    expect(await screen.findByText(/No suggestions/)).toBeTruthy();
    expect(within(screen.getByRole('list', { name: 'Active suppression rules' })).getAllByRole('listitem')).toHaveLength(2);
  });

  it('“Edit first” prefills the form; the form refuses more than 90 days', async () => {
    const base = mockAdminApi();
    const createSuppression = vi.fn(base.createSuppression);
    await renderSection({ ...base, createSuppression });
    await userEvent.click(screen.getByRole('button', { name: 'Edit first: PAY: Customer email leaks in webhook logs' }));
    const form = screen.getByRole('form', { name: 'New suppression rule' });
    expect((within(form).getByRole('textbox', { name: 'Threat title (similar titles match)' }) as HTMLInputElement).value).toBe('Customer email leaks in webhook logs');
    const days = within(form).getByRole('spinbutton', { name: 'Days (1 to 90)' });
    await userEvent.clear(days);
    await userEvent.type(days, '120');
    await userEvent.click(within(form).getByRole('button', { name: 'Create rule' }));
    expect(await within(form).findByText('A rule lasts 1 to 90 days.')).toBeTruthy();
    expect(createSuppression).not.toHaveBeenCalled();
    await userEvent.clear(days);
    await userEvent.type(days, '30');
    await userEvent.click(within(form).getByRole('button', { name: 'Create rule' }));
    expect(createSuppression).toHaveBeenCalledWith(expect.objectContaining({ expiryDays: 30, title: 'Customer email leaks in webhook logs' }));
    expect(await screen.findByText(/Rule created for PAY/)).toBeTruthy();
  });

  it('revoke asks for a reason and shows the server’s refusal', async () => {
    const revokeSuppression = vi.fn(async () => ({ error: 'validation' as const, message: 'Write a reason of at least 10 characters.' }));
    await renderSection({ ...mockAdminApi(), revokeSuppression });
    await userEvent.click(screen.getByRole('button', { name: /^Revoke PAY:/ }));
    const form = screen.getByRole('form', { name: /^Revoke PAY:/ });
    await userEvent.type(within(form).getByRole('textbox', { name: 'Why revoke it' }), 'short');
    await userEvent.click(within(form).getByRole('button', { name: 'Confirm revoke' }));
    expect(revokeSuppression).toHaveBeenCalledWith('sup_01JDEMO0000000000000000000', 'short');
    expect(await screen.findByText('Write a reason of at least 10 characters.')).toBeTruthy();
  });

  it('a revoked rule leaves the list', async () => {
    await renderSection();
    await userEvent.click(screen.getByRole('button', { name: /^Revoke PAY:/ }));
    await userEvent.type(screen.getByRole('textbox', { name: 'Why revoke it' }), 'The gateway limiter was removed.');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm revoke' }));
    expect(await screen.findByText('No active rules.')).toBeTruthy();
  });

  it('a forbidden load says so', async () => {
    render(<Suppressions api={{ ...mockAdminApi(), suppressions: async () => ({ error: 'forbidden', message: 'Only a security champion or a Jira administrator can manage suppression rules.' }) }} />);
    expect(await screen.findByText('Only a security champion or a Jira administrator can manage suppression rules.')).toBeTruthy();
  });

  it('has no axe violations', async () => {
    const { container } = await renderSection();
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => v.id)).toEqual([]);
  });
});

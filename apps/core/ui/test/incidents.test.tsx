// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEventLib from '@testing-library/user-event';
import axe from 'axe-core';
import { IssuePanel } from '../src/panel/IssuePanel.js';
import { AdminPage } from '../src/admin/AdminPage.js';
import { INCIDENT_DEFAULTS } from '../src/admin/Incidents.js';
import { reopenedText } from '../src/panel/reopened.js';
import { mockAdminApi, mockApi } from '../src/mock-bridge.js';
import type { AdminApi } from '../src/bridge.js';
import type { SitePolicy } from '../src/types.js';
import { DEFAULT_INCIDENT_POLICY } from '../../../../packages/core/src/incidents.js';
import { DEMO_COMPONENT } from '../../src/seeder/content/demo.js';

afterEach(cleanup);
const userEvent = userEventLib.setup({ delay: null });

describe('panel: why a revision exists', () => {
  it('says which incident reopened the review, on the threats tab and in the history', async () => {
    render(<IssuePanel api={mockApi('reopened')} />);
    await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
    expect(screen.getByText('Re-reviewed because PAY-9 (incident) hit component Payments API on 2026-11-21.')).toBeTruthy();
    await userEvent.click(screen.getByRole('tab', { name: 'History' }));
    const why = screen.getByRole('list', { name: 'Why these revisions exist' });
    expect(within(why).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['Revision 2: Re-reviewed because PAY-9 (incident) hit component Payments API on 2026-11-21.']);
  });

  it('a review no incident reopened shows no reason', async () => {
    render(<IssuePanel api={mockApi('revised')} />);
    await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
    expect(screen.queryByText(/Re-reviewed because/)).toBeNull();
  });

  it('words: several components, a linked incident, an incident the viewer cannot open', () => {
    const at = '2026-11-21T09:11:00.000Z';
    expect(reopenedText({ incidentKey: 'PAY-9', components: ['API', 'Web', 'Jobs'], linked: false, at })).toBe('Re-reviewed because PAY-9 (incident) hit components API, Web and Jobs on 2026-11-21.');
    expect(reopenedText({ incidentKey: 'OPS-3', components: [], linked: true, at })).toBe('Re-reviewed because OPS-3 (incident), linked to this work item, was raised on 2026-11-21.');
    expect(reopenedText({ incidentKey: null, components: ['API'], linked: false, at })).toBe('Re-reviewed because an incident you cannot open hit component API on 2026-11-21.');
  });

  it('has no axe violations', async () => {
    const { container } = render(<IssuePanel api={mockApi('reopened')} />);
    await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
    const r = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });
});

describe('admin: demo data', () => {
  it('after loading, says how to show incidents reopening reviews (on the demo component)', async () => {
    const seed = vi.fn(async () => ({ epicKey: 'PAY-100', storyKeys: ['PAY-101'], designPageUrl: 'https://x/wiki/pages/500', incidentKeys: ['PAY-103'] }));
    render(<AdminPage api={{ ...mockAdminApi(), seed }} />);
    const f = await screen.findByRole('form', { name: 'Load demo data' });
    await userEvent.type(within(f).getByRole('textbox', { name: 'Jira project key' }), 'PAY');
    await userEvent.type(within(f).getByRole('textbox', { name: 'Confluence space key' }), 'PAY');
    await userEvent.click(within(f).getByRole('button', { name: 'Load demo data' }));
    expect(await screen.findByText(/create a work item labelled incident on the support-agent component/)).toBeTruthy();
  });

  it('names the seeder’s component', () => {
    expect(DEMO_COMPONENT).toBe('support-agent');
  });
});

describe('admin: incidents setting', () => {
  const withSpy = () => {
    const base = mockAdminApi();
    const setPolicy = vi.fn(base.setPolicy);
    return { api: { ...base, setPolicy } as AdminApi, setPolicy };
  };
  const form = () => screen.findByRole('form', { name: 'Incidents' });

  it('its defaults are the server’s', () => {
    expect(INCIDENT_DEFAULTS).toEqual(DEFAULT_INCIDENT_POLICY);
  });

  it('shows the defaults on a site that never saved it, and saves the setting into the site policy', async () => {
    const { api, setPolicy } = withSpy();
    render(<AdminPage api={api} />);
    const f = await form();
    expect((within(f).getByRole('checkbox', { name: 'Incidents reopen reviews' }) as HTMLInputElement).checked).toBe(true);
    expect((within(f).getByRole('textbox', { name: 'Incident labels (comma-separated)' }) as HTMLInputElement).value).toBe('incident');
    expect((within(f).getByRole('textbox', { name: 'Incident work types (comma-separated)' }) as HTMLInputElement).value).toBe('Incident');
    const max = within(f).getByRole('spinbutton', { name: 'Most work items re-reviewed per incident' });
    await userEvent.clear(max);
    await userEvent.type(max, '10');
    await userEvent.type(within(f).getByRole('textbox', { name: 'Incident labels (comma-separated)' }), ', sev1');
    await userEvent.click(within(f).getByRole('checkbox', { name: 'Comment on the incident with the work items re-reviewed' }));
    await userEvent.click(within(f).getByRole('button', { name: 'Save incident settings' }));
    await waitFor(() => expect(setPolicy).toHaveBeenCalled());
    const saved = setPolicy.mock.calls[0]![0] as SitePolicy;
    expect(saved.incidents).toEqual({ enabled: true, labels: ['incident', 'sev1'], issueTypes: ['Incident'], maxItems: 10, comment: false });
    expect(await within(f).findByText(/Saved/)).toBeTruthy();
  });

  it('refuses a cap outside 1 to 50 and an enabled rule that names nothing, without saving', async () => {
    const { api, setPolicy } = withSpy();
    render(<AdminPage api={api} />);
    const f = await form();
    const max = within(f).getByRole('spinbutton', { name: 'Most work items re-reviewed per incident' });
    await userEvent.clear(max);
    await userEvent.type(max, '80');
    await userEvent.click(within(f).getByRole('button', { name: 'Save incident settings' }));
    expect(await within(f).findByRole('alert')).toHaveProperty('textContent', 'An incident re-reviews 1 to 50 work items.');
    await userEvent.clear(max);
    await userEvent.type(max, '5');
    await userEvent.clear(within(f).getByRole('textbox', { name: 'Incident labels (comma-separated)' }));
    await userEvent.clear(within(f).getByRole('textbox', { name: 'Incident work types (comma-separated)' }));
    await userEvent.click(within(f).getByRole('button', { name: 'Save incident settings' }));
    expect(await within(f).findByText('Name at least one incident label or work type.')).toBeTruthy();
    expect(setPolicy).not.toHaveBeenCalled();
  });

  it('can be switched off', async () => {
    const { api, setPolicy } = withSpy();
    render(<AdminPage api={api} />);
    const f = await form();
    await userEvent.click(within(f).getByRole('checkbox', { name: 'Incidents reopen reviews' }));
    await userEvent.click(within(f).getByRole('button', { name: 'Save incident settings' }));
    await waitFor(() => expect(setPolicy).toHaveBeenCalled());
    expect((setPolicy.mock.calls[0]![0] as SitePolicy).incidents?.enabled).toBe(false);
  });
});

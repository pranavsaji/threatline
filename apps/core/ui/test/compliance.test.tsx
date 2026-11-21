// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import userEventLib from '@testing-library/user-event';
import axe from 'axe-core';
import { AdminPage } from '../src/admin/AdminPage.js';
import { ControlsView } from '../src/posture/ControlsView.js';
import { PostureDashboard } from '../src/posture/PostureDashboard.js';
import { RequirementsTab } from '../src/panel/RequirementsTab.js';
import { mockAdminApi, mockApi, mockPostureApi } from '../src/mock-bridge.js';
import { FIXTURES } from '../src/fixtures.js';
import type { PostureApi } from '../src/bridge.js';

afterEach(cleanup);
const userEvent = userEventLib.setup({ delay: null });

describe('Admin: controls summary export (compliance evidence)', () => {
  it('exports the controls summary for a project and date range, with downloads and a copy fallback', async () => {
    const exportControls = vi.fn(async () => ({ csv: 'framework,control_id\nSOC2,CC6.1\n', json: '{"frameworks":[]}' }));
    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    render(<AdminPage api={{ ...mockAdminApi(), exportControls }} />);
    const form = await screen.findByRole('form', { name: 'Controls summary' });
    expect(within(form).getByText(/indicative, not an audit opinion/i)).toBeTruthy();
    await userEvent.type(within(form).getByRole('textbox', { name: 'Project key' }), 'pay');
    await userEvent.type(within(form).getByLabelText('From'), '2026-11-01');
    await userEvent.type(within(form).getByLabelText('To'), '2026-11-30');
    await userEvent.click(within(form).getByRole('button', { name: 'Export controls' }));
    expect(exportControls).toHaveBeenCalledWith('PAY', '2026-11-01', '2026-11-30');
    const csv = await within(form).findByRole('link', { name: 'Download controls CSV' });
    expect(csv.getAttribute('download')).toBe('threatline-controls-PAY-2026-11-01-2026-11-30.csv');
    expect(within(form).getByRole('link', { name: 'Download controls JSON' }).getAttribute('download')).toBe('threatline-controls-PAY-2026-11-01-2026-11-30.json');
    await userEvent.click(within(form).getByRole('button', { name: 'Copy controls CSV' }));
    expect(writeText).toHaveBeenCalledWith('framework,control_id\nSOC2,CC6.1\n');
    expect(await within(form).findByText(/Copied the controls CSV/)).toBeTruthy();
  });

  it('asks for the inputs, and shows the server error', async () => {
    const exportControls = vi.fn(async () => ({ error: 'forbidden' as const, message: 'Only a Jira administrator can do this.' }));
    render(<AdminPage api={{ ...mockAdminApi(), exportControls }} />);
    const form = await screen.findByRole('form', { name: 'Controls summary' });
    await userEvent.click(within(form).getByRole('button', { name: 'Export controls' }));
    expect((await within(form).findByRole('alert')).textContent).toMatch(/project key and both dates/);
    expect(exportControls).not.toHaveBeenCalled();
    await userEvent.type(within(form).getByRole('textbox', { name: 'Project key' }), 'PAY');
    await userEvent.type(within(form).getByLabelText('From'), '2026-11-01');
    await userEvent.type(within(form).getByLabelText('To'), '2026-11-30');
    await userEvent.click(within(form).getByRole('button', { name: 'Export controls' }));
    expect((await within(form).findByRole('alert')).textContent).toBe('Only a Jira administrator can do this.');
  });
});

describe('Posture: Controls view', () => {
  it('lists controls per framework, coloured by state, and says it is indicative', async () => {
    render(<ControlsView api={mockPostureApi()} project="" />);
    const region = await screen.findByRole('region', { name: /Controls/ });
    expect(within(region).getByRole('heading', { name: 'Controls (indicative)' })).toBeTruthy();
    expect(within(region).getByText(/not an audit opinion/i)).toBeTruthy();
    const soc2 = within(region).getByRole('list', { name: 'SOC 2 Trust Services Criteria controls' });
    expect(within(soc2).getByRole('button', { name: /CC6\.1.*Open: 3 open, 4 verified, 1 accepted risk/ })).toBeTruthy();
    expect(within(soc2).getByRole('button', { name: /CC6\.3.*Accepted risk/ })).toBeTruthy();
    expect(within(soc2).getByRole('button', { name: /CC8\.1.*Verified/ })).toBeTruthy();
    await userEvent.click(within(region).getByRole('button', { name: 'PCI DSS', pressed: false }));
    const pci = within(region).getByRole('list', { name: 'PCI DSS controls' });
    expect(within(pci).getByRole('button', { name: /8\.3\.4/ })).toBeTruthy();
    expect(within(region).queryByRole('list', { name: 'SOC 2 Trust Services Criteria controls' })).toBeNull();
  });

  it('a control drills down to its work items', async () => {
    const controlDrill = vi.fn(mockPostureApi().controlDrill);
    render(<ControlsView api={{ ...mockPostureApi(), controlDrill }} project="PAY" />);
    await userEvent.click(await screen.findByRole('button', { name: /CC6\.1/ }));
    expect(controlDrill).toHaveBeenCalledWith({ framework: 'SOC2', control: 'CC6.1', project: 'PAY' });
    const drill = await screen.findByRole('region', { name: /Work items: SOC2 CC6\.1/ });
    expect(within(drill).getByRole('link', { name: 'PAY-7' }).getAttribute('href')).toBe('https://example.atlassian.net/browse/PAY-7');
  });

  it('with nothing mapped it says so; a failed load shows the error', async () => {
    render(<ControlsView api={mockPostureApi('empty')} project="" />);
    expect(await screen.findByText(/No requirements you can see map to/)).toBeTruthy();
    cleanup();
    const api: PostureApi = { ...mockPostureApi(), controls: async () => ({ error: 'unavailable' as const }) };
    render(<ControlsView api={api} project="" />);
    expect(await screen.findByRole('alert')).toBeTruthy();
  });

  it('is on the posture page but not in the gadget, and has no axe violations', async () => {
    const { container } = render(<PostureDashboard api={mockPostureApi()} />);
    await screen.findByRole('list', { name: 'SOC 2 Trust Services Criteria controls' });
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => v.id)).toEqual([]);
    cleanup();
    render(<PostureDashboard api={mockPostureApi()} compact />);
    await screen.findByRole('list', { name: 'Key numbers' });
    expect(screen.queryByRole('region', { name: /Controls/ })).toBeNull();
  });
});

describe('Panel: requirement control lozenges', () => {
  it('shows each mapped control id with its title (indicative) on the requirement card', async () => {
    const dto = structuredClone(FIXTURES.ready!);
    render(<RequirementsTab dto={dto} api={mockApi()} onChanged={() => {}} />);
    const list = screen.getByRole('list', { name: 'Security requirements' });
    const card = within(list).getByText('Re-authenticate before changing the account email').closest('li')!;
    const controls = within(card).getByRole('list', { name: 'Compliance controls (indicative)' });
    const iso = within(controls).getByLabelText(/ISO\/IEC 27001:2022 A\.8\.28: Secure coding/);
    expect(iso.textContent).toBe('A.8.28');
    expect(iso.getAttribute('aria-label')).toMatch(/indicative, not an audit opinion/);
    expect(within(controls).getAllByRole('listitem')).toHaveLength(5);
    // A requirement with no mapped control shows no list.
    const other = within(list).getByText('Magic links expire after 15 minutes').closest('li')!;
    expect(within(other).queryByRole('list', { name: 'Compliance controls (indicative)' })).toBeNull();
  });

  it('shows nothing when the server sends no controls', () => {
    const dto = { ...structuredClone(FIXTURES.ready!), requirementControls: undefined };
    render(<RequirementsTab dto={dto} api={mockApi()} onChanged={() => {}} />);
    expect(screen.queryByRole('list', { name: 'Compliance controls (indicative)' })).toBeNull();
  });
});

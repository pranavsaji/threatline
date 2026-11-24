// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { IssuePanel } from '../src/panel/IssuePanel.js';
import { AdminPage } from '../src/admin/AdminPage.js';
import { mockAdminApi, mockApi } from '../src/mock-bridge.js';
import type { AdminApi, PanelApi } from '../src/bridge.js';

afterEach(cleanup);

const TITLE = "Threatline's license for this site is inactive";

const panel = async (api: PanelApi) => {
  render(<IssuePanel api={api} />);
  await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
};

describe('Paid via Atlassian: the inactive-license banner (docs/LICENSING.md)', () => {
  it('the panel shows it, and still shows the review', async () => {
    const base = mockApi('ready');
    const dto = await base.get();
    if ('error' in dto) throw new Error('fixture');
    await panel({ ...base, get: async () => ({ ...dto, licenseInactive: true }) });
    expect(screen.getByText(TITLE)).toBeTruthy();
    expect(screen.getByText(/the Done gate does not block/)).toBeTruthy();
    expect(screen.getAllByText(/Blocks Done and merge/).length).toBeGreaterThan(0);
  });

  it('the panel shows no banner while the license is active or not applicable', async () => {
    await panel(mockApi('ready'));
    expect(screen.queryByText(TITLE)).toBeNull();
  });

  it('the admin page shows it above the sections', async () => {
    const base = mockAdminApi();
    const dto = await base.getPolicy();
    if ('error' in dto) throw new Error('fixture');
    const api: AdminApi = { ...base, getPolicy: async () => ({ ...dto, licenseInactive: true }) };
    render(<AdminPage api={api} />);
    expect(await screen.findByText(TITLE)).toBeTruthy();
  });

  it('the admin page shows no banner otherwise', async () => {
    render(<AdminPage api={mockAdminApi()} />);
    await screen.findByRole('list', { name: 'Setup checklist' });
    expect(screen.queryByText(TITLE)).toBeNull();
  });
});

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
import type { PanelDto } from '../src/types.js';

afterEach(cleanup);
const userEvent = userEventLib.setup({ delay: null });

const withRoles = (roles: PanelDto['roles']): PanelApi => ({ ...mockApi('fix_check'), get: async () => ({ ...structuredClone(FIXTURES.fix_check!), roles }) });
async function open(api: PanelApi) {
  const r = render(<IssuePanel api={api} />);
  await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
  await userEvent.click(screen.getByRole('tab', { name: /Requirements/ }));
  return r;
}

describe('fix check in the Requirements tab (docs/FIX_CHECK.md)', () => {
  it('says which verified requirement the pull request does not fix, and the one it does, with its line', async () => {
    await open(withRoles(['viewer', 'developer']));
    expect(screen.getByText('Not fixed by the pull request')).toBeTruthy();
    expect(screen.getByText(/changeEmail\(\) still updates the address straight away/)).toBeTruthy();
    const fixed = screen.getByTestId('fix-req_2');
    expect(fixed.textContent).toContain('The pull request fixes it · src/auth/magic-link.ts:41');
    // Only a champion confirms.
    expect(screen.queryByRole('button', { name: 'Confirm it is fixed' })).toBeNull();
  });

  it('opens what is still needed and a suggested change to copy; the evidence of a fix shows the checked lines', async () => {
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    await open(withRoles(['viewer', 'developer']));
    await userEvent.click(screen.getByRole('button', { name: 'Why and how to fix' }));
    expect(screen.getByText(/A one-time code sent to the old address/)).toBeTruthy();
    await userEvent.click(screen.getByRole('button', { name: 'Copy suggested change' }));
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining('otp.verify(user.email, code)'));
    expect(screen.getByText(/adds 2 test lines named for this requirement/)).toBeTruthy();
    await userEvent.click(screen.getByRole('button', { name: 'Evidence' }));
    const evidence = screen.getByRole('list', { name: 'Fix evidence' });
    expect(within(evidence).getAllByRole('listitem')).toHaveLength(2);
    expect(evidence.textContent).toContain('src/auth/magic-link.ts:43');
  });

  it('a champion confirms a held requirement and the panel reloads', async () => {
    const api = withRoles(['viewer', 'developer', 'champion']);
    const confirmFix = vi.fn(async () => ({ ok: true as const }));
    const get = vi.fn(api.get);
    await open({ ...api, get, confirmFix });
    const before = get.mock.calls.length;
    await userEvent.click(screen.getByRole('button', { name: 'Confirm it is fixed' }));
    expect(confirmFix).toHaveBeenCalledWith('req_1');
    await waitFor(() => expect(get.mock.calls.length).toBeGreaterThan(before));
  });

  it('has no accessibility violations with the details open', async () => {
    const { container } = await open(withRoles(['viewer', 'developer', 'champion']));
    await userEvent.click(screen.getByRole('button', { name: 'Why and how to fix' }));
    const r = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });
});

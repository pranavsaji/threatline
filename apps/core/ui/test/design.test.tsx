// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEventLib from '@testing-library/user-event';
import axe from 'axe-core';
import { IssuePanel } from '../src/panel/IssuePanel.js';
import { Router } from '../src/router.js';
import { SeverityLozenge } from '../src/components/SeverityLozenge.js';
import { FIXTURES } from '../src/fixtures.js';
import { mockAdminApi, mockApi, mockPostureApi } from '../src/mock-bridge.js';
import type { PanelApi } from '../src/bridge.js';
import type { PanelDto, Severity } from '../src/types.js';

afterEach(cleanup);
const userEvent = userEventLib.setup({ delay: null });

const panel = async (api: PanelApi) => {
  const r = render(<IssuePanel api={api} />);
  await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
  return r;
};
const withDto = (state: string, patch: (d: PanelDto) => void): PanelApi => {
  const api = mockApi(state);
  return {
    ...api,
    get: async () => {
      const d = structuredClone(FIXTURES[state]!);
      patch(d);
      return d;
    },
  };
};
const violations = async (container: HTMLElement) => {
  const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  return results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
};
/** Every button and link a keyboard or screen-reader user can reach has a name in words. */
const unnamedControls = (container: HTMLElement) =>
  [...container.querySelectorAll<HTMLElement>('button, a[href], [role=tab], summary')]
    .filter((el) => !(el.getAttribute('aria-label') || el.textContent || '').trim())
    .map((el) => el.outerHTML.slice(0, 80));

describe('plain language (Task 32)', () => {
  it('dates read the same way everywhere: "reviewed 2026-11-15", not the browser locale', async () => {
    await panel(withDto('ready', (d) => (d.review!.updatedAt = '2026-11-15T10:00:00.000Z')));
    expect(screen.getByText(/reviewed 2026-11-15$/)).toBeTruthy();
  });

  it('warn-only shows its end time in UTC', async () => {
    await panel(withDto('ready', (d) => Object.assign(d.verdict!, { state: 'warn', validUntil: '2026-11-30T09:15:00.000Z' })));
    expect(screen.getByText('until 2026-11-30 09:15 UTC')).toBeTruthy();
  });

  it('hidden counts read as words: "1 threat cites a source you cannot open"', async () => {
    await panel(withDto('ready', (d) => Object.assign(d, { hiddenThreats: 1, hiddenRequirements: 2 })));
    expect(screen.getByText(/1 threat cites a source you cannot open and is not shown\./)).toBeTruthy();
    await userEvent.click(screen.getByRole('tab', { name: /Requirements/ }));
    expect(screen.getByText(/2 requirements come from sources you cannot open and are not shown\./)).toBeTruthy();
  });

  it('no "(s)" plurals and no raw status codes anywhere in the ready panel', async () => {
    const { container } = await panel(mockApi('ready'));
    for (const tab of ['Threats', 'Requirements', 'Acceptances', 'History']) {
      await userEvent.click(screen.getByRole('tab', { name: new RegExp(`^${tab}`) }));
      expect(container.textContent).not.toMatch(/\w\(s\)/);
      expect(container.textContent).not.toMatch(/\b(awaiting_agent|agent_timeout|needs_human|InProgress|NotApplicable|AcceptedRisk)\b/);
    }
  });
});

describe('standards chips name their framework (Task 32)', () => {
  it('"ASVS V2.1.1" rather than a bare "V2.1.1"; CWE ids are left as they are', async () => {
    await panel(mockApi('ready'));
    const chips = within(screen.getAllByRole('article')[0]!).getByRole('list', { name: 'Standards' });
    expect(within(chips).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['ASVS V2.1.1', 'CWE-640']);
  });
});

describe('colour is never the only signal (Task 32)', () => {
  it.each(['Critical', 'High', 'Medium', 'Low'] as Severity[])('%s severity is spelled out', (s) => {
    const { container } = render(<SeverityLozenge severity={s} />);
    expect(container.textContent).toBe(s);
  });

  it('every threat card says its severity, its STRIDE category in words, and uses the one STRIDE icon set', async () => {
    await panel(mockApi('ready'));
    for (const card of screen.getAllByRole('article')) {
      expect(within(card).getByText(/^(Critical|High|Medium|Low)$/)).toBeTruthy();
      expect(within(card).getByText(/^(Spoofing|Tampering|Repudiation|Information disclosure|Denial of service|Elevation of privilege)$/)).toBeTruthy();
      const icons = card.querySelectorAll('svg[data-stride]');
      expect(icons.length).toBe(1);
      expect(icons[0]!.getAttribute('aria-hidden')).toBe('true');
    }
  });
});

describe('keyboard path (Task 32)', () => {
  it('panel: Tab reaches the tasks action, the past incident, What if, the tabs and each threat’s Details; Enter opens details; arrow keys move between tabs', async () => {
    await panel(mockApi('ready'));
    await screen.findByTestId('threatline-happened-before');
    // Under the headline's list: the incident it repeats, then the one positive action.
    await userEvent.tab();
    expect(document.activeElement!.textContent).toBe('INC-7');
    await userEvent.tab();
    expect(document.activeElement!.textContent).toBe('Turn 2 requirements into tasks');
    await userEvent.tab();
    expect(document.activeElement!.textContent).toMatch(/What if/);
    // The delivery alert (shipped while open) links its deployment before the tab row.
    await userEvent.tab();
    expect(document.activeElement!.textContent).toBe('payments-service #128');
    await userEvent.tab();
    expect(document.activeElement!.getAttribute('role')).toBe('tab');
    await userEvent.keyboard('{ArrowRight}');
    expect(document.activeElement!.textContent).toMatch(/^Requirements/);
    await userEvent.keyboard('{ArrowLeft}');
    await userEvent.tab();
    // Focus moves into the Threats panel and on to the first card's Details button.
    while (document.activeElement && document.activeElement.textContent !== 'Details') await userEvent.tab();
    await userEvent.keyboard('{Enter}');
    expect(document.activeElement!.getAttribute('aria-expanded')).toBe('true');
  });

  it('accept risk: opening moves focus to Reason; Escape closes it and focus returns to "Accept risk"', async () => {
    await panel(mockApi('ready'));
    await userEvent.click(screen.getByRole('tab', { name: /Requirements/ }));
    const trigger = screen.getAllByRole('button', { name: 'Accept risk' })[0]!;
    trigger.focus();
    await userEvent.keyboard('{Enter}');
    const form = screen.getByRole('form', { name: 'Accept risk' });
    expect(document.activeElement).toBe(within(form).getByLabelText('Reason'));
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('form', { name: 'Accept risk' })).toBeNull();
    await waitFor(() => expect(document.activeElement!.textContent).toBe('Accept risk'));
  });

  it('accept risk: Cancel also returns focus to the button that opened it', async () => {
    await panel(mockApi('ready'));
    await userEvent.click(screen.getByRole('tab', { name: /Requirements/ }));
    await userEvent.click(screen.getAllByRole('button', { name: 'Accept risk' })[0]!);
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(document.activeElement!.textContent).toBe('Accept risk'));
  });

  it('verification evidence: choosing Verified moves focus into the form; Escape returns it to Status', async () => {
    await panel(mockApi('ready'));
    await userEvent.click(screen.getByRole('tab', { name: /Requirements/ }));
    const status = screen.getAllByRole('combobox', { name: 'Status' })[0]!;
    await userEvent.selectOptions(status, 'Verified');
    const form = screen.getByRole('form', { name: 'Verification evidence' });
    expect(form.contains(document.activeElement)).toBe(true);
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('form', { name: 'Verification evidence' })).toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(screen.getAllByRole('combobox', { name: 'Status' })[0]));
  });

  it('champion triage: opening focuses the editor; Escape closes it and focus returns to Triage', async () => {
    await panel(withDto('ready', (d) => (d.roles = ['viewer', 'champion'])));
    const card = screen.getAllByRole('article')[0]!;
    await userEvent.click(within(card).getByRole('button', { name: 'Triage' }));
    const editor = within(card).getByRole('form', { name: 'Triage threat' });
    expect(editor.contains(document.activeElement)).toBe(true);
    await userEvent.keyboard('{Escape}');
    expect(within(card).queryByRole('form', { name: 'Triage threat' })).toBeNull();
    expect(document.activeElement).toBe(within(card).getByRole('button', { name: 'Triage' }));
  });

  it('admin: the first Tab lands on the section index, and each link targets a section that exists', async () => {
    render(<Router moduleKey="threatline-admin" api={mockApi('ready')} admin={mockAdminApi('ready')} posture={mockPostureApi('ready')} />);
    await screen.findByRole('heading', { name: 'Severity policy' });
    await userEvent.tab();
    const nav = screen.getByRole('navigation', { name: 'Admin sections' });
    expect(nav.contains(document.activeElement)).toBe(true);
    for (const a of within(nav).getAllByRole('link')) expect(document.getElementById(a.getAttribute('href')!.slice(1))).toBeTruthy();
  });
});

describe('axe and control names on every surface (Task 32)', () => {
  const PANEL_STATES = ['not_reviewed', 'in_progress', 'ready', 'partial', 'failed', 'timeout', 'budget', 'injection', 'stale', 'pass', 'revised'];
  it.each(PANEL_STATES.flatMap((s) => [`${s} light`, `${s} dark`]))('panel %s', async (name) => {
    const [state, mode] = name.split(' ') as [string, string];
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = await panel(mockApi(state));
    expect(await violations(container)).toEqual([]);
    expect(unnamedControls(container)).toEqual([]);
  });

  it.each(['light', 'dark'])('panel tabs: requirements with accept-risk open, acceptances, history (%s)', async (mode) => {
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = await panel(mockApi('ready'));
    await userEvent.click(screen.getByRole('tab', { name: /Requirements/ }));
    await userEvent.click(screen.getAllByRole('button', { name: 'Accept risk' })[0]!);
    expect(await violations(container)).toEqual([]);
    for (const tab of ['Acceptances', 'History']) {
      await userEvent.click(screen.getByRole('tab', { name: new RegExp(`^${tab}`) }));
      expect(await violations(container)).toEqual([]);
      expect(unnamedControls(container)).toEqual([]);
    }
  });

  it.each(['light', 'dark'])('panel what-if and threat details open (%s)', async (mode) => {
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = await panel(mockApi('ready'));
    await userEvent.click(screen.getByRole('button', { name: /What if/ }));
    for (const b of screen.getAllByRole('button', { name: 'Details' })) await userEvent.click(b);
    expect(await violations(container)).toEqual([]);
  });

  it.each([
    ['threatline-admin', 'first'],
    ['threatline-posture', 'empty'],
    ['threatline-posture-gadget', 'ready'],
  ])('%s (%s state)', async (moduleKey, state) => {
    const { container } = render(<Router moduleKey={moduleKey} api={mockApi('ready')} admin={mockAdminApi(state)} posture={mockPostureApi(state)} />);
    await waitFor(() => expect(container.querySelector('[aria-busy="true"], [role="status"][aria-label^="Loading"]')).toBeNull());
    await waitFor(() => expect(container.textContent!.length).toBeGreaterThan(40));
    expect(await violations(container)).toEqual([]);
    expect(unnamedControls(container)).toEqual([]);
  });
});

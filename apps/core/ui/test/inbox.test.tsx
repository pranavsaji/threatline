// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEventLib from '@testing-library/user-event';
import axe from 'axe-core';
import { ChampionInbox, DECIDE_BATCH, SHORTCUTS } from '../src/inbox/ChampionInbox.js';
import { GlobalPage } from '../src/inbox/GlobalPage.js';
import { INBOX_FIXTURE } from '../src/inbox/fixtures.js';
import { mockAdminApi, mockApi, mockInboxApi, mockPostureApi } from '../src/mock-bridge.js';
import { Router } from '../src/router.js';
import { inboxApiOver, type InboxApi, type InboxDecisionInput } from '../src/bridge.js';
import type { InboxDto, InboxRow } from '../src/types.js';

afterEach(cleanup);
const userEvent = userEventLib.setup({ delay: null });

const violations = async (container: HTMLElement) => {
  const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
  return results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
};
const unnamedControls = (container: HTMLElement) =>
  [...container.querySelectorAll<HTMLElement>('button, a[href], [role=tab], input')]
    .filter((el) => !(el.getAttribute('aria-label') || el.textContent || el.closest('label')?.textContent || '').trim())
    .map((el) => el.outerHTML.slice(0, 80));

const ROWS = INBOX_FIXTURE.clusters.flatMap((c) => c.rows);
const rowItem = (r: Pick<InboxRow, 'title' | 'issueKey'>) => screen.getByRole('checkbox', { name: `Select ${r.title} on ${r.issueKey}` }).closest('li')!;
const press = (key: string, target: Element = document.body) => fireEvent.keyDown(target, { key });

/** A recording inbox API over the mock (decisions remove rows, as the server does). */
function recording(over: Partial<InboxApi> = {}) {
  const base = mockInboxApi('ready');
  const decide = vi.fn(over.decide ?? base.decide);
  const list = vi.fn(over.list ?? base.list);
  return { api: { list, decide } as InboxApi, decide, list };
}
const inbox = async (api: InboxApi) => {
  const r = render(<ChampionInbox api={api} />);
  await screen.findByRole('heading', { name: 'Champion inbox' });
  return r;
};

describe('champion inbox: the global page tab', () => {
  it('champions and admins get a Champion inbox tab next to the posture dashboard, with the waiting count', async () => {
    render(<Router moduleKey="threatline-posture" api={mockApi()} admin={mockAdminApi()} posture={mockPostureApi()} inbox={mockInboxApi('ready')} />);
    const tab = await screen.findByRole('tab', { name: /Champion inbox/ });
    expect(within(tab).getByLabelText('5 waiting').textContent).toBe('5');
    expect(screen.getByRole('tab', { name: 'Security posture' }).getAttribute('aria-selected')).toBe('true');
    await userEvent.click(tab);
    expect(await screen.findByRole('heading', { name: 'Champion inbox' })).toBeTruthy();
    expect(screen.getByText('5 threats waiting for a security champion, most severe and oldest first. 1 more threat rests only on sources you cannot open.')).toBeTruthy();
  });

  it('everyone else sees the dashboard alone: the server says forbidden, so there is no tab', async () => {
    const list = vi.fn(mockInboxApi('forbidden').list);
    render(<GlobalPage posture={mockPostureApi()} inbox={{ ...mockInboxApi('forbidden'), list }} />);
    expect(await screen.findByRole('heading', { name: 'Security posture' })).toBeTruthy();
    await waitFor(() => expect(list).toHaveBeenCalled());
    expect(screen.queryByRole('tab', { name: /Champion inbox/ })).toBeNull();
    expect(screen.queryByText(/Champion inbox/)).toBeNull();
  });

  it('shortcuts work only while the inbox tab is open', async () => {
    const decide = vi.fn(mockInboxApi('ready').decide);
    render(<GlobalPage posture={mockPostureApi()} inbox={{ ...mockInboxApi('ready'), decide }} />);
    await screen.findByRole('tab', { name: /Champion inbox/ });
    press('c');
    press('?');
    expect(decide).not.toHaveBeenCalled();
    expect(screen.queryByRole('list', { name: 'Keyboard shortcuts' })).toBeNull();
  });

  it('the count badge follows decisions', async () => {
    render(<GlobalPage posture={mockPostureApi()} inbox={mockInboxApi('ready')} />);
    await userEvent.click(await screen.findByRole('tab', { name: /Champion inbox/ }));
    await userEvent.click(await screen.findByRole('button', { name: 'Confirm Card numbers written to logs on PAY-3' }));
    await waitFor(() => expect(screen.getByLabelText('4 waiting')).toBeTruthy());
  });

  it('the bridge calls inbox.list and inbox.decide', async () => {
    const invoke = vi.fn(async () => ({}) as never);
    const api = inboxApiOver(invoke);
    await api.list();
    await api.list(2);
    await api.decide({ decision: 'dismiss', reason: 'duplicate', items: [{ issueId: '1', threatId: 't' }] });
    expect(invoke.mock.calls).toEqual([
      ['inbox.list', {}],
      ['inbox.list', { cursor: 2 }],
      ['inbox.decide', { decision: 'dismiss', reason: 'duplicate', items: [{ issueId: '1', threatId: 't' }] }],
    ]);
  });
});

describe('champion inbox: rows and clusters', () => {
  it('each row shows the work item key, summary and link, the threat, STRIDE, severity, why it needs a person and its age', async () => {
    await inbox(recording().api);
    const li = rowItem(ROWS[0]!);
    const link = within(li).getByRole('link', { name: 'PAY-9' });
    expect(link.getAttribute('href')).toBe('https://example.atlassian.net/browse/PAY-9');
    expect(link.getAttribute('target')).toBe('_top');
    expect(li.textContent).toContain('Partner refunds API');
    expect(li.textContent).toContain('Forged refund webhooks');
    expect(li.textContent).toContain('Critical');
    expect(li.textContent).toContain('Spoofing');
    expect(li.textContent).toContain('looked like instructions to an AI');
    expect(li.textContent).toContain('Waiting 10 days');
    expect(rowItem(ROWS[2]!).textContent).toContain('Waiting 2 days');
    expect(rowItem(ROWS[3]!).textContent).toContain('repeats “Magic links never expire”');
  });

  it('groups similar threats across work items and verifier duplicates, and a cluster is selected at once', async () => {
    await inbox(recording().api);
    expect(screen.getByRole('region', { name: '2 similar threats on 2 work items' })).toBeTruthy();
    expect(screen.getByRole('region', { name: '2 threats on PAY-6 the verifier marked as duplicates' })).toBeTruthy();
    await userEvent.click(screen.getByRole('checkbox', { name: /Select all 2: 2 similar threats/ }));
    expect(screen.getByText('2 selected')).toBeTruthy();
    expect((screen.getByRole('checkbox', { name: 'Select Forged refund webhooks on PAY-7' }) as HTMLInputElement).checked).toBe(true);
  });

  it('shows the empty state and a retryable error', async () => {
    await inbox(mockInboxApi('empty'));
    expect(screen.getByText('Nothing is waiting for a security champion.')).toBeTruthy();
    cleanup();
    let fail = true;
    const list = vi.fn(async (): Promise<InboxDto | { error: 'unavailable' }> => (fail ? { error: 'unavailable' } : structuredClone(INBOX_FIXTURE)));
    render(<ChampionInbox api={{ list, decide: mockInboxApi().decide }} />);
    const alert = await screen.findByRole('alert');
    fail = false;
    await userEvent.click(within(alert).getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('heading', { name: 'Champion inbox' })).toBeTruthy();
  });

  it('loads further pages with Show more', async () => {
    const page2: InboxDto = { ...structuredClone(INBOX_FIXTURE), cursor: null, clusters: [{ id: 'x', kind: 'single', rows: [{ ...ROWS[4]!, threatId: 'thr_more', title: 'One more threat' }] }] };
    const list = vi.fn(async (cursor?: number) => (cursor ? page2 : { ...structuredClone(INBOX_FIXTURE), cursor: 3 }));
    await inbox({ list, decide: mockInboxApi().decide });
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }));
    expect(await screen.findByText('One more threat')).toBeTruthy();
    expect(list).toHaveBeenLastCalledWith(3);
    expect(screen.getByText('Card numbers written to logs')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Show more' })).toBeNull();
  });

  it.each(['light', 'dark'])('has no axe violations and every control is named (%s), with the shortcut help and dismiss form open', async (mode) => {
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = render(<GlobalPage posture={mockPostureApi()} inbox={mockInboxApi('ready')} />);
    await userEvent.click(await screen.findByRole('tab', { name: /Champion inbox/ }));
    await screen.findByRole('heading', { name: 'Champion inbox' });
    await userEvent.click(screen.getByRole('button', { name: 'Keyboard shortcuts' }));
    await userEvent.click(screen.getByRole('button', { name: 'Dismiss Card numbers written to logs on PAY-3' }));
    expect(await violations(container)).toEqual([]);
    expect(unnamedControls(container)).toEqual([]);
  });
});

describe('champion inbox: decisions', () => {
  it('Confirm on a row confirms that threat and reports it', async () => {
    const { api, decide } = recording();
    await inbox(api);
    await userEvent.click(screen.getByRole('button', { name: 'Confirm Forged refund webhooks on PAY-7' }));
    expect(decide).toHaveBeenCalledWith({ decision: 'confirm', items: [{ issueId: '66407', threatId: 'thr_7_1' }] });
    expect(await screen.findByText('Confirmed 1 threat.')).toBeTruthy();
    await waitFor(() => expect(screen.queryByRole('checkbox', { name: 'Select Forged refund webhooks on PAY-7' })).toBeNull());
  });

  it('Dismiss needs a reason; the note is optional', async () => {
    const { api, decide } = recording();
    await inbox(api);
    await userEvent.click(screen.getByRole('button', { name: 'Dismiss Card numbers written to logs on PAY-3' }));
    const form = screen.getByRole('form', { name: 'Dismiss threats' });
    expect(document.activeElement).toBe(within(form).getByRole('combobox', { name: 'Reason' }));
    await userEvent.click(within(form).getByRole('button', { name: 'Dismiss 1 threat' }));
    expect(within(form).getByRole('alert').textContent).toBe('Choose a reason.');
    expect(decide).not.toHaveBeenCalled();
    await userEvent.selectOptions(within(form).getByRole('combobox', { name: 'Reason' }), 'already_mitigated');
    await userEvent.type(within(form).getByRole('textbox', { name: 'Note (optional)' }), 'Vault masks card numbers');
    await userEvent.click(within(form).getByRole('button', { name: 'Dismiss 1 threat' }));
    expect(decide).toHaveBeenCalledWith({ decision: 'dismiss', reason: 'already_mitigated', note: 'Vault masks card numbers', items: [{ issueId: '66403', threatId: 'thr_3_1' }] });
    expect(await screen.findByText('Dismissed 1 threat.')).toBeTruthy();
  });

  it('bulk: a selection is decided as individual items, in batches the server accepts, and partial failures are listed per item', async () => {
    const many: InboxDto = {
      ...structuredClone(INBOX_FIXTURE),
      total: DECIDE_BATCH + 2,
      clusters: Array.from({ length: DECIDE_BATCH + 2 }, (_, i) => ({ id: `t${i}`, kind: 'single' as const, rows: [{ ...ROWS[4]!, threatId: `t${i}`, issueId: String(1000 + i), issueKey: `PAY-${1000 + i}`, title: `Threat ${i}` }] })),
    };
    const decide = vi.fn(async (input: InboxDecisionInput) => ({
      results: input.items.map((it) => (it.threatId === 't3' ? { ...it, ok: false as const, error: 'conflict' as const, message: 'Someone already decided this threat. Reload the inbox.' } : { ...it, ok: true as const, state: 'dismissed' })),
      decided: input.items.filter((it) => it.threatId !== 't3').length,
      failed: input.items.some((it) => it.threatId === 't3') ? 1 : 0,
    }));
    await inbox({ list: async () => structuredClone(many), decide });
    for (let i = 0; i < DECIDE_BATCH + 2; i++) fireEvent.click(screen.getByRole('checkbox', { name: `Select Threat ${i} on PAY-${1000 + i}` }));
    expect(screen.getByText(`${DECIDE_BATCH + 2} selected`)).toBeTruthy();
    await userEvent.click(screen.getByRole('button', { name: 'Dismiss selected' }));
    const form = screen.getByRole('form', { name: 'Dismiss threats' });
    await userEvent.selectOptions(within(form).getByRole('combobox', { name: 'Reason' }), 'duplicate');
    await userEvent.click(within(form).getByRole('button', { name: `Dismiss ${DECIDE_BATCH + 2} threats` }));
    await waitFor(() => expect(decide).toHaveBeenCalledTimes(2));
    expect(decide.mock.calls[0]![0].items).toHaveLength(DECIDE_BATCH);
    expect(decide.mock.calls[1]![0].items).toHaveLength(2);
    expect(decide.mock.calls.every(([i]) => i.decision === 'dismiss' && 'reason' in i && i.reason === 'duplicate')).toBe(true);
    expect(await screen.findByText(`Dismissed ${DECIDE_BATCH + 1} threats. 1 threat could not be dismissed.`)).toBeTruthy();
    const failed = screen.getByRole('list', { name: 'Decisions that failed' });
    expect(failed.textContent).toBe('PAY-1003 · Threat 3: Someone already decided this threat. Reload the inbox.');
    // The failed one stays selected so it can be retried; the decided ones leave the selection.
    expect(screen.getByText('1 selected')).toBeTruthy();
  });

  it('a whole batch refused by the server is reported for each of its items', async () => {
    const { api } = recording({ decide: async () => ({ error: 'forbidden', message: 'Only security champions and Jira admins can open the champion inbox.' }) });
    await inbox(api);
    await userEvent.click(screen.getByRole('button', { name: 'Confirm Forged refund webhooks on PAY-7' }));
    expect((await screen.findByRole('list', { name: 'Decisions that failed' })).textContent).toBe('PAY-7 · Forged refund webhooks: Only security champions and Jira admins can open the champion inbox.');
  });
});

describe('champion inbox: keyboard', () => {
  it('lists its shortcuts accessibly', async () => {
    await inbox(recording().api);
    expect(screen.queryByRole('list', { name: 'Keyboard shortcuts' })).toBeNull();
    press('?');
    const help = screen.getByRole('list', { name: 'Keyboard shortcuts' });
    for (const [k, what] of SHORTCUTS) expect(help.textContent).toContain(`${k} ${what}`);
    expect(screen.getByRole('button', { name: 'Keyboard shortcuts' }).getAttribute('aria-expanded')).toBe('true');
  });

  it('j/k move between threats, x selects, c confirms the selection', async () => {
    const { api, decide } = recording();
    await inbox(api);
    expect(rowItem(ROWS[0]!).getAttribute('aria-current')).toBe('true');
    press('j');
    press('j');
    expect(document.activeElement).toBe(rowItem(ROWS[2]!));
    expect(rowItem(ROWS[2]!).getAttribute('aria-current')).toBe('true');
    press('k');
    expect(document.activeElement).toBe(rowItem(ROWS[1]!));
    press('x');
    press('j');
    press('x');
    expect(screen.getByText('2 selected')).toBeTruthy();
    press('c');
    await waitFor(() => expect(decide).toHaveBeenCalledTimes(1));
    expect(decide).toHaveBeenCalledWith({ decision: 'confirm', items: [{ issueId: '66407', threatId: 'thr_7_1' }, { issueId: '66406', threatId: 'thr_6_1' }] });
    expect(await screen.findByText('Confirmed 2 threats.')).toBeTruthy();
  });

  it('k stops at the first threat and j at the last', async () => {
    await inbox(recording().api);
    press('k');
    expect(rowItem(ROWS[0]!).getAttribute('aria-current')).toBe('true');
    for (let i = 0; i < 10; i++) press('j');
    expect(rowItem(ROWS[ROWS.length - 1]!).getAttribute('aria-current')).toBe('true');
  });

  it('d opens the dismiss form for the current threat; shortcuts stay off while typing in it, and Escape closes it', async () => {
    const { api, decide } = recording();
    await inbox(api);
    press('j');
    press('d');
    const form = screen.getByRole('form', { name: 'Dismiss threats' });
    const note = within(form).getByRole('textbox', { name: 'Note (optional)' });
    note.focus();
    for (const k of ['c', 'j', 'x', 'd', '?']) press(k, note);
    press('c', within(form).getByRole('combobox', { name: 'Reason' }));
    expect(decide).not.toHaveBeenCalled();
    expect(screen.getByText('0 selected')).toBeTruthy();
    expect(screen.queryByRole('list', { name: 'Keyboard shortcuts' })).toBeNull();
    fireEvent.keyDown(note, { key: 'Escape' });
    expect(screen.queryByRole('form', { name: 'Dismiss threats' })).toBeNull();
    // With the form closed, d on the second threat dismisses only it.
    press('d');
    const again = screen.getByRole('form', { name: 'Dismiss threats' });
    await userEvent.selectOptions(within(again).getByRole('combobox', { name: 'Reason' }), 'false_positive');
    await userEvent.click(within(again).getByRole('button', { name: 'Dismiss 1 threat' }));
    expect(decide).toHaveBeenCalledWith({ decision: 'dismiss', reason: 'false_positive', items: [{ issueId: '66407', threatId: 'thr_7_1' }] });
  });

  it('no shortcut fires in any text field or with a modifier key', async () => {
    const { api, decide } = recording();
    render(
      <div>
        <input aria-label="Search" />
        <ChampionInbox api={api} />
      </div>,
    );
    await screen.findByRole('heading', { name: 'Champion inbox' });
    const search = screen.getByRole('textbox', { name: 'Search' });
    press('c', search);
    press('x', search);
    fireEvent.keyDown(document.body, { key: 'c', metaKey: true });
    fireEvent.keyDown(document.body, { key: 'x', ctrlKey: true });
    expect(decide).not.toHaveBeenCalled();
    expect(screen.getByText('0 selected')).toBeTruthy();
  });
});

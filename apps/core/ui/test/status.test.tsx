// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
import axe from 'axe-core';
import { Router } from '../src/router.js';
import { IssueStatus } from '../src/status/IssueStatus.js';
import { mockAdminApi, mockApi, mockInboxApi, mockPostureApi } from '../src/mock-bridge.js';
import type { PanelApi } from '../src/bridge.js';
import type { StatusDto } from '../src/types.js';

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

const status = () => screen.findByRole('status');

describe('the context column (jira:issueContext)', () => {
  it('the router serves it for threatline-status, from panel.status', async () => {
    const api = mockApi('ready');
    const get = vi.spyOn(api, 'get');
    render(<Router moduleKey="threatline-status" api={api} admin={mockAdminApi()} posture={mockPostureApi()} inbox={mockInboxApi()} />);
    expect((await status()).textContent).toBe('✕ Blocks Done· 2 open');
    expect(screen.getByText('2 open security requirements at High or above.')).toBeTruthy();
    expect(get).not.toHaveBeenCalled();
  });

  it('the icon is decorative: the accessible text is words only', async () => {
    render(<IssueStatus api={mockApi('pass')} />);
    const s = await status();
    expect(s.textContent).toBe('✓ Ready for Done');
    expect([...s.querySelectorAll('[aria-hidden="true"]')].map((n) => n.textContent)).toEqual(['✓ ']);
    expect(s.closest('section')!.querySelector('p')).toBeNull();
  });

  it('without a status call (an API built by hand) it derives the status from the panel load', async () => {
    const { status: _s, ...api } = mockApi('not_reviewed');
    render(<IssueStatus api={api as PanelApi} />);
    expect((await status()).textContent).toBe('✕ Not reviewed');
    expect(screen.getByText('Blocks Done until Threatline reviews it.')).toBeTruthy();
  });

  it('shows Reviewing… while a review runs, and turns to the verdict when it lands', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const running: StatusDto = { issueKey: 'PAY-6', verdict: { state: 'block', blockingCount: 0, reasons: [{ code: 'agent_missing', message: 'Review in progress (1 of 3 agent runs received).' }] }, review: { status: 'awaiting_agent' }, inScope: true };
    const done: StatusDto = { ...running, verdict: { state: 'pass', blockingCount: 0, reasons: [] }, review: { status: 'ready' } };
    const calls = vi.fn<() => Promise<StatusDto>>().mockResolvedValueOnce(running).mockResolvedValue(done);
    render(<IssueStatus api={{ ...mockApi('ready'), status: calls }} />);
    expect((await status()).textContent).toBe('Reviewing…');
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect((await status()).textContent).toBe('✓ Ready for Done');
    expect(calls).toHaveBeenCalledTimes(2);
  });

  it('a viewer who cannot open the work item is told so, and sees no status', async () => {
    render(<IssueStatus api={{ ...mockApi('ready'), status: async () => ({ error: 'not_found' as const }) }} />);
    expect(await screen.findByText('You do not have access to this work item.')).toBeTruthy();
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('a failed call says Threatline is unavailable rather than leaving the column blank', async () => {
    render(<IssueStatus api={{ ...mockApi('ready'), status: () => Promise.reject(new Error('network')) }} />);
    expect(await screen.findByText(/Threatline is unavailable right now/)).toBeTruthy();
  });

  it.each(['light', 'dark'])('has no axe violations (%s)', async (mode) => {
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = render(<IssueStatus api={mockApi('ready')} />);
    await status();
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
  });
});

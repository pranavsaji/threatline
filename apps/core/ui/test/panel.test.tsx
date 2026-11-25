// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import axe from 'axe-core';
import { IssuePanel } from '../src/panel/IssuePanel.js';
import { mockApi } from '../src/mock-bridge.js';
import type { PanelApi } from '../src/bridge.js';

afterEach(cleanup);

const renderState = async (state: string, api: PanelApi = mockApi(state)) => {
  const r = render(<IssuePanel api={api} />);
  await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
  return r;
};

describe('IssuePanel states render their key text', () => {
  it.each([
    ['not_reviewed', /Threatline has not reviewed this work item yet/],
    ['in_progress', /Review in progress/],
    ['ready', /Blocks Done and merge/],
    ['partial', /Partial context/],
    ['failed', /The review failed/],
    ['timeout', /The AI review did not arrive in time/],
    ['budget', /Reviews are paused at the AI budget/],
    ['injection', /Threatline ignored instructions found in this page/],
    ['stale', /Context changed since the last review/],
    ['pass', /Ready for Done/],
  ])('%s', async (state, text) => {
    await renderState(state);
    expect(screen.getAllByText(text).length).toBeGreaterThan(0);
  });

  it('the in-progress state shows the live step list', async () => {
    await renderState('in_progress');
    const steps = screen.getByRole('list', { name: 'Review progress' });
    expect(within(steps).getByText('Agent run 2 of 3')).toBeTruthy();
  });

  it('the injection banner names the source as a chip', async () => {
    await renderState('injection');
    expect(within(screen.getByRole('list', { name: 'Sources with suspected instructions' })).getByText(/Magic link design/)).toBeTruthy();
  });

  it('a viewer without access sees a plain message, not data', async () => {
    const api = { ...mockApi('ready'), get: async () => ({ error: 'not_found' as const }) };
    render(<IssuePanel api={api} />);
    expect(await screen.findByText('You do not have access to this work item.')).toBeTruthy();
  });
});

describe('final review I4: the header re-run action re-runs the review', () => {
  it('"Re-run review" next to a stale reason is a button that calls rerun, not a link that reloads the page', async () => {
    let calls = 0;
    const base = mockApi('stale');
    await renderState('stale', { ...base, rerun: async () => (calls++, { ok: true }) });
    const next = screen.getByRole('list', { name: 'What to do next' });
    expect(within(next).queryByRole('link', { name: 'Re-run review' })).toBeNull();
    await userEvent.click(within(next).getByRole('button', { name: 'Re-run review' }));
    await waitFor(() => expect(calls).toBe(1));
  });
});

describe('feature: rules-only reviews are labelled', () => {
  it('a review made by the rule-based checks alone says so, and says how to turn AI review on', async () => {
    const api = mockApi('ready');
    const dto = await api.get();
    if ('error' in dto) throw new Error('fixture');
    await renderState('ready', { ...api, get: async () => ({ ...dto, review: { ...dto.review!, modelIds: ['threatline-rules'], samplesExpected: 0 } }) });
    expect(screen.getByText('Rule-based review')).toBeTruthy();
    expect(screen.getByText(/AI review is off on this site/)).toBeTruthy();
  });
});

describe('feature: Threatline Engine reviews', () => {
  it('say how the review was made, and show the verifier\'s call on each threat', async () => {
    const api = mockApi('ready');
    const dto = await api.get();
    if ('error' in dto) throw new Error('fixture');
    const [a, b, ...rest] = dto.threats;
    const threats = [
      { ...a!, verification: { keep: true, reason: 'the design quotes a public webhook' } },
      { ...b!, state: 'needs_human' as const, verification: { keep: false, reason: 'the quote does not mention an admin console' } },
      ...rest,
    ];
    await renderState('ready', { ...api, get: async () => ({ ...dto, threats, review: { ...dto.review!, modelIds: ['claude-sonnet-5', 'claude-opus-5'], samplesReceived: 3 } }) });
    // The method waits behind one quiet button at the foot of the panel, not a banner on every work item.
    expect(screen.queryByText(/claude-sonnet-5, claude-opus-5/)).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: 'How this review works' }));
    expect(screen.getByText(/claude-sonnet-5, claude-opus-5/)).toBeTruthy();
    expect(screen.getAllByText('Evidence verified').length).toBe(1);
    expect(screen.getByText(/The verifier doubted this: the quote does not mention an admin console/)).toBeTruthy();
  });
});

describe('feature: rule-based checks covered by a more specific AI threat', () => {
  it('are not listed on their own; the covering threat names them', async () => {
    const api = mockApi('ready');
    const dto = await api.get();
    if ('error' in dto) throw new Error('fixture');
    const cover = dto.threats[0]!;
    await renderState('ready', { ...api, get: async () => ({ ...dto, covered: [{ title: 'Tool misuse by an over-privileged agent', coveredBy: cover.id }] }) });
    expect(screen.getByText("Also covers Threatline's rule-based check: Tool misuse by an over-privileged agent.")).toBeTruthy();
  });
});

describe('feature: fix-by dates and test skeletons on requirements', () => {
  it('shows when each open requirement is due, and how overdue it is', async () => {
    const api = mockApi('ready');
    const dto = await api.get();
    if ('error' in dto) throw new Error('fixture');
    const day = 86_400_000;
    const reqs = [
      { ...dto.requirements[0]!, severity: 'Critical' as const, createdAt: new Date(Date.now() - 10 * day).toISOString() },
      { ...dto.requirements[1]!, severity: 'High' as const, createdAt: new Date(Date.now() - 1 * day).toISOString() },
    ];
    await renderState('ready', { ...api, get: async () => ({ ...dto, requirements: reqs }) });
    await userEvent.click(screen.getByRole('tab', { name: /^Requirements/ }));
    const list = screen.getByRole('list', { name: 'Security requirements' });
    expect(within(list).getByText('Overdue by 3 days')).toBeTruthy();
    expect(within(list).getByText(/^Fix by \d{4}-\d{2}-\d{2}$/)).toBeTruthy();
  });

  it('copies a test skeleton in the chosen language', async () => {
    const copied: string[] = [];
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async (s: string) => void copied.push(s) } });
    await renderState('ready');
    await userEvent.click(screen.getByRole('tab', { name: /^Requirements/ }));
    const item = screen.getAllByRole('listitem').find((li) => li.textContent?.includes('Re-authenticate before changing the account email'))!;
    await userEvent.selectOptions(within(item).getByLabelText('Test language'), 'python');
    await userEvent.click(within(item).getByRole('button', { name: 'Copy test skeleton' }));
    await waitFor(() => expect(copied).toHaveLength(1));
    expect(copied[0]).toMatch(/^# Threatline requirement req_1/);
    expect(copied[0]).toMatch(/^def test_/m);
    expect(within(item).getByText('Copied a Python test skeleton.')).toBeTruthy();
  });
});

describe('risk ring', () => {
  it('keeps the score once nothing blocks, without the alarm colour, and says so', async () => {
    await renderState('pass');
    expect(screen.getByRole('img', { name: /^Risk score \d+ of 100, nothing blocking$/ })).toBeTruthy();
  });

  it('a blocking verdict keeps the plain label', async () => {
    await renderState('ready');
    expect(screen.getByRole('img', { name: 'Risk score 72 of 100' })).toBeTruthy();
  });
});

describe('break-glass override in the header', () => {
  it('says the gate is overridden and until when, and keeps the reasons visible', async () => {
    const base = mockApi('ready');
    const dto = await base.get();
    if ('error' in dto) throw new Error('fixture');
    const api: PanelApi = { ...base, get: async () => ({ ...dto, verdict: { ...dto.verdict!, state: 'pass', overridden: true, validUntil: '2026-11-17T10:57:00.000Z' } }) };
    await renderState('ready', api);
    expect(screen.getByText(/Gate overridden/)).toBeTruthy();
    expect(screen.getByText(/until 2026-11-17 10:57 UTC/)).toBeTruthy();
    expect(screen.queryByText('Ready for Done')).toBeNull();
    expect(screen.getByRole('list', { name: 'What to do next' })).toBeTruthy();
  });
});

describe('ready state', () => {
  it('shows the risk score as text, plain-language titles first, and verdict with an icon and words', async () => {
    await renderState('ready');
    expect(screen.getByRole('img', { name: 'Risk score 72 of 100' })).toBeTruthy();
    const cards = screen.getAllByRole('article');
    expect(within(cards[0]!).getByRole('heading').textContent).toBe('A stolen link lets an attacker lock the real owner out for good.');
    expect(screen.getAllByText('3 of 3 runs').length).toBe(2);
  });

  it('expanding a threat shows the scenario and its cited quote with the source link', async () => {
    await renderState('ready');
    const card = screen.getAllByRole('article')[1]!;
    await userEvent.click(within(card).getByRole('button', { name: 'Details' }));
    expect(within(card).getByText(/reuses the sign-in link weeks later/)).toBeTruthy();
    expect(within(card).getByRole('link', { name: /Source: PAY-6 Password reset by magic link/ })).toBeTruthy();
  });

  it('"Explain like I’m new" shows the deterministic explanation', async () => {
    await renderState('ready');
    const card = screen.getAllByRole('article')[0]!;
    await userEvent.click(within(card).getByRole('button', { name: 'Details' }));
    await userEvent.click(within(card).getByRole('button', { name: /Explain like I’m new/ }));
    expect(await within(card).findByRole('region', { name: 'Explanation' })).toBeTruthy();
  });

  it('"Show discarded threats" lists them with reasons', async () => {
    await renderState('ready');
    await userEvent.click(screen.getByRole('button', { name: /Show discarded threats \(2\)/ }));
    const list = screen.getByRole('list', { name: 'Discarded threats' });
    expect(within(list).getByText(/Its quote is not in the sources/)).toBeTruthy();
  });

  it.each(['light', 'dark'])('has no axe violations (%s)', async (mode) => {
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = await renderState('ready');
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
  });
});

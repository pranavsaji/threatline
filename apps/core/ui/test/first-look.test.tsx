// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEventLib from '@testing-library/user-event';
import axe from 'axe-core';
import { VERDICT as SHARED, OVERRIDDEN as SHARED_OVERRIDDEN } from '@threatline/shared/verdict-words';
import { AdminPage } from '../src/admin/AdminPage.js';
import { FIXTURES } from '../src/fixtures.js';
import { mockAdminApi, mockApi } from '../src/mock-bridge.js';
import { FirstLook, firstLookLabel } from '../src/panel/FirstLook.js';
import { IssuePanel } from '../src/panel/IssuePanel.js';
import { OVERRIDDEN, VERDICT } from '../src/panel/verdict-labels.js';
import { IssueStatus } from '../src/status/IssueStatus.js';
import { statusOf } from '../src/status/status-view.js';
import type { FactDto, PanelDto } from '../src/types.js';

afterEach(cleanup);
const userEvent = userEventLib.setup({ delay: null });

const reviewing = FIXTURES.reviewing!;
const renderPanel = async (state: string) => {
  const r = render(<IssuePanel api={mockApi(state)} />);
  await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
  return r;
};

describe('the first look in the panel', () => {
  it('while the review runs: the rules-only risks in plain language, severity and quoted evidence, clearly labelled', async () => {
    const { container } = await renderPanel('reviewing');
    const section = screen.getByTestId('threatline-first-look');
    expect(within(section).getByRole('heading', { name: 'First look' })).toBeTruthy();
    expect(within(section).getByText("First look from Threatline's rules. The AI review is running (stage 3 of 6) and will replace this.")).toBeTruthy();
    expect(within(section).getByText('Now: Independent AI runs, 1 of 3 done.')).toBeTruthy();
    const items = within(within(section).getByRole('list', { name: 'First look risks' })).getAllByRole('listitem');
    expect(items).toHaveLength(3);
    expect(items[0]!.textContent).toContain('High');
    expect(items[0]!.textContent).toContain('Someone could log in as a customer using a stolen password or session.');
    expect(items[0]!.textContent).toContain('“Customers sign in with a magic link sent to their email address.”');
    // It does not change the verdict: the gate still blocks while the review runs.
    expect(screen.getByText('Blocks Done and merge')).toBeTruthy();
    const r = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(r.violations.map((v) => v.id)).toEqual([]);
  });

  it('gone once the review is in (and never on a review without one)', async () => {
    await renderPanel('ready');
    expect(screen.queryByTestId('threatline-first-look')).toBeNull();
    cleanup();
    await renderPanel('in_progress');
    expect(screen.queryByTestId('threatline-first-look')).toBeNull();
  });

  it('a settled review that somehow still carries one does not show it (the panel trusts the review status)', async () => {
    const api = mockApi('reviewing');
    const settled: PanelDto = { ...structuredClone(reviewing), review: { ...reviewing.review!, status: 'ready' } };
    vi.spyOn(api, 'get').mockResolvedValue(settled);
    render(<IssuePanel api={api} />);
    await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
    expect(screen.queryByTestId('threatline-first-look')).toBeNull();
  });

  it('says how many risks it leaves out for sources the viewer cannot open, and when the rules found nothing', () => {
    const facts = new Map<string, FactDto>();
    render(<FirstLook firstLook={{ risks: 2, threats: [], hidden: 2 }} facts={facts} />);
    expect(screen.getByText('2 more risks cite sources you cannot open.')).toBeTruthy();
    expect(screen.queryByText(/found nothing to flag/)).toBeNull();
    cleanup();
    render(<FirstLook firstLook={{ risks: 0, threats: [], hidden: 0 }} facts={facts} />);
    expect(screen.getByText("Threatline's rules found nothing to flag. The AI review may still find threats.")).toBeTruthy();
  });

  it('the label: with Threatline Engine its stage of six, for a Rovo agent review no stage', () => {
    expect(firstLookLabel({ stage: { n: 2, of: 6, name: 'Injection check' } })).toBe("First look from Threatline's rules. The AI review is running (stage 2 of 6) and will replace this.");
    expect(firstLookLabel({})).toBe("First look from Threatline's rules. The AI review is running and will replace this.");
  });
});

describe('the context column with a first look', () => {
  it('Reviewing… · first look: N risks', async () => {
    expect(statusOf(reviewing)).toMatchObject({ kind: 'reviewing', label: 'Reviewing…', open: 'first look: 3 risks' });
    expect(statusOf({ ...reviewing, firstLook: { ...reviewing.firstLook!, risks: 1 } }).open).toBe('first look: 1 risk');
    expect(statusOf({ ...reviewing, firstLook: { ...reviewing.firstLook!, risks: 0 } }).open).toBeNull();
    render(<IssueStatus api={mockApi('reviewing')} />);
    expect((await screen.findByRole('status')).textContent).toBe('Reviewing…· first look: 3 risks');
  });

  it('a settled review never shows a first-look count', () => {
    expect(String(statusOf({ ...reviewing, review: { ...reviewing.review!, status: 'ready' } }).open)).not.toMatch(/first look/);
  });
});

describe('one wording for the verdict', () => {
  it('the panel and the context column use the same words as the comment Threatline posts (@threatline/shared)', () => {
    expect(VERDICT).toBe(SHARED);
    expect(OVERRIDDEN).toBe(SHARED_OVERRIDDEN);
    expect(VERDICT.block).toEqual({ label: 'Blocks Done and merge', icon: '✕', appearance: 'removed' });
  });
});

describe('admin: the review comment toggle', () => {
  it('on by default; an admin turns it off and the policy saves postReviewComments false', async () => {
    const api = mockAdminApi();
    const setPolicy = vi.fn(api.setPolicy);
    render(<AdminPage api={{ ...api, setPolicy }} />);
    const form = await screen.findByRole('form', { name: 'Review comments' });
    const box = within(form).getByRole('checkbox', { name: 'Comment on the work item when its review finishes' }) as HTMLInputElement;
    expect(box.checked).toBe(true);
    expect(within(form).getByText(/A re-run comments only when the verdict changes/)).toBeTruthy();
    await userEvent.click(box);
    await userEvent.click(within(form).getByRole('button', { name: 'Save review comments' }));
    expect(setPolicy).toHaveBeenCalledWith(expect.objectContaining({ postReviewComments: false }));
  });
});

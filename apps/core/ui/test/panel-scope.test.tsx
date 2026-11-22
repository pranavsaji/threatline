// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { IssuePanel } from '../src/panel/IssuePanel.js';
import { mockApi } from '../src/mock-bridge.js';
import type { PanelApi } from '../src/bridge.js';
import type { PanelDto } from '../src/types.js';

afterEach(cleanup);

const renderWith = async (api: PanelApi) => {
  render(<IssuePanel api={api} />);
  await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
};

const dtoOf = async (state: string): Promise<PanelDto> => {
  const dto = await mockApi(state).get();
  if ('error' in dto) throw new Error('fixture');
  return dto;
};

describe('a work item Threatline does not review', () => {
  it('says Threatline is not on here, and offers no Run review', async () => {
    const dto = await dtoOf('not_reviewed');
    let reruns = 0;
    const scopeMessage = 'Threatline is not turned on for project OPS, so it does not review its work items.';
    await renderWith({ ...mockApi('not_reviewed'), get: async () => ({ ...dto, inScope: false, scopeMessage }), rerun: async () => (reruns++, { ok: true }) });
    expect(screen.getByText('Threatline is not on for this project or work type')).toBeTruthy();
    expect(screen.getByText(new RegExp(scopeMessage))).toBeTruthy();
    expect(screen.queryByText(/Threatline has not reviewed this work item yet/)).toBeNull();
    expect(screen.queryByRole('button', { name: /Run review|Re-run review/ })).toBeNull();
    expect(reruns).toBe(0);
  });
});

describe('re-run notices', () => {
  const clickRerun = async () => {
    const next = screen.getByRole('list', { name: 'What to do next' });
    await userEvent.click(within(next).getByRole('button', { name: 'Re-run review' }));
  };

  it("a refusal from the server (a review still running) is shown in the server's words", async () => {
    const dto = await dtoOf('stale');
    await renderWith({ ...mockApi('stale'), get: async () => dto, rerun: async () => ({ error: 'conflict', message: 'A review of this work item is still running.' }) });
    await clickRerun();
    expect(await screen.findByText('A review of this work item is still running.')).toBeTruthy();
  });

  it('Threatline Engine says a few minutes, and "Review started" goes away once the new revision lands', async () => {
    const dto = await dtoOf('stale');
    let started = false;
    const next = { ...dto, reviewMode: 'engine' as const, review: { ...dto.review!, id: `${dto.review!.id}-next`, revision: dto.review!.revision + 1, status: 'awaiting_agent' as const } };
    let reveal = false;
    await renderWith({
      ...mockApi('stale'),
      get: async () => (started && reveal ? next : { ...dto, reviewMode: 'engine' }),
      rerun: async () => ((started = true), { ok: true }),
    });
    await clickRerun();
    expect(await screen.findByText('Review started. Threatline Engine reviews take a few minutes.')).toBeTruthy();
    reveal = true;
    // The panel polls while it waits; any reload after the revision lands clears the notice.
    await waitFor(() => expect(screen.queryByText(/Review started/)).toBeNull(), { timeout: 15_000 });
  }, 20_000);
});

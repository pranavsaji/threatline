// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import userEventLib from '@testing-library/user-event';
import axe from 'axe-core';
import { IssuePanel } from '../src/panel/IssuePanel.js';
import { createdParts, openWithoutTask } from '../src/panel/CreateTasks.js';
import { mockApi } from '../src/mock-bridge.js';
import { FIXTURES, SEEN_BEFORE_FIXTURE } from '../src/fixtures.js';
import type { PanelApi } from '../src/bridge.js';
import type { PanelDto } from '../src/types.js';

afterEach(cleanup);
const userEvent = userEventLib.setup({ delay: null });

async function open(api: PanelApi) {
  const r = render(<IssuePanel api={api} />);
  await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
  return r;
}
const header = () => document.querySelector('header') as HTMLElement;
const cardOf = (title: string) => screen.getAllByRole('article').find((a) => within(a).queryByRole('heading', { name: title }))!;

/** A panel whose requirements get their keys once created, as the real resolver's next panel.get would show. */
function stateful(over: Partial<PanelDto> = {}, create?: PanelApi['createRequirements']): PanelApi {
  const base = mockApi('ready');
  let dto: PanelDto = { ...structuredClone(FIXTURES.ready!), ...over };
  return {
    ...base,
    get: async () => structuredClone(dto),
    createRequirements: async (ids) => {
      const r = create ? await create(ids) : await base.createRequirements(ids);
      if (!('error' in r)) dto = { ...dto, requirements: dto.requirements.map((q) => { const c = r.created.find((x) => x.requirementId === q.id); return c ? { ...q, subtaskKey: c.subtaskKey } : q; }) };
      return r;
    },
  };
}

describe('Turn requirements into tasks (the header’s one positive action)', () => {
  it('counts only open requirements without a work item', () => {
    const reqs = FIXTURES.ready!.requirements;
    expect(openWithoutTask({ requirements: reqs }).map((r) => r.id)).toEqual(['req_1', 'req_2']);
    expect(openWithoutTask({ requirements: [{ ...reqs[0]!, subtaskKey: 'PAY-1' }, { ...reqs[1]!, status: 'Verified' }] })).toEqual([]);
    expect(openWithoutTask({ requirements: [{ ...reqs[0]!, status: 'InProgress' }] })).toHaveLength(1);
  });

  it('a developer turns the open requirements into tasks from the header; the new keys are links, announced, and focused', async () => {
    const create = vi.fn(async (ids: string[]) => ({ created: ids.map((id, i) => ({ requirementId: id === 'thr_3' ? 'req_1' : 'req_2', subtaskKey: `PAY-${12 + i}` })), skipped: [] }));
    await open(stateful({}, create));
    const button = within(header()).getByRole('button', { name: 'Turn 2 requirements into tasks' });
    expect(header().querySelector('[data-testid="threatline-headline"]')!.compareDocumentPosition(button) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await userEvent.click(button);
    expect(create).toHaveBeenCalledWith(['thr_3', 'thr_1']);
    const status = within(header()).getByRole('status');
    await waitFor(() => expect(status.textContent).toBe('Created PAY-12, PAY-13.'));
    const link = within(status).getByRole('link', { name: 'PAY-12' });
    expect(link.getAttribute('href')).toBe('/browse/PAY-12');
    expect(link.getAttribute('target')).toBe('_top');
    // Every requirement has its task now, so the button goes and focus lands on the result instead of the page body.
    await waitFor(() => expect(within(header()).queryByRole('button', { name: /into tasks/ })).toBeNull());
    expect(document.activeElement).toBe(status);
  });

  it('one requirement left reads in the singular, and the Requirements tab keeps its own control', async () => {
    const dto = structuredClone(FIXTURES.ready!);
    dto.requirements[0]!.subtaskKey = 'PAY-12';
    dto.requirements.push({ ...dto.requirements[1]!, id: 'req_3', threatId: 'thr_2', status: 'Verified' });
    await open(stateful(dto));
    expect(within(header()).getByRole('button', { name: 'Turn 1 requirement into tasks' })).toBeTruthy();
    await userEvent.click(screen.getByRole('tab', { name: /Requirements/ }));
    expect(screen.getByRole('button', { name: /Create sub-tasks \(2\)/ })).toBeTruthy();
  });

  it('an epic without Task or Story types, and a Jira failure, get the same messages as the Requirements tab', async () => {
    expect(createdParts({ created: [], skipped: [{ reason: 'no_child_type' }] })).toMatchObject({ keys: [], none: 'Nothing was created.' });
    await open(stateful({}, async (ids) => ({ created: [], skipped: ids.map((threatId) => ({ threatId, reason: 'no_child_type' })) })));
    await userEvent.click(within(header()).getByRole('button', { name: 'Turn 2 requirements into tasks' }));
    expect(await within(header()).findByText(/Nothing was created\. 2 could not be created: Jira allows no sub-tasks under an epic/)).toBeTruthy();
    cleanup();
    await open(stateful({}, async () => ({ error: 'unavailable' as const })));
    await userEvent.click(within(header()).getByRole('button', { name: 'Turn 2 requirements into tasks' }));
    expect(await within(header()).findByText(/Threatline could not reach Jira/)).toBeTruthy();
    expect(within(header()).getByRole('button', { name: 'Turn 2 requirements into tasks' })).toBeTruthy();
  });

  it('a viewer who cannot edit sees no action', async () => {
    await open(stateful({ roles: ['viewer'] }));
    expect(within(header()).queryByRole('button', { name: /into tasks/ })).toBeNull();
  });
});

describe('Seen before', () => {
  it('each threat card lists its history: the key opens the work item, the PR opens the evidence, and the reason is given', async () => {
    await open(mockApi('ready'));
    const card = await waitFor(() => {
      const c = cardOf('Someone could reuse an old sign-in link to take over an account.');
      expect(within(c).getByRole('list', { name: 'Seen before' })).toBeTruthy();
      return c;
    });
    const list = within(card).getByRole('list', { name: 'Seen before' });
    const rows = within(list).getAllByRole('listitem').map((li) => li.textContent);
    expect(rows[0]).toBe('INC-7 · Incident · Old sign-in links reused to take over accounts (Sev-2, accounts)Why: same component accounts; shared words: account, link, sign, takeover');
    expect(rows[1]).toMatch(/^PAY-3 · same threat · Verified with PR #41Why: same CWE-640/);
    const key = within(list).getByRole('link', { name: 'INC-7' });
    expect(key.getAttribute('href')).toBe('/browse/INC-7');
    expect(key.getAttribute('target')).toBe('_top');
    const pr = within(list).getByRole('link', { name: 'PR #41' });
    expect(pr.getAttribute('href')).toBe('https://bitbucket.org/acme/payments-service/pull-requests/41');
    expect(pr.getAttribute('rel')).toBe('noopener noreferrer');
    expect(within(cardOf('Anyone can learn which email addresses are customers.')).getByText(/dismissed as a false positive/)).toBeTruthy();
    expect(within(cardOf('A stolen link lets an attacker lock the real owner out for good.')).getByText(/risk accepted until 2027-01-31/)).toBeTruthy();
    // A threat with no history shows no block.
    expect(within(cardOf('Someone could send thousands of reset emails.')).queryByRole('list', { name: 'Seen before' })).toBeNull();
  });

  it('the headline names the past incident behind a blocking threat', async () => {
    await open(mockApi('ready'));
    const line = await screen.findByTestId('threatline-happened-before');
    expect(line.textContent).toBe('This happened before: INC-7 — Old sign-in links reused to take over accounts.');
    expect(within(line).getByRole('link', { name: 'INC-7' }).getAttribute('target')).toBe('_top');
  });

  it('inside Jira the links go through the Forge router', async () => {
    const navigate = vi.fn(async () => undefined);
    await open({ ...mockApi('ready'), navigate });
    await userEvent.click(within(await screen.findByTestId('threatline-happened-before')).getByRole('link', { name: 'INC-7' }));
    expect(navigate).toHaveBeenCalledWith('/browse/INC-7', { newTab: false });
  });

  it('is loaded only for a ready review, once; a failure or an older bridge shows no history', async () => {
    const memory = vi.fn(async () => structuredClone(SEEN_BEFORE_FIXTURE));
    await open({ ...mockApi('in_progress'), memory });
    expect(memory).not.toHaveBeenCalled();
    cleanup();
    await open({ ...mockApi('ready'), memory });
    await screen.findByTestId('threatline-happened-before');
    expect(memory).toHaveBeenCalledTimes(1);
    cleanup();
    await open({ ...mockApi('ready'), memory: async () => ({ error: 'unavailable' as const }) });
    await screen.findByText('Magic links never expire');
    expect(screen.queryByRole('list', { name: 'Seen before' })).toBeNull();
    expect(screen.queryByTestId('threatline-happened-before')).toBeNull();
    cleanup();
    const { memory: _omit, ...older } = mockApi('ready');
    await open(older);
    expect(screen.queryByRole('list', { name: 'Seen before' })).toBeNull();
  });

  it('has no axe violations with the history and the tasks result shown', async () => {
    const r = await open(stateful());
    await screen.findByTestId('threatline-happened-before');
    await userEvent.click(within(header()).getByRole('button', { name: 'Turn 2 requirements into tasks' }));
    await within(header()).findByText(/^Created/);
    expect((await axe.run(r.container, { rules: { 'color-contrast': { enabled: false } } })).violations.map((v) => v.id)).toEqual([]);
  });
});

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
// No per-keystroke timers: typing a URL is one task, not forty.
const userEvent = userEventLib.setup({ delay: null });

const withRoles = (state: string, roles: PanelDto['roles']): PanelApi => {
  const base = mockApi(state);
  return { ...base, get: async () => ({ ...structuredClone(FIXTURES[state]!), roles }) };
};

async function open(api: PanelApi, tab?: RegExp) {
  const r = render(<IssuePanel api={api} />);
  await waitFor(() => expect(screen.queryByText(/Loading the security review/)).toBeNull());
  if (tab) await userEvent.click(screen.getByRole('tab', { name: tab }));
  return r;
}

describe('Requirements tab', () => {
  it('a developer creates sub-tasks for requirements that have none, and sees the new keys', async () => {
    const api = withRoles('ready', ['viewer', 'developer']);
    const create = vi.fn(async (threatIds: string[]) => ({ created: threatIds.map((_, i) => ({ requirementId: `req_${i + 1}`, subtaskKey: `PAY-${100 + i}` })), skipped: [] }));
    await open({ ...api, createRequirements: create }, /Requirements/);
    await userEvent.click(screen.getByRole('button', { name: 'Create sub-tasks (2)' }));
    expect(create).toHaveBeenCalledWith(['thr_3', 'thr_1']);
    expect(await screen.findByText('Created PAY-100, PAY-101.')).toBeTruthy();
  });

  it('a viewer without edit permission sees no controls', async () => {
    await open(withRoles('ready', ['viewer']), /Requirements/);
    expect(screen.queryByRole('button', { name: /Create sub-tasks/ })).toBeNull();
    // No control that changes anything; copying a test skeleton (read-only) is open to every viewer.
    expect(screen.queryByRole('combobox', { name: 'Status' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Accept risk' })).toBeNull();
    expect(screen.getAllByRole('button', { name: 'Copy test skeleton' }).length).toBeGreaterThan(0);
  });

  it('a requirement with a sub-task links to it', async () => {
    const api = withRoles('ready', ['viewer', 'developer']);
    const dto = { ...structuredClone(FIXTURES.ready!), requirements: FIXTURES.ready!.requirements.map((r, i) => ({ ...r, subtaskKey: `PAY-${100 + i}` })) };
    await open({ ...api, get: async () => dto }, /Requirements/);
    expect(screen.getByRole('link', { name: 'PAY-100' }).getAttribute('href')).toBe('/browse/PAY-100');
    expect(screen.queryByRole('button', { name: /Create sub-tasks/ })).toBeNull();
  });

  it('Verified asks for evidence; the evidence goes to the server and its error is shown', async () => {
    const setStatus = vi.fn(async () => ({ error: 'validation' as const, message: 'A PR or Confluence link must start with https://.' }));
    await open({ ...withRoles('ready', ['viewer', 'developer']), setStatus }, /Requirements/);
    const item = screen.getAllByRole('listitem').find((li) => within(li).queryByText('Magic links expire after 15 minutes'))!;
    await userEvent.selectOptions(within(item).getByRole('combobox', { name: 'Status' }), 'Verified');
    const form = within(item).getByRole('form', { name: 'Verification evidence' });
    await userEvent.click(within(form).getByRole('button', { name: 'Save evidence' }));
    expect(within(form).getByText('Add a link, path or note.')).toBeTruthy();
    expect(setStatus).not.toHaveBeenCalled();
    await userEvent.click(within(form).getByRole('radio', { name: 'PR link' }));
    await userEvent.type(within(form).getByRole('textbox', { name: 'PR link' }), 'http://bitbucket.org/x/y/pull-requests/1');
    await userEvent.click(within(form).getByRole('button', { name: 'Save evidence' }));
    expect(setStatus).toHaveBeenCalledWith('req_2', 'Verified', { kind: 'pr', ref: 'http://bitbucket.org/x/y/pull-requests/1' });
    expect(await within(form).findByText('A PR or Confluence link must start with https://.')).toBeTruthy();
  });

  it('Not applicable is offered to security champions only', async () => {
    await open(withRoles('ready', ['viewer', 'developer']), /Requirements/);
    const dev = screen.getAllByRole('combobox', { name: 'Status' })[0]!;
    expect(within(dev).queryByRole('option', { name: 'Not applicable' })).toBeNull();
    cleanup();
    await open(withRoles('ready', ['viewer', 'developer', 'champion']), /Requirements/);
    const champ = screen.getAllByRole('combobox', { name: 'Status' })[0]!;
    expect(within(champ).getByRole('option', { name: 'Not applicable' })).toBeTruthy();
  });

  it('shows the evidence of a verified requirement', async () => {
    await open(withRoles('pass', ['viewer']), /Requirements/);
    expect(screen.getAllByText(/Evidence:/).length).toBeGreaterThan(0);
  });

  it('a PR evidence link opens the PR itself, with its note shown beside it', async () => {
    const url = 'https://bitbucket.org/acme/payments/pull-requests/42';
    const api = withRoles('pass', ['viewer']);
    const get: PanelApi['get'] = async () => {
      const dto = (await api.get()) as PanelDto;
      return { ...dto, requirements: dto.requirements.map((r) => ({ ...r, evidence: { kind: 'pr' as const, ref: url, note: 'test_webhook_rejects_bad_signature', attester: 'acc-dev' } })) };
    };
    await open({ ...api, get }, /Requirements/);
    const links = screen.getAllByRole('link', { name: url });
    expect(links[0]!.getAttribute('href')).toBe(url);
    expect(screen.getAllByText(/test_webhook_rejects_bad_signature/).length).toBeGreaterThan(0);
  });

  it.each(['light', 'dark'])('has no axe violations with the evidence form open (%s)', async (mode) => {
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = await open(withRoles('ready', ['viewer', 'developer', 'champion']), /Requirements/);
    await userEvent.selectOptions(screen.getAllByRole('combobox', { name: 'Status' })[0]!, 'Verified');
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
  });
});

describe('Threat triage (champions)', () => {
  it('developers do not see triage', async () => {
    await open(withRoles('ready', ['viewer', 'developer']));
    expect(screen.queryByRole('button', { name: /^Triage/ })).toBeNull();
  });

  it('a champion dismisses a threat with a reason code', async () => {
    const triage = vi.fn(async () => []);
    await open({ ...withRoles('ready', ['viewer', 'champion']), triage });
    const card = screen.getAllByRole('article')[1]!;
    await userEvent.click(within(card).getByRole('button', { name: /^Triage/ }));
    const editor = within(card).getByRole('form', { name: 'Triage threat' });
    await userEvent.selectOptions(within(editor).getByRole('combobox', { name: 'Action' }), 'dismiss');
    await userEvent.click(within(editor).getByRole('button', { name: 'Apply' }));
    expect(within(editor).getByText('Choose a reason.')).toBeTruthy();
    await userEvent.selectOptions(within(editor).getByRole('combobox', { name: 'Reason' }), 'already_mitigated');
    await userEvent.click(within(editor).getByRole('button', { name: 'Apply' }));
    expect(triage).toHaveBeenCalledWith({ threatId: 'thr_1', op: 'dismiss', reason: 'already_mitigated' });
  });

  it('a champion edits likelihood and impact', async () => {
    const triage = vi.fn(async () => []);
    await open({ ...withRoles('ready', ['viewer', 'champion']), triage });
    const card = screen.getAllByRole('article')[1]!;
    await userEvent.click(within(card).getByRole('button', { name: /^Triage/ }));
    const editor = within(card).getByRole('form', { name: 'Triage threat' });
    await userEvent.selectOptions(within(editor).getByRole('combobox', { name: 'Action' }), 'edit');
    await userEvent.selectOptions(within(editor).getByRole('combobox', { name: 'Likelihood' }), '5');
    await userEvent.click(within(editor).getByRole('button', { name: 'Apply' }));
    expect(triage).toHaveBeenCalledWith({ threatId: 'thr_1', op: 'edit', patch: { likelihood: 5 } });
  });

  it('a champion confirms a budget pause from the banner', async () => {
    const confirm = vi.fn(async () => ({ seq: 1 }));
    await open({ ...withRoles('budget', ['viewer', 'champion']), confirm });
    await userEvent.click(screen.getByRole('button', { name: 'Confirm this work item' }));
    expect(confirm).toHaveBeenCalledWith('rev_66405_1', 'budget');
  });

  it('a champion confirms threats that need a human', async () => {
    const confirm = vi.fn(async () => ({ seq: 1 }));
    const dto = { ...structuredClone(FIXTURES.ready!), roles: ['viewer', 'champion'] as PanelDto['roles'] };
    dto.verdict!.reasons.push({ code: 'needs_human', message: '1 threat needs a security champion to confirm it.' });
    await open({ ...mockApi('ready'), get: async () => dto, confirm });
    await userEvent.click(screen.getByRole('button', { name: 'Confirm threats' }));
    expect(confirm).toHaveBeenCalledWith('rev_66405_1', 'review');
  });

  it('the header reason carries Confirm threats; no banner repeats it, and a viewer sees the reason without the button', async () => {
    const confirm = vi.fn(async () => ({ seq: 1 }));
    const dto = { ...structuredClone(FIXTURES.ready!), roles: ['viewer', 'champion'] as PanelDto['roles'] };
    dto.verdict!.reasons.unshift({ code: 'needs_human', message: '1 threat needs a security champion to confirm it.' });
    await open({ ...mockApi('ready'), get: async () => dto, confirm });
    const next = screen.getByRole('list', { name: 'What to do next' });
    await userEvent.click(within(next).getByRole('button', { name: 'Confirm threats' }));
    expect(confirm).toHaveBeenCalledWith('rev_66405_1', 'review');
    expect(screen.queryByText('Threats need a security champion')).toBeNull();
    cleanup();
    await open({ ...mockApi('ready'), get: async () => ({ ...dto, roles: ['viewer'] as PanelDto['roles'] }) });
    expect(within(screen.getByRole('list', { name: 'What to do next' })).getByText('1 threat needs a security champion to confirm it.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Confirm threats' })).toBeNull();
    expect(screen.queryByText('Threats need a security champion')).toBeNull();
  });

  it.each(['light', 'dark'])('has no axe violations with the editor open (%s)', async (mode) => {
    document.documentElement.setAttribute('data-color-mode', mode);
    const { container } = await open(withRoles('ready', ['viewer', 'champion']));
    await userEvent.click(within(screen.getAllByRole('article')[0]!).getByRole('button', { name: /^Triage/ }));
    const results = await axe.run(container, { rules: { 'color-contrast': { enabled: false } } });
    expect(results.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([]);
  });
});

describe('Confluence threat-model page (RQ-5)', () => {
  it('a developer publishes from the History tab and then sees the page link', async () => {
    const publish = vi.fn(async () => ({ pageId: '900', url: 'https://x/wiki/pages/900', created: true }));
    await open({ ...withRoles('ready', ['viewer', 'developer']), publish }, /History/);
    await userEvent.click(screen.getByRole('button', { name: 'Publish to Confluence' }));
    expect(publish).toHaveBeenCalled();
    expect((await screen.findByRole('link', { name: 'Open the threat-model page' })).getAttribute('href')).toBe('https://x/wiki/pages/900');
  });

  it('an already published item shows the link and an Update button; publish errors are shown', async () => {
    const publish = vi.fn(async () => ({ error: 'validation' as const, message: 'Link a Confluence design page to this work item first.' }));
    const api = withRoles('ready', ['viewer', 'developer']);
    const dto = { ...structuredClone(FIXTURES.ready!), roles: ['viewer', 'developer'] as PanelDto['roles'], threatModelPage: { url: 'https://x/wiki/pages/900' } };
    await open({ ...api, get: async () => dto, publish }, /History/);
    expect(screen.getByRole('link', { name: 'Open the threat-model page' })).toBeTruthy();
    await userEvent.click(screen.getByRole('button', { name: 'Update the Confluence page' }));
    expect(await screen.findByText('Link a Confluence design page to this work item first.')).toBeTruthy();
  });
});

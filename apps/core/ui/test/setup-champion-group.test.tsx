// @vitest-environment jsdom
import './setup-dom.js';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { SetupChecklist, championGroupItem } from '../src/admin/SetupChecklist.js';
import { mockAdminApi } from '../src/mock-bridge.js';
import type { ChampionGroupStatus } from '../../src/resolvers/setup-groups.js';

afterEach(cleanup);

const status = (over: Partial<ChampionGroupStatus>): ChampionGroupStatus => ({ group: 'threatline-security-champions', exists: true, member: true, groupsUrl: 'https://admin.atlassian.com/', ...over });
const setupStatus = async () => ({ keys: true, sqlVersion: 3, validatorSeenOn: ['PAY'], automationRuleSeen: false, mcpEnabledHint: 'x', bitbucketKeyCopied: false });

describe('Setup checklist: security champion group (fresh site)', () => {
  it('a missing group is a to-do with where to create it and a link; it never offers to create it', async () => {
    render(<SetupChecklist api={{ ...mockAdminApi(), setupStatus, championGroupStatus: async () => status({ exists: false, member: false }) }} reviewMode="engine" />);
    const list = await screen.findByRole('list', { name: 'Setup checklist' });
    const item = (await within(list).findByText(/Security champion group “threatline-security-champions” not found/)).closest('li')!;
    expect(item.textContent).toMatch(/To do/);
    expect(item.textContent).toMatch(/Atlassian Administration → Directory → Groups/);
    expect(item.textContent).toMatch(/second person/);
    expect(within(item).getByRole('link', { name: 'Open Atlassian Administration' }).getAttribute('href')).toBe('https://admin.atlassian.com/');
    expect(within(item).queryByRole('button')).toBeNull();
  });

  it('a group the admin is not in is a to-do; one they are in is done and still mentions the second approver', () => {
    expect(championGroupItem(status({ member: false }))).toMatchObject({ done: false, text: expect.stringMatching(/exists, but you are not in it: add yourself/) });
    const ok = championGroupItem(status({}));
    expect(ok).toMatchObject({ done: true, text: expect.stringMatching(/exists and you are in it\. High and Critical risk acceptances need a second person/) });
    expect(ok.link).toBeUndefined();
    expect(championGroupItem(status({ exists: null, member: null }))).toMatchObject({ done: null, text: expect.stringMatching(/Could not check/) });
  });

  it('when the group check fails or the bridge lacks it, the rest of the checklist still shows', async () => {
    render(<SetupChecklist api={{ ...mockAdminApi(), setupStatus, championGroupStatus: async () => ({ error: 'unavailable' as const }) }} reviewMode="engine" />);
    const list = await screen.findByRole('list', { name: 'Setup checklist' });
    expect(within(list).getByText(/Signing keys created/)).toBeTruthy();
    expect(within(list).queryByText(/Security champion group/)).toBeNull();
    cleanup();
    render(<SetupChecklist api={{ ...mockAdminApi(), setupStatus }} reviewMode="engine" />);
    expect(await screen.findByText(/Signing keys created/)).toBeTruthy();
  });

  it('offers a group the admin is already in: one click points the policy at it, and the item turns done', async () => {
    const base = mockAdminApi();
    const saved: string[] = [];
    let current = status({ exists: false, member: false, candidates: ['site-admins'] });
    const api = {
      ...base,
      setupStatus,
      championGroupStatus: async () => current,
      setPolicy: async (policy: Parameters<typeof base.setPolicy>[0]) => {
        saved.push(policy.championGroup);
        current = status({ group: policy.championGroup });
        return { policy };
      },
    };
    render(<SetupChecklist api={api} reviewMode="engine" />);
    const list = await screen.findByRole('list', { name: 'Setup checklist' });
    const item = (await within(list).findByText(/not found\. Use a group you are already in/)).closest('li')!;
    fireEvent.click(within(item).getByRole('button', { name: 'Use “site-admins”' }));
    await waitFor(() => expect(within(list).getByText(/Security champion group “site-admins” exists and you are in it/)).toBeTruthy());
    expect(saved).toEqual(['site-admins']);
  });
});


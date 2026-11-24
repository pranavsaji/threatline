import { describe, expect, it } from 'vitest';
import { ok } from '@threatline/shared';
import { adminChampionGroupStatus, championCandidates, GROUPS_ADMIN_URL } from '../../src/resolvers/setup-groups.js';
import { coreDeps } from '../support/core-deps.js';

const admin = { accountId: 'acc-admin' };
const GROUP = 'threatline-security-champions';

function deps(o: { exists?: boolean | 'error' | 'missing'; groups?: string[]; isAdmin?: boolean } = {}) {
  const t = coreDeps();
  t.jira.isAdmin = async () => ok(o.isAdmin ?? true);
  t.jira.groupsOf = async () => ok(o.groups ?? []);
  if (o.exists === 'missing') delete (t.jira as { groupExists?: unknown }).groupExists;
  else t.jira.groupExists = async (name) => (o.exists === 'error' ? { ok: false, error: { code: 'forbidden', message: 'no' } } : ok(name === GROUP && o.exists !== false));
  return t;
}

describe('admin.championGroupStatus (setup checklist)', () => {
  it('a fresh site: the default champion group does not exist and the admin is not in it', async () => {
    expect(await adminChampionGroupStatus(deps({ exists: false }).deps, admin)).toEqual({ group: GROUP, exists: false, member: false, groupsUrl: GROUPS_ADMIN_URL });
  });

  it('the group exists and the admin is a member', async () => {
    expect(await adminChampionGroupStatus(deps({ exists: true, groups: [GROUP, 'jira-users'] }).deps, admin)).toMatchObject({ exists: true, member: true });
  });

  it('a failed group lookup is unknown, unless membership proves the group exists', async () => {
    expect(await adminChampionGroupStatus(deps({ exists: 'error' }).deps, admin)).toMatchObject({ exists: null, member: false });
    expect(await adminChampionGroupStatus(deps({ exists: 'missing', groups: [GROUP] }).deps, admin)).toMatchObject({ exists: true, member: true });
  });

  it('Jira administrators only; it creates nothing', async () => {
    const t = deps({ isAdmin: false });
    expect(await adminChampionGroupStatus(t.deps, admin)).toEqual({ error: 'forbidden', message: 'Only a Jira administrator can do this.' });
  });

  it('offers groups the admin is already in, security and admin groups first, never everyone-groups', async () => {
    const groups = ['jira-users-acme', 'site-admins', 'confluence-users', 'appsec', 'jira-admins-acme', 'atlassian-addons-admin', 'trusted-users-1', 'security-team'];
    expect(await adminChampionGroupStatus(deps({ exists: false, groups }).deps, admin)).toMatchObject({
      exists: false,
      member: false,
      candidates: ['security-team', 'jira-admins-acme', 'site-admins', 'appsec'],
    });
  });

  it('offers nothing once the admin is in the champion group', async () => {
    expect(await adminChampionGroupStatus(deps({ exists: true, groups: [GROUP, 'site-admins'] }).deps, admin)).not.toHaveProperty('candidates');
  });

  it('candidates: at most five, no duplicates, never the current group', () => {
    expect(championCandidates(['g1', 'g2', 'g3', 'g4', 'g5', 'g6', 'g1', GROUP], GROUP)).toEqual(['g1', 'g2', 'g3', 'g4', 'g5']);
    expect(championCandidates(['jira-software-users', 'jira-servicemanagement-users-acme', 'users'], GROUP)).toEqual([]);
  });
});

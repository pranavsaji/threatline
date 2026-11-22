import { describe, expect, it } from 'vitest';
import { ok } from '@threatline/shared';
import { adminChampionGroupStatus, GROUPS_ADMIN_URL } from '../../src/resolvers/setup-groups.js';
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
});

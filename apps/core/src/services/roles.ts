import type { Role } from '@threatline/core';
import type { SitePolicy } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';

/**
 * Roles for showing or hiding controls (every write re-checks on the server). developer = can edit the work item;
 * tech_lead / champion = member of the policy's groups; admin = Jira administrator. Lookup failures grant nothing.
 */
export async function rolesOf(deps: Pick<CoreDeps, 'jira'>, accountId: string, issueId: string, policy: SitePolicy): Promise<Role[]> {
  const [edit, groups, admin] = await Promise.all([deps.jira.canEdit(accountId, issueId), deps.jira.groupsOf(accountId), deps.jira.isAdmin(accountId)]);
  const roles: Role[] = ['viewer'];
  if (edit.ok && edit.value) roles.push('developer');
  const g = groups.ok ? groups.value : [];
  if (g.includes(policy.techLeadGroup)) roles.push('tech_lead');
  if (g.includes(policy.championGroup)) roles.push('champion');
  if (admin.ok && admin.value) roles.push('admin');
  return roles;
}

/** Deciding threats that wait for a person is a security champion's job (separation of duties): admins are not enough. */
export async function isChampion(deps: Pick<CoreDeps, 'jira'>, accountId: string, policy: SitePolicy): Promise<boolean> {
  if (!accountId) return false;
  const groups = await deps.jira.groupsOf(accountId);
  return groups.ok && groups.value.includes(policy.championGroup);
}

/**
 * Site-wide surfaces with no work item (the champion inbox): a member of the policy's champion group or a Jira admin.
 * Lookup failures grant nothing.
 */
export async function isChampionOrAdmin(deps: Pick<CoreDeps, 'jira'>, accountId: string, policy: SitePolicy): Promise<boolean> {
  if (!accountId) return false;
  const [groups, admin] = await Promise.all([deps.jira.groupsOf(accountId), deps.jira.isAdmin(accountId)]);
  return (groups.ok && groups.value.includes(policy.championGroup)) || (admin.ok && admin.value);
}

import type { CoreDeps } from '../deps.js';
import { apiError, type ApiError } from './errors.js';
import { requireAdmin } from './admin.js';

/** Where groups are managed on Atlassian Cloud (Directory → Groups); Jira's own group page redirects there. */
export const GROUPS_ADMIN_URL = 'https://admin.atlassian.com/';

/**
 * The setup checklist's champion-group item. A fresh site has no `threatline-security-champions` group, so nobody can
 * confirm flagged threats or approve High/Critical risk acceptances until an org admin creates it and adds people.
 * `exists` / `member` are null when Jira could not say. Threatline never creates groups or changes membership.
 */
export interface ChampionGroupStatus {
  group: string;
  exists: boolean | null;
  /** Whether the admin looking at the checklist is in the group. */
  member: boolean | null;
  groupsUrl: string;
}

/** `admin.championGroupStatus`: does the policy's champion group exist, and is the calling admin in it? Jira administrators only. */
export async function adminChampionGroupStatus(deps: CoreDeps, a: { accountId: string }): Promise<ChampionGroupStatus | ApiError> {
  const denied = await requireAdmin(deps, a);
  if (denied) return denied;
  const policy = await deps.config.site();
  if (!policy.ok) return apiError(policy.error);
  const group = policy.value.championGroup;
  const [exists, mine] = await Promise.all([
    deps.jira.groupExists ? deps.jira.groupExists(group).catch(() => null) : Promise.resolve(null),
    deps.jira.groupsOf(a.accountId).catch(() => null),
  ]);
  const member = mine?.ok ? mine.value.includes(group) : null;
  // Being in the group proves it exists, whatever the group lookup said.
  const found = member === true ? true : exists?.ok ? exists.value : null;
  return { group, exists: found, member, groupsUrl: GROUPS_ADMIN_URL };
}

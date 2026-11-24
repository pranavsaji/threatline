import type { CoreDeps } from '../deps.js';
import { apiError, type ApiError } from './errors.js';
import { requireAdmin } from './admin.js';

/** Where groups are managed on Atlassian Cloud (Directory → Groups); Jira's own group page redirects there. */
export const GROUPS_ADMIN_URL = 'https://admin.atlassian.com/';

/**
 * The setup checklist's champion-group item. A fresh site has no `threatline-security-champions` group, so nobody can
 * confirm flagged threats or approve High/Critical risk acceptances until an org admin creates it and adds people.
 * `exists` / `member` are null when Jira could not say. Threatline never creates groups or changes membership; it
 * can only point the policy at a group the admin is already in.
 */
export interface ChampionGroupStatus {
  group: string;
  exists: boolean | null;
  /** Whether the admin looking at the checklist is in the group. */
  member: boolean | null;
  groupsUrl: string;
  /**
   * Groups the calling admin is already in that could serve as the champion group, offered as one click when the named
   * group is missing or the admin is not in it. Everyone-groups (product access, add-ons) are left out.
   */
  candidates?: string[];
}

/** Product-access and app groups: everyone on the site, or no person at all, so never a champion group. */
const NOT_A_CHAMPION_GROUP = /(^|-)users?(-|$)|addons?|^trusted-users|^atlassian-|^system-/i;

/** At most five of the admin's groups, security and admin groups first. */
export function championCandidates(groups: readonly string[], current: string): string[] {
  const rank = (g: string) => (/secur|champion/i.test(g) ? 0 : /admin/i.test(g) ? 1 : 2);
  return [...new Set(groups)]
    .filter((g) => g !== current && !NOT_A_CHAMPION_GROUP.test(g))
    .sort((a, b) => rank(a) - rank(b) || a.localeCompare(b))
    .slice(0, 5);
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
  const candidates = member !== true && mine?.ok ? championCandidates(mine.value, group) : [];
  return { group, exists: found, member, groupsUrl: GROUPS_ADMIN_URL, ...(candidates.length > 0 ? { candidates } : {}) };
}

import { useEffect, useId, useState } from 'react';
import Lozenge from '@atlaskit/lozenge';
import { token } from '@atlaskit/tokens';
import { errorText, isError, type AdminApi, type SetupStatus } from '../bridge.js';
import type { ApiError } from '../types.js';
import type { ChampionGroupStatus } from '../../../src/resolvers/setup-groups.js';
import { AddGate } from './AddGate.js';

type Item = { done: boolean | null; text: string; gate?: boolean; link?: { href: string; label: string } };

/** `admin.championGroupStatus`, when the bridge offers it. */
type GroupApi = { championGroupStatus?: () => Promise<ChampionGroupStatus | ApiError> };

const SECOND_APPROVER = 'High and Critical risk acceptances need a second person (another champion or a Jira admin) to approve them: nobody approves their own.';

/**
 * A fresh site has no champion group: until one exists with people in it, nobody can confirm flagged threats or approve
 * High/Critical risk acceptances. Threatline only checks; creating the group and adding members is the org admin's.
 */
export function championGroupItem(g: ChampionGroupStatus): Item {
  const link = { href: g.groupsUrl, label: 'Open Atlassian Administration' };
  const where = 'Atlassian Administration → Directory → Groups';
  if (g.exists === false)
    return {
      done: false,
      text: `Security champion group “${g.group}” not found. Create it in ${where} and add yourself, or name an existing group under Roles. Until then nobody can confirm flagged threats. ${SECOND_APPROVER}`,
      link,
    };
  if (g.exists === null)
    return { done: null, text: `Could not check the security champion group “${g.group}”: make sure it exists in ${where} and that you are in it. ${SECOND_APPROVER}`, link };
  if (g.member === true) return { done: true, text: `Security champion group “${g.group}” exists and you are in it. ${SECOND_APPROVER}` };
  return {
    done: false,
    text: `Security champion group “${g.group}” exists, but ${g.member === false ? 'you are not in it' : 'Threatline could not tell whether you are in it'}: add yourself in ${where} to confirm flagged threats. ${SECOND_APPROVER}`,
    link,
  };
}

const itemsOf = (s: SetupStatus, mode: 'engine' | 'agent' | 'rules_only', authors: number): Item[] => {
  const rulesOnly = mode === 'rules_only';
  const engine = mode === 'engine';
  return [
    {
      done: s.keys,
      text: s.keys
        ? 'Signing keys created'
        : 'Signing keys not created yet (Threatline creates them with the first merge-gate attestation)',
    },
    {
      done: s.sqlVersion > 0,
      text: s.sqlVersion > 0 ? `Database ready (schema version ${s.sqlVersion})` : 'Database not migrated yet',
    },
    {
      done: s.validatorSeenOn.length > 0,
      text:
        s.validatorSeenOn.length > 0
          ? `Done gate seen on ${s.validatorSeenOn.join(', ')}`
          : 'Done gate not seen yet: add "Threatline security gate" to the Done transition',
      gate: s.validatorSeenOn.length === 0,
    },
    engine
      ? { done: true, text: 'Threatline Engine runs every review itself: no Rovo agent or Automation rule needed' }
      : rulesOnly
        ? { done: true, text: 'Rule-based checks only: no Rovo or Automation rule needed' }
        : {
            done: s.automationRuleSeen,
            text: s.automationRuleSeen
              ? 'Automation agent runs arriving'
              : 'No Automation agent run in the last 7 days: check the Threatline review rule. No Rovo on this site? Choose rule-based checks under Review mode.',
          },
    engine || rulesOnly
      ? {
          done: true,
          text: engine
            ? 'Threatline Engine writes reviews itself: no one can submit review runs'
            : 'Rule-based checks only: no AI review runs to lock',
        }
      : authors > 0
        ? { done: true, text: `AI review runs locked to ${authors} ${authors === 1 ? 'account' : 'accounts'}` }
        : {
            done: false,
            text: 'Anyone who can edit a work item can submit its AI review runs: lock them to the Automation rule owner under Review mode',
          },
    {
      done: s.bitbucketKeyCopied,
      text: s.bitbucketKeyCopied ? 'Public key copied to Bitbucket' : 'Copy the public key to Threatline for Bitbucket',
    },
    { done: null, text: s.mcpEnabledHint },
  ];
};

/** Task 24: what Threatline has seen working on this site. */
export function SetupChecklist({
  api,
  reviewMode = 'agent',
  reviewAuthors = 0,
}: {
  api: AdminApi & GroupApi;
  reviewMode?: 'engine' | 'agent' | 'rules_only';
  reviewAuthors?: number;
}) {
  const id = useId();
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [group, setGroup] = useState<ChampionGroupStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api
      .setupStatus()
      .catch((): ApiError => ({ error: 'unavailable' }))
      .then((r) => (isError(r) ? setError(errorText(r)) : setStatus(r)));
    // The group check is its own item: when it fails, the rest of the checklist still shows.
    void api
      .championGroupStatus?.()
      .catch((): ApiError => ({ error: 'unavailable' }))
      .then((r) => (r && !isError(r) ? setGroup(r) : undefined));
  }, [api]);

  return (
    <section aria-labelledby={`${id}-h`} style={{ display: 'grid', gap: 8 }}>
      <h2 id={`${id}-h`} style={{ font: token('font.heading.small'), margin: 0 }}>
        Setup checklist
      </h2>
      {error && <p style={{ margin: 0 }}>{error}</p>}
      {status && (
        <ul aria-label="Setup checklist" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 6 }}>
          {[...itemsOf(status, reviewMode, reviewAuthors), ...(group ? [championGroupItem(group)] : [])].map((item) => (
            <li key={item.text} style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <span style={{ flexShrink: 0 }}>
                {item.done === null ? (
                  <Lozenge>Info</Lozenge>
                ) : (
                  <Lozenge appearance={item.done ? 'success' : 'moved'}>{item.done ? 'Done' : 'To do'}</Lozenge>
                )}
              </span>
              <span>{item.text}</span>
              {item.link && (
                <a href={item.link.href} target="_blank" rel="noreferrer" style={{ color: token('color.link') }}>
                  {item.link.label}
                </a>
              )}
              {item.gate && <AddGate api={api} />}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

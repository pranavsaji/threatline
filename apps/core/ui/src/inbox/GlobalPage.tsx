import { useCallback, useEffect, useState } from 'react';
import Tabs, { Tab, TabList, TabPanel } from '@atlaskit/tabs';
import { token } from '@atlaskit/tokens';
import { isError, type InboxApi, type PostureApi } from '../bridge.js';
import type { ApiError, InboxDto } from '../types.js';
import { PostureDashboard } from '../posture/PostureDashboard.js';
import { ChampionInbox } from './ChampionInbox.js';

/** The waiting count on the tab: a number in words for screen readers, never colour alone. */
function CountBadge({ n }: { n: number }) {
  return (
    <span
      aria-label={`${n} waiting`}
      style={{ marginLeft: 6, padding: '0 6px', borderRadius: 8, font: token('font.body.small'), background: n > 0 ? token('color.background.accent.blue.subtler') : token('color.background.neutral'), color: token('color.text') }}
    >
      {n > 99 ? '99+' : n}
    </span>
  );
}

/**
 * The global page: the security posture dashboard and, for security champions and Jira admins, the champion inbox. The
 * server decides who sees the inbox (a forbidden answer hides the tab); the posture dashboard is shown to everyone.
 */
export function GlobalPage({ posture, inbox }: { posture: PostureApi; inbox: InboxApi }) {
  const [first, setFirst] = useState<InboxDto | ApiError | null>(null);
  const [tab, setTab] = useState(0);

  useEffect(() => {
    let live = true;
    void inbox
      .list()
      .catch((): ApiError => ({ error: 'unavailable' }))
      .then((r) => live && setFirst(r));
    return () => {
      live = false;
    };
  }, [inbox]);
  const onLoaded = useCallback((dto: InboxDto) => setFirst(dto), []);

  // Not a champion or an admin (or not signed in): the page is the dashboard alone.
  const hidden = first !== null && isError(first) && (first.error === 'forbidden' || first.error === 'not_found');
  if (first === null || hidden) return <PostureDashboard api={posture} />;

  return (
    <div style={{ padding: '8px 16px 0', background: token('elevation.surface'), color: token('color.text') }}>
      <Tabs id="threatline-global" selected={tab} onChange={setTab}>
        <TabList>
          <Tab>Security posture</Tab>
          <Tab>
            <span>
              Champion inbox
              {!isError(first) && <CountBadge n={first.total} />}
            </span>
          </Tab>
        </TabList>
        <TabPanel>
          <PostureDashboard api={posture} />
        </TabPanel>
        <TabPanel>
          <div style={{ padding: '16px 0', maxWidth: 1040, width: '100%' }}>
            <ChampionInbox api={inbox} {...(isError(first) ? {} : { initial: first })} onLoaded={onLoaded} />
          </div>
        </TabPanel>
      </Tabs>
    </div>
  );
}

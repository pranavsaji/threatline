import type { AdminApi, InboxApi, PanelApi, PostureApi } from './bridge.js';
import { AdminPage } from './admin/AdminPage.js';
import { IssuePanel } from './panel/IssuePanel.js';
import { PostureDashboard } from './posture/PostureDashboard.js';
import { GlobalPage } from './inbox/GlobalPage.js';

/** One UI bundle serves every Threatline surface; the module key picks the view. */
export function Router({ moduleKey, api, admin, posture, inbox }: { moduleKey: string; api: PanelApi; admin: AdminApi; posture: PostureApi; inbox?: InboxApi }) {
  switch (moduleKey) {
    case 'threatline-admin':
      return <AdminPage api={admin} />;
    case 'threatline-posture':
      // The global page: with an inbox API, champions and admins also get the Champion inbox tab.
      return inbox ? <GlobalPage posture={posture} inbox={inbox} /> : <PostureDashboard api={posture} />;
    case 'threatline-posture-gadget':
      return <PostureDashboard api={posture} compact />;
    case 'threatline-panel':
    default:
      return <IssuePanel api={api} />;
  }
}

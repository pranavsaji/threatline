import '@atlaskit/css-reset';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { adminApiOver, forgeAdminApi, forgeApi, forgeInboxApi, forgePostureApi, inboxApiOver, panelApiOver, postureApiOver, type AdminApi, type InboxApi, type PanelApi, type PostureApi } from './bridge.js';
import { Router } from './router.js';
import { enableTheme } from './theme.js';

/** Inside Forge the page is framed by Atlassian; opened directly (vite dev) it uses the fixture bridge. */
const inForge = window.self !== window.top;

async function start() {
  await enableTheme(inForge);
  let api: PanelApi;
  let admin: AdminApi;
  let posture: PostureApi;
  let inbox: InboxApi;
  let moduleKey = 'threatline-panel';
  if (inForge) {
    api = await forgeApi();
    admin = await forgeAdminApi();
    posture = await forgePostureApi();
    inbox = await forgeInboxApi();
    const { view } = await import('@forge/bridge');
    moduleKey = ((await view.getContext()) as { moduleKey?: string }).moduleKey ?? moduleKey;
  } else {
    const params = new URLSearchParams(window.location.search);
    if (params.get('bridge') === 'local') {
      // e2e/local: the real resolvers over in-memory fakes; `as` picks the signed-in user, `issue` the work item.
      const { localInvoke } = await import('./local-bridge.js');
      const invoke = localInvoke(params.get('api') ?? 'http://localhost:5190', params.get('as') ?? 'acc-dev', params.get('issue') ?? '10042');
      api = panelApiOver(invoke);
      admin = adminApiOver(invoke);
      posture = postureApiOver(invoke);
      inbox = inboxApiOver(invoke);
    } else {
      const mock = await import('./mock-bridge.js');
      api = mock.mockApi();
      admin = mock.mockAdminApi();
      posture = mock.mockPostureApi();
      inbox = mock.mockInboxApi();
    }
    const view = params.get('view');
    if (view === 'admin') moduleKey = 'threatline-admin';
    if (view === 'posture') moduleKey = 'threatline-posture';
    if (view === 'gadget') moduleKey = 'threatline-posture-gadget';
  }
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <Router moduleKey={moduleKey} api={api} admin={admin} posture={posture} inbox={inbox} />
    </StrictMode>,
  );
}
void start();

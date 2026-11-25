import type { CoreDeps } from '../deps.js';
import { seenBefore, type SeenBeforeDto } from '../services/memory-service.js';
import type { ApiError } from './errors.js';
import { authorise, type Viewer } from './panel.js';

/**
 * `panel.memory`: "Seen before" for the threats on this work item's latest review (docs/MEMORY.md). Loaded by the panel
 * after `panel.get`, so it never slows the panel down; `panel.status` (the context column) does not call it. Only what
 * this viewer may open is returned.
 */
export async function panelMemory(deps: CoreDeps, v: Viewer): Promise<SeenBeforeDto | ApiError> {
  const auth = await authorise(deps, v, 'browse');
  if ('error' in auth) return auth;
  return seenBefore(deps, v, auth.issue);
}

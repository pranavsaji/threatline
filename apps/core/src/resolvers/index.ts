import Resolver from '@forge/resolver';
import { getAppContext, webTrigger } from '@forge/api';
import queryKeys from '../../graph/query-keys.json';
import { composeCore } from '../composition.js';
import { forgeGraphRequest, graphEnricher } from '../adapters/graph-enricher.js';
import { graphDelivery } from '../adapters/graph-delivery.js';
import { kvsSigningKeys } from '../adapters/signing-keys.js';
import { systemClock } from '../adapters/clock.js';
import { resolverTable, type ResolverViewer } from './table.js';
import { gateExtensionKey } from '../adapters/workflow-gate.js';

type Ctx = { accountId?: unknown; cloudId?: unknown; extension?: { issue?: { id?: unknown } } };

/** Identity and work item come from the Forge context (the panel's own issue), never from the payload. */
const viewerOf = (context: Ctx): ResolverViewer => ({
  accountId: typeof context.accountId === 'string' ? context.accountId : '',
  issueId: String(context.extension?.issue?.id ?? ''),
  cloudId: typeof context.cloudId === 'string' ? context.cloudId : '',
});

const table = resolverTable({
  enricher: () => graphEnricher(forgeGraphRequest, queryKeys as Record<string, string>),
  delivery: () => graphDelivery(forgeGraphRequest),
  signingKeysReady: async () => {
    const keys = await kvsSigningKeys(systemClock).publicKeys();
    return keys.ok && Object.keys(keys.value).length > 0;
  },
  ciTriggerUrl: () => webTrigger.getUrl('ci-verify'),
  gateExtensionKey: () => {
    try {
      const c = getAppContext();
      return gateExtensionKey(`ari:cloud:ecosystem::environment/${c.appAri.appId}/${c.environmentAri.environmentId}`);
    } catch {
      return null;
    }
  },
});

const resolver = new Resolver();
for (const [key, fn] of Object.entries(table)) {
  resolver.define(key, async ({ payload, context }) => {
    const v = viewerOf(context as Ctx);
    return fn(composeCore({ cloudId: v.cloudId }), v, (payload ?? {}) as Record<string, unknown>);
  });
}

export const panelResolver = resolver.getDefinitions();

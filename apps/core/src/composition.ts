import { ownPageId } from './services/confluence-page.js';
import { forgeLlm } from './adapters/forge-llm.js';
import { DEFAULT_INCIDENT_POLICY, incidentPolicyOf } from '@threatline/core';
import api, { route } from '@forge/api';
import { sqlAttestationRepo, sqlTreeHeadRepo, sqlFeedbackRepo, sqlIssueRepo, sqlLedgerRepo, sqlRequirementRepo, sqlReviewRepo, sqlUsageRepo } from '@threatline/db';
import type { CoreDeps } from './deps.js';
import { systemClock } from './adapters/clock.js';
import { confluenceClient } from './adapters/confluence.js';
import { forgeMigrate } from './adapters/forge-migrate.js';
import { forgeQueue } from './adapters/forge-queue.js';
import { forgeSqlExecutor } from './adapters/forge-sql.js';
import { jiraClient } from './adapters/jira.js';
import { ceilingFromEnv, defaultsFromEnv, forgeKvs, kvsConfigStore, type KvsPort } from './adapters/kvs-config.js';
import { restGatherer } from './adapters/rest-gatherer.js';
import { sqlRetention, sqlSuppressionRepo } from '@threatline/db';
import { kvsSigningKeys } from './adapters/signing-keys.js';
import { jiraVerdictSink } from './adapters/verdict-sink.js';
import { invocationLicense, LICENSE_OVERRIDE_VAR } from './services/license.js';

export interface ForgeContext {
  cloudId?: string;
  installContext?: string;
  /** Paid via Atlassian: `{ active: boolean }` for a paid app in production, undefined otherwise (docs/LICENSING.md). */
  license?: unknown;
}

/** `ari:cloud:jira::site/<cloudId>` → cloudId. */
export const cloudIdOf = (ctx: ForgeContext | undefined): string => ctx?.cloudId ?? ctx?.installContext?.split('/').pop() ?? '';

const SITE_URL_KEY = 'site:url';

function siteUrl(state: KvsPort): () => Promise<string> {
  let cached: string | undefined;
  return async () => {
    if (cached) return cached;
    try {
      const stored = await state.get<string>(SITE_URL_KEY);
      if (typeof stored === 'string' && stored.startsWith('https://')) return (cached = stored);
      const res = await api.asApp().requestJira(route`/rest/api/3/serverInfo`, { headers: { Accept: 'application/json' } });
      const base = ((await res.json()) as { baseUrl?: unknown }).baseUrl;
      if (typeof base === 'string' && base.startsWith('https://')) {
        await state.set(SITE_URL_KEY, base);
        return (cached = base);
      }
    } catch {
      // fall through: panel links become site-relative
    }
    return '';
  };
}

/**
 * The single composition root: every Forge handler builds its dependencies here (app identity; no user).
 * `licenseAuthoritative`: the caller is a resolver, which Forge always gives the license when the app has one.
 */
export function composeCore(ctx?: ForgeContext, opts: { licenseAuthoritative?: boolean } = {}): CoreDeps {
  const x = forgeSqlExecutor();
  const reviews = sqlReviewRepo(x);
  const issues = sqlIssueRepo(x);
  const jira = jiraClient('app');
  const confluence = confluenceClient('app');
  const state = forgeKvs();
  const config = kvsConfigStore(state, defaultsFromEnv(process.env), ceilingFromEnv(process.env));
  // The gatherer reads incidents by the site's incident rule, so every gather (the queue's and the agent's) agrees.
  const incidentRule = async () => {
    const p = await config.site();
    return p.ok ? incidentPolicyOf(p.value) : DEFAULT_INCIDENT_POLICY;
  };
  return {
    reviews,
    requirements: sqlRequirementRepo(x),
    ledger: sqlLedgerRepo(x),
    feedback: sqlFeedbackRepo(x),
    issues,
    usage: sqlUsageRepo(x),
    attestations: sqlAttestationRepo(x),
    treeHeads: sqlTreeHeadRepo(x),
    suppressions: sqlSuppressionRepo(x),
    keys: kvsSigningKeys(systemClock, state),
    llm: forgeLlm(),
    jira,
    confluence,
    gatherer: restGatherer({ jira, confluence, reviews, issues, clock: systemClock, cloudId: cloudIdOf(ctx), siteUrl: siteUrl(state), incidentRule, ownPage: (id) => ownPageId({ state }, id) }),
    verdicts: jiraVerdictSink(jira),
    config,
    state,
    retention: sqlRetention(x),
    queue: forgeQueue(),
    clock: systemClock,
    migrate: forgeMigrate(),
    siteUrl: siteUrl(state),
    license: invocationLicense(state, systemClock, { context: ctx?.license, override: process.env[LICENSE_OVERRIDE_VAR], authoritative: opts.licenseAuthoritative === true }),
  };
}

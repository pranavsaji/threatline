import api from '@forge/api';
import { normalizeFact } from '@threatline/core';
import { appError, err, ok, type ContextFact, type Result, type SourceType } from '@threatline/shared';

export type GraphRequest = (query: string, variables: object) => Promise<{ data?: unknown; errors?: unknown[] }>;

export interface GraphEnrichment {
  facts: ContextFact[];
  partial: boolean;
  reasons: string[];
}

/** CE-2: persisted queries only. `value` is a union; Threatline reads node ids only (no untrusted titles). */
export const CUSTOM_QUERY = `query threatline_customQuery($queryKey: String!, $queryParams: CypherRequestParams, $first: Int, $after: String) {
  customQuery(queryKey: $queryKey, queryParams: $queryParams, first: $first, after: $after) {
    edges { node { columns { key value { __typename ... on CypherQueryResultNode { id } } } } }
    pageInfo { hasNextPage endCursor }
  }
}`;

const PAGE_SIZE = 25;
const MAX_PAGES = 4;
const MAX_RETRIES = 3;
const RETRYABLE = new Set(['QUERY_NOT_FOUND', 'RATE_LIMITED', 'TOO_MANY_REQUESTS']);
const ISSUE_ARI = /^ari:cloud:jira:[A-Za-z0-9-]*:issue\/\d{1,18}$/;

/** Fact type from the ARI's resource type. Unknown resources are skipped rather than guessed. */
export function sourceTypeOfAri(ari: string, queryName: string): SourceType | null {
  const resource = /^ari:cloud:[^:]+:[^:]*:([a-z-]+)\//.exec(ari)?.[1] ?? '';
  if (/commit/.test(resource)) return 'commit';
  if (/pull-request|pullrequest/.test(resource)) return 'pull_request';
  if (/team/.test(resource)) return 'team';
  if (/page|blogpost/.test(resource)) return 'confluence_page';
  if (/incident/.test(resource) || /incident/i.test(queryName)) return 'incident';
  if (/component/.test(resource)) return 'component';
  if (/issue|work-item/.test(resource)) return 'jira_issue';
  return null;
}

const label: Record<SourceType, string> = {
  commit: 'Linked commit',
  pull_request: 'Linked pull request',
  team: 'Assigned team',
  confluence_page: 'Linked page',
  incident: 'Linked incident',
  component: 'Impacted component',
  jira_issue: 'Related work item',
  jira_comment: 'Comment',
  review: 'Review',
};

type Page = { ids: string[]; hasNext: boolean; cursor: string | null };

function parsePage(res: { data?: unknown; errors?: unknown[] }): Result<Page, string> {
  // CE-4: success means data present AND errors empty. Teamwork Graph reports failures as HTTP 200 with errors[].
  if (Array.isArray(res.errors) && res.errors.length > 0) {
    const code = (res.errors[0] as { extensions?: { code?: unknown } })?.extensions?.code;
    return err(typeof code === 'string' ? code : 'UNKNOWN');
  }
  const cq = (res.data as { customQuery?: unknown } | undefined)?.customQuery as
    | { edges?: Array<{ node?: { columns?: Array<{ value?: { id?: unknown } }> } }>; pageInfo?: { hasNextPage?: unknown; endCursor?: unknown } }
    | null
    | undefined;
  if (!cq) return err('NO_DATA');
  const ids: string[] = [];
  for (const e of cq.edges ?? []) for (const c of e.node?.columns ?? []) if (typeof c.value?.id === 'string') ids.push(c.value.id);
  return ok({ ids, hasNext: cq.pageInfo?.hasNextPage === true, cursor: typeof cq.pageInfo?.endCursor === 'string' ? cq.pageInfo.endCursor : null });
}

/**
 * Teamwork Graph enrichment (as the user, Preview). Additive only: facts are stored with the review and shown in the
 * panel but carry version 'graph' and must be excluded from `contextHash`, so enrichment never makes a review stale.
 */
export function graphEnricher(
  request: GraphRequest,
  queryKeys: Record<string, string>,
  opts: { sleep?: (ms: number) => Promise<void>; random?: () => number } = {},
): { enrich(issueAri: string): Promise<Result<GraphEnrichment>> } {
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const random = opts.random ?? Math.random;

  async function runQuery(name: string, queryKey: string, issueAri: string): Promise<{ ids: string[]; reasons: string[] }> {
    const ids: string[] = [];
    let after: string | null = null;
    for (let page = 0; page < MAX_PAGES; page++) {
      let parsed: Result<Page, string> | null = null;
      for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        let res: { data?: unknown; errors?: unknown[] };
        try {
          res = await request(CUSTOM_QUERY, { queryKey, queryParams: { issueAri }, first: PAGE_SIZE, after });
        } catch {
          return { ids, reasons: [`graph_unavailable:${name}`] };
        }
        parsed = parsePage(res);
        if (parsed.ok || !RETRYABLE.has(parsed.error) || attempt === MAX_RETRIES) break;
        await sleep(Math.min(1000 * 2 ** attempt + Math.floor(random() * 250), 8000));
      }
      if (!parsed || !parsed.ok) return { ids, reasons: [`graph_error:${name}:${parsed && !parsed.ok ? parsed.error : 'UNKNOWN'}`] };
      ids.push(...parsed.value.ids);
      if (!parsed.value.hasNext || !parsed.value.cursor) return { ids, reasons: ids.length === 0 ? [`scope_or_empty:${name}`] : [] };
      after = parsed.value.cursor;
    }
    return { ids, reasons: [`graph_truncated:${name}`] };
  }

  return {
    async enrich(issueAri) {
      if (!ISSUE_ARI.test(issueAri)) return err(appError('validation', 'expected a Jira issue ARI'));
      const entries = Object.entries(queryKeys);
      if (entries.length === 0) return ok({ facts: [], partial: true, reasons: ['graph_not_configured'] });
      const results = await Promise.all(entries.map(([name, key]) => runQuery(name, key, issueAri).then((r) => ({ name, ...r }))));
      const facts: ContextFact[] = [];
      const seen = new Set<string>();
      const reasons: string[] = [];
      for (const r of results) {
        reasons.push(...r.reasons);
        for (const id of r.ids) {
          const type = sourceTypeOfAri(id, r.name);
          if (!type || seen.has(id) || id === issueAri) continue;
          seen.add(id);
          facts.push(normalizeFact({ sourceAri: id, sourceType: type, title: `${label[type]} ${id.split('/').pop() ?? ''}`.trim(), url: '', text: '', version: 'graph', trusted: true, origin: 'graph' }));
        }
      }
      return ok({ facts, partial: reasons.length > 0, reasons });
    },
  };
}

/** Forge-backed request: Teamwork Graph is asUser only (not callable from triggers or consumers). */
export const forgeGraphRequest: GraphRequest = async (query, variables) => {
  const res = await (api.asUser() as unknown as { requestTeamworkGraph(q: string, v: object): Promise<{ json(): Promise<{ data?: unknown; errors?: unknown[] }> }> }).requestTeamworkGraph(query, variables);
  return res.json();
};

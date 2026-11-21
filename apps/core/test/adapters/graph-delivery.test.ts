import { describe, expect, it } from 'vitest';
import { DEPLOYMENTS_QUERY, PULL_REQUESTS_QUERY, cleanText, graphDelivery, safeUrl } from '../../src/adapters/graph-delivery.js';
import type { GraphRequest } from '../../src/adapters/graph-enricher.js';

const ISSUE = 'ari:cloud:jira:c0ffee:issue/10042';
const PR_FIELD = 'jiraWorkItemLinkedExternalPullRequests';
const DEP_FIELD = 'jiraWorkItemLinkedExternalDeployments';

const conn = (field: string, nodes: unknown[], next: string | null = null) => ({
  data: { [field]: { edges: nodes.map((node) => ({ node })), pageInfo: { hasNextPage: next !== null, endCursor: next } } },
});

const pr = (id: string, over: Record<string, unknown> = {}) => ({
  __typename: 'ExternalPullRequest', id, displayId: '12', title: 'Verify webhook signatures', url: `https://bitbucket.org/acme/pay/pull-requests/${id}`, status: 'MERGED', lastUpdatedAt: '2026-11-20T10:00:00Z', ...over,
});
const dep = (id: string, over: Record<string, unknown> = {}) => ({
  __typename: 'ExternalDeployment', id, displayName: 'Deploy #42', url: `https://bitbucket.org/acme/pay/deployments/${id}`, state: 'SUCCESSFUL', lastUpdatedAt: '2026-11-21T09:00:00Z',
  environment: { displayName: 'prod-eu', type: 'PRODUCTION' }, ...over,
});

function scripted(byQuery: Map<string, Array<{ data?: unknown; errors?: unknown[] } | Error>>) {
  const calls: Array<{ query: string; vars: Record<string, unknown> }> = [];
  const request: GraphRequest = async (query, vars) => {
    calls.push({ query, vars: vars as Record<string, unknown> });
    const queue = byQuery.get(query)!;
    const next = queue.length > 1 ? queue.shift()! : queue[0]!;
    if (next instanceof Error) throw next;
    return next;
  };
  return { request, calls };
}

describe('graphDelivery', () => {
  it('queries both curated fields with the work item ARI and maps nodes', async () => {
    const { request, calls } = scripted(new Map([
      [PULL_REQUESTS_QUERY, [conn(PR_FIELD, [pr('1')])]],
      [DEPLOYMENTS_QUERY, [conn(DEP_FIELD, [dep('d1')])]],
    ]));
    const r = await graphDelivery(request).links(ISSUE);
    expect(calls.map((c) => c.vars)).toEqual([
      { id: ISSUE, first: 25, after: null },
      { id: ISSUE, first: 25, after: null },
    ]);
    expect(r.partial).toBe(false);
    expect(r.pullRequests).toEqual([{ id: '1', title: '#12 Verify webhook signatures', url: 'https://bitbucket.org/acme/pay/pull-requests/1', status: 'MERGED', updatedAt: '2026-11-20T10:00:00.000Z' }]);
    expect(r.deployments).toEqual([
      { id: 'd1', name: 'Deploy #42', url: 'https://bitbucket.org/acme/pay/deployments/d1', state: 'SUCCESSFUL', environment: { name: 'prod-eu', type: 'PRODUCTION' }, at: '2026-11-21T09:00:00.000Z' },
    ]);
  });

  it('a failing field (HTTP 200 with errors) keeps the other field and marks the result partial', async () => {
    const { request } = scripted(new Map([
      [PULL_REQUESTS_QUERY, [{ errors: [{ message: 'nope', extensions: { code: 'FORBIDDEN' } }] }]],
      [DEPLOYMENTS_QUERY, [conn(DEP_FIELD, [dep('d1')])]],
    ]));
    const r = await graphDelivery(request).links(ISSUE);
    expect(r.pullRequests).toEqual([]);
    expect(r.deployments).toHaveLength(1);
    expect(r.partial).toBe(true);
    expect(r.reasons).toEqual([`graph_error:${PR_FIELD}:FORBIDDEN`]);
  });

  it('a thrown request is graph_unavailable, never an exception', async () => {
    const { request } = scripted(new Map<string, Array<{ data?: unknown } | Error>>([
      [PULL_REQUESTS_QUERY, [new Error('network')]],
      [DEPLOYMENTS_QUERY, [new Error('network')]],
    ]));
    const r = await graphDelivery(request).links(ISSUE);
    expect(r).toEqual({ pullRequests: [], deployments: [], partial: true, reasons: [`graph_unavailable:${PR_FIELD}`, `graph_unavailable:${DEP_FIELD}`] });
  });

  it('follows one cursor, then reports truncation; duplicates are dropped and newest comes first', async () => {
    const { request, calls } = scripted(new Map([
      [PULL_REQUESTS_QUERY, [conn(PR_FIELD, [pr('1', { lastUpdatedAt: '2026-11-01T00:00:00Z' })], 'c1'), conn(PR_FIELD, [pr('2', { lastUpdatedAt: '2026-11-21T00:00:00Z' }), pr('1')], 'c2')]],
      [DEPLOYMENTS_QUERY, [conn(DEP_FIELD, [])]],
    ]));
    const r = await graphDelivery(request).links(ISSUE);
    expect(calls.filter((c) => c.query === PULL_REQUESTS_QUERY).map((c) => c.vars.after)).toEqual([null, 'c1']);
    expect(r.pullRequests.map((p) => p.id)).toEqual(['2', '1']);
    expect(r.reasons).toEqual([`graph_truncated:${PR_FIELD}`]);
  });

  it('treats third-party strings as untrusted: unsafe links dropped, control characters stripped, unknown enums defaulted', async () => {
    const { request } = scripted(new Map([
      [PULL_REQUESTS_QUERY, [conn(PR_FIELD, [pr('1', { url: 'javascript:alert(1)', title: 'Fix\u0000 it‮ now', status: 'weird', displayId: null }), { id: 7 }, null])]],
      [DEPLOYMENTS_QUERY, [conn(DEP_FIELD, [dep('d1', { url: 'http://insecure.example/x', environment: { type: 'moon' }, state: 'successful' })])]],
    ]));
    const r = await graphDelivery(request).links(ISSUE);
    expect(r.pullRequests).toEqual([{ id: '1', title: 'Fix it now', url: null, status: 'UNKNOWN', updatedAt: '2026-11-20T10:00:00.000Z' }]);
    expect(r.deployments[0]).toMatchObject({ url: null, state: 'SUCCESSFUL', environment: { name: 'Unnamed environment', type: 'UNMAPPED' } });
  });

  it('refuses anything that is not a Jira issue ARI without calling the graph', async () => {
    const { request, calls } = scripted(new Map());
    expect(await graphDelivery(request).links('PAY-7')).toEqual({ pullRequests: [], deployments: [], partial: true, reasons: ['bad_issue_ari'] });
    expect(calls).toEqual([]);
  });
});

describe('cleanText and safeUrl', () => {
  it('caps length with an ellipsis and ignores non-strings', () => {
    expect(cleanText('a'.repeat(200), 10)).toBe(`${'a'.repeat(9)}…`);
    expect(cleanText(42)).toBe('');
  });
  it('keeps only credential-free https URLs', () => {
    expect(safeUrl('https://github.com/acme/pay/pull/3')).toBe('https://github.com/acme/pay/pull/3');
    expect(safeUrl('https://user:pw@github.com/x')).toBeNull();
    expect(safeUrl('/relative')).toBeNull();
    expect(safeUrl('data:text/html,hi')).toBeNull();
  });
});

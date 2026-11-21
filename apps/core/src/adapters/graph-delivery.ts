import type { GraphRequest } from './graph-enricher.js';

/**
 * Teamwork Graph delivery links (Preview, as the viewing user): the pull requests and deployments linked to a Jira work
 * item, from any connected provider (Bitbucket, GitHub, GitLab, Jenkins, ...). Curated query fields need no persisted
 * query registration. Every string here comes from a third-party tool: it is display-only, trimmed and never sent to a
 * model, and links are kept only when they are https.
 */

export type PullRequestStatus = 'OPEN' | 'MERGED' | 'DECLINED' | 'DRAFT' | 'UNKNOWN';
export type DeploymentState = 'SUCCESSFUL' | 'FAILED' | 'IN_PROGRESS' | 'PENDING' | 'ROLLED_BACK' | 'CANCELLED' | 'UNKNOWN';
export type EnvironmentType = 'PRODUCTION' | 'STAGING' | 'TESTING' | 'DEVELOPMENT' | 'UNMAPPED';

export interface LinkedPullRequest {
  id: string;
  title: string;
  url: string | null;
  status: PullRequestStatus;
  updatedAt: string | null;
}

export interface LinkedDeployment {
  id: string;
  name: string;
  url: string | null;
  state: DeploymentState;
  environment: { name: string; type: EnvironmentType };
  at: string | null;
}

export interface DeliveryLinks {
  pullRequests: LinkedPullRequest[];
  deployments: LinkedDeployment[];
  /** True when a query failed, was truncated or returned nothing because a scope is missing (TWG returns empty, not an error). */
  partial: boolean;
  reasons: string[];
}

const PAGE = 25;
const MAX_PAGES = 2;

export const PULL_REQUESTS_QUERY = `query threatline_linkedPullRequests($id: ID!, $first: Int, $after: String) {
  jiraWorkItemLinkedExternalPullRequests(id: $id, first: $first, after: $after) {
    edges { node { __typename ... on ExternalPullRequest { id displayId title url status lastUpdatedAt } } }
    pageInfo { hasNextPage endCursor }
  }
}`;

export const DEPLOYMENTS_QUERY = `query threatline_linkedDeployments($id: ID!, $first: Int, $after: String) {
  jiraWorkItemLinkedExternalDeployments(id: $id, first: $first, after: $after) {
    edges { node { __typename ... on ExternalDeployment { id displayName url state lastUpdatedAt environment { displayName type } } } }
    pageInfo { hasNextPage endCursor }
  }
}`;

const ISSUE_ARI = /^ari:cloud:jira:[A-Za-z0-9-]*:issue\/\d{1,18}$/;
const PR_STATUS = new Set<PullRequestStatus>(['OPEN', 'MERGED', 'DECLINED', 'DRAFT', 'UNKNOWN']);
const DEPLOY_STATE = new Set<DeploymentState>(['SUCCESSFUL', 'FAILED', 'IN_PROGRESS', 'PENDING', 'ROLLED_BACK', 'CANCELLED', 'UNKNOWN']);
const ENV_TYPE = new Set<EnvironmentType>(['PRODUCTION', 'STAGING', 'TESTING', 'DEVELOPMENT', 'UNMAPPED']);

/** Third-party text: control characters stripped, whitespace collapsed, at most `max` characters. */
export function cleanText(v: unknown, max = 160): string {
  if (typeof v !== 'string') return '';
  const s = v.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, ' ').replace(/\s+/g, ' ').trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** Only absolute https links survive: no javascript:, data: or relative URLs reach the panel. */
export function safeUrl(v: unknown): string | null {
  if (typeof v !== 'string' || v.length > 2048) return null;
  try {
    const u = new URL(v);
    return u.protocol === 'https:' && !u.username && !u.password ? u.toString() : null;
  } catch {
    return null;
  }
}

const isoOrNull = (v: unknown): string | null => (typeof v === 'string' && !Number.isNaN(Date.parse(v)) ? new Date(v).toISOString() : null);
const pick = <T extends string>(v: unknown, allowed: Set<T>, fallback: T): T => (typeof v === 'string' && allowed.has(v.toUpperCase() as T) ? (v.toUpperCase() as T) : fallback);

function toPullRequest(n: Record<string, unknown>): LinkedPullRequest | null {
  if (typeof n.id !== 'string' || !n.id) return null;
  const display = cleanText(n.displayId, 24);
  const title = cleanText(n.title) || 'Untitled pull request';
  return {
    id: n.id,
    title: display ? `${display.startsWith('#') ? display : `#${display}`} ${title}` : title,
    url: safeUrl(n.url),
    status: pick(n.status, PR_STATUS, 'UNKNOWN'),
    updatedAt: isoOrNull(n.lastUpdatedAt),
  };
}

function toDeployment(n: Record<string, unknown>): LinkedDeployment | null {
  if (typeof n.id !== 'string' || !n.id) return null;
  const env = (typeof n.environment === 'object' && n.environment !== null ? n.environment : {}) as Record<string, unknown>;
  return {
    id: n.id,
    name: cleanText(n.displayName) || 'Deployment',
    url: safeUrl(n.url),
    state: pick(n.state, DEPLOY_STATE, 'UNKNOWN'),
    environment: { name: cleanText(env.displayName, 60) || 'Unnamed environment', type: pick(env.type, ENV_TYPE, 'UNMAPPED') },
    at: isoOrNull(n.lastUpdatedAt),
  };
}

type Field = 'jiraWorkItemLinkedExternalPullRequests' | 'jiraWorkItemLinkedExternalDeployments';

async function runField<T>(
  request: GraphRequest,
  query: string,
  field: Field,
  id: string,
  map: (n: Record<string, unknown>) => T | null,
): Promise<{ items: T[]; reasons: string[] }> {
  const items: T[] = [];
  let after: string | null = null;
  for (let page = 0; page < MAX_PAGES; page++) {
    let res: { data?: unknown; errors?: unknown[] };
    try {
      res = await request(query, { id, first: PAGE, after });
    } catch {
      return { items, reasons: [`graph_unavailable:${field}`] };
    }
    // Teamwork Graph reports failures as HTTP 200 with errors[]; a field error makes this source partial, not fatal.
    if (Array.isArray(res.errors) && res.errors.length > 0) {
      const first = res.errors[0] as { message?: unknown; extensions?: { code?: unknown; errorType?: unknown; classification?: unknown } };
      const code = [first?.extensions?.code, first?.extensions?.errorType, first?.extensions?.classification].find((c) => typeof c === 'string') as string | undefined;
      // Schema and permission messages only (no third-party content): kept short for the operator log.
      const detail = cleanText(first?.message, 120);
      return { items, reasons: [`graph_error:${field}:${code ?? 'UNKNOWN'}${detail ? `:${detail}` : ''}`] };
    }
    const conn = (res.data as Record<string, unknown> | undefined)?.[field] as
      | { edges?: Array<{ node?: unknown }>; pageInfo?: { hasNextPage?: unknown; endCursor?: unknown } }
      | null
      | undefined;
    if (!conn) return { items, reasons: [`graph_no_data:${field}`] };
    for (const e of conn.edges ?? []) {
      if (typeof e?.node !== 'object' || e.node === null) continue;
      const mapped = map(e.node as Record<string, unknown>);
      if (mapped) items.push(mapped);
    }
    const next = conn.pageInfo?.hasNextPage === true && typeof conn.pageInfo.endCursor === 'string' ? conn.pageInfo.endCursor : null;
    if (!next) return { items, reasons: [] };
    after = next;
  }
  return { items, reasons: [`graph_truncated:${field}`] };
}

const newestFirst = (a: string | null, b: string | null) => (b ?? '').localeCompare(a ?? '');

export function graphDelivery(request: GraphRequest): { links(issueAri: string): Promise<DeliveryLinks> } {
  return {
    async links(issueAri) {
      if (!ISSUE_ARI.test(issueAri)) return { pullRequests: [], deployments: [], partial: true, reasons: ['bad_issue_ari'] };
      const [prs, deps] = await Promise.all([
        runField(request, PULL_REQUESTS_QUERY, 'jiraWorkItemLinkedExternalPullRequests', issueAri, toPullRequest),
        runField(request, DEPLOYMENTS_QUERY, 'jiraWorkItemLinkedExternalDeployments', issueAri, toDeployment),
      ]);
      const uniq = <T extends { id: string }>(xs: T[]) => [...new Map(xs.map((x) => [x.id, x])).values()];
      return {
        pullRequests: uniq(prs.items).sort((a, b) => newestFirst(a.updatedAt, b.updatedAt)),
        deployments: uniq(deps.items).sort((a, b) => newestFirst(a.at, b.at)),
        partial: prs.reasons.length + deps.reasons.length > 0,
        reasons: [...prs.reasons, ...deps.reasons],
      };
    },
  };
}

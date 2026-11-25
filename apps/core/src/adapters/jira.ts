import api, { assumeTrustedRoute } from '@forge/api';
import { z } from 'zod';
import { appError, err, ok, type Result } from '@threatline/shared';
import { httpJson, seg, type FetchLike, type HttpOptions } from './http.js';
import { planGate, updateBody, type WorkflowRead } from './workflow-gate.js';

export interface AdfNode {
  type: string;
  text?: string;
  attrs?: Record<string, unknown>;
  content?: AdfNode[];
  marks?: Array<{ type: string; attrs?: Record<string, unknown> }>;
}
export interface AdfDoc {
  type: 'doc';
  version: 1;
  content: AdfNode[];
}

export interface JiraLinkedIssue {
  id: string;
  key: string;
  summary: string;
  status: string;
  issueType: string;
}
export interface JiraIssue {
  id: string;
  key: string;
  summary: string;
  /** Description as plain text (ADF flattened). Untrusted. */
  description: string;
  issueType: { id: string; name: string; subtask: boolean };
  parent?: { id: string; key: string };
  links: Array<{ type: string; direction: 'inward' | 'outward'; issue: JiraLinkedIssue }>;
  components: string[];
  labels: string[];
  project: { id: string; key: string };
  status: { name: string; category: string };
  fixVersions: string[];
  assignee?: string;
  created?: string;
  /** Only when the search asked for the `priority` field. */
  priority?: string;
}

/**
 * How many of the newest comments are read. The gatherer keeps the newest 20 that are not Threatline's own, so the window
 * is wider: Threatline's own comments must not push a person's comment out of the review context (and change its hash).
 */
export const COMMENT_WINDOW = 50;

export interface JiraComment {
  id: string;
  body: string;
  author: string;
  created: string;
  /** Visible only to a role or group: never gather it (the app can read it, the issue's audience may not). */
  restricted: boolean;
}

export interface PostedComment {
  id: string;
  /** Empty when Jira did not say (it normally does). */
  authorAccountId: string;
}

export interface JiraClient {
  issue(idOrKey: string): Promise<Result<JiraIssue>>;
  children(issueId: string): Promise<Result<JiraIssue[]>>;
  /** The newest comments first, at most COMMENT_WINDOW. */
  comments(issueId: string): Promise<Result<JiraComment[]>>;
  remoteLinks(issueId: string): Promise<Result<Array<{ url: string; title: string; globalId?: string }>>>;
  canBrowse(accountId: string, issueId: string): Promise<Result<boolean>>;
  canEdit(accountId: string, issueId: string): Promise<Result<boolean>>;
  /** Of these numeric issue ids, the ones the user may browse (one permission check per 100 ids). */
  browsable(accountId: string, issueIds: readonly string[]): Promise<Result<string[]>>;
  groupsOf(accountId: string): Promise<Result<string[]>>;
  /** Whether a group of exactly this name exists on the site (the setup checklist's champion-group check). */
  groupExists?(name: string): Promise<Result<boolean>>;
  isAdmin(accountId: string): Promise<Result<boolean>>;
  setProperty(issueId: string, key: string, value: unknown): Promise<Result<void>>;
  /** The property's value, or null when the work item has no such property. */
  getProperty(issueIdOrKey: string, key: string): Promise<Result<unknown>>;
  projectInfo(projectKey: string): Promise<Result<{ id: string; key: string; issueTypes: Array<{ id: string; name: string; subtask: boolean }> }>>;
  /** Every workflow status name used in the project, across its issue types, in first-seen order. */
  projectStatuses(projectKey: string): Promise<Result<string[]>>;
  ensureComponent(projectKey: string, name: string): Promise<Result<void>>;
  createIssue(f: { projectId: string; issueTypeId: string; summary: string; description: AdfDoc; labels: string[]; components?: string[]; parentId?: string }): Promise<Result<{ id: string; key: string }>>;
  /** The project's sub-task issue type id (Threatline requirements are created as sub-tasks). */
  subtaskType(projectId: string): Promise<Result<string>>;
  createSubtask(parentId: string, fields: { summary: string; description: AdfDoc; labels: string[]; issueTypeId: string }): Promise<Result<{ id: string; key: string }>>;
  addLabel(issueId: string, label: string): Promise<Result<void>>;
  /** Creates or updates (same globalId) a web link on the work item. */
  addRemoteLink(issueId: string, link: { globalId: string; url: string; title: string }): Promise<Result<void>>;
  removeLabel(issueId: string, label: string): Promise<Result<void>>;
  /**
   * Adds a comment as the caller (the app, for every Threatline comment). Returns the new comment's id and its author's
   * account id, which for the app's own comments is Threatline's account (see services/own-account.ts).
   */
  comment(issueId: string, adf: AdfDoc): Promise<Result<PostedComment>>;
  search(jql: string, fields: string[], max: number): Promise<Result<JiraIssue[]>>;
  /**
   * Adds the security gate to every transition into `toStatus` in the project's workflows, acting as the admin who
   * asked (Jira checks they may edit workflows). Idempotent.
   */
  installGate(accountId: string, projectKey: string, toStatus: string, extensionKey: string): Promise<Result<{ added: string[]; already: string[]; readOnly: string[] }>>;
}

export const ISSUE_FIELDS = [
  'summary',
  'description',
  'issuetype',
  'parent',
  'issuelinks',
  'components',
  'labels',
  'project',
  'status',
  'fixVersions',
  'assignee',
  'created',
];

const ISSUE_REF = /^(\d{1,18}|[A-Z][A-Z0-9_]{0,254}-\d{1,18})$/i;
const NUMERIC_ID = /^\d{1,18}$/;
const PROJECT_KEY = /^[A-Z][A-Z0-9_]{0,254}$/;
const PROPERTY_KEY = /^[A-Za-z0-9._-]{1,255}$/;
const MAX_DEPTH = 64;

const LinkedSchema = z.object({
  id: z.string(),
  key: z.string(),
  fields: z
    .object({
      summary: z.string().nullish(),
      status: z.object({ name: z.string() }).nullish(),
      issuetype: z.object({ name: z.string() }).nullish(),
    })
    .nullish(),
});
const IssueSchema = z.object({
  id: z.string(),
  key: z.string(),
  fields: z.object({
    summary: z.string().nullish(),
    description: z.unknown().optional(),
    issuetype: z.object({ id: z.string(), name: z.string(), subtask: z.boolean().nullish() }).nullish(),
    parent: z.object({ id: z.string(), key: z.string() }).nullish(),
    issuelinks: z
      .array(
        z.object({
          type: z.object({ name: z.string(), inward: z.string().nullish(), outward: z.string().nullish() }),
          inwardIssue: LinkedSchema.nullish(),
          outwardIssue: LinkedSchema.nullish(),
        }),
      )
      .nullish(),
    components: z.array(z.object({ name: z.string() })).nullish(),
    labels: z.array(z.string()).nullish(),
    project: z.object({ id: z.string(), key: z.string() }).nullish(),
    status: z.object({ name: z.string(), statusCategory: z.object({ key: z.string() }).nullish() }).nullish(),
    fixVersions: z.array(z.object({ name: z.string() })).nullish(),
    assignee: z.object({ accountId: z.string() }).nullish(),
    created: z.string().nullish(),
    priority: z.object({ name: z.string() }).nullish(),
  }),
});

const linked = (l: z.infer<typeof LinkedSchema>): JiraLinkedIssue => ({
  id: l.id,
  key: l.key,
  summary: l.fields?.summary ?? '',
  status: l.fields?.status?.name ?? '',
  issueType: l.fields?.issuetype?.name ?? '',
});

function toIssue(raw: z.infer<typeof IssueSchema>): JiraIssue {
  const f = raw.fields;
  const links: JiraIssue['links'] = [];
  for (const l of f.issuelinks ?? []) {
    if (l.outwardIssue) links.push({ type: l.type.outward ?? l.type.name, direction: 'outward', issue: linked(l.outwardIssue) });
    if (l.inwardIssue) links.push({ type: l.type.inward ?? l.type.name, direction: 'inward', issue: linked(l.inwardIssue) });
  }
  const issue: JiraIssue = {
    id: raw.id,
    key: raw.key,
    summary: f.summary ?? '',
    description: adfToText(f.description),
    issueType: { id: f.issuetype?.id ?? '', name: f.issuetype?.name ?? '', subtask: f.issuetype?.subtask ?? false },
    links,
    components: (f.components ?? []).map((c) => c.name),
    labels: f.labels ?? [],
    project: { id: f.project?.id ?? '', key: f.project?.key ?? raw.key.split('-')[0] ?? '' },
    status: { name: f.status?.name ?? '', category: f.status?.statusCategory?.key ?? '' },
    fixVersions: (f.fixVersions ?? []).map((v) => v.name),
  };
  if (f.parent) issue.parent = { id: f.parent.id, key: f.parent.key };
  if (f.assignee) issue.assignee = f.assignee.accountId;
  if (f.created) issue.created = f.created;
  if (f.priority?.name) issue.priority = f.priority.name;
  return issue;
}

function parse<S extends z.ZodTypeAny>(schema: S, value: unknown, what: string): Result<z.infer<S>> {
  const p = schema.safeParse(value);
  return p.success ? ok(p.data) : err(appError('upstream', `unexpected ${what} response from Jira`, { issues: p.error.issues.slice(0, 3).map((i) => i.path.join('.')) }));
}

const badRef = (what: string) => err(appError('validation', `invalid ${what}`));

// ---------- ADF → plain text ----------

function inline(nodes: unknown, depth: number): string {
  if (!Array.isArray(nodes) || depth > MAX_DEPTH) return '';
  let out = '';
  for (const n of nodes as AdfNode[]) {
    if (!n || typeof n !== 'object') continue;
    const a = n.attrs ?? {};
    switch (n.type) {
      case 'text':
        out += typeof n.text === 'string' ? n.text : '';
        break;
      case 'hardBreak':
        out += '\n';
        break;
      case 'mention':
      case 'status':
        out += typeof a.text === 'string' ? a.text : '';
        break;
      case 'emoji':
        out += typeof a.text === 'string' ? a.text : typeof a.shortName === 'string' ? a.shortName : '';
        break;
      case 'inlineCard':
      case 'blockCard':
      case 'embedCard':
        out += typeof a.url === 'string' ? a.url : '';
        break;
      case 'date':
        out += typeof a.timestamp === 'string' ? new Date(Number(a.timestamp)).toISOString().slice(0, 10) : '';
        break;
      default:
        out += inline(n.content, depth + 1);
    }
  }
  return out;
}

function blocks(nodes: unknown, depth: number): string[] {
  if (!Array.isArray(nodes) || depth > MAX_DEPTH) return [];
  const lines: string[] = [];
  for (const n of nodes as AdfNode[]) {
    if (!n || typeof n !== 'object') continue;
    switch (n.type) {
      case 'paragraph':
      case 'heading':
      case 'codeBlock':
        lines.push(...inline(n.content, depth + 1).split('\n'));
        break;
      case 'bulletList':
      case 'orderedList':
        for (const li of n.content ?? []) {
          let first = true;
          for (const child of li?.content ?? []) {
            const nested = child?.type === 'bulletList' || child?.type === 'orderedList';
            for (const line of blocks([child], depth + 2)) {
              if (nested) lines.push(`  ${line}`);
              else {
                lines.push(`${first ? '- ' : '  '}${line}`);
                first = false;
              }
            }
          }
        }
        break;
      case 'text':
      case 'mention':
      case 'emoji':
      case 'inlineCard':
      case 'blockCard':
      case 'embedCard':
      case 'hardBreak':
      case 'status':
      case 'date':
        lines.push(...inline([n], depth + 1).split('\n'));
        break;
      default:
        lines.push(...blocks(n.content, depth + 1));
    }
  }
  return lines;
}

/** Flattens Atlassian Document Format to plain text. Strings pass through; anything else yields ''. Depth-bounded. */
export function adfToText(doc: unknown): string {
  if (typeof doc === 'string') return doc;
  if (!doc || typeof doc !== 'object') return '';
  return blocks((doc as AdfNode).content, 0)
    .filter((l) => l.trim() !== '')
    .join('\n');
}

// ---------- client ----------

export interface JiraClientOptions extends HttpOptions {
  /**
   * Transport acting as a given user (Forge `asUser(accountId)`, needs allowImpersonation). When present, permission
   * checks ask Jira as that user (`mypermissions`); the app-level bulk check needs Administer Jira, which apps lack.
   */
  asUser?: (accountId: string) => FetchLike;
}

export function createJiraClient(request: FetchLike, opts: JiraClientOptions = {}): JiraClient {
  const call = httpJson(request, opts);
  const userCall = (accountId: string) => httpJson(opts.asUser!(accountId), opts);

  async function myPermission(accountId: string, permission: string, issueId?: string): Promise<Result<boolean>> {
    const q = issueId ? `issueId=${seg(issueId)}&permissions=${permission}` : `permissions=${permission}`;
    const r = await userCall(accountId)(`/rest/api/3/mypermissions?${q}`);
    if (!r.ok) return r.error.code === 'not_found' || r.error.code === 'forbidden' || r.error.code === 'validation' ? ok(false) : r;
    const perms = (r.value as { permissions?: Record<string, { havePermission?: unknown }> } | undefined)?.permissions;
    return ok(perms?.[permission]?.havePermission === true);
  }
  const json = (method: 'POST' | 'PUT', body: unknown) => ({ method, body: JSON.stringify(body) });

  async function issue(idOrKey: string): Promise<Result<JiraIssue>> {
    if (!ISSUE_REF.test(idOrKey)) return badRef('issue id or key');
    const r = await call(`/rest/api/3/issue/${seg(idOrKey)}?fields=${ISSUE_FIELDS.join(',')}`);
    if (!r.ok) return r;
    const p = parse(IssueSchema, r.value, 'issue');
    return p.ok ? ok(toIssue(p.value)) : p;
  }

  async function resolveId(idOrKey: string): Promise<Result<string | null>> {
    if (NUMERIC_ID.test(idOrKey)) return ok(idOrKey);
    const i = await issue(idOrKey);
    if (i.ok) return ok(i.value.id);
    return i.error.code === 'not_found' || i.error.code === 'forbidden' || i.error.code === 'validation' ? ok(null) : i;
  }

  async function hasIssuePermission(accountId: string, idOrKey: string, permission: 'BROWSE_PROJECTS' | 'EDIT_ISSUES'): Promise<Result<boolean>> {
    if (!accountId) return ok(false);
    const id = await resolveId(idOrKey);
    if (!id.ok) return id;
    if (id.value === null) return ok(false);
    if (opts.asUser) return myPermission(accountId, permission, id.value);
    const r = await call('/rest/api/3/permissions/check', json('POST', { accountId, projectPermissions: [{ permissions: [permission], issues: [Number(id.value)] }] }));
    if (!r.ok) return r.error.code === 'not_found' ? ok(false) : r;
    const p = parse(
      z.object({ projectPermissions: z.array(z.object({ permission: z.string(), issues: z.array(z.number()).nullish() })).nullish() }),
      r.value,
      'permissions check',
    );
    if (!p.ok) return p;
    return ok((p.value.projectPermissions ?? []).some((pp) => pp.permission === permission && (pp.issues ?? []).includes(Number(id.value))));
  }

  async function search(jql: string, fields: string[], max: number): Promise<Result<JiraIssue[]>> {
    const out: JiraIssue[] = [];
    let token: string | undefined;
    for (let page = 0; page < 20 && out.length < max; page++) {
      const body: Record<string, unknown> = { jql, fields, maxResults: Math.min(100, max - out.length) };
      if (token) body.nextPageToken = token;
      const r = await call('/rest/api/3/search/jql', json('POST', body));
      if (!r.ok) return r;
      const p = parse(z.object({ issues: z.array(IssueSchema), nextPageToken: z.string().nullish() }), r.value, 'search');
      if (!p.ok) return p;
      out.push(...p.value.issues.map(toIssue));
      token = p.value.nextPageToken ?? undefined;
      if (!token) break;
    }
    return ok(out.slice(0, max));
  }

  const voidOf = (r: Result<unknown>): Result<void> => (r.ok ? ok(undefined) : r);

  return {
    issue,
    search,

    async children(issueId) {
      if (!NUMERIC_ID.test(issueId)) return badRef('issue id');
      return search(`parent = ${issueId}`, ISSUE_FIELDS, 100);
    },

    async comments(issueId) {
      if (!ISSUE_REF.test(issueId)) return badRef('issue id');
      const r = await call(`/rest/api/3/issue/${seg(issueId)}/comment?orderBy=-created&maxResults=${COMMENT_WINDOW}`);
      if (!r.ok) return r;
      const p = parse(
        z.object({
          comments: z.array(
            z.object({ id: z.string(), body: z.unknown().optional(), author: z.object({ accountId: z.string() }).nullish(), created: z.string().nullish(), visibility: z.unknown().optional() }),
          ),
        }),
        r.value,
        'comments',
      );
      if (!p.ok) return p;
      return ok(p.value.comments.map((c) => ({ id: c.id, body: adfToText(c.body), author: c.author?.accountId ?? '', created: c.created ?? '', restricted: c.visibility != null })));
    },

    async remoteLinks(issueId) {
      if (!ISSUE_REF.test(issueId)) return badRef('issue id');
      const r = await call(`/rest/api/3/issue/${seg(issueId)}/remotelink`);
      if (!r.ok) return r;
      const p = parse(z.array(z.object({ globalId: z.string().nullish(), object: z.object({ url: z.string(), title: z.string().nullish() }).nullish() })), r.value, 'remote links');
      if (!p.ok) return p;
      return ok(p.value.flatMap((l) => (l.object ? [{ url: l.object.url, title: l.object.title || l.object.url, ...(l.globalId ? { globalId: l.globalId } : {}) }] : [])));
    },

    canBrowse: (accountId, issueId) => hasIssuePermission(accountId, issueId, 'BROWSE_PROJECTS'),
    canEdit: (accountId, issueId) => hasIssuePermission(accountId, issueId, 'EDIT_ISSUES'),

    async browsable(accountId, issueIds) {
      const ids = [...new Set(issueIds.filter((id) => NUMERIC_ID.test(id)))];
      if (!accountId || ids.length === 0) return ok([]);
      if (opts.asUser) {
        // Apps get 403 asking permissions/check about other users; a search as the user returns only what they can see.
        const seen = new Set<string>();
        for (let i = 0; i < ids.length; i += 100) {
          const r = await userCall(accountId)('/rest/api/3/search/jql', json('POST', { jql: `id in (${ids.slice(i, i + 100).join(',')})`, fields: ['id'], maxResults: 100 }));
          if (!r.ok) return r;
          const p = parse(z.object({ issues: z.array(z.object({ id: z.string() })) }), r.value, 'search');
          if (!p.ok) return p;
          for (const x of p.value.issues) seen.add(x.id);
        }
        return ok(ids.filter((id) => seen.has(id)));
      }
      const allowed = new Set<number>();
      for (let i = 0; i < ids.length; i += 100) {
        const chunk = ids.slice(i, i + 100).map(Number);
        const r = await call('/rest/api/3/permissions/check', json('POST', { accountId, projectPermissions: [{ permissions: ['BROWSE_PROJECTS'], issues: chunk }] }));
        if (!r.ok) return r;
        const p = parse(
          z.object({ projectPermissions: z.array(z.object({ permission: z.string(), issues: z.array(z.number()).nullish() })).nullish() }),
          r.value,
          'permissions check',
        );
        if (!p.ok) return p;
        for (const pp of p.value.projectPermissions ?? []) if (pp.permission === 'BROWSE_PROJECTS') for (const n of pp.issues ?? []) if (chunk.includes(n)) allowed.add(n);
      }
      return ok(ids.filter((id) => allowed.has(Number(id))));
    },

    async groupsOf(accountId) {
      if (!accountId) return ok([]);
      const r = await call(`/rest/api/3/user/groups?accountId=${seg(accountId)}`);
      if (!r.ok) return r;
      const p = parse(z.array(z.object({ name: z.string() })), r.value, 'groups');
      return p.ok ? ok(p.value.map((g) => g.name)) : p;
    },

    async groupExists(name) {
      if (!name || name.length > 255) return ok(false);
      const r = await call(`/rest/api/3/group/bulk?groupName=${encodeURIComponent(name)}&maxResults=1`);
      if (!r.ok) return r.error.code === 'not_found' ? ok(false) : r;
      const p = parse(z.object({ values: z.array(z.object({ name: z.string() })).nullish() }), r.value, 'groups');
      return p.ok ? ok((p.value.values ?? []).some((g) => g.name === name)) : p;
    },

    async isAdmin(accountId) {
      if (!accountId) return ok(false);
      if (opts.asUser) return myPermission(accountId, 'ADMINISTER');
      const r = await call('/rest/api/3/permissions/check', json('POST', { accountId, globalPermissions: ['ADMINISTER'] }));
      if (!r.ok) return r;
      const p = parse(z.object({ globalPermissions: z.array(z.string()).nullish() }), r.value, 'permissions check');
      return p.ok ? ok((p.value.globalPermissions ?? []).includes('ADMINISTER')) : p;
    },

    async setProperty(issueId, key, value) {
      if (!ISSUE_REF.test(issueId)) return badRef('issue id');
      if (!PROPERTY_KEY.test(key)) return badRef('property key');
      return voidOf(await call(`/rest/api/3/issue/${seg(issueId)}/properties/${seg(key)}`, json('PUT', value)));
    },

    async getProperty(issueIdOrKey, key) {
      if (!ISSUE_REF.test(issueIdOrKey)) return badRef('issue id');
      if (!PROPERTY_KEY.test(key)) return badRef('property key');
      const r = await call(`/rest/api/3/issue/${seg(issueIdOrKey)}/properties/${seg(key)}`);
      if (!r.ok) return r.error.code === 'not_found' ? ok(null) : r;
      const v = (r.value as { value?: unknown } | undefined)?.value;
      return ok(v === undefined ? null : v);
    },

    async projectInfo(projectKey) {
      if (!PROJECT_KEY.test(projectKey)) return badRef('project key');
      const r = await call(`/rest/api/3/project/${seg(projectKey)}`);
      if (!r.ok) return r;
      const p = parse(z.object({ id: z.string(), key: z.string(), issueTypes: z.array(z.object({ id: z.string(), name: z.string(), subtask: z.boolean().nullish() })).nullish() }), r.value, 'project');
      if (!p.ok) return p;
      return ok({ id: p.value.id, key: p.value.key, issueTypes: (p.value.issueTypes ?? []).map((t) => ({ id: t.id, name: t.name, subtask: t.subtask === true })) });
    },

    async installGate(accountId, projectKey, toStatus, extensionKey) {
      if (!PROJECT_KEY.test(projectKey)) return badRef('project key');
      if (!opts.asUser) return err(appError('internal', 'installGate needs a user transport'));
      const as = userCall(accountId);
      const p = await this.projectInfo(projectKey);
      if (!p.ok) return p;
      const types = p.value.issueTypes.map((t) => ({ projectId: p.value.id, issueTypeId: t.id }));
      if (types.length === 0) return ok({ added: [], already: [], readOnly: [] });
      const r = await as('/rest/api/3/workflows', json('POST', { projectAndIssueTypes: types }));
      if (!r.ok) return r;
      const read = r.value as WorkflowRead;
      if (!Array.isArray(read?.workflows) || !Array.isArray(read?.statuses)) return err(appError('upstream', 'unexpected workflows response'));
      const plan = planGate(read, toStatus, extensionKey);
      if (plan.changed.length > 0) {
        const u = await as('/rest/api/3/workflows/update', json('POST', updateBody(read, plan.changed)));
        if (!u.ok) return u;
      }
      return ok({ added: plan.added, already: plan.already, readOnly: plan.readOnly });
    },

    async projectStatuses(projectKey) {
      if (!PROJECT_KEY.test(projectKey)) return badRef('project key');
      const r = await call(`/rest/api/3/project/${seg(projectKey)}/statuses`);
      if (!r.ok) return r;
      const p = parse(z.array(z.object({ statuses: z.array(z.object({ name: z.string() })).nullish() })), r.value, 'project statuses');
      if (!p.ok) return p;
      return ok([...new Set(p.value.flatMap((t) => (t.statuses ?? []).map((x) => x.name)))]);
    },

    async ensureComponent(projectKey, name) {
      if (!PROJECT_KEY.test(projectKey)) return badRef('project key');
      const r = await call(`/rest/api/3/project/${seg(projectKey)}/components`);
      if (!r.ok) return r;
      const p = parse(z.array(z.object({ name: z.string() })), r.value, 'components');
      if (!p.ok) return p;
      if (p.value.some((c) => c.name === name)) return ok(undefined);
      return voidOf(await call('/rest/api/3/component', json('POST', { name, project: projectKey })));
    },

    async createIssue(f) {
      if (!NUMERIC_ID.test(f.projectId) || !NUMERIC_ID.test(f.issueTypeId) || (f.parentId !== undefined && !NUMERIC_ID.test(f.parentId))) return badRef('project, type or parent id');
      const fields: Record<string, unknown> = { project: { id: f.projectId }, issuetype: { id: f.issueTypeId }, summary: f.summary, description: f.description, labels: f.labels };
      if (f.components?.length) fields.components = f.components.map((name) => ({ name }));
      if (f.parentId) fields.parent = { id: f.parentId };
      const r = await call('/rest/api/3/issue', json('POST', { fields }));
      if (!r.ok) return r;
      const p = parse(z.object({ id: z.string(), key: z.string() }), r.value, 'create issue');
      return p.ok ? ok({ id: p.value.id, key: p.value.key }) : p;
    },

    async subtaskType(projectId) {
      if (!NUMERIC_ID.test(projectId)) return badRef('project id');
      const r = await call(`/rest/api/3/issuetype/project?projectId=${seg(projectId)}`);
      if (!r.ok) return r;
      const p = parse(z.array(z.object({ id: z.string(), subtask: z.boolean().nullish() })), r.value, 'issue types');
      if (!p.ok) return p;
      const sub = p.value.find((t) => t.subtask === true);
      return sub ? ok(sub.id) : err(appError('not_found', 'this project has no sub-task issue type'));
    },

    async createSubtask(parentId, f) {
      const parent = await issue(parentId);
      if (!parent.ok) return parent;
      const r = await call(
        '/rest/api/3/issue',
        json('POST', {
          fields: {
            project: { id: parent.value.project.id },
            parent: { id: parent.value.id },
            summary: f.summary,
            description: f.description,
            labels: f.labels,
            issuetype: { id: f.issueTypeId },
          },
        }),
      );
      if (!r.ok) return r;
      const p = parse(z.object({ id: z.string(), key: z.string() }), r.value, 'create issue');
      return p.ok ? ok({ id: p.value.id, key: p.value.key }) : p;
    },

    async addRemoteLink(issueId, l) {
      if (!ISSUE_REF.test(issueId)) return badRef('issue id');
      return voidOf(await call(`/rest/api/3/issue/${seg(issueId)}/remotelink`, json('POST', { globalId: l.globalId, object: { url: l.url, title: l.title } })));
    },

    async addLabel(issueId, label) {
      if (!ISSUE_REF.test(issueId)) return badRef('issue id');
      return voidOf(await call(`/rest/api/3/issue/${seg(issueId)}`, json('PUT', { update: { labels: [{ add: label }] } })));
    },

    async removeLabel(issueId, label) {
      if (!ISSUE_REF.test(issueId)) return badRef('issue id');
      return voidOf(await call(`/rest/api/3/issue/${seg(issueId)}`, json('PUT', { update: { labels: [{ remove: label }] } })));
    },

    async comment(issueId, adf) {
      if (!ISSUE_REF.test(issueId)) return badRef('issue id');
      const r = await call(`/rest/api/3/issue/${seg(issueId)}/comment`, json('POST', { body: adf }));
      if (!r.ok) return r;
      // The comment exists now: an unexpected reply shape must not turn it into a failure (a retry would post it twice).
      const p = z.object({ id: z.string().optional(), author: z.object({ accountId: z.string() }).nullish() }).safeParse(r.value ?? {});
      return ok({ id: p.success ? (p.data.id ?? '') : '', authorAccountId: p.success ? (p.data.author?.accountId ?? '') : '' });
    },
  };
}

/**
 * Forge-backed client. `as: 'user'` needs a user context (resolvers, actions); everything else runs as the app.
 * Permission checks always impersonate the account being checked (read:jira-work allowImpersonation).
 */
export function jiraClient(as: 'app' | 'user'): JiraClient {
  const request: FetchLike = (path, init) => {
    const product = as === 'app' ? api.asApp() : api.asUser();
    return product.requestJira(assumeTrustedRoute(path), init);
  };
  const asUser = (accountId: string): FetchLike => (path, init) => api.asUser(accountId).requestJira(assumeTrustedRoute(path), init);
  return createJiraClient(request, { asUser });
}

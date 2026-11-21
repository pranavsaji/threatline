# Forge API notes (researched 2026-11-15)

Source: developer.atlassian.com (plus api.bitbucket.org/swagger.json and the Jira v3 OpenAPI spec for REST paths).
Rules: names, paths and shapes below come from the docs. Anything marked **UNCONFIRMED** was not stated on the page fetched.
Base URL for the relative links below: `https://developer.atlassian.com/platform/forge/`.

---

## 1. Manifest

### `function`: manifest-reference/modules/function/
- Properties: `key` (≤23 chars, `[a-zA-Z0-9_-]`), `handler` (`file.export`, resolved under `src/`), `providers`, `timeoutSeconds` (1–900), `runtime` (only `memoryMB` allowed).
- `timeoutSeconds` **applies only to scheduled triggers and async event consumers**. If one function serves several such modules, the lowest timeout wins. Default runtime limits (limits-invocation/): 55 s for async events/scheduled triggers (max 900 s). **UI modules: 25 s.** Web trigger / `action` / `rovo:agentConnector`: 55 s. Memory: default 512 MB, max 1024 MB. `/tmp`: 512 MB. Invocation payload: 5 MB. Front-end invoke request: 500 KB, response: 5 MB. Outbound request timeout in long-running async functions: 180 s.
```yaml
function:
  - key: main
    handler: index.run
    timeoutSeconds: 900        # only honoured for consumer / scheduledTrigger
    runtime: { memoryMB: 1024 }
```

### `trigger`: manifest-reference/modules/trigger/
- Properties: `key`, `function` | `endpoint`, `events` (string[]), `filter` { `appIsLicensed`, `ignoreSelf`, `expression`, `onError` }, `payload.include.propertyPaths` (entity property paths, without the `event.runtime.` prefix).
- `onError` (only with `expression`): `IGNORE_AND_LOG` (default) | `IGNORE` | `RECEIVE_AND_LOG` | `RECEIVE`. If you set `filter`, set at least one of the first three. Handler: `(event, context)`. Delivery "may take up to 3 minutes".
```yaml
trigger:
  - key: issue-events
    function: main
    events: [avi:jira:created:issue, avi:jira:updated:issue]
    filter:
      ignoreSelf: true
      expression: event.issue.fields?.issueType.name == 'Bug'
      onError: RECEIVE_AND_LOG
```
**Jira events** (events-reference/jira/; scope `read:jira-work`): `avi:jira:created:issue`, `avi:jira:updated:issue`, `avi:jira:deleted:issue`, `avi:jira:commented:issue` (fires on comment create or edit).
- created: `eventType`, `selfGenerated`, `issue`, `atlassianId?`, `associatedUsers?`, `clonedFrom?`, `customFields?`, `customFieldsStatus?` (`INCLUDED` | `OMITTED`), `skippedCustomFieldIds?`, `timestamp`, `webhookTraceValue?`. updated: same fields plus `changelog` (required; items carry `from`/`to` and `fromString`/`toString`), `jiraEventTypeName?` (`issue_resolved`, `issue_moved`, `issue_generic`, ...) and `associatedStatuses?`. `customFields` is included only if it is ≤25 KB. Treat a missing `customFieldsStatus` as `OMITTED`.

**Confluence events** (events-reference/confluence/; scope `read:confluence-content.summary`): `avi:confluence:created:page`, `avi:confluence:updated:page`, plus live-doc events (`initialized`, `started`, `snapshotted`, `published`).
```ts
// avi:confluence:updated:page
{ eventType, atlassianId?, eventCreatedDate, suppressNotifications, selfGenerated, updateTrigger,
  content: { id, type: 'page'|'blogpost', subType?: 'live', status, title,
             space: { id, key, alias, name, type, icon, status },
             history: { latest, createdBy, ownedBy, createdDate },
             version: { by, when, number } } }
```
- The payload does **not** include the page body. Fetch it with `requestConfluence`.

**Lifecycle events** (events-reference/life-cycle/):
- `avi:forge:installed:app` → `{ id, installerAccountId?, app: { id, version, name?, ownerAccountId? }, environment?: { id } }` `avi:forge:upgraded:app` → `{ id, upgraderAccountId?, app, environment?, permissions?: { scopes?, external? } }`. **Fires only on MAJOR version upgrades.** Just after install, `asApp()` calls may return 401/403 for a few minutes. Retry with `InvocationError` (`retryAfter`, `FUNCTION_RETRY_REQUEST`); Forge retries up to 4 times. `preUninstall` gets 55 s.

### `scheduledTrigger`: manifest-reference/modules/scheduled-trigger/
- `interval`: `fiveMinute` | `hour` | `day` | `week`. `filter` supports only `appIsLicensed`. Max **5** per app. First run is ~5 min after deploy. Changing any scheduledTrigger resets all of them. Duplicate runs are possible. There is no user context. The return value is ignored, and a throw is **not retried**.

### `consumer` + `@forge/events` (v2): manifest-reference/modules/consumer/, runtime-reference/async-events-api/
```yaml
consumer:
  - key: analysis-consumer
    queue: analysis-queue
    function: analysisWorker     # v2+: `function`; v1 `resolver:{function,method}` is deprecated
function:
  - key: analysisWorker
    handler: worker.handler
    timeoutSeconds: 900          # how you get 15 min
```
```ts
import { Queue, AsyncEvent, InvocationError, InvocationErrorCode } from '@forge/events';
const queue = new Queue({ key: 'analysis-queue' });
const { jobId } = await queue.push({ body: { issueKey }, delayInSeconds: 5 });   // or an array of events
// PushEvent: { body: object (required), delayInSeconds?: ≤900, concurrency?: { key, limit } }
export async function handler(event: AsyncEvent<{ issueKey: string }>, context) {
  const { issueKey } = event.body;            // v2: event.body (NOT event.payload)
  // event.retryContext?.retryCount
  return new InvocationError({ retryAfter: 60, retryReason: InvocationErrorCode.FUNCTION_UPSTREAM_RATE_LIMITED, retryData: {} });
}
const stats = await queue.getJob(jobId).getStats();   // { success, inProgress, failed }; job.cancel()
```
- Limits (limits-async-events/): 50 events per push, **200 KB combined per push**, **100 KB per event when the consumer timeout is >55 s**, 500 events/min per installation, `retryData` ≤4 KB, chain depth 1000 pushes. `retryAfter` is capped at 900 s. Max retry count and retention: **UNCONFIRMED**.

### `app`, `resources`, `permissions`: manifest-reference/, .../resources/, .../permissions/
```yaml
app:
  id: ari:cloud:ecosystem::app/<uuid>
  runtime:
    name: nodejs24.x        # nodejs24.x (recommended) | nodejs22.x | nodejs20.x
    architecture: arm64     # or x86_64 (default)
    memoryMB: 512           # 128–1024
  # storage: custom entities + indexes (Custom Entity Store). Not needed if using KVS/SQL.
  # package: { bundler: manual@2026, path: dist, extraFiles: [...] }   -> see §12
resources:
  - key: main-ui
    path: static/main/build      # Custom UI: dir containing index.html
    # entry: { a: a.html }       # optional named entries, referenced as main-ui/a
    # bundler: manual@2026       # Preview, UI Kit resources only
permissions:
  scopes: [read:jira-work, write:jira-work]
  external: { fetch: { backend: ['api.example.com'], client: [] } }
  content: { styles: ['unsafe-inline'] }
```
- The scope map form `{ scope: { allowImpersonation: true } }` is required for `asUser(accountId)`.

---

## 2. Forge SQL: storage-reference/sql/, sql-api/, sql-api-schema/, manifest-reference/modules/sql/
```yaml
modules:
  sql:
    - key: main
      engine: mysql     # only value
```
```ts
import sql, { UpdateQueryResponse, Result, errorCodes, migrationRunner } from '@forge/sql';   // `{ sql }` named import also documented
sql.prepare<T>(query: string): SqlStatement<Result<T>>    // .bindParams(...params).execute()
sql.executeRaw<T>(query: string): Promise<Result<T>>      // no params
interface Result<T> { rows: T extends UpdateQueryResponse ? UpdateQueryResponse : T[]; metadata?: Record<string, any> }
const r = await sql.prepare<{ id: string }>('SELECT id FROM t WHERE k = ?').bindParams(k).execute();
```
Migrations: `migrationRunner.enqueue(name, ddl)` is chainable, then `.run()`, then `.list()` returns `[{ name, migratedAt }]`.
```ts
const m = migrationRunner.enqueue('v001_create_t', CREATE_T).enqueue('v002_idx', CREATE_IDX);
await m.run();
```
- The recommended pattern is to push to a queue from the `avi:forge:installed:app` / `avi:forge:upgraded:app` triggers and run the migrations in a 900 s consumer. Because upgraded fires on major versions only, minor/patch DDL needs a scheduled trigger (`hour`/`day`) as well. Retry `run()` on error.
- Dialect: MySQL-compatible TiDB. Use ANSI SQL and avoid TiDB-specific features. Restricted syntax fails with `SQL_POLICY_VIOLATION`. **No foreign keys** (JOINs are OK, but there are no cascades). **One statement per query.** Transactions: **UNCONFIRMED** (not mentioned).
- Limits per install: 1 GiB prod / 256 MiB staging / 128 MiB dev; 200 tables; 150 DML req/s; 25 DDL req/min; 6 MiB per row; 62.5 s total query time per minute. Limits per query: 16 MiB memory; 1 MiB request; 4 MiB response; timeouts of 5 s SELECT, 10 s INSERT/UPDATE/DELETE, 20 s DDL. Each installation gets an isolated DB per environment. Adding `sql` to an existing app is a **major version** change. Not available on Government Cloud.

## 3. KVS: storage-reference/kvs-api/, kvs-api-secret/, limits-kvs-ce/
```ts
import { kvs, WhereConditions, MetadataField } from '@forge/kvs';
await kvs.set(key, value, { ttl: { value: 7, unit: 'DAYS' }, keyPolicy: 'FAIL_IF_EXISTS' });  // Promise<void>
await kvs.get(key, { metadataFields: [MetadataField.EXPIRE_TIME] });   // undefined if missing
await kvs.delete(key);
const { results, nextCursor } = await kvs.query()
  .where('key', WhereConditions.beginsWith('run:')).limit(10).cursor(c).getMany();  // results: [{ key, value, ... }]
await kvs.setSecret(k, v, opts?); await kvs.getSecret(k); await kvs.deleteSecret(k);   // query() never returns secrets
```
- `SetOptions`: `ttl { value, unit: SECONDS|MINUTES|HOURS|DAYS }` (max 1 year), `keyPolicy: OVERRIDE|FAIL_IF_EXISTS`, `returnValue: PREVIOUS|LATEST` (requires OVERRIDE), `returnMetadataFields`. TTL deletion is lazy, up to 48 h. Request `EXPIRE_TIME` and ignore expired values if you need strict expiry. Limits: key ≤500 chars matching `/^(?!\s+$)[a-zA-Z0-9:._\s-#]+$/`; value ≤240 KiB; object depth ≤31; 1000 RPS per installation; transactions ≤25 ops / 4 MB (storage-reference/kvs-transactions/).

## 4. `@forge/api` product fetch: apis-reference/fetch-api-product.requestjira/ (also .requestbitbucket/)
```ts
import api, { route } from '@forge/api';
const res = await api.asApp().requestJira(route`/rest/api/3/issue/${key}?${new URLSearchParams({ fields: 'summary' })}`);
if (!res.ok) throw new Error(`${res.status}`); const json = await res.json();
api.asUser().requestConfluence(route`/wiki/api/v2/pages/${id}?body-format=storage`);
api.asApp().requestBitbucket(route`/2.0/repositories/${wsUuid}/${repoUuid}/pullrequests/${prId}`);
```
- `asApp()` acts as the app. `asUser()` acts as the current user and is **"only available in modules that support the UI kit"**, so it is not usable in triggers, consumers or scheduled triggers. `asUser(accountId)` needs `allowImpersonation` scopes. Options follow undici fetch. **VERIFIED 2026-11-15 (spike): there is NO default JSON content type**: a body without `headers: { 'Content-Type': 'application/json' }` is sent as `text/plain` and Jira returns 415. The default method is GET. `route` encodes interpolations and blocks path manipulation. `assumeTrustedRoute` is an escape hatch.

**Issue entity properties** (Jira v3 OpenAPI):
- `PUT /rest/api/3/issue/{issueIdOrKey}/properties/{propertyKey}` sets a property. Scope `write:jira-work`. The body is non-empty JSON, ≤32768 chars. The calling identity needs Browse + Edit issue permissions. `GET` on the same path reads it (`read:jira-work`).
- Properties are JQL-searchable **only if indexed** via `jira:entityProperty` (manifest-reference/modules/jira-entity-property/):
```yaml
jira:entityProperty:
  - key: threatline-index
    entityType: issue          # issue (default) | user | project
    propertyKey: threatline
    values:
      - { path: score,  type: number, searchAlias: threatlineScore }   # types: number|string|text|user|date
      - { path: status, type: string, searchAlias: threatlineStatus }
```
- JQL: `threatlineScore > 3` or `issue.property['threatline'].score > 3`. All `jira:entityProperty` modules share a limit of 100 values; use `jira:entityPropertySet` for more.

## 5. `jira:workflowValidator`: manifest-reference/modules/jira-workflow-validator/ (Preview)
- Properties: `key`, `name`, `description`, `function` **or** `expression` (not both), `errorMessage` (string | i18n | `{expression}`), `create`/`edit`/`view` `{ resource }` (config UI), `projectTypes`, `configurationDescription`, `resolver` (the page lists it as "required"; probably only needed with config UI, **UNCONFIRMED**).
```yaml
jira:workflowValidator:
  - key: threatline-gate
    name: Threatline gate
    description: Blocks transition when the issue fails Threatline checks
    function: validate
```
```ts
export const validate = async ({ issue, configuration, transition, modifiedFields }) =>
  // issue.key; transition.from.id / transition.to.id; modifiedFields only with read:jira-work (v3 format)
  ({ result: false, errorMessage: 'Missing acceptance criteria' });   // errorMessage ignored when result:true
```
- Expression validators exist. The Jira expression must evaluate to `true`. A string result is shown as the error, and anything else (or an error) blocks and emits `avi:jira:failed:expression`. Context variables: `user`, `issue`, `originalIssue`, `project`, `transition`, `workflow`, `config`. Timeout: **UNCONFIRMED** on the module page. Design for a short synchronous budget and keep LLM calls out of the validator.

## 6. `action` (Rovo/Automation) + `automation:actionProvider`: manifest-reference/modules/rovo-action/, .../automation-action/
- The module name is **`action`** (no `rovo:` prefix). It is shared by Rovo agents, `rovo:mcp`, `rovo:skill` and Automation.
```yaml
action:
  - key: analyze-issue
    name: Analyze issue
    function: analyzeIssue
    actionVerb: GET              # GET | CREATE | UPDATE | DELETE | TRIGGER
    description: Analyzes a Jira issue and returns findings.   # the agent uses this to decide when to call
    inputs:
      issueKey:
        title: Issue key
        type: string             # string | integer | number | boolean
        required: true
        description: The Jira issue key
```
```ts
export async function analyzeIssue(payload, context) {
  const { issueKey } = payload;          // inputs are top-level keys on payload
  // payload.context: { cloudId, moduleKey, jira?: { resourceType, issueKey, issueId, issueType, issueTypeId, projectKey, projectId },
  //                    confluence?: { resourceType, contentId, spaceKey, spaceId } }
  // context.accountId: use this for authz, never inputs (they can be hallucinated)
  return { findings: [] };               // string or JSON (≤5 MB), the agent phrases it
}
```
- Confirmation: Rovo shows a platform-generated confirm card for non-GET verbs. This comes from community posts and the ECO-1654 ticket, not the module page, so it is **UNCONFIRMED** in docs. Documented earlier: **agents run by Automation rules will not invoke CREATE/UPDATE/DELETE/TRIGGER actions**. **SEEN 2026-11-15 (spike):** the Automation "Use agent" step now has a "Let this agent take actions" checkbox ("Allows the agent to use tools that create, edit, or delete"); the agent then runs with the rule actor's permissions.

**Automation** (Jira only per the page; a GA post mentions Confluence, **UNCONFIRMED**):
```yaml
automation:actionProvider:
  - key: threatline-automation
    actions: [analyze-issue]       # only listed actions appear in the rule builder
```
- For Automation the `action` also **requires** `config: { resource, render: native }` (a UI Kit/Custom UI config form). It can declare `outputs` (`type`, `nullable`, `description`) and `outputContext` (`entityName` ≤12, `outputType` OBJECT|LIST, `outputDomain` ≤12). Smart values: declare a hidden input whose value is a smart value (e.g. `"{{issue.key}}"`); Automation resolves it at run time. The handler reads `payload.<input>`. Errors: return `{ errors: [...] }` to fail the rule, which writes to the audit log and emails the rule owner. Outputs become a smart value named from `actionVerb`+`outputDomain`+`entityName`. Limits: 20 Automation actions per app; config JSON ≤100 KB; changes can take up to 20 min to appear (caching).

## 7. Rovo agent / skill / MCP
`rovo:agent` (manifest-reference/modules/rovo-agent/):
```yaml
rovo:agent:
  - key: threatline-agent
    name: Threatline             # ≤30 chars
    description: Reviews requirements for risk
    icon: resource:assets;icons/agent.svg
    prompt: resource:prompts;agent.md        # inline string also OK; resource refs need CLI ≥10.6.0
    conversationStarters: [Review this issue, Summarize open risks]
    followUpPrompt: Suggest next steps.
    actions: [analyze-issue]
    skills: [threatline-review]                 # rovo:skill keys (Preview)
```
`rovo:skill` (**Preview**, not EAP; .../rovo-skill/):
```yaml
rovo:skill:
  - key: threatline-review
    source: { dir: skills/threatline-review }      # must contain SKILL.md
    dependencies: { tools: [analyze-issue] }    # action keys; SKILL.md `allowed-tools` must include them
```
- No skill-to-skill dependencies and no scripts. The agent selects a skill by its description.

`rovo:mcp` (**Preview**; .../rovo-mcp/):
```yaml
rovo:mcp:
  - key: threatline-mcp
    name: Threatline MCP           # ≤30 chars
    tools: [analyze-issue]      # action keys (<64 chars each), max 50; ONE rovo:mcp per app
```
- Each listed `action` becomes a tool, and the action's `inputs` presumably form the tool schema (implied, not explicit). The endpoint is `https://mcp.atlassian.com/forge/<appId>` (the UUID part of `app.id`). Clients use OAuth 2.1 consent, and calls are bound by the user's permissions. External exposure is **off by default**. An admin enables it per site under Admin → Apps → Sites → Connected apps.

## 8. Forge LLMs: runtime-reference/forge-llms-api-reference/, forge-llms-models/, manifest-reference/modules/llm/
```yaml
modules:
  llm:
    - key: main-llm
      model: [claude]     # only family supported; once per app; adding it = major version upgrade
```
```ts
import { chat, stream, list } from '@forge/llm';
const res = await chat({ model: 'claude-sonnet-4-6', max_completion_tokens: 2000,
  messages: [{ role: 'system', content: '...' }, { role: 'user', content: '...' }],
  tools: [{ type: 'function', function: { name, description, parameters } }], tool_choice: 'auto' });
res.choices[0].message.content; res.choices[0].message.tool_calls; res.usage?.total_tokens;
// stream(): async iterable of LlmResponse chunks, call .close() afterwards. list(): { models: [{ model, status: 'active'|'deprecated' }] }
// error detail: err.context?.responseText
```
- Model IDs: `claude-haiku-4-5-20251001`, `claude-sonnet-4-5-20250929`, `claude-sonnet-4-6`, `claude-sonnet-5`, `claude-opus-4-6`, `claude-opus-4-7`, `claude-opus-4-8`, `claude-opus-5`.
- **Omit `temperature` AND `top_p` for `claude-opus-4-7`, `claude-opus-4-8`, `claude-opus-5`, `claude-sonnet-5`.** `temperature` and `top_p` can never be sent together.
- Limits per install: 100 requests/min across models; 500k tokens/min per model. Inference can run up to 5 min, but only inside an async consumer with timeout ≥300 s. Otherwise the function timeout applies. Context windows: Haiku 200K/64K; Sonnet and Opus 1M/128K. Text only. No extra scope is documented. The `llm` module is the gate, and lint fails if the SDK is used without it.

## 9. Teamwork Graph: forge/call-the-teamwork-graph-api/, teamwork-graph/persisted-cypher-queries/ (Preview)
```ts
import api from '@forge/api';
const r = await api.asUser().requestTeamworkGraph(query, variables /*, null, null, headers */);
const { data, errors } = await r.json();
// frontend: import { requestTeamworkGraph } from '@forge/bridge'; const { data } = await requestTeamworkGraph(query, variables);
```
- **asUser only**: the `@forge/api` typings omit it from `asApp()`. So it is not callable from triggers or consumers that have no user.
- Raw `cypherQuery` is unavailable to new apps. Use curated query fields or **persisted queries** instead: GraphQL `customQuery(queryKey:, queryParams:, first: ≤25, after:)`. Result shape: `data.customQuery.edges[].node.columns[{ key, value{ __typename ... } }]`.
- Register persisted queries with `POST https://<site>/gateway/api/twg/cypher-queries` `{ appId, name, cypher, paramsSchema? }`. You must be an app contributor. They are immutable, take about 1 min to propagate (`QUERY_NOT_FOUND` until then), and only the owning app can run them.
- Scopes are per object type (e.g. `read:graph:issue:jira`, `read:graph:page:confluence`, `read:graph:user:atlassian`). **A missing scope returns empty data, not an error.** Errors come back as HTTP 200 with `errors[].extensions.code`.
- **VERIFIED 2026-11-21 (live, dev env): the GraphQL operation name must be `company_operation`** (company ≥3 chars, operation ≥4), e.g. `query threatline_linkedPullRequests(...)`. Anything else (`ThreatlineCustomQuery`, or an anonymous query) fails every field with `DataFetchingException: You must set an operation name of the shape [company]_[operation]...` and **no** `extensions.code`, so log `errors[0].message` to see it.
- Curated fields need no registration: `jiraWorkItemLinkedExternalPullRequests(id: <issue ARI>)` and `jiraWorkItemLinkedExternalDeployments(id:)`, nodes `... on ExternalPullRequest { id displayId title url status lastUpdatedAt }` / `... on ExternalDeployment { id displayName url state lastUpdatedAt environment { displayName type } }`. Scopes: `read:graph:issue:jira`, `read:graph:pull-request:external`, `read:graph:deployment:external` (adding them = major version; `forge deploy --approve MAJOR_VERSION_RULE`, then `forge install --upgrade --confirm-scopes`). Used by the panel's Delivery check (`apps/core/src/adapters/graph-delivery.ts`).

## 10. Custom UI: forge/custom-ui/, apis-reference/ui-api-bridge/{invoke,view}/, runtime-reference/forge-resolver/, design-tokens-and-theming/
```yaml
jira:issuePanel:
  - key: threatline-panel
    resource: main-ui
    resolver: { function: resolver }
    title: Threatline
resources:
  - { key: main-ui, path: static/main/build }   # must contain index.html; set Vite `base: './'`, outDir to this path
function:
  - { key: resolver, handler: resolver.handler }
```
```ts
// frontend
import { invoke, view } from '@forge/bridge';
await view.theme.enable();                       // sync host theme; style with --ds-* CSS vars / @atlaskit/tokens token()
const ctx = await view.getContext();             // { accountId, cloudId, workspaceId?, extension, localId, moduleKey, siteUrl, locale, timezone, theme, license?, installation }
const out = await invoke<Result>('getFindings', { issueKey: ctx.extension.issue.key });
// backend
import Resolver from '@forge/resolver';
const resolver = new Resolver();
resolver.define('getFindings', async ({ payload, context }) => ({ ok: true }));
export const handler = resolver.getDefinitions();
```
- CSP: all assets come from the resource dir (use relative paths). External scripts and fetches are blocked unless listed in `permissions.external.fetch.client`. Inline styles need `permissions.content.styles: ['unsafe-inline']`, which most CSS-in-JS (incl. Atlaskit/emotion) requires. Context is not trustworthy for authz; re-check on the backend. Vite output path: no Forge-documented Vite default. Point `resources.path` at your build dir.
- Atlaskit/ADS inside Custom UI: no current Forge page restricts or recommends specific `@atlaskit/*` components (**UNCONFIRMED**). Documented: `@atlaskit/tokens` + `view.theme.enable()`, linted with `@atlaskit/eslint-plugin-design-system` / `@atlaskit/stylelint-design-system`. Community notice: Atlaskit majors after 2026-06-15 drop TypeScript 4.x (use TS 5). UI Kit (`@forge/react`, `render: native`) gets ADS automatically; UI Kit 1 (`@forge/ui`) is removed.

## 11. Bitbucket: manifest-reference/modules/bitbucket-merge-check/, .../bitbucket-repository-settings-menu-page
```yaml
modules:
  bitbucket:mergeCheck:
    - key: threatline-check
      function: mergeCheck
      name: Threatline requirements check
      description: Blocks merge when linked requirements fail
      triggers: [on-code-pushed, on-reviewer-status-changed, on-merge]   # ≥1
  bitbucket:repoSettingsMenuPage:
    - key: threatline-repo-settings
      title: Threatline
      resource: settings-ui           # + render: native for UI Kit; resolver: { function: ... }
permissions:
  scopes: [read:pullrequest:bitbucket, read:repository:bitbucket]   # mergeCheck REQUIRES read:pullrequest:bitbucket
```
```ts
// PRCheckEvent
export const mergeCheck = async (event) => {
  const { workspace: { uuid: ws }, repository: { uuid: repo }, pullrequest: { id }, trigger: { type } } = event;
  // event.mergeProperties (on-merge only): { commitMessage, commitMessageTruncated, mergeStrategy, closeSourceBranch }
  return { success: false, message: 'REQ-12 not approved' };   // a throw counts as failure
};
```
- The payload has **no commit hashes**. Fetch the PR for `source.commit.hash` / `destination.commit.hash`.
- repoSettingsMenuPage extension context: `{ type, repository: { uuid /* "{...}" wrapped */ }, location }`. Use `unwrapUuid`/`wrapUuid` for APIs (e.g. storage) that reject braces.

REST paths (api.bitbucket.org swagger). `{workspace}` / `{repo_slug}` accept a slug or a `{uuid}` with braces, and the Forge docs say requestBitbucket expects the workspace **UUID**.
| Need | Path | Scope |
|---|---|---|
| PR (description = `summary.raw`; `source/destination.commit.hash`) | `GET /2.0/repositories/{ws}/{repo}/pullrequests/{id}` | read:pullrequest:bitbucket |
| PR diffstat | `GET /2.0/repositories/{ws}/{repo}/pullrequests/{id}/diffstat` (**redirects** to repo diffstat) | read:pullrequest:bitbucket |
| Diffstat direct | `GET /2.0/repositories/{ws}/{repo}/diffstat/{src}..{dest}?topic=true` (paginated `values[{status, lines_added, lines_removed, old, new}]`) | read:repository:bitbucket |
| File at commit | `GET /2.0/repositories/{ws}/{repo}/src/{commit}/{path}` (raw bytes; dir → listing; `?format=meta`; LFS → 301) | read:repository:bitbucket |
- Whether requestBitbucket follows the diffstat redirect: **UNCONFIRMED**. Prefer the direct `diffstat/{spec}` form.
- Enforcement: a workspace admin must enable "Custom merge checks"; a check blocks only where set to **Required** (workspace/project/repo) and runs once per configured level; personal workspaces are unsupported.
- Merge check timeout: **UNCONFIRMED**. It is probably the 25 s/55 s class; keep the check fast and precompute in a consumer.

## 12. Forge CLI: forge/cli-reference/*, forge/set-up-cicd, manifest-reference/packaging/
- `forge create -t <template> -d <dir> -s <developerSpaceId> -y` (`-y/--accept-terms` for non-interactive). Template names are not documented in the CLI reference (**UNCONFIRMED**). Run `forge create` interactively to browse them.
- `forge lint [--fix] [-e env]` `forge deploy -e development [--non-interactive] [-f/--no-verify] [--inspect] [-t tag]`
- `forge install -e development -s <site>.atlassian.net -p jira|confluence|bitbucket|compass --non-interactive [--upgrade] [--confirm-scopes] [--license active]`
  - Bitbucket: the tutorials use `forge install -p bitbucket` and enter the workspace URL `bitbucket.org/<workspace>`. The exact `--site` value for non-interactive Bitbucket installs is **UNCONFIRMED**.
  - Deploy before install.
- `forge tunnel [-e env] [-d -f handler...]`. Needs no extra setup on CLI ≥10.1 (Cloudflare). `forge logs`, `forge variables set`, `forge environments`, `forge module add` also exist.
- CI: set **`FORGE_EMAIL`** and **`FORGE_API_TOKEN`** (an Atlassian *scoped* API token). The CLI reads them, so no `forge login` is needed. `forge login -u <email> -t <token> --non-interactive` is the alternative.
- Packaging (default bundler: Webpack). **`app.package.bundler: manual@2026` + `app.package.path: dist`** (Preview) uploads a prebuilt dir as-is; it must contain every handler file/export plus deps (`node_modules` inside `path`, or one bundled file). All-or-nothing across functions; no type/dep checking (errors surface at runtime); `forge tunnel` watches `path`, so run your build in watch mode. Docs example: `tsc` → `dist`, then `yarn install --production --modules-folder ./dist/node_modules`. `app.package.extraFiles` copies extra globs. UI Kit resources take `bundler: manual@2026` per resource; Custom UI is always prebuilt static files.
- pnpm/symlinks (community, not docs): installing the CLI with pnpm breaks `keytar` (use `npm i -g @forge/cli`); monorepo hoisting/symlinks cause "Can't resolve" in the default bundler, and `forge tunnel` failed on linked packages. Mitigation (**UNCONFIRMED** by Atlassian): `manual@2026` with an esbuild single-file bundle, or a flattened `node_modules` (`pnpm deploy` / `node-linker=hoisted`).

---

## Gotchas
1. `timeoutSeconds` only works on consumer/scheduledTrigger functions. Actions and web triggers stay at 55 s, UI resolvers at 25 s; product-event trigger limit is not stated (assume 55 s, UNCONFIRMED). Push long work (LLM calls) to a 900 s consumer.
2. Consumers with a timeout above 55 s are limited to **100 KB per event** (200 KB per push). Pass IDs, not documents.
3. `@forge/events` v2 reads `event.body`, and `push()` requires the `{ body }` wrapper. Consumers use `function:`, not `resolver:`.
4. `avi:forge:upgraded:app` fires only on **major** upgrades. Run SQL migrations from a scheduled trigger too.
5. Adding the `sql`, `llm` or new-scope modules forces a major version, and admins must re-consent.
6. Forge SQL: no FKs, one statement per call, 5 s SELECT timeout, avoid TiDB-only syntax.
7. Product events can arrive up to 3 min late and can duplicate. Use `filter.ignoreSelf: true` so the app's own writes don't loop, and make handlers idempotent.
8. `asUser()` is documented only for UI-Kit-capable modules, so treat it as unavailable in triggers, consumers and scheduled jobs, so `requestTeamworkGraph` (asUser-only) can't run there either. Missing TWG scopes return empty results silently.
9. Entity properties are not JQL-searchable unless indexed by `jira:entityProperty` (100-value cap). The value must be non-empty JSON ≤32 KB.
10. Opus 4.7/4.8/5 and Sonnet 5 reject `temperature` and `top_p`. Never send both, to any model.
11. Rovo agents started by Automation call non-GET actions only when the step's "Let this agent take actions" box is ticked (seen 2026-11-15). Inputs may be hallucinated, so authorize with `context.accountId`.
12. Automation needs both `automation:actionProvider` **and** an action `config` UI. There is a 20-action cap and up to 20 min of cache delay.
13. Bitbucket merge-check payload has only UUIDs/ids (no hashes, no workspace slug). `read:pullrequest:bitbucket` is mandatory. A check blocks only when set to Required, and the "Custom merge checks" feature must be enabled. **VERIFIED 2026-11-15: "Required" (and workspace/project-level checks) need Bitbucket Premium** — on Free the check runs and reports but cannot block. Repo UUIDs come wrapped in `{}`.
14. `rovo:mcp`: one per app, max 50 tools, and admins must switch exposure on per site.
15. With `manual@2026`, Forge does no bundling or validation. A missing handler export or dependency fails only at runtime. Keep deploy output self-contained (no pnpm symlinks).


## 16. Spike-verified platform facts (2026-11-15) — see docs/research/spike-results.md
- `POST /rest/api/3/expression/eval` returns **410 Gone**; use `POST /rest/api/3/expression/evaluate` (same body; result under `value`). Needs `read:jira-user` in the manifest (forge lint enforces it).
- Free "Cloud Developer Bundle" sites (go.atlassian.com/cloud-dev) have **no Rovo agents** ("your org admin needs to activate AI"). Use `forge site provision` → a Forge **demo site** (enterprise Jira/Confluence/JSM + Rovo, 90 days, one per developer).
- Forge Rovo agents appear (a) in Automation "Use agent", (b) in the work item "Agents" menu, and (c) in the **Assignee** picker as an app user. Assigning a work item to the agent **starts an agent session automatically**, labelled "<Agent> with <assigner>"; the reply waits for review and is "Only visible to you" until someone drafts a comment.
- Automation Forge actions need a Custom UI/UI Kit config page that calls `view.submit({...inputs})` (and listens for `AUTOMATION_ACTION_SUBMIT`); a static page leaves Next disabled. Config resource changes are cached (observed >10 min).
- A web trigger in the manifest triggers "RoA trust signal loss" → major version; `forge deploy --approve MAJOR_VERSION_RULE` acknowledges it.
- `forge register` needs a Developer Space; on first use the CLI prompts for its name (TTY required — `script -q /dev/null forge register …` works).
- Forge CLI 15.x requires Node ^22.23.4 / ^24.22.1 / >=26.12.1; 14.2.0 works on Node 22.22.

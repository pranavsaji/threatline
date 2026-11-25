import { contextHash, DEFAULT_INCIDENT_POLICY, isIncident, normalizeFacts, type ClockPort, type ContextGatherer, type GatherOptions, type IssueRepo, type RawFact, type ReviewRepo } from '@threatline/core';
import { sha256Hex } from '@threatline/crypto';
import { ok, type ContextBundle, type ContextFact, type IncidentPolicy, type Result } from '@threatline/shared';
import type { ConfluenceClient } from './confluence.js';
import type { JiraClient, JiraComment, JiraIssue } from './jira.js';

export interface RestGathererDeps {
  jira: JiraClient;
  confluence: ConfluenceClient;
  reviews: ReviewRepo;
  issues: IssueRepo;
  clock: ClockPort;
  /** Site cloud id, used to build real ARIs (from the Forge invocation context). */
  cloudId: string;
  /** Site base URL ("https://acme.atlassian.net"), so Jira sources get absolute links; relative ones break in the panel iframe. */
  siteUrl?: () => Promise<string>;
  /** What counts as an incident (the site policy's rule; the default when absent or unreadable). */
  incidentRule?: () => Promise<Pick<IncidentPolicy, 'labels' | 'issueTypes'>>;
  /** The Confluence page Threatline published for this work item (its threat model), if any: never read as context. */
  ownPage?: (issueId: string) => Promise<string | null>;
  /** Threatline's own Atlassian account (services/own-account.ts): its comments are never read as context. */
  ownAccount?: () => Promise<string | null>;
}

/** The newest comments read as context: people's comments only, never Threatline's own. */
const MAX_COMMENTS = 20;

/**
 * The comments that are review context: the newest MAX_COMMENTS that Threatline did not write, then without restricted
 * ones. Threatline's own comments (its verdict comment, risk-acceptance notes) are its output, not evidence: read back
 * they would feed the model its own verdict and change the context hash, marking the review out of date, which would
 * ask for a re-run that comments again. They are skipped before the window is cut, so they never push a person's comment
 * out of it either. Without a known own account (Threatline has not commented yet) every comment is read.
 */
export function contextComments(comments: readonly JiraComment[], ownAccount: string | null): JiraComment[] {
  return comments.filter((c) => !ownAccount || c.author !== ownAccount).slice(0, MAX_COMMENTS).filter((c) => !c.restricted);
}

/** The remote-link globalId Threatline gives the threat-model page it links on a work item (confluence-page.ts). */
export const THREAT_MODEL_LINK_PREFIX = 'threatline-threat-model-';

/**
 * Threatline's own threat-model page for this work item, known only by the page id Threatline recorded when it published
 * (state no user can write). Reading it as context would make every re-publish change the context (its version), mark
 * the review out of date, and feed the model its own output as evidence. Nothing a user controls (a page title, its
 * headings, a remote link's globalId) can mark a page as Threatline's: that would let anyone hide a design page from
 * review. Without the record (a failed read), the page is read like any other: stricter, never looser.
 */
export function isOwnThreatModel(page: { id: string }, ownPageId: string | null): boolean {
  return ownPageId !== null && page.id === ownPageId;
}

const MAX_PAGES = 10;
const MAX_CHILDREN = 20;

/** Content-derived version: a fact's version changes exactly when its text changes, so duplicate events keep the hash. */
const versionOf = (...parts: string[]) => sha256Hex(parts.join('\u0000')).slice(0, 16);

/** JQL string literal: Jira-supplied names may contain quotes or backslashes. */
const jqlString = (s: string) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

/** Confluence page id from a remote-link URL, or null when it is not a Confluence page link. */
export function pageIdFromUrl(url: string): string | null {
  if (!/\/wiki\//.test(url)) return null;
  const m = /\/pages\/(\d{1,20})(?:[/?#]|$)/.exec(url) ?? /[?&]pageId=(\d{1,20})(?:&|#|$)/.exec(url);
  return m ? m[1]! : null;
}

const hostOf = (url: string): string | null => {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return null;
  }
};

/**
 * The incidents search for a work item: recent work items in its project, linked to it or on its components, that the
 * incident rule may match (labels, or work types the project has: Jira refuses a JQL naming a type it does not know).
 * Null when the rule names nothing to search for.
 */
async function incidentQuery(jira: JiraClient, issue: JiraIssue, rule: Pick<IncidentPolicy, 'labels' | 'issueTypes'>, reasons: string[]): Promise<string | null> {
  let types: string[] = [];
  if (rule.issueTypes.length > 0) {
    const p = await jira.projectInfo(issue.project.key);
    if (p.ok) {
      const wanted = new Set(rule.issueTypes.map((t) => t.toLowerCase()));
      types = [...new Set(p.value.issueTypes.filter((t) => wanted.has(t.name.toLowerCase())).map((t) => t.name))];
    } else reasons.push('incident_types_unavailable');
  }
  const match = [...(rule.labels.length ? [`labels in (${rule.labels.map(jqlString).join(', ')})`] : []), ...(types.length ? [`issuetype in (${types.map(jqlString).join(', ')})`] : [])];
  if (match.length === 0) return null;
  const scope = `issue in linkedIssues(${jqlString(issue.key)})${issue.components.length ? ` OR component in (${issue.components.map(jqlString).join(', ')})` : ''}`;
  return `project = ${jqlString(issue.project.key)} AND ${match.length > 1 ? `(${match.join(' OR ')})` : match[0]} AND created >= -90d AND (${scope}) ORDER BY created DESC`;
}

/**
 * CE-1 over REST, as the app. Trusted: key, type, status, project, components, fix versions, earlier reviews.
 * Untrusted: summary, description, parent/children/linked summaries, comments, Confluence page bodies, incidents.
 * Any sub-fetch failure sets `partial` with a named reason (CE-5, CE-6); only the work item itself is required.
 *
 * Security: the app can read more than the people who see the bundle. Linked Confluence pages and incidents are
 * included only when the actor (the person whose action caused this gather) can read them; with no actor they are left
 * out. Left-out pages still count towards `contextHash` (by id and version) so the hash never depends on who triggered it.
 */
export function restGatherer(d: RestGathererDeps): ContextGatherer {
  const issueAri = (id: string) => `ari:cloud:jira:${d.cloudId}:issue/${id}`;
  let base = '';
  /** Versions hash the site-relative path, so adding the site URL never changes a context hash (no reviews go stale). */
  const raw = (f: Omit<RawFact, 'origin' | 'version'> & { version?: string }): RawFact => ({
    ...f,
    version: f.version ?? versionOf(f.title, f.text, base && f.url.startsWith(base) ? f.url.slice(base.length) : f.url),
    origin: 'rest',
  });
  const browse = (key: string) => `${base}/browse/${key}`;
  const issueText = (i: JiraIssue) => `${i.summary}\n${i.description}`.trim();

  return {
    async gather(issueId, opts: GatherOptions = {}): Promise<Result<ContextBundle>> {
      const actor = opts.actorAccountId ?? '';
      base = d.siteUrl ? ((await d.siteUrl().catch(() => '')) ?? '').replace(/\/+$/, '') : '';
      const main = await d.jira.issue(issueId);
      if (!main.ok) return main;
      const issue = main.value;
      const facts: RawFact[] = [];
      const reasons: string[] = [];
      /** Sources left out for permission reasons: hashed, never shown. */
      const withheld: Array<{ sourceAri: string; version: string }> = [];

      facts.push(
        raw({
          sourceAri: `${issueAri(issue.id)}#meta`,
          sourceType: 'jira_issue',
          title: `${issue.key} (${issue.issueType.name || 'work item'})`,
          url: browse(issue.key),
          text: [
            `Key: ${issue.key}`,
            `Type: ${issue.issueType.name}`,
            `Status: ${issue.status.name}`,
            `Project: ${issue.project.key}`,
            `Components: ${issue.components.join(', ') || 'none'}`,
            `Fix versions: ${issue.fixVersions.join(', ') || 'none'}`,
          ].join('\n'),
          trusted: true,
        }),
        raw({ sourceAri: issueAri(issue.id), sourceType: 'jira_issue', title: `${issue.key} ${issue.summary}`, url: browse(issue.key), text: issueText(issue), trusted: false }),
      );
      for (const l of issue.links) {
        facts.push(
          raw({
            sourceAri: issueAri(l.issue.id),
            sourceType: 'jira_issue',
            title: `${l.type} ${l.issue.key}`,
            url: browse(l.issue.key),
            text: `${l.issue.issueType} ${l.issue.key} (${l.issue.status}): ${l.issue.summary}`,
            trusted: false,
          }),
        );
      }

      const rule = d.incidentRule ? await d.incidentRule().catch(() => DEFAULT_INCIDENT_POLICY) : DEFAULT_INCIDENT_POLICY;
      const incidentJql = await incidentQuery(d.jira, issue, rule, reasons);

      const [parent, children, comments, links, incidents, history, ownPage, ownAccount] = await Promise.all([
        issue.parent ? d.jira.issue(issue.parent.id) : Promise.resolve(null),
        d.jira.children(issue.id),
        d.jira.comments(issue.id),
        d.jira.remoteLinks(issue.id),
        incidentJql ? d.jira.search(incidentJql, ['summary', 'description', 'issuetype', 'labels', 'project', 'status', 'created'], 20) : Promise.resolve(ok([])),
        d.reviews.history(issue.id),
        d.ownPage ? d.ownPage(issue.id).catch(() => null) : Promise.resolve(null),
        d.ownAccount ? d.ownAccount().catch(() => null) : Promise.resolve(null),
      ]);

      if (parent) {
        if (parent.ok)
          facts.push(raw({ sourceAri: issueAri(parent.value.id), sourceType: 'jira_issue', title: `Parent ${parent.value.key} ${parent.value.summary}`, url: browse(parent.value.key), text: issueText(parent.value), trusted: false }));
        else reasons.push('parent_unavailable');
      }
      if (children.ok) {
        for (const c of children.value.slice(0, MAX_CHILDREN))
          facts.push(raw({ sourceAri: issueAri(c.id), sourceType: 'jira_issue', title: `Child ${c.key}`, url: browse(c.key), text: `${c.issueType.name} ${c.key} (${c.status.name}): ${c.summary}`, trusted: false }));
        if (children.value.length > MAX_CHILDREN) reasons.push('children_truncated');
      } else reasons.push('children_unavailable');

      if (comments.ok) {
        for (const c of contextComments(comments.value, ownAccount))
          facts.push(
            raw({
              sourceAri: `ari:cloud:jira:${d.cloudId}:issue-comment/${c.id}`,
              sourceType: 'jira_comment',
              title: `Comment on ${issue.key}`,
              url: `${browse(issue.key)}?focusedCommentId=${c.id}`,
              text: c.body,
              trusted: false,
            }),
          );
      } else reasons.push('comments_unavailable');

      if (incidents.ok) {
        // The search is only a pre-filter: what counts is the rule, applied to what Jira returned.
        const candidates = incidents.value.filter((i) => i.id !== issue.id && isIncident({ labels: i.labels, issueType: i.issueType.name }, rule));
        if (!actor && candidates.length > 0) reasons.push('incidents_unverified');
        const visible = actor ? await Promise.all(candidates.map((i) => d.jira.canBrowse(actor, i.id))) : [];
        for (const [n, i] of candidates.entries()) {
          const sourceAri = `${issueAri(i.id)}#incident`;
          const version = versionOf(i.key, i.summary, i.description);
          const v = visible[n];
          if (!actor || !v || !v.ok || !v.value) {
            withheld.push({ sourceAri, version });
            if (actor) reasons.push(v && !v.ok ? `incident_unverified:${i.key}` : `incident_restricted:${i.key}`);
            continue;
          }
          facts.push(raw({ sourceAri, sourceType: 'incident', title: `${i.issueType.name} ${i.key}: ${i.summary}`, url: browse(i.key), text: issueText(i), version, trusted: false }));
        }
      } else reasons.push('incidents_unavailable');

      if (links.ok) {
        const pageLinks = new Map<string, string>();
        for (const l of links.value) {
          const id = pageIdFromUrl(l.url);
          if (id && id !== ownPage && !pageLinks.has(id)) pageLinks.set(id, l.url);
        }
        if (pageLinks.size > MAX_PAGES) reasons.push('confluence_pages_truncated');
        const ids = [...pageLinks.keys()].slice(0, MAX_PAGES);
        // The app reads each page for its version (hashing only); the body is used only when the actor may read it.
        const [pages, readable] = await Promise.all([
          Promise.all(ids.map((id) => d.confluence.page(id))),
          Promise.all(ids.map((id) => (actor ? d.confluence.canRead(id, actor) : Promise.resolve(null)))),
        ]);
        for (const [n, id] of ids.entries()) {
          const p = pages[n]!;
          const sourceAri = `ari:cloud:confluence:${d.cloudId}:page/${id}`;
          if (!p.ok) {
            withheld.push({ sourceAri, version: 'unavailable' });
            reasons.push(`confluence_page_unavailable:${id}`);
            continue;
          }
          // A link to another site's wiki would otherwise fetch an unrelated page with the same id on this site.
          const linkHost = hostOf(pageLinks.get(id)!);
          const pageHost = hostOf(p.value.url);
          if (linkHost && pageHost && linkHost !== pageHost) {
            reasons.push(`confluence_page_other_site:${id}`);
            continue;
          }
          // Threatline's own output is not evidence, and is neither shown, hashed nor watched for edits.
          if (isOwnThreatModel(p.value, ownPage)) continue;
          // Linked even when withheld: a restricted page's edits must still mark the review out of date.
          const linked = await d.issues.linkPage(issue.id, p.value.id);
          if (!linked.ok) reasons.push(`page_link_unsaved:${id}`);
          const version = `v${p.value.version}-${versionOf(p.value.storage)}`;
          const r = readable[n];
          if (!actor || !r || !r.ok || !r.value) {
            withheld.push({ sourceAri, version });
            reasons.push(!actor ? `confluence_page_unverified:${id}` : r && !r.ok ? `confluence_page_unavailable:${id}` : `confluence_page_restricted:${id}`);
            continue;
          }
          facts.push(raw({ sourceAri, sourceType: 'confluence_page', title: p.value.title, url: p.value.url, text: p.value.storage, version, trusted: false }));
        }
      } else reasons.push('remote_links_unavailable');

      if (history.ok) {
        const last = history.value.reduce<(typeof history.value)[number] | null>((a, r) => (!a || r.revision > a.revision ? r : a), null);
        if (last) {
          // Numbers and enums only: threat titles came from a model that read untrusted text, so they are not repeated here.
          facts.push(
            raw({
              sourceAri: `ari:threatline:review/${last.id}`,
              sourceType: 'review',
              title: `Earlier Threatline review, revision ${last.revision}`,
              url: browse(issue.key),
              text: `Revision ${last.revision} (${last.status}${last.partial ? ', partial context' : ''}): risk score ${last.riskScore} of 100, reviewed ${last.createdAt}.`,
              version: `${last.revision}-${last.status}-${last.riskScore}`,
              trusted: true,
            }),
          );
        }
      } else reasons.push('reviews_unavailable');

      const normalized: ContextFact[] = [];
      const seen = new Set<string>();
      for (const f of facts.flatMap(normalizeFacts)) {
        if (seen.has(f.id)) continue;
        seen.add(f.id);
        normalized.push(f);
      }
      return ok({
        issueId: issue.id,
        issueKey: issue.key,
        facts: normalized,
        partial: reasons.length > 0,
        partialReasons: reasons,
        // M4: Threatline's own review summary is context for the agent, not a source; it must not change the hash, or a
        // redelivered "created" event would open a new revision that no Automation run fills.
        contextHash: contextHash([...normalized.filter((f) => f.sourceType !== 'review'), ...withheld]),
        gatheredAt: d.clock.now().toISOString(),
        components: issue.components.map((c) => c.slice(0, 255)),
      });
    },
  };
}

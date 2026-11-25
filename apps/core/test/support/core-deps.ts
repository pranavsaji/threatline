import type { LlmPort } from '@threatline/core';
import { FakeLlm } from '../../../../packages/core/test/fakes/fake-llm.js';
import {
  fixedClock,
  memoryAttestationRepo,
  memoryFeedbackRepo,
  memoryIssueRepo,
  memoryLedgerRepo,
  memoryRequirementRepo,
  memoryReviewRepo,
  memorySuppressionRepo,
  memoryTreeHeadRepo,
  memoryUsageRepo,
  memoryVerdictSink,
} from '@threatline/core/testing';
import { DEFAULT_SITE_POLICY } from '@threatline/core';
import { ok, type ContextBundle, type Result, type SitePolicy } from '@threatline/shared';
import { normalizeFact } from '@threatline/core';
import type { CoreDeps } from '../../src/deps.js';
import type { JiraClient, JiraIssue } from '../../src/adapters/jira.js';
import type { ConfluenceClient } from '../../src/adapters/confluence.js';
import type { ReviewJob } from '../../src/jobs/types.js';
import { memoryKvs } from './memory-kvs.js';
import { kvsSigningKeys } from '../../src/adapters/signing-keys.js';
import { contextHash } from '@threatline/core';
import type { LicenseState } from '../../src/services/license.js';

export const POLICY: SitePolicy = { ...DEFAULT_SITE_POLICY, enabledProjects: ['PAY'], reviewIssueTypes: ['Story', 'Epic'], agentSamples: 3, agentTimeoutMinutes: 15, reviewMode: 'agent' };

export function jiraIssue(over: Partial<JiraIssue> & { id: string; key: string }): JiraIssue {
  return {
    summary: 'Refund webhook',
    description: 'Accept refund webhooks from the payment provider',
    issueType: { id: '10001', name: 'Story', subtask: false },
    links: [],
    components: ['payments'],
    labels: [],
    project: { id: '10000', key: 'PAY' },
    status: { name: 'To Do', category: 'new' },
    fixVersions: [],
    ...over,
  };
}

/** The account the fake Jira says Threatline's comments are written by (the app user). */
export const APP_ACCOUNT = '557058:threatline-app';

/** A Jira fake: issues by id, records properties, comments and label changes. */
export function fakeJira(issues: JiraIssue[]): JiraClient & { props: Map<string, unknown>; commented: Array<{ issueId: string; adf: unknown }>; labels: string[] } {
  const byRef = (ref: string) => issues.find((i) => i.id === ref || i.key === ref);
  const props = new Map<string, unknown>();
  const commented: Array<{ issueId: string; adf: unknown }> = [];
  const labels: string[] = [];
  const nf = () => ({ ok: false as const, error: { code: 'not_found' as const, message: 'nf' } });
  return {
    props,
    commented,
    labels,
    issue: async (ref) => (byRef(ref) ? ok(structuredClone(byRef(ref)!)) : nf()),
    children: async (id) => ok(issues.filter((i) => i.parent?.id === id)),
    comments: async () => ok([]),
    remoteLinks: async () => ok([]),
    canBrowse: async () => ok(true),
    canEdit: async () => ok(true),
    async browsable(accountId, ids) {
      const out: string[] = [];
      for (const id of ids) {
        const r = await this.canBrowse(accountId, id);
        if (!r.ok) return r;
        if (r.value) out.push(id);
      }
      return ok(out);
    },
    groupsOf: async () => ok([]),
    isAdmin: async () => ok(false),
    setProperty: async (id, key, value) => {
      props.set(`${id}:${key}`, structuredClone(value));
      return ok(undefined);
    },
    getProperty: async (id, key) => ok(props.get(`${id}:${key}`) ?? null),
    subtaskType: async () => ok('10003'),
    projectInfo: async (key) => ok({ id: '10000', key, issueTypes: [] }),
    projectStatuses: async () => ok(['To Do', 'In Progress', 'Done']),
    installGate: async () => ok({ added: [], already: [], readOnly: [] }),
    ensureComponent: async () => ok(undefined),
    createIssue: async () => ok({ id: '2', key: 'X-2' }),
    createSubtask: async () => ok({ id: '1', key: 'X-1' }),
    addRemoteLink: async () => ok(undefined),
    addLabel: async (_id, l) => {
      labels.push(`+${l}`);
      return ok(undefined);
    },
    removeLabel: async (_id, l) => {
      labels.push(`-${l}`);
      return ok(undefined);
    },
    comment: async (issueId, adf) => {
      commented.push({ issueId, adf });
      return ok({ id: String(30000 + commented.length), authorAccountId: APP_ACCOUNT });
    },
    search: async () => ok([]),
  };
}

/** A gatherer whose bundle text can be changed between calls (to simulate edits). */
export function fakeGatherer(texts: Record<string, string>) {
  const calls: Array<{ issueId: string; actor?: string }> = [];
  return {
    texts,
    calls,
    async gather(issueId: string, opts?: { actorAccountId?: string }): Promise<Result<ContextBundle>> {
      calls.push({ issueId, ...(opts?.actorAccountId ? { actor: opts.actorAccountId } : {}) });
      const text = texts[issueId] ?? 'Public webhook that receives refund events with customer email address';
      const facts = [normalizeFact({ sourceAri: `ari:t:issue/${issueId}`, sourceType: 'jira_issue', title: 'Item', url: '', text, version: text, trusted: false, origin: 'rest' })];
      return ok({ issueId, issueKey: `PAY-${issueId}`, facts, partial: false, partialReasons: [], contextHash: contextHash(facts), gatheredAt: '2026-11-15T12:00:00.000Z', components: ['payments'] });
    },
  };
}

export function coreDeps(o: { issues?: JiraIssue[]; policy?: SitePolicy; now?: string; llm?: LlmPort; license?: LicenseState } = {}) {
  const clock = fixedClock(o.now ?? '2026-11-15T12:00:00Z');
  const kv = memoryKvs();
  const pushed: ReviewJob[] = [];
  const jira = fakeJira(o.issues ?? [jiraIssue({ id: '10042', key: 'PAY-7' })]);
  const gatherer = fakeGatherer({});
  const verdicts = memoryVerdictSink();
  const purged: string[] = [];
  const purgedProjects: string[] = [];
  let policy = o.policy ?? POLICY;
  let migrations = 0;
  // Paid via Atlassian: not applicable (a free or development install) unless a test says otherwise.
  let license: LicenseState = o.license ?? 'not_applicable';
  const deps: CoreDeps = {
    reviews: memoryReviewRepo(),
    requirements: memoryRequirementRepo(),
    ledger: memoryLedgerRepo(),
    feedback: memoryFeedbackRepo(),
    issues: memoryIssueRepo(),
    usage: memoryUsageRepo(),
    attestations: memoryAttestationRepo(),
    treeHeads: memoryTreeHeadRepo(),
    suppressions: memorySuppressionRepo(),
    keys: kvsSigningKeys(clock, kv),
    llm: o.llm ?? new FakeLlm({}),
    jira,
    confluence: {} as ConfluenceClient,
    gatherer,
    verdicts,
    config: { site: async () => ok(policy), setSite: async (p) => ((policy = p), ok(undefined)), flag: async () => false },
    state: kv,
    retention: {
      purgeBefore: async (iso) => {
        purged.push(iso);
        return ok({ reviews: 0 });
      },
      snapshotPosture: async () => ok(undefined),
      postureTrend: async () => ok([]),
      purgeProject: async (key) => (purgedProjects.push(key), ok({ reviews: 3, requirements: 2 })),
    },
    queue: { push: async (jobs) => (pushed.push(...jobs), ok(undefined)) },
    clock,
    migrate: async () => (migrations++, ok({ to: 1 })),
    siteUrl: async () => 'https://one-atlas-mefc.atlassian.net',
    license: { state: async () => license },
  };
  const setLicense = (s: LicenseState) => void (license = s);
  return { deps, clock, kv, pushed, jira, gatherer, verdicts, purged, purgedProjects, migrations: () => migrations, setLicense };
}

/** Runs queued jobs (and the jobs they push) until the queue is empty. */
export async function drain(handle: (job: ReviewJob) => Promise<unknown>, pushed: ReviewJob[], max = 50): Promise<ReviewJob[]> {
  const ran: ReviewJob[] = [];
  while (pushed.length > 0 && ran.length < max) {
    const job = pushed.shift()!;
    ran.push(job);
    await handle(job);
  }
  return ran;
}

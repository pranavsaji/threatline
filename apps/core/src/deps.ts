import type {
  AttestationRepo,
  ClockPort,
  ContextGatherer,
  FeedbackRepo,
  IssueRepo,
  LedgerRepo,
  LlmPort,
  RequirementRepo,
  ReviewRepo,
  SigningKeyStore,
  SuppressionRepo,
  UsageRepo,
  VerdictSink, TreeHeadRepo
} from '@threatline/core';
import type { Result } from '@threatline/shared';
import type { ConfluenceClient } from './adapters/confluence.js';
import type { JiraClient } from './adapters/jira.js';
import type { ConfigStore, KvsPort } from './adapters/kvs-config.js';
import type { RetentionStore } from '@threatline/db';
import type { ReviewJob } from './jobs/types.js';
import type { LicensePort } from './services/license.js';

export interface JobQueue {
  push(jobs: ReviewJob[]): Promise<Result<void>>;
}

/** Everything a handler needs, wired once by composeCore(); tests build it from memory repos and fakes. */
export interface CoreDeps {
  reviews: ReviewRepo;
  requirements: RequirementRepo;
  ledger: LedgerRepo;
  feedback: FeedbackRepo;
  issues: IssueRepo;
  usage: UsageRepo;
  attestations: AttestationRepo;
  /** R5: signed Merkle tree heads over the ledger. */
  treeHeads: TreeHeadRepo;
  /** Team suppression rules per project, and where each hid or was unhidden (docs/SUPPRESSIONS.md). */
  suppressions: SuppressionRepo;
  /** Ed25519 merge-attestation keys (private halves in Forge secret storage). */
  keys: SigningKeyStore;
  /** Threatline Engine's model (Forge LLMs in production, a fake in tests). Billed to the app's developer. */
  llm: LlmPort;
  /** Jira as the app (triggers, consumers and jobs have no user). */
  jira: JiraClient;
  confluence: ConfluenceClient;
  gatherer: ContextGatherer;
  verdicts: VerdictSink;
  config: ConfigStore;
  /** Small app state in KVS: current context hashes, counters, schema version, alert de-duplication. */
  state: KvsPort;
  retention: RetentionStore;
  queue: JobQueue;
  clock: ClockPort;
  /** Applies pending SQL migrations (Forge migrationRunner in production). */
  migrate(): Promise<Result<{ to: number }>>;
  /** Site base URL, e.g. https://example.atlassian.net (for panel links). */
  siteUrl(): Promise<string>;
  /** Paid via Atlassian license of this invocation (docs/LICENSING.md): unlicensed starts no new AI work. */
  license: LicensePort;
}

import type {
  AgentThreatModel,
  ContextBundle,
  ContextFact,
  DismissReason,
  Requirement,
  Result,
  Review,
  ReviewStatus,
  Stride,
  Threat,
  Verdict,
} from '@threatline/shared';
import type { KeyPair } from '@threatline/crypto';

export interface ClockPort {
  now(): Date;
}

export type ModelTier = 'fast' | 'balanced' | 'deep';
export type LlmPurpose = 'extract' | 'propose' | 'verify' | 'requirements' | 'explain' | 'release';

export interface LlmRequest {
  system: string;
  user: string;
  tier: ModelTier;
  maxOutputTokens: number;
  purpose: LlmPurpose;
}
export interface LlmResponse {
  text: string;
  modelId: string;
  tokensIn: number;
  tokensOut: number;
}
export interface LlmPort {
  complete(req: LlmRequest): Promise<Result<LlmResponse>>;
}

export interface GatherOptions {
  /**
   * The person whose action caused this gather. Content the app can read but this person cannot (restricted
   * Confluence pages, incidents under issue security) is left out of the bundle. Without an actor it is left out too.
   */
  actorAccountId?: string;
}
export interface ContextGatherer {
  gather(issueId: string, opts?: GatherOptions): Promise<Result<ContextBundle>>;
}

export type FailedSample = { failed: string };
export type Sample = AgentThreatModel | FailedSample;
export const isFailedSample = (s: Sample): s is FailedSample => 'failed' in s;

export interface DiscardedThreat {
  title: string;
  stride?: Stride;
  reason: 'low_votes' | 'unsupported_citation' | 'duplicate_of_dismissed' | 'schema';
}

export interface ReviewRepo {
  latest(issueId: string): Promise<Result<Review | null>>;
  get(id: string): Promise<Result<Review | null>>;
  history(issueId: string): Promise<Result<Review[]>>;
  byStatus(status: ReviewStatus, olderThan?: string): Promise<Result<Review[]>>;
  create(r: Review): Promise<Result<Review>>;
  update(id: string, patch: Partial<Review>): Promise<Result<void>>;
  /**
   * Compare-and-set: writes the patch only while the stored review still has `expect.status` and at most
   * `expect.samplesReceivedAtMost` samples assembled; true when it was written (false too when there is no such review).
   */
  updateWhere(id: string, expect: { status?: ReviewStatus; samplesReceivedAtMost?: number }, patch: Partial<Review>): Promise<Result<boolean>>;
  /** Reviews in this status updated at or after `since`, newest first, at most `limit` (capped at 500). Indexed. */
  updatedSince(status: ReviewStatus, since: string, limit: number): Promise<Result<Review[]>>;
  /** Atomically adds token counts (negative to settle a reservation) and merges model ids. */
  addUsage(id: string, delta: { tokensIn: number; tokensOut: number; modelIds: readonly string[] }): Promise<Result<void>>;
  /**
   * Security: reserves tokens for one model call atomically, only while the review's totals stay within the caps; false
   * when they would not. Parallel engine stages cannot together overshoot the per-review budget.
   */
  reserveUsage(id: string, est: { tokensIn: number; tokensOut: number }, cap: { tokensIn: number; tokensOut: number }): Promise<Result<boolean>>;
  saveFacts(reviewId: string, facts: ContextFact[]): Promise<Result<void>>;
  facts(reviewId: string): Promise<Result<ContextFact[]>>;
  /**
   * Replaces the review's threat set. Threat ids must be unique (a duplicate is a `conflict` and nothing is written).
   * Never leaves a partial set: a failure part-way leaves the old set (possibly plus some of the new one), so a retry
   * or a later assembly completes it.
   */
  saveThreats(reviewId: string, threats: Threat[], discarded: DiscardedThreat[]): Promise<Result<void>>;
  threats(reviewId: string): Promise<Result<Threat[]>>;
  discarded(reviewId: string): Promise<Result<DiscardedThreat[]>>;
  updateThreat(id: string, patch: Partial<Threat>): Promise<Result<void>>;
  /** Inserts run `n`; a number already taken is a `conflict` (never an overwrite), so the caller takes the next one. */
  saveSample(reviewId: string, n: number, sample: Sample): Promise<Result<void>>;
  samples(reviewId: string): Promise<Result<Sample[]>>;
  /** `at` is when the stage reached this status (defaults to now); the admin page reads it as the run's trace. */
  saveStage(reviewId: string, stage: string, status: 'running' | 'done' | 'failed', checkpoint?: unknown, error?: string, at?: string): Promise<Result<void>>;
  stage(reviewId: string, stage: string): Promise<Result<{ status: string; checkpoint?: unknown } | null>>;
  /** Newest first by createdAt, at most `limit` (capped at 500); with `since`, only reviews created at or after it. */
  recent(limit: number, since?: string): Promise<Result<Review[]>>;
  /** The review's stage trace in time order, without checkpoints. */
  stages(reviewId: string): Promise<Result<StageTrace[]>>;
}

export interface StageTrace {
  stage: string;
  status: string;
  error?: string;
  at: string;
}

export interface RequirementRepo {
  forIssue(issueId: string): Promise<Result<Requirement[]>>;
  get(id: string): Promise<Result<Requirement | null>>;
  upsert(r: Requirement): Promise<Result<void>>;
  /** Removes a requirement row nobody has started (used when its rule-based threat becomes covered). */
  remove(id: string): Promise<Result<void>>;
}

export type LedgerEventType =
  | 'acceptance.requested'
  | 'acceptance.approved'
  | 'acceptance.rejected'
  | 'acceptance.revoked'
  | 'acceptance.expired'
  | 'attestation.issued'
  | 'override.breakglass'
  | 'review.champion_confirmed'
  | 'budget.champion_confirmed'
  | 'policy.warn_only'
  | 'policy.changed'
  | 'requirement.verified'
  | 'requirement.status_changed'
  | 'requirement.status_change_failed'
  | 'project.purged'
  | 'reviews.resumed'
  | 'review.sample'
  | 'review.sample_rejected'
  | 'key.rotated'
  | 'suppression.created'
  | 'suppression.revoked'
  | 'suppression.expired'
  | 'suppression.unhidden';

export interface LedgerInsert {
  seq: number;
  eventType: LedgerEventType;
  payload: Record<string, unknown>;
  actor: string;
  createdAt: string;
  prevHash: string;
  entryHash: string;
}
export type LedgerRow = LedgerInsert;

export interface LedgerRepo {
  head(): Promise<Result<{ seq: number; entryHash: string } | null>>;
  /** Must fail with `conflict` when prevHash (or seq) already exists, so concurrent appends cannot fork the chain. */
  append(e: LedgerInsert): Promise<Result<LedgerRow>>;
  range(fromSeq: number, toSeq: number): Promise<Result<LedgerRow[]>>;
  all(): Promise<Result<LedgerRow[]>>;
  /** Only rows of these event types, in seq order (indexed): what verdicts and the panel read on every refresh. */
  ofTypes(types: readonly LedgerEventType[]): Promise<Result<LedgerRow[]>>;
  /**
   * Scale: rows of these types for these work items (indexed on the payload's issueId), in seq order. Rows that name no
   * work item (entries from before the index, or events about no work item) are included too, so nothing is missed.
   */
  forIssues(types: readonly LedgerEventType[], issueIds: readonly string[]): Promise<Result<LedgerRow[]>>;
  /** Scale: the newest `limit` rows of these types, in seq order. */
  latestOfTypes(types: readonly LedgerEventType[], limit: number): Promise<Result<LedgerRow[]>>;
  /** Scale: rows of these types created at or after `sinceIso`, in seq order (indexed on type and time). */
  ofTypesSince(types: readonly LedgerEventType[], sinceIso: string): Promise<Result<LedgerRow[]>>;
  /**
   * Scale: one page of the Merkle leaves' inputs — seq and entry hash only, for seq > `afterSeq`, in seq order, at most
   * `limit` (capped at 5000). The tree head pages through these instead of reading every full entry.
   */
  entryHashes(afterSeq: number, limit: number): Promise<Result<Array<{ seq: number; entryHash: string }>>>;
}

export interface FeedbackRow {
  threatId: string;
  component: string;
  title: string;
  stride: Stride;
  actor: string;
  action: 'dismiss' | 'accept' | 'edit';
  reason?: DismissReason;
  note?: string;
  /** The work item and when (written from migration v7 on; older rows have none and feed no suppression suggestion). */
  issueId?: string;
  issueKey?: string;
  projectKey?: string;
  at?: string;
}
/** A dismissal with a reason, on a work item of a project: the evidence a suppression suggestion rests on. */
export type DismissalRow = Required<Pick<FeedbackRow, 'threatId' | 'component' | 'title' | 'stride' | 'actor' | 'reason' | 'issueId' | 'issueKey' | 'projectKey' | 'at'>>;
export interface FeedbackRepo {
  dismissedFor(component: string): Promise<Result<Array<{ title: string; stride: Stride; reason: DismissReason }>>>;
  record(f: FeedbackRow): Promise<Result<void>>;
  /** Dismissals with a reason recorded at or after `sinceIso` on a known work item, newest first, at most `limit` (capped at 2000). */
  dismissalsSince(sinceIso: string, limit: number): Promise<Result<DismissalRow[]>>;
}

export interface IssueRow {
  issueId: string;
  issueKey: string;
  projectKey: string;
  parentId?: string;
}
export interface IssueRepo {
  upsert(i: IssueRow): Promise<Result<void>>;
  get(issueId: string): Promise<Result<IssueRow | null>>;
  byKey(issueKey: string): Promise<Result<IssueRow | null>>;
  children(issueId: string): Promise<Result<IssueRow[]>>;
  linkPage(issueId: string, pageId: string): Promise<Result<void>>;
  issuesForPage(pageId: string): Promise<Result<string[]>>;
}

export interface AttestationRow {
  id: string;
  issueKey: string;
  repo: string;
  commitSha: string;
  kid: string;
  expiresAt: string;
  nonce: string;
}
export interface AttestationRepo {
  record(a: AttestationRow): Promise<Result<void>>;
  forIssue(issueKey: string): Promise<Result<AttestationRow[]>>;
}

/** R5: a signed head of the Merkle tree over the ledger's entry hashes (RFC 9162 style). */
export interface TreeHead {
  treeSize: number;
  rootHash: string;
  timestamp: string;
  kid: string;
  signature: string;
  /** The Confluence page it was published to, once it has been. */
  publishedPageId?: string;
}
export interface TreeHeadRepo {
  /** Fails with `conflict` when a head for this size already exists. */
  add(h: TreeHead): Promise<Result<void>>;
  latest(): Promise<Result<TreeHead | null>>;
  lastPublished(): Promise<Result<TreeHead | null>>;
  /** Newest (largest) first. */
  list(limit: number): Promise<Result<TreeHead[]>>;
  markPublished(treeSize: number, pageId: string): Promise<Result<void>>;
}

export interface UsageRepo {
  add(month: string, delta: { tokensIn: number; tokensOut: number; reviews: number }): Promise<Result<void>>;
  get(month: string): Promise<Result<{ tokensIn: number; tokensOut: number; reviews: number }>>;
  /**
   * Security: atomically takes one of `limit` slots in `bucket` for `window` (a different window starts again at zero)
   * and returns how many are used now, or null when none is left. Parallel callers can never together exceed `limit`.
   */
  takeSlot(bucket: string, window: string, limit: number): Promise<Result<number | null>>;
  /** Atomically counts one review for the month only while the count stays within `cap`; false when it would not. */
  reserveReview(month: string, cap: number): Promise<Result<boolean>>;
}

export interface VerdictSink {
  write(issueId: string, v: Verdict & Record<string, unknown>): Promise<Result<void>>;
}

export interface PublicKeyInfo {
  active: { kid: string; publicKey: string };
  /** Still trusted until retireAt (the grace period after a rotation). */
  previous?: { kid: string; publicKey: string; retireAt: string };
}

export interface SigningKeyStore {
  active(): Promise<Result<KeyPair>>;
  publicKeys(): Promise<Result<Record<string, string>>>;
  rotate(): Promise<Result<KeyPair>>;
  /** Active and in-grace previous public keys (creates the first key pair if there is none). */
  describe(): Promise<Result<PublicKeyInfo>>;
}

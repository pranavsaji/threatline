import { count } from '@threatline/core';
import { headlineOf, verdictWords } from '@threatline/shared/verdict-words';
import { SEVERITIES, severityRank, type ContextFact, type Requirement, type Review, type Severity, type Threat, type Verdict } from '@threatline/shared';
import type { AdfDoc, AdfNode } from '../adapters/jira.js';
import { log } from '../adapters/log.js';
import type { CoreDeps } from '../deps.js';
import { postComment } from './notify.js';
import { readVerdict } from './verdict-service.js';
import { citesOnlyTheWorkItem } from './viewer-scope.js';

/**
 * The verdict comment (docs/ENGINE.md, "When a review settles"): one plain comment on the work item, as Threatline,
 * when a review revision reaches its final state. It answers where people already look, without opening the panel.
 *
 * - Once per revision: the `comment` stage is claimed (insert-only) before posting, so a redelivered or concurrent job
 *   never posts twice.
 * - A re-run comments only when the verdict (state, or break-glass) or the blocking count changed from the revision
 *   Threatline last commented on.
 * - No leaks: everyone who can see the work item can read the comment, so it names a threat only when every source the
 *   threat cites is the work item's own (citesOnlyTheWorkItem, as for sub-task titles). Anything else is counted, never
 *   named. AI-written text is named only when no source in the review looked like instructions to an AI.
 * - Site policy `postReviewComments: false` turns it off. A failure is logged and never fails the review.
 */
export const COMMENT_STAGE = 'comment';
/** What Threatline last commented on for a work item: a re-run whose verdict says the same thing stays quiet. */
export const lastCommentKey = (issueId: string) => `comment:last:${issueId}`;

interface LastComment {
  reviewId: string;
  revision: number;
  state: string;
  blockingCount: number;
}

const LIVE: ReadonlySet<Threat['state']> = new Set(['accepted', 'needs_human', 'proposed']);
const OPEN: ReadonlySet<Requirement['status']> = new Set(['Open', 'InProgress']);
const MAX_TEXT = 200;
const MAX_REASONS = 3;
/** A line starting with this is a list item (consecutive ones become one bullet list in the comment). */
export const BULLET = '• ';

/** Model and page text as one short line of plain text (the comment is ADF text nodes: no markup, links or mentions). */
const oneLine = (s: string) => {
  const t = s.replace(/[\u0000-\u001f\u007f\u2028\u2029]+/g, ' ').replace(/\s+/g, ' ').trim();
  return t.length > MAX_TEXT ? `${t.slice(0, MAX_TEXT - 1).trimEnd()}…` : t;
};

/** The verdict a re-run is compared on: break-glass counts as its own state. */
const stateOf = (v: Pick<Verdict, 'state' | 'overridden'>) => (v.state === 'pass' && v.overridden ? 'overridden' : v.state);

export interface CommentInput {
  issueId: string;
  review: Pick<Review, 'status' | 'failureReason' | 'modelIds'>;
  verdict: Pick<Verdict, 'state' | 'reasons' | 'overridden' | 'blockingCount'> & { inheritedFrom?: readonly string[] };
  threats: readonly Threat[];
  facts: readonly ContextFact[];
  requirements: readonly Requirement[];
}

/**
 * Whether the comment may name this threat. Its every citation must be a source everyone who can see the work item can
 * read. Rule-based threats are Threatline's fixed wording; an AI threat's words came from a model that read the whole
 * bundle, so it is named only once it is accepted (a champion or the vote and quote checks) and nothing in the review
 * looked like instructions to the AI (attacker text must never be posted by Threatline).
 */
function nameable(t: Threat, i: CommentInput): boolean {
  if (!LIVE.has(t.state) || !citesOnlyTheWorkItem(t, i.facts, i.issueId)) return false;
  if (t.origin === 'baseline') return true;
  return t.state === 'accepted' && !i.facts.some((f) => f.injectionSuspected);
}

const bySeverity = (a: Threat, b: Threat) => severityRank(b.severity) - severityRank(a.severity) || b.votes - a.votes || a.title.localeCompare(b.title);

/** The comment's paragraphs, first one the verdict. Pure, so the wording and the leak rule are testable on their own. */
export function verdictCommentLines(i: CommentInput): string[] {
  const words = verdictWords(i.verdict);
  const lines = [`Threatline security review: ${words.icon} ${words.label}`];
  // What stands in the way, as the panel's header says it: the headline, then the first three reasons. A reason
  // inherited from a parent names that parent, which not everyone here may be able to open, so it is not repeated.
  const shown = i.verdict.reasons.slice(0, MAX_REASONS);
  const headline = headlineOf(i.verdict, { listed: shown.length > 0 });
  if (headline) lines.push(headline);
  for (const reason of shown) {
    const inherited = (i.verdict.inheritedFrom ?? []).some((k) => reason.message.startsWith(`${k}: `));
    lines.push(`${BULLET}${inherited ? 'A parent work item blocks this too: see the Threatline panel there.' : oneLine(reason.message)}`);
  }

  // A review that did not finish says so in its reasons; the way out is a re-run (a paused one: a champion, per its reason).
  const r = i.review;
  if ((r.status === 'failed' && r.failureReason !== 'budget') || r.status === 'agent_timeout') lines.push('Done and merge stay blocked until the review runs again: re-run it from the Threatline panel.');

  const live = i.threats.filter((t) => LIVE.has(t.state)).sort(bySeverity);
  if (r.status === 'ready' || live.length > 0) {
    const by = new Map<Severity, number>();
    for (const t of live) by.set(t.severity, (by.get(t.severity) ?? 0) + 1);
    const parts = [...SEVERITIES].reverse().flatMap((s) => (by.get(s) ? [`${by.get(s)} ${s}`] : []));
    lines.push(live.length === 0 ? 'No threats found.' : `${count(live.length, 'threat')}: ${parts.join(', ')}.`);
  }
  if (live.length > 0) {
    // The most severe threat, named only when everyone here may read where it comes from; otherwise counted only.
    const top = live.filter((t) => t.severity === live[0]!.severity).find((t) => nameable(t, i));
    const text = top ? oneLine(top.plainLanguage || top.title) : '';
    lines.push(
      top && text
        ? `Top risk (${top.severity}): ${text}`
        : `The most severe threat (${live[0]!.severity}) cites sources that not everyone who can see this work item can open, so it is named only in the Threatline panel.`,
    );
  }

  const liveIds = new Set(live.map((t) => t.id));
  const reqs = i.requirements.filter((q) => liveIds.has(q.threatId));
  const open = reqs.filter((q) => OPEN.has(q.status));
  if (reqs.length > 0) {
    const untasked = open.filter((q) => !q.subtaskKey).length;
    const head = `${count(reqs.length, 'security requirement')}${open.length < reqs.length ? ` (${open.length} open)` : ''}.`;
    lines.push(untasked > 0 ? `${head} ${untasked === 1 ? 'It' : 'Each'} can become a task in one click: Threatline panel → Requirements → Create sub-tasks.` : head);
  }
  if (r.modelIds.includes('threatline-rules')) lines.push("From Threatline's rule-based checks: AI review is off on this site.");
  lines.push('Evidence, requirements and next steps are in the Threatline panel on this work item.');
  return lines;
}

/** The lines as an ADF comment: the verdict line bold, a paragraph per line, and the reasons as one bullet list. */
export function verdictCommentDoc(lines: readonly string[]): AdfDoc {
  const para = (text: string, bold = false): AdfNode => ({ type: 'paragraph', content: [{ type: 'text', text, ...(bold ? { marks: [{ type: 'strong' }] } : {}) }] });
  const content: AdfNode[] = [];
  lines.forEach((l, n) => {
    if (!l.startsWith(BULLET)) return void content.push(para(l, n === 0));
    const item: AdfNode = { type: 'listItem', content: [para(l.slice(BULLET.length))] };
    const last = content.at(-1);
    if (last?.type === 'bulletList') last.content!.push(item);
    else content.push({ type: 'bulletList', content: [item] });
  });
  return { type: 'doc', version: 1, content };
}

/** Final: ready (for Threatline Engine, once its verifier has run or failed), failed, or timed out. */
async function isFinal(deps: Pick<CoreDeps, 'reviews'>, review: Review): Promise<boolean> {
  if (review.status === 'failed' || review.status === 'agent_timeout') return true;
  if (review.status !== 'ready') return false;
  // An engine review (its marker stage, or an extract checkpoint from before the marker) settles after verification.
  const [marker, extract, verify] = await Promise.all([deps.reviews.stage(review.id, 'engine'), deps.reviews.stage(review.id, 'extract'), deps.reviews.stage(review.id, 'verify')]);
  const engine = (marker.ok && !!marker.value) || (extract.ok && !!extract.value);
  if (!engine) return true;
  return verify.ok && (verify.value?.status === 'done' || verify.value?.status === 'failed');
}

type Outcome = 'off' | 'not_final' | 'superseded' | 'already' | 'unchanged' | 'no_verdict' | 'posted' | 'failed';

async function settle(deps: CoreDeps, reviewId: string): Promise<Outcome> {
  const policy = await deps.config.site();
  if (!policy.ok) return 'failed';
  if (policy.value.postReviewComments === false) return 'off';
  const got = await deps.reviews.get(reviewId);
  if (!got.ok || !got.value) return 'failed';
  const review = got.value;
  if (!(await isFinal(deps, review))) return 'not_final';
  const latest = await deps.reviews.latest(review.issueId);
  if (!latest.ok) return 'failed';
  if (latest.value && latest.value.id !== review.id) return 'superseded';
  const done = await deps.reviews.stage(review.id, COMMENT_STAGE);
  if (!done.ok) return 'failed';
  if (done.value) return 'already';
  const read = await readVerdict(deps, review.issueId);
  const verdict = read.ok ? read.value : undefined;
  if (!verdict || typeof verdict !== 'object' || (verdict.reviewId && verdict.reviewId !== review.id)) return 'no_verdict';
  const key = { state: stateOf(verdict), blockingCount: verdict.blockingCount };
  const last = await deps.state.get<LastComment>(lastCommentKey(review.issueId)).catch(() => undefined);
  const unchanged = !!last && typeof last === 'object' && last.revision < review.revision && last.state === key.state && last.blockingCount === key.blockingCount;

  // Claimed before posting: only the job that inserts the stage posts.
  const at = deps.clock.now().toISOString();
  const claim = await deps.reviews.claimStage(review.id, COMMENT_STAGE, unchanged ? 'done' : 'running', unchanged ? { skipped: 'unchanged', since: last!.revision } : undefined, at);
  if (!claim.ok) return 'failed';
  if (!claim.value) return 'already';
  if (unchanged) return 'unchanged';

  const [threats, facts, requirements] = await Promise.all([deps.reviews.threats(review.id), deps.reviews.facts(review.id), deps.requirements.forIssue(review.issueId)]);
  if (!threats.ok || !facts.ok || !requirements.ok) {
    await deps.reviews.saveStage(review.id, COMMENT_STAGE, 'failed', undefined, 'unreadable', at);
    return 'failed';
  }
  const lines = verdictCommentLines({ issueId: review.issueId, review, verdict, threats: threats.value, facts: facts.value, requirements: requirements.value });
  const posted = await postComment(deps, review.issueId, verdictCommentDoc(lines));
  // Not retried: a failed post leaves the stage failed (visible under Recent runs), never a second comment later.
  await deps.reviews.saveStage(review.id, COMMENT_STAGE, posted ? 'done' : 'failed', posted ? { state: key.state, blockingCount: key.blockingCount } : undefined, posted ? undefined : 'comment_failed', at);
  if (!posted) return 'failed';
  try {
    await deps.state.set<LastComment>(lastCommentKey(review.issueId), { reviewId: review.id, revision: review.revision, ...key });
  } catch {
    log('comment.last_unsaved', { reviewId: review.id });
  }
  return 'posted';
}

/**
 * Called wherever a review may have just settled (gather for rules-only and paused reviews, assembly, the verifier, the
 * sweeper). Does nothing until the review is final. Never throws and never fails the caller.
 */
export async function commentOnSettle(deps: CoreDeps, reviewId: string): Promise<void> {
  try {
    const outcome = await settle(deps, reviewId);
    if (outcome === 'posted' || outcome === 'unchanged' || outcome === 'failed' || outcome === 'no_verdict') log('review.comment', { reviewId, outcome });
  } catch (e) {
    log('review.comment', { reviewId, outcome: 'threw', message: e instanceof Error ? e.message.slice(0, 120) : 'unknown' });
  }
}

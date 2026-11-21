import { InvocationError, InvocationErrorCode } from '@forge/events';
import { getReviewContext } from './actions/get-review-context.js';
import { submitThreatModel } from './actions/submit-threat-model.js';
import { withCaller } from './actions/common.js';
import { getMergeAttestation } from './actions/get-merge-attestation.js';
import { getReview } from './actions/get-review.js';
import { getSecurityRequirements } from './actions/get-security-requirements.js';
import { checkChangeRisk } from './actions/check-change-risk.js';
import { requestRiskAcceptance } from './actions/request-risk-acceptance.js';
import { verifyRequirement } from './actions/verify-requirement.js';
import { explainThreat } from './actions/explain-threat.js';
import { getReleaseReadiness } from './actions/release-readiness.js';
import { startReview } from './actions/start-review.js';
import { getPostureSummary } from './actions/posture-summary.js';
import { composeCore, type ForgeContext } from './composition.js';
import { reviewConsumer } from './consumers/review-consumer.js';
import { daily } from './jobs/daily.js';
import { hourly } from './jobs/hourly.js';
import { sweep } from './jobs/sweeper.js';
import { onInstallJobs } from './triggers/on-install.js';
import { onIssueChange } from './triggers/on-issue-change.js';
import { onPageChange } from './triggers/on-page-change.js';
import { validateTransition } from './validators/validate-transition.js';
import { ciVerify, type WebTriggerRequestLike } from './webtriggers/ci-verify.js';

/** Forge entry points for triggers, the job queue and scheduled jobs. Each builds its dependencies per invocation. */
export async function issueEventHandler(event: unknown, ctx: ForgeContext): Promise<void> {
  await onIssueChange(composeCore(ctx), event);
}

export async function pageEventHandler(event: unknown, ctx: ForgeContext): Promise<void> {
  await onPageChange(composeCore(ctx), event);
}

export async function lifecycleHandler(_event: unknown, ctx: ForgeContext): Promise<void> {
  await composeCore(ctx).queue.push(onInstallJobs());
}

export async function jobConsumerHandler(event: { body?: unknown; retryContext?: { retryCount?: number } }, ctx: ForgeContext): Promise<InvocationError | void> {
  const r = await reviewConsumer(event, composeCore(ctx));
  // Transient platform failures (Jira/KVS/SQL briefly unavailable, e.g. just after install) are retried a few times.
  if (!r.ok && (r.error.code === 'upstream' || r.error.code === 'timeout') && (event.retryContext?.retryCount ?? 0) < 3)
    return new InvocationError({ retryAfter: 60, retryReason: InvocationErrorCode.FUNCTION_RETRY_REQUEST });
}

/** jira:workflowValidator `threatline-gate`: reads the verdict from app storage (never the user-editable property). */
export const validateTransitionHandler = async (args: { issue?: { key?: string; id?: string } }, ctx: ForgeContext) => validateTransition(composeCore(ctx), args);

/** webtrigger `ci-verify`: CI reports passing tests; authenticated by a per-site CI token, never by a user. */
export const ciVerifyHandler = async (request: WebTriggerRequestLike, ctx: ForgeContext) => ciVerify(composeCore(ctx), request);

export const sweeperHandler = async (_e: unknown, ctx: ForgeContext) => sweep(composeCore(ctx));
export const hourlyHandler = async (_e: unknown, ctx: ForgeContext) => hourly(composeCore(ctx));
export const dailyHandler = async (_e: unknown, ctx: ForgeContext) => daily(composeCore(ctx));

type ActionPayload = { context?: { cloudId?: unknown; accountId?: unknown } } & Record<string, unknown>;
/** Forge's invocation context names the calling user; MCP calls carry the caller only here. */
type Principal = { principal?: { accountId?: unknown } };
const actionCtx = (payload: ActionPayload, ctx?: ForgeContext): ForgeContext => ({
  ...(ctx ?? {}),
  ...(typeof payload.context?.cloudId === 'string' ? { cloudId: payload.context.cloudId } : {}),
});

/** Rovo actions (agent-invoked). Identity comes only from payload.context.accountId. */
export const getReviewContextHandler = async (payload: ActionPayload, ctx?: ForgeContext & Principal) => getReviewContext(withCaller(payload, ctx), composeCore(actionCtx(payload, ctx)));
export const submitThreatModelHandler = async (payload: ActionPayload, ctx?: ForgeContext & Principal) => submitThreatModel(withCaller(payload, ctx), composeCore(actionCtx(payload, ctx)));
export const getMergeAttestationHandler = async (payload: ActionPayload, ctx?: ForgeContext & Principal) => getMergeAttestation(withCaller(payload, ctx), composeCore(actionCtx(payload, ctx)));
export const getReviewHandler = async (payload: ActionPayload, ctx?: ForgeContext & Principal) => getReview(withCaller(payload, ctx), composeCore(actionCtx(payload, ctx)));
export const getSecurityRequirementsHandler = async (payload: ActionPayload, ctx?: ForgeContext & Principal) => getSecurityRequirements(withCaller(payload, ctx), composeCore(actionCtx(payload, ctx)));
export const checkChangeRiskHandler = async (payload: ActionPayload, ctx?: ForgeContext & Principal) => checkChangeRisk(withCaller(payload, ctx), composeCore(actionCtx(payload, ctx)));
export const requestRiskAcceptanceHandler = async (payload: ActionPayload, ctx?: ForgeContext & Principal) => requestRiskAcceptance(withCaller(payload, ctx), composeCore(actionCtx(payload, ctx)));
export const verifyRequirementHandler = async (payload: ActionPayload, ctx?: ForgeContext & Principal) => verifyRequirement(withCaller(payload, ctx), composeCore(actionCtx(payload, ctx)));
export const explainThreatHandler = async (payload: ActionPayload, ctx?: ForgeContext & Principal) => explainThreat(withCaller(payload, ctx), composeCore(actionCtx(payload, ctx)));
export const releaseReadinessHandler = async (payload: ActionPayload, ctx?: ForgeContext & Principal) => getReleaseReadiness(withCaller(payload, ctx), composeCore(actionCtx(payload, ctx)));
export const startReviewHandler = async (payload: ActionPayload, ctx?: ForgeContext & Principal) => startReview(withCaller(payload, ctx), composeCore(actionCtx(payload, ctx)));
export const postureSummaryHandler = async (payload: ActionPayload, ctx?: ForgeContext & Principal) => getPostureSummary(withCaller(payload, ctx), composeCore(actionCtx(payload, ctx)));

import { panelDelivery, panelDiff, panelEnrich, panelGet, panelRerun, panelStatus, panelThreats, panelWhatIf, threatExplain, type Viewer } from './panel.js';
import { requirementsCreate, requirementsSetStatus } from './requirements.js';
import { reviewConfirm, threatsTriage } from './threats.js';
import { confluencePublish } from './confluence.js';
import { adminGetPolicy, adminInstallGate, adminProjectStatuses, adminPurgeProject, adminResumeReviews, adminRuns, adminSeed, adminSetNotifications, adminSetPolicy, adminSetupStatus, adminUsage, adminWarnOnly, adminWarnOnlyEnd } from './admin.js';
import { adminChampionGroupStatus } from './setup-groups.js';
import { acceptanceDecide, acceptanceRequest, acceptanceRevoke, breakGlassOverride } from './acceptances.js';
import { ledgerExport, ledgerProof, ledgerTreeHead, ledgerVerify } from './ledger.js';
import { postureDrill, postureGet, releaseReport } from './posture.js';
import { complianceExport, postureControlDrill, postureControls } from './compliance.js';
import { attestationCheck, attestationCopy, keysCopied, keysPublic, keysRotate } from './attestations.js';
import { inboxDecide, inboxList } from './inbox.js';
import { suppressionsCreate, suppressionsList, suppressionsRevoke, suppressionsUnhide } from './suppressions.js';
import { ciCreateToken, ciRevokeToken, ciTokens } from './ci.js';
import type { CoreDeps } from '../deps.js';

type Enricher = Parameters<typeof panelEnrich>[2];
type DeliverySource = Parameters<typeof panelDelivery>[2];

/** Who is calling and from which work item: taken from the Forge context, never from the payload. */
export type ResolverViewer = Viewer & { cloudId: string };
export type ResolverFn = (deps: CoreDeps, v: ResolverViewer, payload: Record<string, unknown>) => Promise<unknown>;

/**
 * Every Custom UI resolver, by key. Forge registers this table (resolvers/index.ts); the local end-to-end harness
 * (e2e/local) serves the same table over in-memory deps, so the journeys exercise exactly these functions.
 */
export function resolverTable(env: { enricher: () => Enricher; delivery?: () => DeliverySource; signingKeysReady: () => Promise<boolean>; gateExtensionKey?: () => string | null; ciTriggerUrl?: () => Promise<string> }): Record<string, ResolverFn> {
  return {
    'panel.get': (deps, v) => panelGet(deps, v),
    'panel.status': (deps, v) => panelStatus(deps, v),
    'panel.threats': (deps, v, payload) => panelThreats(deps, v, payload as { cursor?: unknown }),
    'panel.rerun': (deps, v) => panelRerun(deps, v),
    'panel.enrich': (deps, v) => panelEnrich(deps, v, env.enricher()),
    'panel.delivery': (deps, v) =>
      panelDelivery(deps, v, env.delivery?.() ?? { links: async () => ({ pullRequests: [], deployments: [], partial: true, reasons: ['graph_not_configured'] }) }),
    'panel.diff': (deps, v, payload) => panelDiff(deps, v, payload),
    'panel.whatIf': (deps, v, payload) => panelWhatIf(deps, v, payload),
    'threat.explain': (deps, v, payload) => threatExplain(deps, v, payload as { reviewId?: unknown; threatId?: unknown }),
    'requirements.create': (deps, v, payload) => requirementsCreate(deps, v, payload),
    'requirements.setStatus': (deps, v, payload) => requirementsSetStatus(deps, v, payload),
    'threats.triage': (deps, v, payload) => threatsTriage(deps, v, payload),
    'review.confirm': (deps, v, payload) => reviewConfirm(deps, v, payload),
    'confluence.publish': (deps, v, payload) => confluencePublish(deps, v, payload),
    'admin.seed': (deps, v, payload) => adminSeed(deps, { accountId: v.accountId }, payload),
    'admin.setupStatus': (deps, v) => adminSetupStatus(deps, { accountId: v.accountId }, { signingKeys: env.signingKeysReady }),
    'admin.championGroupStatus': (deps, v) => adminChampionGroupStatus(deps, { accountId: v.accountId }),
    'admin.getPolicy': (deps, v) => adminGetPolicy(deps, { accountId: v.accountId }),
    'admin.setPolicy': (deps, v, payload) => adminSetPolicy(deps, { accountId: v.accountId }, payload),
    'admin.warnOnly': (deps, v, payload) => adminWarnOnly(deps, { accountId: v.accountId }, payload),
    'admin.warnOnlyEnd': (deps, v, payload) => adminWarnOnlyEnd(deps, { accountId: v.accountId }, payload),
    'admin.purgeProject': (deps, v, payload) => adminPurgeProject(deps, { accountId: v.accountId }, payload),
    'admin.resumeReviews': (deps, v, payload) => adminResumeReviews(deps, { accountId: v.accountId }, payload),
    'admin.runs': (deps, v) => adminRuns(deps, { accountId: v.accountId }),
    'admin.usage': (deps, v) => adminUsage(deps, { accountId: v.accountId }),
    'admin.setNotifications': (deps, v, payload) => adminSetNotifications(deps, { accountId: v.accountId }, payload),
    'admin.installGate': (deps, v) => adminInstallGate(deps, { accountId: v.accountId }, env.gateExtensionKey?.() ?? null),
    'admin.projectStatuses': (deps, v, payload) => adminProjectStatuses(deps, { accountId: v.accountId }, payload),
    'posture.get': (deps, v, payload) => postureGet(deps, { accountId: v.accountId }, payload as { project?: unknown; team?: unknown }),
    'posture.drill': (deps, v, payload) => postureDrill(deps, { accountId: v.accountId }, payload as Record<string, unknown>),
    'release.report': (deps, v, payload) => releaseReport(deps, { accountId: v.accountId }, payload as { fixVersion?: unknown }),
    'acceptance.request': (deps, v, payload) => acceptanceRequest(deps, v, payload),
    'acceptance.decide': (deps, v, payload) => acceptanceDecide(deps, v, payload),
    'acceptance.revoke': (deps, v, payload) => acceptanceRevoke(deps, v, payload),
    'override.breakglass': (deps, v, payload) => breakGlassOverride(deps, v, payload),
    'ledger.verify': (deps, v) => ledgerVerify(deps, { accountId: v.accountId }),
    'ledger.export': (deps, v, payload) => ledgerExport(deps, { accountId: v.accountId }, payload),
    'compliance.export': (deps, v, payload) => complianceExport(deps, { accountId: v.accountId }, payload),
    'posture.controls': (deps, v, payload) => postureControls(deps, { accountId: v.accountId }, payload as { project?: unknown }),
    'posture.controlDrill': (deps, v, payload) => postureControlDrill(deps, { accountId: v.accountId }, payload),
    'ledger.proof': (deps, v, payload) => ledgerProof(deps, { accountId: v.accountId }, payload),
    'ledger.treeHead': (deps, v) => ledgerTreeHead(deps, { accountId: v.accountId }),
    'attestation.copy': (deps, v, payload) => attestationCopy(deps, v, payload),
    'attestation.check': (deps, v, payload) => attestationCheck(deps, v, payload),
    'keys.public': (deps, v) => keysPublic(deps, { accountId: v.accountId }),
    'keys.rotate': (deps, v) => keysRotate(deps, { accountId: v.accountId }),
    'keys.copied': (deps, v) => keysCopied(deps, { accountId: v.accountId }),
    'inbox.list': (deps, v, payload) => inboxList(deps, { accountId: v.accountId }, payload),
    'inbox.decide': (deps, v, payload) => inboxDecide(deps, { accountId: v.accountId }, payload),
    'suppressions.list': (deps, v) => suppressionsList(deps, { accountId: v.accountId }),
    'suppressions.create': (deps, v, payload) => suppressionsCreate(deps, { accountId: v.accountId }, payload),
    'suppressions.revoke': (deps, v, payload) => suppressionsRevoke(deps, { accountId: v.accountId }, payload),
    'suppressions.unhide': (deps, v, payload) => suppressionsUnhide(deps, v, payload),
    'ci.tokens': (deps, v) => ciTokens(deps, { accountId: v.accountId }, { triggerUrl: env.ciTriggerUrl ?? (async () => Promise.reject(new Error('no web trigger here'))) }),
    'ci.createToken': (deps, v, payload) => ciCreateToken(deps, { accountId: v.accountId }, payload),
    'ci.revokeToken': (deps, v, payload) => ciRevokeToken(deps, { accountId: v.accountId }, payload),
  };
}

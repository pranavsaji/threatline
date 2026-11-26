import { z } from 'zod';

const issueId = z.string().regex(/^\d{1,18}$/);

/** Why an incident re-review exists (trusted Jira metadata only: never the incident's text). */
export const IncidentCauseSchema = z
  .object({
    id: issueId,
    key: z.string().regex(/^[A-Z][A-Z0-9_]{0,254}-\d{1,18}$/),
    /** The incident's components this work item shares. */
    components: z.array(z.string().max(255)).max(10),
    /** The incident is linked to this work item. */
    linked: z.boolean(),
    at: z.string().max(40),
  })
  .strict();
export type IncidentCause = z.infer<typeof IncidentCauseSchema>;

export const ReviewJobSchema = z.discriminatedUnion('kind', [
  z
    .object({
      kind: z.literal('gather'),
      issueId,
      reason: z.enum(['created', 'updated', 'page_changed', 'rerun', 'install', 'incident']),
      /** Who caused it; scopes what the gatherer may read (see GatherOptions). */
      actorAccountId: z.string().max(128).optional(),
      /** reason `incident`: the incident that reopened this review (docs/INCIDENTS.md). */
      incident: IncidentCauseSchema.optional(),
    })
    .strict(),
  /** An incident appeared: re-review the open reviewed work on its components or linked to it (never queued by a re-run). */
  z.object({ kind: z.literal('incident'), issueId, actorAccountId: z.string().max(128).optional() }).strict(),
  z.object({ kind: z.literal('assemble'), reviewId: z.string().min(1).max(64) }).strict(),
  /** Recompute verdicts for children (inheritance). */
  z.object({ kind: z.literal('propagate'), issueId }).strict(),
  /** Recompute one work item's verdict (used for non-reviewed issue types under a reviewed parent). */
  z.object({ kind: z.literal('verdict'), issueId }).strict(),
  z.object({ kind: z.literal('publish'), issueId }).strict(),
  z.object({ kind: z.literal('migrate') }).strict(),
  /** Threatline Engine: one stage of a review Threatline runs itself on Forge LLMs (each stage is its own job and timeout). */
  z
    .object({ kind: z.literal('engine'), reviewId: z.string().min(1).max(64), stage: z.enum(['extract', 'propose', 'verify']), n: z.number().int().min(0).max(4).optional() })
    .strict(),
  /** Fix check (docs/FIX_CHECK.md): judge the stored change of this commit against the work item's requirements. */
  z.object({ kind: z.literal('fix_check'), issueId, commitSha: z.string().regex(/^[0-9a-f]{40}$/) }).strict(),
]);
export type ReviewJob = z.infer<typeof ReviewJobSchema>;

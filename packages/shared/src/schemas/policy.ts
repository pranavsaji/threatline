import { z } from 'zod';
import { SeveritySchema } from './enums.js';

/**
 * Incidents reopen reviews (docs/INCIDENTS.md): a work item is an incident when it has one of `labels` (exact) or its
 * work type is one of `issueTypes` (any case). When one appears on a component, the open reviewed work on that
 * component (or linked to it) is re-reviewed with it as context, at most `maxItems` per incident.
 */
export const IncidentPolicySchema = z
  .object({
    enabled: z.boolean(),
    labels: z.array(z.string().regex(/^\S{1,255}$/, 'A Jira label has no spaces.')).max(10),
    issueTypes: z.array(z.string().trim().min(1).max(255)).max(10),
    maxItems: z.number().int().min(1).max(50),
    /** Comment on the incident listing the work items re-reviewed (plain text; never repeats the incident's text). */
    comment: z.boolean(),
  })
  .strict()
  .refine((p) => !p.enabled || p.labels.length + p.issueTypes.length > 0, { message: 'Name at least one incident label or work type.', path: ['labels'] });
export type IncidentPolicy = z.infer<typeof IncidentPolicySchema>;

export const SitePolicySchema = z
  .object({
    blockAtOrAbove: SeveritySchema,
    guardedTransitions: z.array(z.string()),
    enabledProjects: z.array(z.string()),
    reviewIssueTypes: z.array(z.string()).min(1),
    techLeadGroup: z.string(),
    championGroup: z.string(),
    maxExpiryDays: z.object({ Critical: z.number().int().min(1).max(30), default: z.number().int().min(1).max(90) }).strict(),
    techLeadMaxSeverity: SeveritySchema,
    agentSamples: z.union([z.literal(1), z.literal(3), z.literal(5)]),
    agentTimeoutMinutes: z.number().int().min(1).max(120),
    /**
     * `engine` (default for new sites): Threatline Engine runs the review itself on Forge LLMs (quarantined extract, independent
     * proposals, adversarial verifier), with no Rovo or Automation setup. `agent`: reviews wait for the Threatline Rovo agent's runs. `rules_only`: an admin's explicit choice for
     * sites without Rovo; every review settles at once from Threatline's rule-based checks and says so.
     */
    reviewMode: z.enum(['engine', 'agent', 'rules_only']).optional(),
    /**
     * Who may submit AI review runs (Atlassian account IDs, normally the owner of the Automation rule that runs the
     * Threatline agent). Empty or absent: anyone who can edit the work item, which lets a developer fill their own review.
     */
    reviewAuthors: z.array(z.string().trim().min(1).max(128)).max(10).optional(),
    warnOnly: z.array(z.object({ projectKey: z.string(), since: z.string(), until: z.string() }).strict()),
    attestationTtlHours: z.number().int().min(1).max(168),
    sensitivePaths: z.array(z.string()),
    budget: z
      .object({
        tokensInPerReview: z.number().int().min(1),
        tokensOutPerReview: z.number().int().min(1),
        reviewsPerMonth: z.number().int().min(1),
      })
      .strict(),
    /** Absent on sites saved before it existed: read it with incidentPolicyOf (defaults). */
    incidents: IncidentPolicySchema.optional(),
  })
  .strict();
export type SitePolicy = z.infer<typeof SitePolicySchema>;

export const RepoPolicySchema = z
  .object({
    sensitivePaths: z.array(z.string()).default([]),
    mode: z.enum(['warn', 'block']).default('block'),
    diffScoreThreshold: z.number().min(0).max(100).default(40),
  })
  .strict();
export type RepoPolicy = z.infer<typeof RepoPolicySchema>;

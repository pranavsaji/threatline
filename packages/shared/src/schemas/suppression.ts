import { z } from 'zod';
import { StrideSchema } from './enums.js';

/** A rule lasts at most this long; the default is the maximum. Re-approval means creating it again. */
export const SUPPRESSION_MAX_DAYS = 90;

/**
 * `pending`: written but its creation is not in the ledger yet, so it never applies. `active` until `expiresAt`, then
 * `expired` (by the hourly job; an active rule past its expiry never applies either). `revoked` by a champion or admin.
 */
export const SuppressionStatusSchema = z.enum(['pending', 'active', 'expired', 'revoked']);
export type SuppressionStatus = z.infer<typeof SuppressionStatusSchema>;

/**
 * Team learning: a project's champion hides one kind of below-threshold threat in new reviews of that project. It
 * matches a threat of the same STRIDE category whose title is similar to `title` (the anchor), and, when `component`
 * is set, whose component matches too.
 */
export const SuppressionRuleSchema = z
  .object({
    id: z.string().min(1).max(40),
    projectKey: z.string().min(1).max(40),
    stride: StrideSchema,
    title: z.string().min(1).max(200),
    component: z.string().min(1).max(200).optional(),
    reason: z.string().min(1).max(300),
    createdBy: z.string().min(1).max(128),
    createdAt: z.string().max(30),
    expiresAt: z.string().max(30),
    status: SuppressionStatusSchema,
    /** Work items whose dismissals suggested this rule (issue keys, at most 10). */
    evidence: z.array(z.string().max(40)).max(10),
    endedBy: z.string().max(128).optional(),
    endedAt: z.string().max(30).optional(),
    endReason: z.string().max(300).optional(),
  })
  .strict();
export type SuppressionRule = z.infer<typeof SuppressionRuleSchema>;

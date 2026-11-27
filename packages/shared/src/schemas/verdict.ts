import { z } from 'zod';
import { SeveritySchema } from './enums.js';

export const BlockReasonCodeSchema = z.enum([
  'no_review',
  'review_failed',
  'agent_missing',
  'review_stale',
  'budget_paused',
  'open_requirement',
  'needs_human',
  'injection_unconfirmed',
  'fix_check_pending',
  'fix_unconfirmed',
]);
export type BlockReasonCode = z.infer<typeof BlockReasonCodeSchema>;

export const BlockReasonSchema = z
  .object({
    code: BlockReasonCodeSchema,
    message: z.string(),
    requirementIds: z.array(z.string()).optional(),
    action: z.object({ label: z.string(), href: z.string() }).strict().optional(),
  })
  .strict();
export type BlockReason = z.infer<typeof BlockReasonSchema>;

export const VerdictSchema = z
  .object({
    state: z.enum(['pass', 'block', 'warn']),
    reviewId: z.string().optional(),
    revision: z.number().int().optional(),
    blockingCount: z.number().int().min(0),
    maxOpenSeverity: SeveritySchema.nullable(),
    reasons: z.array(BlockReasonSchema),
    inheritedFrom: z.array(z.string()),
    overridden: z.boolean().optional(),
    /** Set for warn-only and break-glass verdicts: when the leniency ends. Attestations never outlive it. */
    validUntil: z.string().optional(),
    updatedAt: z.string(),
  })
  .strict();
export type Verdict = z.infer<typeof VerdictSchema>;

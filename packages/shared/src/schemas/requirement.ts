import { z } from 'zod';
import { RequirementStatusSchema, SeveritySchema } from './enums.js';

export const CriterionSchema = z.object({ given: z.string(), when: z.string(), then: z.string() }).strict();
export type Criterion = z.infer<typeof CriterionSchema>;

export const EvidenceSchema = z
  .object({
    /** `ci`: tests named for the requirement passed in a CI run (ref is the run's https link). Only the CI web trigger sets it. */
    kind: z.enum(['pr', 'test', 'confluence', 'manual', 'ci']),
    /** The link or path itself (kept clean so the panel can open it). */
    ref: z.string().min(1).max(2000),
    /** Free text about the evidence (e.g. the test that covers it), shown beside the link. */
    note: z.string().max(500).optional(),
    /** CI evidence: the commit the tests ran on, and the repository (owner/repository or workspace/repository). */
    commitSha: z.string().regex(/^[0-9a-f]{40}$/).optional(),
    repo: z.string().min(1).max(201).optional(),
    attester: z.string().min(1),
  })
  .strict();
export type Evidence = z.infer<typeof EvidenceSchema>;

export const RequirementSchema = z
  .object({
    id: z.string().min(1),
    threatId: z.string().min(1),
    issueId: z.string().min(1),
    issueKey: z.string().min(1),
    subtaskKey: z.string().optional(),
    title: z.string().min(1).max(255),
    criteria: z.array(CriterionSchema).min(1),
    asvsIds: z.array(z.string()),
    severity: SeveritySchema,
    status: RequirementStatusSchema,
    ownerAccountId: z.string().optional(),
    verifiedBy: z.string().optional(),
    evidence: EvidenceSchema.optional(),
    fileHints: z.array(z.string()).optional(),
    /** When Threatline first created the requirement, and when it was last marked Verified (mean time to verify, PR-1). */
    createdAt: z.string().datetime({ offset: true }).optional(),
    verifiedAt: z.string().datetime({ offset: true }).optional(),
  })
  .strict();
export type Requirement = z.infer<typeof RequirementSchema>;

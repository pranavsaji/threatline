import { z } from 'zod';
import { DismissReasonSchema, FrameworkSchema, SeveritySchema, StrideSchema, ThreatStateSchema } from './enums.js';

const score = z.number().int().min(1).max(5);

export const CitationSchema = z.object({ factId: z.string().min(1), quote: z.string().max(400) }).strict();
export type Citation = z.infer<typeof CitationSchema>;

export const MappingSchema = z.object({ framework: FrameworkSchema, refId: z.string().min(1) }).strict();
export type Mapping = z.infer<typeof MappingSchema>;

export const GroundingSchema = z.enum(['supported', 'weak', 'unsupported']);
export type Grounding = z.infer<typeof GroundingSchema>;

export const ThreatSchema = z
  .object({
    id: z.string().min(1),
    reviewId: z.string().min(1),
    stride: StrideSchema,
    title: z.string().min(1).max(200),
    scenario: z.string().max(1200),
    component: z.string().max(200),
    likelihood: score,
    impact: score,
    severity: SeveritySchema,
    votes: z.number().int().min(0),
    samples: z.number().int().min(0),
    grounding: GroundingSchema,
    confidence: z.number().min(0).max(1),
    state: ThreatStateSchema,
    dismissReason: DismissReasonSchema.optional(),
    /** Threatline Engine's verifier on an AI threat: whether the quoted evidence supports it, and why (stage 4). */
    verification: z
      .object({
        keep: z.boolean(),
        reason: z.string().max(300),
        /** A doubted threat sent to a champion that the verifier said repeats this other threat (same review). */
        duplicateOf: z.string().min(1).max(120).optional(),
      })
      .strict()
      .optional(),
    /** For a `covered` rule-based threat: the id of the AI threat in the same review that covers it. */
    coveredBy: z.string().min(1).optional(),
    origin: z.enum(['baseline', 'agent', 'pipeline']),
    citations: z.array(CitationSchema).min(1),
    mappings: z.array(MappingSchema),
    plainLanguage: z.string().max(400),
    suggestedRequirement: z
      .object({ title: z.string().max(200), given: z.string().max(300), when: z.string().max(300), then: z.string().max(300) })
      .strict()
      .optional(),
  })
  .strict();
export type Threat = z.infer<typeof ThreatSchema>;

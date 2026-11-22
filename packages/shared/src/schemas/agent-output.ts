import { z } from 'zod';
import { DataClassSchema, ExposureSchema, StrideSchema } from './enums.js';
import { MAX_SKETCH_STRING } from './context.js';

const score = z.number().int().min(1).max(5);
const s = z.string().max(MAX_SKETCH_STRING);

export const ThreatRatingSchema = z
  .object({
    attacker: z.enum(['anyone', 'user', 'insider']),
    effort: z.enum(['low', 'medium', 'high']),
    reach: z.enum(['one', 'many', 'all']),
    harm: z.enum(['takeover', 'money', 'sensitive_data', 'integrity', 'personal_data', 'availability', 'minor']),
  })
  .strict();
export type ThreatRating = z.infer<typeof ThreatRatingSchema>;

export const AgentThreatSchema = z
  .object({
    stride: StrideSchema,
    title: z.string().min(1).max(120),
    scenario: z.string().max(600),
    component: z.string().max(80),
    likelihood: score,
    impact: score,
    evidence: z.array(z.object({ quote: z.string().min(1).max(200) }).strict()).min(1).max(3),
    asvs: z.array(z.string().max(20)).max(10).optional(),
    cwe: z.array(z.string().max(20)).max(10).optional(),
    plainLanguage: z.string().max(200).optional(),
    /** The facts severity is computed from (Threatline's table, not the model's own numbers). Absent: likelihood x impact. */
    rating: ThreatRatingSchema.optional(),
    requirement: z
      .object({ title: z.string().max(200), given: z.string().max(300), when: z.string().max(300), then: z.string().max(300) })
      .strict()
      .optional(),
  })
  .strict();
export type AgentThreat = z.infer<typeof AgentThreatSchema>;

export const AgentSketchSchema = z
  .object({
    components: z.array(s).max(30),
    dataStores: z.array(s).max(30),
    externalServices: z.array(s).max(30),
    trustBoundaries: z.array(s).max(30),
    dataClasses: z.array(DataClassSchema),
    exposure: ExposureSchema,
    llmFeatures: z.boolean(),
  })
  .strict()
  .partial();

export const AgentThreatModelSchema = z
  .object({
    // `redline.threatmodel.v1`: runs recorded before the rename to Threatline.
    schema: z.enum(['threatline.threatmodel.v1', 'redline.threatmodel.v1']),
    issueKey: z.string().min(1),
    sketch: AgentSketchSchema.optional(),
    threats: z.array(AgentThreatSchema).max(25),
  })
  .strict();
export type AgentThreatModel = z.infer<typeof AgentThreatModelSchema>;

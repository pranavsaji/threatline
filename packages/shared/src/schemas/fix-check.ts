import { z } from 'zod';

/**
 * What the fix check concluded for one requirement (docs/FIX_CHECK.md). `unclear`: the model's claim could not be
 * checked against the change (no answer, or none of its quotes is an added line of code), so it counts as not shown.
 */
export const FixVerdictSchema = z.enum(['fixed', 'partial', 'not_addressed', 'unclear']);
export type FixVerdict = z.infer<typeof FixVerdictSchema>;

export const FixQuoteSchema = z.object({ path: z.string().min(1).max(500), line: z.number().int().min(1), text: z.string().min(1).max(300) }).strict();
export type FixQuote = z.infer<typeof FixQuoteSchema>;

export const FixFindingSchema = z
  .object({
    requirementId: z.string().min(1),
    verdict: FixVerdictSchema,
    reason: z.string().max(400),
    /** Added lines of the change, each checked by code to be in the diff at that path and line (±3). */
    quotes: z.array(FixQuoteSchema).max(5),
    missing: z.string().max(300).optional(),
    /** A suggested change (never applied by Threatline). */
    suggestion: z.object({ summary: z.string().max(200), code: z.string().max(3000) }).strict().optional(),
    /** Deterministic: added lines that carry this requirement's id (a test named for it). */
    testsNamed: z.number().int().min(0),
    /** Deterministic: the change touches a file the requirement's hints point to; null when it has no hints. */
    touchesHints: z.boolean().nullable(),
  })
  .strict();
export type FixFinding = z.infer<typeof FixFindingSchema>;

export const FixCheckRecordSchema = z
  .object({
    issueId: z.string().min(1),
    issueKey: z.string().min(1),
    repo: z.string().min(1).max(201),
    commitSha: z.string().regex(/^[0-9a-f]{40}$/),
    /** The pull request the change is (https), when CI named one. */
    prUrl: z.string().max(2000).optional(),
    runUrl: z.string().max(2000),
    status: z.enum(['pending', 'done', 'failed']),
    failure: z.string().max(300).optional(),
    requestedAt: z.string(),
    finishedAt: z.string().optional(),
    /** The CI token that sent the change. */
    by: z.string().max(128),
    model: z.string().max(200).optional(),
    promptVersion: z.string().max(40).optional(),
    /** The change carries text that reads like instructions to an AI: every finding goes to a champion. */
    injectionSuspected: z.boolean().optional(),
    files: z.number().int().min(0),
    /** Changed files left out of what the model saw (generated, binary, or over the size budget). */
    omittedFiles: z.number().int().min(0),
    findings: z.array(FixFindingSchema).max(40),
    /** A security champion confirmed these requirements are fixed by this commit despite the check. */
    confirmations: z.array(z.object({ requirementId: z.string().min(1), by: z.string().min(1).max(128), at: z.string() }).strict()).max(40),
  })
  .strict();
export type FixCheckRecord = z.infer<typeof FixCheckRecordSchema>;

import { z } from 'zod';

export const SEVERITIES = ['Low', 'Medium', 'High', 'Critical'] as const;
export const SeveritySchema = z.enum(SEVERITIES);
export type Severity = z.infer<typeof SeveritySchema>;
export const severityRank = (s: Severity): number => SEVERITIES.indexOf(s);

export const STRIDE = [
  'Spoofing',
  'Tampering',
  'Repudiation',
  'InformationDisclosure',
  'DenialOfService',
  'ElevationOfPrivilege',
] as const;
export const StrideSchema = z.enum(STRIDE);
export type Stride = z.infer<typeof StrideSchema>;

export const TrustLevelSchema = z.enum(['trusted', 'untrusted']);
export type TrustLevel = z.infer<typeof TrustLevelSchema>;

export const SourceTypeSchema = z.enum([
  'jira_issue',
  'jira_comment',
  'confluence_page',
  'pull_request',
  'commit',
  'incident',
  'team',
  'component',
  'review',
]);
export type SourceType = z.infer<typeof SourceTypeSchema>;

export const DataClassSchema = z.enum(['pii', 'credentials', 'payment', 'health', 'secrets']);
export type DataClass = z.infer<typeof DataClassSchema>;

export const ExposureSchema = z.enum(['internal', 'partner', 'public']);
export type Exposure = z.infer<typeof ExposureSchema>;

/**
 * `covered`: a generic rule-based threat that a trusted, more specific AI threat (`coveredBy`) already covers. It does
 * not count and has no requirement of its own; it becomes `accepted` again if that AI threat is dismissed.
 * `suppressed`: a below-threshold threat hidden by a project's team suppression rule (`suppression.ruleId`). Like
 * `covered`, it does not count and has no requirement; a champion can unhide it on one work item.
 */
export const ThreatStateSchema = z.enum(['proposed', 'accepted', 'dismissed', 'needs_human', 'covered', 'suppressed']);
export type ThreatState = z.infer<typeof ThreatStateSchema>;

/** `unconfirmed`: a gap-check candidate the verifier has not kept (yet); it never counted and has no requirement. */
export const DismissReasonSchema = z.enum(['false_positive', 'not_applicable', 'duplicate', 'already_mitigated', 'unconfirmed']);
export type DismissReason = z.infer<typeof DismissReasonSchema>;

export const RequirementStatusSchema = z.enum(['Open', 'InProgress', 'Verified', 'AcceptedRisk', 'NotApplicable']);
export type RequirementStatus = z.infer<typeof RequirementStatusSchema>;

export const ReviewStatusSchema = z.enum([
  'queued',
  'gathering',
  'awaiting_agent',
  'modeling',
  'ready',
  'failed',
  'agent_timeout',
]);
export type ReviewStatus = z.infer<typeof ReviewStatusSchema>;

export const FrameworkSchema = z.enum(['ASVS5', 'CWE', 'LLM10', 'ASI10']);
export type Framework = z.infer<typeof FrameworkSchema>;

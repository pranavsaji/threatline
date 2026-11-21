import { COMPLIANCE_DISCLAIMER, COMPLIANCE_FRAMEWORKS, complianceCatalogue, controlsForAsvsIds, type ComplianceFramework, type ControlRef } from '@threatline/frameworks';
import type { Acceptance, AcceptanceState, Evidence, Requirement, RequirementStatus, Severity } from '@threatline/shared';

/**
 * Compliance evidence (indicative, not an audit opinion): which SOC 2, ISO/IEC 27001:2022 and PCI DSS v4.0 controls a
 * requirement's ASVS 5.0 ids map to, and per control the requirements, their status, the latest evidence and the risk
 * acceptances. Pure; the mapping lives in @threatline/frameworks (docs/COMPLIANCE.md).
 */

const DAY = 86_400_000;
const MAX_EVIDENCE = 5;
const BASIS = 'indicative, not an audit opinion';

/** RFC 4180 cell, with spreadsheet formula injection neutralised (a leading = + - @ tab or CR gets a ' prefix). */
export function csvCell(value: string): string {
  const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

export const requirementControls = (r: Pick<Requirement, 'asvsIds'>): ControlRef[] => controlsForAsvsIds(r.asvsIds);

/** "SOC2 CC6.1; ISO27001 A.8.5": a requirement's controls in one cell. */
export const controlsCell = (refs: readonly ControlRef[]): string => refs.map((c) => `${c.framework} ${c.id}`).join('; ');

/** Red while any requirement is open; amber when none is open but some risk is accepted; green otherwise. */
export type ControlState = 'open' | 'accepted' | 'verified';
export interface ControlCounts {
  open: number;
  verified: number;
  acceptedRisk: number;
  notApplicable: number;
}
export interface ControlSummaryRow {
  id: string;
  title: string;
  state: ControlState;
  counts: ControlCounts;
  requirements: Array<{ id: string; issueKey: string; subtaskKey?: string; title: string; severity: Severity; status: RequirementStatus }>;
  /** Newest first, at most five. */
  evidence: Array<{ requirementId: string; issueKey: string; kind: Evidence['kind']; ref: string; verifiedAt?: string }>;
  acceptances: Array<{ acceptanceId: string; requirementId: string; issueKey: string; state: AcceptanceState; severity: Severity; expiresAt: string; approvedBy?: string }>;
}
export interface ControlsSummary {
  disclaimer: string;
  frameworks: Array<{ framework: ComplianceFramework; name: string; version: string; source: string; controls: ControlSummaryRow[] }>;
  /** Requirements in the range (created on or before its end). */
  requirementsCounted: number;
  /** Of those, how many map to no control (no ASVS id, or an id outside the mapping). */
  unmapped: number;
}

export interface ControlsSummaryInput {
  requirements: readonly Requirement[];
  acceptances: readonly Acceptance[];
  /** UTC dates (YYYY-MM-DD), inclusive. Left out: no bound. */
  from?: string;
  to?: string;
}

const bucket = (s: RequirementStatus): keyof ControlCounts => (s === 'Verified' ? 'verified' : s === 'AcceptedRisk' ? 'acceptedRisk' : s === 'NotApplicable' ? 'notApplicable' : 'open');
const stateOf = (c: ControlCounts): ControlState => (c.open > 0 ? 'open' : c.acceptedRisk > 0 ? 'accepted' : 'verified');
const at = (iso: string | undefined): number => (iso ? Date.parse(iso) : NaN);

/**
 * Per framework and control: the requirements that map to it, counted by status (as of now), the latest evidence
 * verified in the range, and the acceptances whose lifetime overlaps the range. A requirement counts when it was
 * created on or before the range's end (one with no creation time always counts); controls with no requirement are left
 * out.
 */
export function controlsSummary(input: ControlsSummaryInput): ControlsSummary {
  const start = input.from ? at(`${input.from}T00:00:00.000Z`) : -Infinity;
  const end = input.to ? at(`${input.to}T00:00:00.000Z`) + DAY : Infinity;
  const inRange = (t: number) => t >= start && t < end;
  const requirements = input.requirements.filter((r) => !(at(r.createdAt) >= end));
  const byRequirement = new Map<string, Requirement>(requirements.map((r) => [r.id, r]));
  const acceptancesOf = new Map<string, Acceptance[]>();
  for (const a of input.acceptances) {
    if (!byRequirement.has(a.requirementId) || at(a.createdAt) >= end || at(a.expiresAt) < start) continue;
    acceptancesOf.set(a.requirementId, [...(acceptancesOf.get(a.requirementId) ?? []), a]);
  }

  const rows = new Map<string, { ref: ControlRef; reqs: Requirement[] }>();
  let unmapped = 0;
  for (const r of requirements) {
    const refs = requirementControls(r);
    if (refs.length === 0) unmapped++;
    for (const ref of refs) {
      const key = `${ref.framework} ${ref.id}`;
      const row = rows.get(key) ?? { ref, reqs: [] };
      row.reqs.push(r);
      rows.set(key, row);
    }
  }

  const toRow = ({ ref, reqs }: { ref: ControlRef; reqs: Requirement[] }): ControlSummaryRow => {
    const counts: ControlCounts = { open: 0, verified: 0, acceptedRisk: 0, notApplicable: 0 };
    for (const r of reqs) counts[bucket(r.status)]++;
    const evidence = reqs
      .filter((r): r is Requirement & { evidence: Evidence } => r.evidence !== undefined && (r.verifiedAt === undefined || inRange(at(r.verifiedAt))))
      .sort((a, b) => (b.verifiedAt ?? '').localeCompare(a.verifiedAt ?? ''))
      .slice(0, MAX_EVIDENCE)
      .map((r) => ({ requirementId: r.id, issueKey: r.issueKey, kind: r.evidence.kind, ref: r.evidence.ref, ...(r.verifiedAt ? { verifiedAt: r.verifiedAt } : {}) }));
    const acceptances = reqs
      .flatMap((r) => acceptancesOf.get(r.id) ?? [])
      .sort((a, b) => a.expiresAt.localeCompare(b.expiresAt))
      .map((a) => ({ acceptanceId: a.id, requirementId: a.requirementId, issueKey: byRequirement.get(a.requirementId)!.issueKey, state: a.state, severity: a.severity, expiresAt: a.expiresAt, ...(a.approvedBy ? { approvedBy: a.approvedBy } : {}) }));
    return {
      id: ref.id,
      title: ref.title,
      state: stateOf(counts),
      counts,
      requirements: reqs.map((r) => ({ id: r.id, issueKey: r.issueKey, ...(r.subtaskKey ? { subtaskKey: r.subtaskKey } : {}), title: r.title, severity: r.severity, status: r.status })),
      evidence,
      acceptances,
    };
  };

  const all = [...rows.values()];
  return {
    disclaimer: COMPLIANCE_DISCLAIMER,
    frameworks: COMPLIANCE_FRAMEWORKS.map((fw) => {
      const c = complianceCatalogue(fw);
      return { framework: fw, name: c.name, version: c.version, source: c.source, controls: all.filter((x) => x.ref.framework === fw).sort((a, b) => a.ref.id.localeCompare(b.ref.id, 'en', { numeric: true })).map(toRow) };
    }),
    requirementsCounted: requirements.length,
    unmapped,
  };
}

const CSV_COLUMNS = ['framework', 'control_id', 'control_title', 'state', 'open', 'verified', 'accepted_risk', 'not_applicable', 'requirements', 'latest_evidence', 'acceptances', 'basis'] as const;

/** The controls summary as CSV: one row per framework and control. */
export function controlsSummaryCsv(s: ControlsSummary): string {
  const lines: string[] = [CSV_COLUMNS.join(',')];
  for (const f of s.frameworks)
    for (const c of f.controls)
      lines.push(
        [
          f.framework,
          c.id,
          c.title,
          c.state,
          String(c.counts.open),
          String(c.counts.verified),
          String(c.counts.acceptedRisk),
          String(c.counts.notApplicable),
          c.requirements.map((r) => `${r.id} (${r.issueKey}${r.subtaskKey ? `, sub-task ${r.subtaskKey}` : ''}) ${r.status}`).join('; '),
          c.evidence.map((e) => `${e.issueKey} ${e.kind} ${e.ref}${e.verifiedAt ? ` ${e.verifiedAt.slice(0, 10)}` : ''}`).join('; '),
          c.acceptances.map((a) => `${a.acceptanceId} (${a.issueKey}) ${a.state} expires ${a.expiresAt.slice(0, 10)}`).join('; '),
          BASIS,
        ]
          .map(csvCell)
          .join(','),
      );
  return `${lines.join('\n')}\n`;
}

/** The dashboard's view: counts and colour per control, and how many work items are behind it; no requirement text. */
export interface ControlsPosture {
  disclaimer: string;
  frameworks: Array<{ framework: ComplianceFramework; name: string; version: string; controls: Array<{ id: string; title: string; state: ControlState; counts: ControlCounts; issues: number }> }>;
}
export function controlsPosture(s: ControlsSummary): ControlsPosture {
  return {
    disclaimer: s.disclaimer,
    frameworks: s.frameworks.map((f) => ({
      framework: f.framework,
      name: f.name,
      version: f.version,
      controls: f.controls.map((c) => ({ id: c.id, title: c.title, state: c.state, counts: { ...c.counts }, issues: new Set(c.requirements.map((r) => r.issueKey)).size })),
    })),
  };
}

/** The requirements that map to one control. */
export function requirementsForControl<R extends Pick<Requirement, 'asvsIds'>>(requirements: readonly R[], framework: ComplianceFramework, id: string): R[] {
  return requirements.filter((r) => requirementControls(r).some((c) => c.framework === framework && c.id === id));
}

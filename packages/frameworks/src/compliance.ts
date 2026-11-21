import data from '../data/compliance-controls.json' with { type: 'json' };

/**
 * An indicative mapping from OWASP ASVS 5.0 chapters and sections to SOC 2 (2017 TSC), ISO/IEC 27001:2022 Annex A and
 * PCI DSS v4.0 controls. A requirement maps through its ASVS ids: its chapter's controls plus any its section adds.
 * It says where a requirement's evidence may help an auditor; it is not an audit opinion and does not mean a control is
 * met. Sources and limits: docs/COMPLIANCE.md.
 */
export const COMPLIANCE_FRAMEWORKS = ['SOC2', 'ISO27001', 'PCIDSS'] as const;
export type ComplianceFramework = (typeof COMPLIANCE_FRAMEWORKS)[number];

export const COMPLIANCE_DISCLAIMER: string = data.note;

/** What each framework's control identifiers look like (SOC 2 criteria, ISO 27001:2022 Annex A, PCI DSS sub-requirements). */
export const CONTROL_ID_FORMAT: Readonly<Record<ComplianceFramework, RegExp>> = {
  SOC2: /^(?:CC[1-9]|A1|C1|PI1|P[1-8])\.[1-9]\d?$/,
  ISO27001: /^A\.(?:5\.(?:[1-9]|[12]\d|3[0-7])|6\.[1-8]|7\.(?:[1-9]|1[0-4])|8\.(?:[1-9]|[12]\d|3[0-4]))$/,
  PCIDSS: /^(?:[1-9]|1[0-2])\.[1-9]\d?\.[1-9]\d?$/,
};

export interface ControlRef {
  framework: ComplianceFramework;
  id: string;
  title: string;
}
export interface ComplianceCatalogue {
  framework: ComplianceFramework;
  name: string;
  version: string;
  source: string;
  titleNote: string;
  controls: ReadonlyArray<{ id: string; title: string }>;
}
type MappingEntry = Partial<Record<ComplianceFramework, readonly string[]>>;

const natural = (a: string, b: string) => a.localeCompare(b, 'en', { numeric: true });
const order = (a: ControlRef, b: ControlRef) => COMPLIANCE_FRAMEWORKS.indexOf(a.framework) - COMPLIANCE_FRAMEWORKS.indexOf(b.framework) || natural(a.id, b.id);

const CATALOGUES = new Map<ComplianceFramework, ComplianceCatalogue>(
  COMPLIANCE_FRAMEWORKS.map((fw) => {
    const f = data.frameworks[fw];
    const controls = Object.entries(f.controls as Record<string, string>).map(([id, title]) => ({ id, title }));
    return [fw, { framework: fw, name: f.name, version: f.version, source: f.source, titleNote: f.titleNote, controls: controls.sort((a, b) => natural(a.id, b.id)) }];
  }),
);
const TITLES = new Map<string, string>(COMPLIANCE_FRAMEWORKS.flatMap((fw) => CATALOGUES.get(fw)!.controls.map((c) => [`${fw} ${c.id}`, c.title] as const)));
const CHAPTERS = data.chapters as Record<string, MappingEntry>;
const SECTIONS = data.sections as Record<string, MappingEntry>;

export const complianceCatalogue = (fw: ComplianceFramework): ComplianceCatalogue => CATALOGUES.get(fw)!;
export function complianceControl(fw: ComplianceFramework, id: string): ControlRef | undefined {
  const title = TITLES.get(`${fw} ${id}`);
  return title === undefined ? undefined : { framework: fw, id, title };
}
/** The raw mapping, for tests and docs. */
export const complianceMapping = (): { note: string; chapters: Readonly<Record<string, MappingEntry>>; sections: Readonly<Record<string, MappingEntry>> } => ({
  note: data.note,
  chapters: CHAPTERS,
  sections: SECTIONS,
});

const ASVS_ID = /^(V\d{1,2})\.(\d{1,2})\.\d{1,2}$/;

function collect(asvsId: string, into: Map<string, ControlRef>): void {
  const m = ASVS_ID.exec(asvsId);
  if (!m) return;
  for (const entry of [CHAPTERS[m[1]!], SECTIONS[`${m[1]}.${m[2]}`]])
    for (const fw of COMPLIANCE_FRAMEWORKS)
      for (const id of entry?.[fw] ?? []) {
        const ref = complianceControl(fw, id);
        if (ref) into.set(`${fw} ${id}`, ref);
      }
}

/** The controls one ASVS 5.0 requirement id maps to (indicative), by framework then control id. */
export function controlsForAsvs(asvsId: string): ControlRef[] {
  return controlsForAsvsIds([asvsId]);
}

/** The union of the controls several ASVS ids map to, de-duplicated, by framework then control id. */
export function controlsForAsvsIds(asvsIds: readonly string[]): ControlRef[] {
  const found = new Map<string, ControlRef>();
  for (const id of asvsIds) collect(id, found);
  return [...found.values()].sort(order);
}

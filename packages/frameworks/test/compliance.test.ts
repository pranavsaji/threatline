import { describe, expect, it } from 'vitest';
import {
  allAsvs,
  COMPLIANCE_DISCLAIMER,
  COMPLIANCE_FRAMEWORKS,
  CONTROL_ID_FORMAT,
  complianceCatalogue,
  complianceControl,
  complianceMapping,
  controlsForAsvs,
  controlsForAsvsIds,
} from '../src/index.js';

const chapterOf = (asvsId: string) => /^(V\d+)\./.exec(asvsId)![1]!;
const chapters = [...new Set(allAsvs().map((r) => chapterOf(r.id)))];
const sections = new Set(allAsvs().map((r) => /^(V\d+\.\d+)\./.exec(r.id)![1]!));

describe('compliance mapping (indicative)', () => {
  it('covers all 17 ASVS 5.0 chapters', () => {
    expect(chapters).toHaveLength(17);
    expect(Object.keys(complianceMapping().chapters).sort()).toEqual([...chapters].sort());
  });

  it.each(COMPLIANCE_FRAMEWORKS)('every ASVS chapter maps to at least one %s control', (fw) => {
    for (const ch of chapters) expect(complianceMapping().chapters[ch]?.[fw]?.length ?? 0, `${ch} → ${fw}`).toBeGreaterThan(0);
  });

  it.each(COMPLIANCE_FRAMEWORKS)('every %s control id matches the framework format and has a title', (fw) => {
    const controls = complianceCatalogue(fw).controls;
    expect(controls.length).toBeGreaterThan(0);
    for (const c of controls) {
      expect(c.id, c.id).toMatch(CONTROL_ID_FORMAT[fw]);
      expect(c.title.trim().length, c.id).toBeGreaterThan(3);
    }
  });

  it('the formats reject look-alikes', () => {
    expect('CC6.1').toMatch(CONTROL_ID_FORMAT.SOC2);
    expect('C1.1').toMatch(CONTROL_ID_FORMAT.SOC2);
    expect('CC10.1').not.toMatch(CONTROL_ID_FORMAT.SOC2);
    expect('A.8.28').toMatch(CONTROL_ID_FORMAT.ISO27001);
    expect('A.8.35').not.toMatch(CONTROL_ID_FORMAT.ISO27001);
    expect('A.9.4.2').not.toMatch(CONTROL_ID_FORMAT.ISO27001); // ISO 27001:2013 numbering
    expect('6.2.4').toMatch(CONTROL_ID_FORMAT.PCIDSS);
    expect('13.1.1').not.toMatch(CONTROL_ID_FORMAT.PCIDSS);
    expect('6.2').not.toMatch(CONTROL_ID_FORMAT.PCIDSS);
  });

  it('every mapped control exists in its catalogue, and every catalogue control is used', () => {
    const { chapters: byChapter, sections: bySection } = complianceMapping();
    const used = new Set<string>();
    for (const entry of [...Object.values(byChapter), ...Object.values(bySection)])
      for (const fw of COMPLIANCE_FRAMEWORKS)
        for (const id of entry[fw] ?? []) {
          expect(complianceControl(fw, id), `${fw} ${id}`).toBeDefined();
          used.add(`${fw} ${id}`);
        }
    for (const fw of COMPLIANCE_FRAMEWORKS) for (const c of complianceCatalogue(fw).controls) expect(used.has(`${fw} ${c.id}`), `${fw} ${c.id} unused`).toBe(true);
  });

  it('every section override names a real ASVS 5.0 section', () => {
    for (const s of Object.keys(complianceMapping().sections)) expect(sections.has(s), s).toBe(true);
  });

  it('every catalogue names its version and a public source', () => {
    for (const fw of COMPLIANCE_FRAMEWORKS) {
      const c = complianceCatalogue(fw);
      expect(c.name.length).toBeGreaterThan(3);
      expect(c.version.length).toBeGreaterThan(0);
      expect(c.source).toMatch(/^https:\/\//);
    }
  });

  it('a requirement id gets its chapter controls plus its section controls, in framework order', () => {
    const refs = controlsForAsvs('V6.2.1');
    expect(refs.map((r) => r.framework)).toEqual([...refs.map((r) => r.framework)].sort((a, b) => COMPLIANCE_FRAMEWORKS.indexOf(a) - COMPLIANCE_FRAMEWORKS.indexOf(b)));
    const ids = refs.map((r) => `${r.framework} ${r.id}`);
    expect(ids).toEqual(expect.arrayContaining(['SOC2 CC6.1', 'ISO27001 A.8.5', 'ISO27001 A.5.17', 'PCIDSS 8.3.1', 'PCIDSS 8.3.6']));
    // V6.3 does not carry the password-length control of V6.2.
    expect(controlsForAsvs('V6.3.1').map((r) => r.id)).not.toContain('8.3.6');
    for (const r of refs) expect(r.title).toBe(complianceControl(r.framework, r.id)!.title);
  });

  it('unknown or malformed ids map to nothing; several ids are de-duplicated and sorted', () => {
    expect(controlsForAsvs('V99.1.1')).toEqual([]);
    expect(controlsForAsvs('nonsense')).toEqual([]);
    const many = controlsForAsvsIds(['V6.2.1', 'V6.2.2', 'V8.2.1']);
    const keys = many.map((r) => `${r.framework} ${r.id}`);
    expect(new Set(keys).size).toBe(keys.length);
    expect(keys).toContain('PCIDSS 7.2.1');
    expect(controlsForAsvsIds([])).toEqual([]);
    // Natural order inside a framework: A.8.5 before A.8.24, 8.3.1 before 8.3.10.
    const iso = many.filter((r) => r.framework === 'ISO27001').map((r) => r.id);
    expect(iso).toEqual([...iso].sort((a, b) => a.localeCompare(b, 'en', { numeric: true })));
  });

  it('says it is indicative, not an audit opinion', () => {
    expect(COMPLIANCE_DISCLAIMER).toMatch(/indicative/i);
    expect(COMPLIANCE_DISCLAIMER).toMatch(/not an audit opinion/i);
    expect(complianceMapping().note).toBe(COMPLIANCE_DISCLAIMER);
  });
});

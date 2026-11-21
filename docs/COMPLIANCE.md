# Compliance evidence

**Indicative, not an audit opinion.** Threatline maps each security requirement to the compliance controls its
evidence may help with. A mapped control does not mean the control is met, designed well or operating effectively;
only your auditor can say that.

## What it maps

Every requirement carries OWASP ASVS 5.0 requirement ids. Threatline maps each ASVS **chapter** (V1 to V17), plus
a few **sections** that add a more specific control, to:

| Framework | Identifiers used | Example |
| --- | --- | --- |
| SOC 2, 2017 Trust Services Criteria (revised points of focus, 2022) | Common Criteria `CC6.x`, `CC7.x`, `CC8.1`, plus `C1.1`, `PI1.2` | V6 Authentication → CC6.1 |
| ISO/IEC 27001:2022 Annex A | `A.5.x`, `A.8.x` | V11 Cryptography → A.8.24 Use of cryptography |
| PCI DSS v4.0 (numbering unchanged in v4.0.1) | sub-requirements `n.n.n` | V6.2 Password Security → 8.3.6 |

A requirement's controls are the union over its ASVS ids: the chapter's controls and its section's additions
(V6.2.1 gets V6's CC6.1, A.5.17, A.8.5 and 8.3.1, and V6.2's 8.3.2 and 8.3.6). CWE ids sit on the threat, not the
requirement, so they are not used.

The mapping is one data file, `packages/frameworks/data/compliance-controls.json`. Tests check that every ASVS chapter
maps to at least one control in each framework, that every id matches its framework's format (SOC 2 `CC6.1`,
ISO `A.8.28` within Annex A's numbering 5.1–5.37, 6.1–6.8, 7.1–7.14 and 8.1–8.34, PCI `6.2.4`), that every mapped id has a title, and that every section
named exists in ASVS 5.0 (`packages/frameworks/test/compliance.test.ts`).

## Where it shows

- **Issue panel:** each requirement card shows its control ids as small lozenges; hover for the framework and title.
- **Security posture → Controls (indicative):** per framework, each control with requirements behind it: red while
  any is open, amber when nothing is open but a risk is accepted, green when all are verified (or not applicable).
  Click a control for its work items. Only work items you can browse are counted, like the rest of the page, and no
  requirement text is shown.
- **Admin → Risk ledger:** the evidence pack gains a `controls` column (CSV) and field (JSON) on each entry about a
  requirement. It is looked up at export time and is not part of the hashed entry. The new **Controls summary**
  export (CSV and JSON) lists, for one project and date range, per framework and control: requirements by status
  (Open, Verified, Accepted risk, Not applicable), the latest five evidence links verified in the range, and risk
  acceptances whose lifetime overlaps the range, with expiry. Statuses are as of the export; requirements created
  after the range's end are left out; work items are those the exporting admin can browse (up to 200, flagged as
  `truncated`).

## Titles

ISO/IEC 27001:2022 titles are the Annex A control names. SOC 2 criteria and PCI DSS requirements have no official
short titles, so each title is a short summary of the criterion or the opening of the defined approach requirement.
Read the full text in the standard before relying on it.

## Sources

Control identifiers and titles were checked against these on 2026-11-21:

- AICPA, [2017 Trust Services Criteria (with revised points of focus, 2022)](https://www.aicpa-cima.com/resources/article/2017-trust-services-criteria-with-revised-points-of-focus-2022).
  Criterion wording cross-checked against public reproductions:
  [Open Security Architecture, SOC 2 TSC](https://opensecurityarchitecture.org/frameworks/soc2-tsc),
  [Cloudaware CC7.1](https://ce.prod.cloudaware.com/frameworks/soc-2/cc7/01/) and
  [CC8.1](https://ce.prod.cloudaware.com/frameworks/soc-2/cc8/01).
- ISO, [ISO/IEC 27001:2022](https://www.iso.org/standard/27001). Annex A control names cross-checked against
  [Advisera's Annex A list](https://advisera.com/iso27001/annex-a-controls/) and
  [Open Security Architecture, ISO 27001:2022](https://opensecurityarchitecture.org/frameworks/iso-27001-2022).
- PCI Security Standards Council, [document library](https://www.pcisecuritystandards.org/document_library/)
  (PCI DSS v4.0.1 Requirements and Testing Procedures). Requirement text cross-checked against
  [myctrl.tools, PCI DSS v4](https://myctrl.tools/frameworks/pci-dss-v4).
- OWASP, [ASVS 5.0.0](https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release) (the bundled
  `packages/frameworks/data/asvs-5.0.json`).

## Limits

- It is a judgement made once per ASVS chapter or section, not per requirement: a chapter-level control such as
  PCI DSS 6.2.4 applies to most of the application chapters.
- It covers application-level controls only. Most of SOC 2, ISO 27001 and PCI DSS (people, physical security, vendor
  management, network segmentation, incident response) is outside what a threat model can evidence.
- PCI DSS controls apply only where cardholder data is in scope; Threatline does not know your CDE.
- A green control means only that the requirements Threatline raised against it are verified. Controls nobody raised
  a requirement for are not listed, and that is not evidence they are met.

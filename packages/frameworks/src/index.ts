import type { Framework, Stride } from '@threatline/shared';
import asvsData from '../data/asvs-5.0.json' with { type: 'json' };
import cweData from '../data/cwe.json' with { type: 'json' };
import llmData from '../data/llm-top10-2025.json' with { type: 'json' };
import asiData from '../data/agentic-top10-2026.json' with { type: 'json' };

export interface AsvsReq {
  id: string;
  chapter: string;
  section: string;
  text: string;
  level: 1 | 2 | 3;
}
export interface FrameworkItem {
  id: string;
  title: string;
  summary: string;
  keywords: string[];
}

const ASVS = asvsData.requirements as AsvsReq[];
const ASVS_BY_ID = new Map(ASVS.map((r) => [r.id, r]));
const CWE = new Map(cweData.items.map((c) => [c.id, c]));
const LLM = llmData.items as FrameworkItem[];
const ASI = asiData.items as FrameworkItem[];

export const ASVS_SOURCE = asvsData.source;

export const allAsvs = (): readonly AsvsReq[] => ASVS;
export const getAsvs = (id: string): AsvsReq | undefined => ASVS_BY_ID.get(id);
export const cweById = (id: string): { id: string; title: string } | undefined => CWE.get(id);
export const llmTop10 = (): readonly FrameworkItem[] => LLM;
export const agenticTop10 = (): readonly FrameworkItem[] => ASI;

export function isValidRef(framework: Framework, id: string): boolean {
  switch (framework) {
    case 'ASVS5':
      return ASVS_BY_ID.has(id);
    case 'CWE':
      return CWE.has(id);
    case 'LLM10':
      return LLM.some((i) => i.id === id);
    case 'ASI10':
      return ASI.some((i) => i.id === id);
  }
}

/** Curated defaults per STRIDE category; every id is checked by tests. */
const STRIDE_DEFAULTS: Record<Stride, { asvs: string[]; cwe: string[] }> = {
  Spoofing: { asvs: ['V6.3.1', 'V6.2.1', 'V7.2.1', 'V9.1.1'], cwe: ['CWE-287', 'CWE-307', 'CWE-384'] },
  Tampering: { asvs: ['V2.2.1', 'V2.3.1', 'V1.2.1', 'V11.4.1'], cwe: ['CWE-20', 'CWE-345', 'CWE-89'] },
  Repudiation: { asvs: ['V16.3.1', 'V16.2.1', 'V16.4.1'], cwe: ['CWE-778', 'CWE-117'] },
  InformationDisclosure: { asvs: ['V8.2.1', 'V14.2.1', 'V8.3.1', 'V13.4.1'], cwe: ['CWE-200', 'CWE-359', 'CWE-639'] },
  DenialOfService: { asvs: ['V2.4.1', 'V4.3.1', 'V5.2.1'], cwe: ['CWE-400', 'CWE-770', 'CWE-799'] },
  ElevationOfPrivilege: { asvs: ['V8.2.1', 'V8.3.1', 'V8.4.1'], cwe: ['CWE-269', 'CWE-285', 'CWE-862'] },
};

export function strideDefaults(stride: Stride): { asvs: string[]; cwe: string[] } {
  const d = STRIDE_DEFAULTS[stride];
  return { asvs: [...d.asvs], cwe: [...d.cwe] };
}

const tokenize = (s: string): string[] => s.toLowerCase().match(/[a-z0-9]+/g) ?? [];

/** Ranks ASVS requirements by keyword overlap (stem prefix match, 5+ chars), ties broken by lower level then id order. */
export function asvsSearch(keywords: string[], limit: number): AsvsReq[] {
  const stems = keywords.flatMap(tokenize).map((k) => (k.length > 5 ? k.slice(0, 5) : k));
  if (stems.length === 0) return [];
  const scored = ASVS.map((r, idx) => {
    const words = tokenize(`${r.section} ${r.text}`);
    const score = stems.reduce((n, stem) => n + (words.some((w) => w.startsWith(stem)) ? 1 : 0), 0);
    return { r, idx, score };
  }).filter((x) => x.score > 0);
  scored.sort((a, b) => b.score - a.score || a.r.level - b.r.level || a.idx - b.idx);
  return scored.slice(0, limit).map((x) => x.r);
}

export * from './compliance.js';

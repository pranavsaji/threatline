import { appError, err, ok, severityRank, type Result, type Severity, type Stride } from '@threatline/shared';
import type { LlmPort } from '@threatline/core';
import type { CleanCase } from '../fixtures/cases.js';
import { retryNote } from './judge.js';

/**
 * Offline eval only, never in the product: a separate model call decides which reported threat, if any, finds each
 * must-find threat of a case. The keyword matcher (metrics.ts `matches`) misses threats worded differently ("find out
 * which email addresses have accounts" for "user enumeration"), so recall is reported both ways. Bump on any rubric
 * change; recordings carry it.
 */
export const MATCH_VERSION = 'match-v1';

export interface MatchItem {
  id: string;
  stride: Stride;
  severity: Severity;
  title: string;
  scenario: string;
}

export interface MatchVerdict {
  expected: string;
  reported: string | null;
  reason: string;
}

export function matchSystemPrompt(): string {
  return `You are a senior application security reviewer checking whether a threat model found the threats an expert expected.

For each expected threat (E1, E2, …), name the one reported threat (T1, T2, …) that describes the same attack: the same
weakness exploited to cause the same kind of harm to the same part of the design. Wording, STRIDE category and severity
may differ; judge the substance. A reported threat that only mentions the topic in passing, or describes a different
attack on the same component, does not count. Use each reported threat for at most one expected threat. If none fits,
answer null.

Reply with JSON only, no prose and no code fences:
{"matches":[{"expected":"E1","reported":"T3"|null,"reason":"<at most 20 words>"}]}
Give exactly one entry per expected threat.`;
}

const line = (t: MatchItem) => `- ${t.id} [${t.stride}, ${t.severity}] ${t.title}: ${t.scenario}`;

export function matchUserPrompt(c: Pick<CleanCase, 'summary' | 'design'>, expected: MatchItem[], reported: MatchItem[]): string {
  return `Feature: ${c.summary}

Design:
${c.design}

Expected threats:
${expected.map(line).join('\n')}

Reported threats:
${reported.length ? reported.map(line).join('\n') : '(none)'}`;
}

export function parseMatch(text: string, expectedIds: string[], reportedIds: string[]): Result<MatchVerdict[]> {
  const body = text.replace(/^\s*```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '');
  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch {
    return err(appError('schema', 'match reply is not JSON'));
  }
  const list = (raw as { matches?: unknown }).matches;
  if (!Array.isArray(list)) return err(appError('schema', 'match reply has no matches array'));
  const known = new Set(reportedIds);
  const byId = new Map<string, MatchVerdict>();
  const used = new Set<string>();
  for (const m of list as Array<Record<string, unknown>>) {
    const reported = m.reported === null || m.reported === undefined ? null : m.reported;
    if (typeof m.expected !== 'string' || byId.has(m.expected) || (reported !== null && (typeof reported !== 'string' || !known.has(reported)))) {
      return err(appError('schema', 'match entry is malformed, repeated or names an unknown threat'));
    }
    // A reported threat used twice keeps its first match; the later expected threat counts as not found.
    const r = reported !== null && !used.has(reported) ? reported : null;
    if (r) used.add(r);
    byId.set(m.expected, { expected: m.expected, reported: r, reason: typeof m.reason === 'string' ? m.reason : '' });
  }
  if (byId.size !== expectedIds.length || expectedIds.some((id) => !byId.has(id))) {
    return err(appError('schema', `match must give one entry per expected threat (${expectedIds.join(', ')})`));
  }
  return ok(expectedIds.map((id) => byId.get(id)!));
}

export async function matchCase(llm: LlmPort, c: CleanCase, reported: MatchItem[]): Promise<Result<MatchVerdict[]>> {
  const expected: MatchItem[] = c.expected.map((e, i) => ({ id: `E${i + 1}`, stride: e.stride, severity: e.severity, title: e.title, scenario: '' }));
  if (reported.length === 0) return ok(expected.map((e) => ({ expected: e.id, reported: null, reason: 'nothing reported' })));
  const user = matchUserPrompt(c, expected, reported);
  const parse = (text: string) => parseMatch(text, expected.map((e) => e.id), reported.map((t) => t.id));
  const r = await llm.complete({ system: matchSystemPrompt(), user, tier: 'balanced', maxOutputTokens: 2000, purpose: 'verify' });
  if (!r.ok) return err(r.error);
  const first = parse(r.value.text);
  if (first.ok || first.error.code !== 'schema') return first;
  const again = await llm.complete({ system: matchSystemPrompt(), user: `${user}\n\n${retryNote(first.error.message, expected.map((e) => e.id))}`, tier: 'balanced', maxOutputTokens: 2000, purpose: 'verify' });
  if (!again.ok) return first;
  return parse(again.value.text);
}

export interface MatchTotals {
  found: number;
  expected: number;
  highFound: number;
  highExpected: number;
  /** Matched threats whose reported severity is above, equal to or below the expected one. */
  severity: { higher: number; same: number; lower: number };
}

/** Adds one case's verdicts to running totals. */
export function addMatch(t: MatchTotals, c: CleanCase, verdicts: MatchVerdict[], reported: MatchItem[]): void {
  verdicts.forEach((v, i) => {
    const e = c.expected[i]!;
    const high = severityRank(e.severity) >= severityRank('High');
    t.expected++;
    if (high) t.highExpected++;
    if (!v.reported) return;
    t.found++;
    if (high) t.highFound++;
    const r = reported.find((x) => x.id === v.reported);
    if (!r) return;
    const d = severityRank(r.severity) - severityRank(e.severity);
    if (d > 0) t.severity.higher++;
    else if (d < 0) t.severity.lower++;
    else t.severity.same++;
  });
}

export const emptyTotals = (): MatchTotals => ({ found: 0, expected: 0, highFound: 0, highExpected: 0, severity: { higher: 0, same: 0, lower: 0 } });

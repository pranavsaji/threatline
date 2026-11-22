import { appError, err, ok, type Result, type Severity, type Stride } from '@threatline/shared';
import type { LlmPort } from '@threatline/core';

/**
 * Offline eval only, never in the product: a separate model call grades each reported threat that is not on a case's
 * short must-find list, so precision can be reported both strictly (against the list) and judged (list + extras the
 * judge rated valid). Bump on any rubric change; recordings carry it.
 */
export const JUDGE_VERSION = 'judge-v1';

export interface JudgeItem {
  id: string;
  stride: Stride;
  severity: Severity;
  title: string;
  scenario: string;
}

export interface JudgeVerdict {
  id: string;
  valid: boolean;
  reason: string;
}

export function judgeSystemPrompt(): string {
  return `You are a senior application security reviewer grading a threat list another reviewer wrote for one feature.

For each threat under "To grade", decide whether it is valid. It is valid only if all of these hold:
1. It follows from the design as written: a plausible attack on this feature, not on components, data or users the design does not mention.
2. It is specific: it names who attacks, what they do and what is harmed. Generic hygiene ("use HTTPS", "keep dependencies updated", "log everything", "validate input") is not valid unless the design makes it material to this feature.
3. It is not a duplicate: the same attack and harm as a threat under "Already counted", or as an earlier threat under "To grade", is invalid even if worded differently.

Severity labels and STRIDE categories may be imperfect; do not reject a threat for those alone.

Reply with JSON only, no prose and no code fences:
{"verdicts":[{"id":"<id>","valid":true|false,"reason":"<at most 20 words>"}]}
Give exactly one verdict per id under "To grade".`;
}

const line = (t: JudgeItem) => `- ${t.id} [${t.stride}, ${t.severity}] ${t.title}: ${t.scenario}`;

export function judgeUserPrompt(c: { summary: string; design: string }, counted: JudgeItem[], extras: JudgeItem[]): string {
  return `Feature: ${c.summary}

Design:
${c.design}

Already counted:
${counted.length ? counted.map(line).join('\n') : '(none)'}

To grade:
${extras.map(line).join('\n')}`;
}

export function parseJudge(text: string, ids: string[]): Result<JudgeVerdict[]> {
  const body = text.replace(/^\s*```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '');
  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch {
    return err(appError('schema', 'judge reply is not JSON'));
  }
  const list = (raw as { verdicts?: unknown }).verdicts;
  if (!Array.isArray(list)) return err(appError('schema', 'judge reply has no verdicts array'));
  const byId = new Map<string, JudgeVerdict>();
  for (const v of list as Array<Record<string, unknown>>) {
    if (typeof v.id !== 'string' || typeof v.valid !== 'boolean' || byId.has(v.id)) return err(appError('schema', 'judge verdict is malformed or repeated'));
    byId.set(v.id, { id: v.id, valid: v.valid, reason: typeof v.reason === 'string' ? v.reason : '' });
  }
  if (byId.size !== ids.length || ids.some((id) => !byId.has(id))) return err(appError('schema', `judge must give one verdict per id (${ids.join(', ')})`));
  return ok(ids.map((id) => byId.get(id)!));
}

export async function judgeExtras(llm: LlmPort, c: { summary: string; design: string }, counted: JudgeItem[], extras: JudgeItem[]): Promise<Result<JudgeVerdict[]>> {
  if (extras.length === 0) return ok([]);
  const ids = extras.map((x) => x.id);
  const user = judgeUserPrompt(c, counted, extras);
  const r = await llm.complete({ system: judgeSystemPrompt(), user, tier: 'balanced', maxOutputTokens: 2000, purpose: 'verify' });
  if (!r.ok) return err(r.error);
  const first = parseJudge(r.value.text, ids);
  if (first.ok || first.error.code !== 'schema') return first;
  // One retry naming what was wrong: a dropped or repeated id otherwise leaves the whole case unjudged.
  const again = await llm.complete({ system: judgeSystemPrompt(), user: `${user}\n\n${retryNote(first.error.message, ids)}`, tier: 'balanced', maxOutputTokens: 2000, purpose: 'verify' });
  if (!again.ok) return first;
  return parseJudge(again.value.text, ids);
}

/** Appended on the one retry after a malformed reply (judge and match grader alike). */
export const retryNote = (problem: string, ids: string[]) =>
  `Your previous reply could not be used (${problem}). Reply again with JSON only, exactly one entry for each of: ${ids.join(', ')}.`;

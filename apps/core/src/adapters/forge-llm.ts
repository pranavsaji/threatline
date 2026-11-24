import type { ChatResponse, Prompt } from '@forge/llm';
import type { LlmPort, LlmRequest, LlmResponse, ModelTier } from '@threatline/core';
import { appError, err, ok, type Result } from '@threatline/shared';
import { log } from './log.js';

/**
 * Threatline Engine's models per tier, newest first. A model the platform refuses (retired, not yet enabled for this app,
 * overloaded) falls through to the next one, so a review still runs on the best model available.
 */
export const ENGINE_MODELS: Readonly<Record<ModelTier, readonly string[]>> = {
  fast: ['claude-haiku-4-5-20251001', 'claude-sonnet-4-6'],
  balanced: ['claude-sonnet-5', 'claude-sonnet-4-6', 'claude-sonnet-4-5-20250929'],
  deep: ['claude-opus-5', 'claude-opus-4-8', 'claude-opus-4-7', 'claude-opus-4-6'],
};

type Chat = (p: Prompt) => Promise<ChatResponse>;

/** Loaded on first use: @forge/llm needs the Forge runtime, which tests and local tools do not have. */
const forgeChat: Chat = async (p) => (await import('@forge/llm')).chat(p);

const textOf = (r: ChatResponse): string => {
  const c = r.choices[0]?.message.content;
  if (typeof c === 'string') return c;
  return Array.isArray(c) ? c.map((p) => p.text).join('') : '';
};

type Failure = { status?: number; code: string; validation: boolean };

/** What a failed call says, without request content: the error's name, HTTP status and platform code only. */
function describe(e: unknown): Failure {
  const x = e as { name?: string; status?: number; code?: string };
  return { ...(typeof x.status === 'number' ? { status: x.status } : {}), code: x.code ?? x.name ?? 'error', validation: x.name === 'PromptValidationError' };
}

/** Rate limits, overload, gateway errors and network failures (no HTTP status): worth another try after a pause. */
const TRANSIENT_STATUS = new Set([408, 425, 429, 500, 502, 503, 504, 529]);
const isTransient = (f: Failure): boolean => !f.validation && (f.status === undefined || TRANSIENT_STATUS.has(f.status));

/**
 * Retries of one model on a transient failure: exponential backoff with full jitter (reviews that started together and
 * hit a rate limit together do not retry together), never past `deadlineMs` from the start of the request, so the
 * retries fit the queue function's 300 s limit. After them the next model of the tier is tried, as before; after that
 * the queue job itself is retried later (consumers/retry.ts).
 */
export interface LlmRetryOptions {
  retries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  deadlineMs: number;
  sleep: (ms: number) => Promise<void>;
  random: () => number;
  now: () => number;
}
export const LLM_RETRY: LlmRetryOptions = {
  retries: 2,
  baseDelayMs: 2_000,
  maxDelayMs: 15_000,
  deadlineMs: 120_000,
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  random: Math.random,
  now: Date.now,
};

/** LlmPort over Forge LLMs (billed to the app's developer). Logs model, tokens and timing; never prompt or reply text. */
export function forgeLlm(models: Readonly<Record<ModelTier, readonly string[]>> = ENGINE_MODELS, chat: Chat = forgeChat, retry: Partial<LlmRetryOptions> = {}): LlmPort {
  const o: LlmRetryOptions = { ...LLM_RETRY, ...retry };
  // Models the platform refused outright (even without sampling options), skipped for the life of this runtime.
  const refused = new Set<string>();
  // Models that accept a call only without `temperature` (newer models fix sampling).
  const noTemperature = new Set<string>();
  return {
    async complete(req: LlmRequest): Promise<Result<LlmResponse>> {
      const begun = o.now();
      let last: Failure | null = null;
      let transient = false;
      let attempts = 0;
      const chain = models[req.tier].filter((m) => !refused.has(m));
      tiers: for (const model of chain.length > 0 ? chain : models[req.tier]) {
        for (let attempt = 0; ; attempt++) {
          const started = o.now();
          attempts++;
          const prompt = (withTemperature: boolean): Prompt => ({
            model,
            messages: [
              { role: 'system', content: req.system },
              { role: 'user', content: req.user },
            ],
            max_completion_tokens: req.maxOutputTokens,
            ...(withTemperature ? { temperature: req.purpose === 'propose' ? 0.7 : 0 } : {}),
          });
          try {
            let r: ChatResponse;
            try {
              r = await chat(prompt(!noTemperature.has(model)));
            } catch (e) {
              // A 400 can mean the model does not take `temperature`: try it once without before moving on.
              if (describe(e).status !== 400 || noTemperature.has(model)) throw e;
              r = await chat(prompt(false));
              noTemperature.add(model);
            }
            const text = textOf(r);
            const tokensIn = r.usage?.input_tokens ?? Math.ceil((req.system.length + req.user.length) / 4);
            const tokensOut = r.usage?.output_tokens ?? Math.ceil(text.length / 4);
            log('llm.call', { purpose: req.purpose, model, tokensIn, tokensOut, ms: o.now() - started, finish: r.choices[0]?.finish_reason ?? 'none', attempt });
            if (!text.trim()) {
              log('llm.empty', { purpose: req.purpose, model });
              return err(appError('upstream', `${model} returned no text`));
            }
            return ok({ text, modelId: model, tokensIn, tokensOut });
          } catch (e) {
            last = describe(e);
            const again = isTransient(last);
            if (again) transient = true;
            const delay = Math.round(o.random() * Math.min(o.maxDelayMs, o.baseDelayMs * 2 ** attempt));
            // The retry may take as long as the call that just failed: only when that still ends before the deadline.
            const retrying = again && attempt < o.retries && o.now() - begun + delay + (o.now() - started) < o.deadlineMs;
            log('llm.failed', { purpose: req.purpose, model, status: last.status ?? 0, code: last.code, ms: o.now() - started, attempt, retrying, ...(retrying ? { delayMs: delay } : {}) });
            if (last.status === 400 || last.status === 404) refused.add(model);
            // Our own malformed request will fail on every model: stop rather than spend on the rest of the list.
            if (last.validation) break tiers;
            if (!retrying) break;
            await o.sleep(delay);
          }
        }
        // Out of time for this request: the next model would not fit either (the queue job is retried later instead).
        if (o.now() - begun >= o.deadlineMs) break;
      }
      const status = last?.status;
      // What the caller can do: a transient failure is worth retrying the job later. A malformed request, or a tier whose
      // every model the platform refused, is not: it fails the same way until Threatline is fixed or its models updated.
      const code = !last ? 'upstream' : last.validation ? 'validation' : !transient ? 'forbidden' : status === 408 || status === 504 ? 'timeout' : 'upstream';
      log('llm.gave_up', { purpose: req.purpose, tier: req.tier, code, status: status ?? 0, attempts, ms: o.now() - begun });
      return err(appError(code, `Forge LLMs: ${last?.code ?? 'no model available'}${status ? ` (HTTP ${status})` : ''}`));
    },
  };
}

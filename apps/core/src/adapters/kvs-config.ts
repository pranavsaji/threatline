import { kvs } from '@forge/kvs';
import { DEFAULT_SITE_POLICY } from '@threatline/core';
import { appError, err, ok, SitePolicySchema, type Result, type SitePolicy } from '@threatline/shared';

/** The subset of `@forge/kvs` Threatline uses. Injected so tests run against an in-memory map. */
export interface KvsPort {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<void>;
  /** Atomically writes `value` and returns what the key held before (undefined if nothing): a get-and-set. */
  swap<T>(key: string, value: unknown): Promise<T | undefined>;
  getSecret<T>(key: string): Promise<T | undefined>;
  setSecret<T>(key: string, value: T): Promise<void>;
  deleteSecret(key: string): Promise<void>;
}

export const forgeKvs = (): KvsPort => ({
  get: (k) => kvs.get(k),
  set: (k, v) => kvs.set(k, v),
  delete: (k) => kvs.delete(k),
  swap: async <T>(k: string, v: unknown) => (await kvs.set<unknown, T>(k, v, { keyPolicy: 'OVERRIDE', returnValue: 'PREVIOUS' }))?.value,
  getSecret: (k) => kvs.getSecret(k),
  setSecret: (k, v) => kvs.setSecret(k, v),
  deleteSecret: (k) => kvs.deleteSecret(k),
});

export interface ConfigStore {
  site(): Promise<Result<SitePolicy>>;
  setSite(p: SitePolicy): Promise<Result<void>>;
  /** Feature flags default off: anything other than a stored `true`, including a KVS failure, reads as false. */
  flag(name: string): Promise<boolean>;
}

const SITE_KEY = 'config:site';
const upstream = (e: unknown) => err(appError('upstream', `kvs: ${e instanceof Error ? e.message : String(e)}`));

/**
 * Upper bounds on the AI budget that only the app developer controls (Forge environment variables), so a site admin
 * cannot raise Forge LLM spend past them. Forge bills LLM usage of every install to the developer.
 */
export type BudgetCeiling = Partial<SitePolicy['budget']>;

/** Each budget field is the smaller of the site's value and the developer's ceiling. */
export function applyCeiling(policy: SitePolicy, ceiling: BudgetCeiling): SitePolicy {
  const b = policy.budget;
  const cap = (v: number, c: number | undefined) => (c === undefined ? v : Math.min(v, c));
  return {
    ...policy,
    budget: {
      tokensInPerReview: cap(b.tokensInPerReview, ceiling.tokensInPerReview),
      tokensOutPerReview: cap(b.tokensOutPerReview, ceiling.tokensOutPerReview),
      reviewsPerMonth: cap(b.reviewsPerMonth, ceiling.reviewsPerMonth),
    },
  };
}

/**
 * `defaults` apply only while no policy is stored (the admin page writes one). `ceiling` applies to every read, stored
 * or default, so the admin page shows (and saves) the effective budget.
 */
export function kvsConfigStore(store: KvsPort = forgeKvs(), defaults: SitePolicy = DEFAULT_SITE_POLICY, ceiling: BudgetCeiling = {}): ConfigStore {
  return {
    async site() {
      let raw: unknown;
      try {
        raw = await store.get(SITE_KEY);
      } catch (e) {
        return upstream(e);
      }
      if (raw === undefined) return ok(applyCeiling(defaults, ceiling));
      const p = SitePolicySchema.safeParse(raw);
      return p.success ? ok(applyCeiling(p.data, ceiling)) : err(appError('schema', 'stored site policy is invalid', { issues: p.error.issues.slice(0, 5).map((i) => i.path.join('.')) }));
    },

    async setSite(policy) {
      const p = SitePolicySchema.safeParse(policy);
      if (!p.success) return err(appError('validation', 'site policy is invalid', { issues: p.error.issues.slice(0, 5).map((i) => i.path.join('.')) }));
      try {
        await store.set(SITE_KEY, p.data);
        return ok(undefined);
      } catch (e) {
        return upstream(e);
      }
    },

    async flag(name) {
      try {
        return (await store.get(`flags:${name}`)) === true;
      } catch {
        return false;
      }
    },
  };
}

/** Bootstrap before the admin page exists: `forge variables set THREATLINE_ENABLED_PROJECTS PAY,SEC`. Keys are validated. */
export function defaultsFromEnv(env: Record<string, string | undefined>): SitePolicy {
  const projects = (env.THREATLINE_ENABLED_PROJECTS ?? '')
    .split(',')
    .map((p) => p.trim().toUpperCase())
    .filter((p) => /^[A-Z][A-Z0-9_]{0,254}$/.test(p));
  return { ...DEFAULT_SITE_POLICY, enabledProjects: [...new Set(projects)] };
}

const CEILING_VARS = {
  reviewsPerMonth: 'THREATLINE_MAX_REVIEWS_PER_MONTH',
  tokensInPerReview: 'THREATLINE_MAX_TOKENS_IN_PER_REVIEW',
  tokensOutPerReview: 'THREATLINE_MAX_TOKENS_OUT_PER_REVIEW',
} as const;

/**
 * The developer's AI budget ceiling: `forge variables set -e production THREATLINE_MAX_REVIEWS_PER_MONTH 100`.
 * A value that is not a positive whole number is ignored (that field has no ceiling).
 */
export function ceilingFromEnv(env: Record<string, string | undefined>): BudgetCeiling {
  const out: BudgetCeiling = {};
  for (const [field, name] of Object.entries(CEILING_VARS) as Array<[keyof BudgetCeiling, string]>) {
    const raw = env[name]?.trim() ?? '';
    if (/^[1-9]\d{0,9}$/.test(raw)) out[field] = Number(raw);
  }
  return out;
}

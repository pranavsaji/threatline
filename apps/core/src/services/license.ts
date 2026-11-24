import type { ClockPort } from '@threatline/core';
import type { LogFields } from '@threatline/shared';
import { log } from '../adapters/log.js';
import type { KvsPort } from '../adapters/kvs-config.js';

/**
 * Paid via Atlassian licensing (docs/LICENSING.md). Forge gives a function `context.license` (`{ active: boolean }`) only
 * for a paid app in production; it is undefined for free and unlisted apps and in development environments, which
 * Threatline treats as licensed ("not applicable"). Unlicensed means reduced functionality, never a trap: no new AI
 * work, while existing data stays readable, the Done gate lets transitions through and merge attestations are issued.
 */
export type LicenseState = 'licensed' | 'unlicensed' | 'not_applicable';

/** Forge variable for testing in development: `active` or `inactive`. It never overrides a license Forge reports. */
export const LICENSE_OVERRIDE_VAR = 'THREATLINE_LICENSE_OVERRIDE';

/** The last license state a Forge context reported, for invocations whose context carries none (validator, queue). */
export const LICENSE_SEEN_KEY = 'license:seen';

export const LICENSE_INACTIVE_MESSAGE =
  "Threatline's license for this site is inactive, so it starts no new reviews. Existing reviews, requirements and the risk ledger stay readable, and the Done gate does not block. A site admin can renew Threatline in Atlassian Administration.";

export const isLicensed = (s: LicenseState): boolean => s !== 'unlicensed';

/** Forge's `context.license` alone: `active` true or false, anything else (absent, malformed) is not applicable. */
export function licenseFromContext(license: unknown): LicenseState {
  if (typeof license !== 'object' || license === null) return 'not_applicable';
  const active = (license as { active?: unknown }).active;
  return typeof active === 'boolean' ? (active ? 'licensed' : 'unlicensed') : 'not_applicable';
}

/** The THREATLINE_LICENSE_OVERRIDE value, or null when unset or not `active`/`inactive`. */
export function overrideOf(raw: unknown): LicenseState | null {
  const v = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  return v === 'active' ? 'licensed' : v === 'inactive' ? 'unlicensed' : null;
}

/** A stored LICENSE_SEEN_KEY value, or null when there is none or it is not one Threatline wrote. */
export function recordedOf(raw: unknown): 'licensed' | 'unlicensed' | null {
  const s = typeof raw === 'object' && raw !== null ? (raw as { state?: unknown }).state : undefined;
  return s === 'licensed' || s === 'unlicensed' ? s : null;
}

/**
 * Which state applies, in order: the license Forge reports now; else (only where Forge may simply not report one) the
 * last one a context reported; else the development override; else not applicable. Resolvers always get the license
 * (authoritative), so for them a missing one really means not applicable and the record is not consulted.
 */
export function resolveLicense(i: { context: unknown; recorded?: unknown; override?: unknown; authoritative?: boolean }): LicenseState {
  const now = licenseFromContext(i.context);
  if (now !== 'not_applicable') return now;
  const recorded = i.authoritative ? null : recordedOf(i.recorded);
  return recorded ?? overrideOf(i.override) ?? 'not_applicable';
}

export interface LicensePort {
  /** This invocation's license state (computed once per invocation). */
  state(): Promise<LicenseState>;
}

/**
 * The license for one invocation. A definite license from the context is recorded (when it changed) for invocations
 * without one; a resolver reporting none clears the record, so a development site tested with `--license inactive` and
 * reinstalled without it is not left unlicensed. Storage failures never fail the caller: an unreadable record is ignored.
 */
export function invocationLicense(state: KvsPort, clock: ClockPort, o: { context: unknown; override: unknown; authoritative: boolean }): LicensePort {
  let memo: Promise<LicenseState> | undefined;
  const compute = async (): Promise<LicenseState> => {
    const now = licenseFromContext(o.context);
    const recorded = await state.get<unknown>(LICENSE_SEEN_KEY).catch(() => undefined);
    const target = now === 'not_applicable' ? null : now;
    // Only a definite license is recorded, and only a resolver (which always gets one when there is one) clears it.
    if ((target !== null || o.authoritative) && recordedOf(recorded) !== target) {
      try {
        if (target === null) await state.delete(LICENSE_SEEN_KEY);
        else await state.set(LICENSE_SEEN_KEY, { state: target, at: clock.now().toISOString() });
        log('license.changed', { from: recordedOf(recorded) ?? 'not_applicable', to: now });
      } catch {
        // best effort: the next invocation with a context records it
      }
    }
    return resolveLicense({ context: o.context, recorded, override: o.override, authoritative: o.authoritative });
  };
  return { state: () => (memo ??= compute()) };
}

/** Logs a refusal and returns the message the caller shows. */
export function licenseRefusal(where: string, fields: Record<string, string> = {}): string {
  log('license.refused', { ...fields, where } as LogFields);
  return LICENSE_INACTIVE_MESSAGE;
}

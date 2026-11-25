import { z } from 'zod';
import { ThreatSchema, type ContextFact, type Review, type Threat } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';

/**
 * The first look (docs/ENGINE.md): Threatline's rule-based threats for a revision, stored by its gather before any model
 * call, so the panel and the context column have something to show in seconds while the AI review runs. Display only:
 * the verdict, requirements and the ledger never read it, and it is no longer shown once the review settles (the full
 * review includes the same rule-based floor).
 */
export const FIRST_LOOK_STAGE = 'first_look';

const STATUSES_RUNNING: ReadonlySet<Review['status']> = new Set(['queued', 'gathering', 'awaiting_agent', 'modeling']);
export const isRunning = (r: Pick<Review, 'status'>) => STATUSES_RUNNING.has(r.status);

const Stored = z.object({ threats: z.array(ThreatSchema).max(50) });

/** Threatline Engine's six stages (docs/ENGINE.md), numbered as the first look shows them. */
export const ENGINE_STAGES = ['Gather', 'Injection check', 'Independent AI runs', 'Assemble', 'Gap check', 'Verify'] as const;

export interface FirstLookDto {
  /** How many rule-based risks the first look found in all (shown and hidden): what the context column counts. */
  risks: number;
  /** Rule-based threats as this viewer may see them (sources they cannot open are left out), most severe first. */
  threats: Threat[];
  /** First-look threats left out because they cite only sources this viewer cannot open. */
  hidden: number;
  /** Where Threatline Engine is (absent for a Rovo agent review, which has no fixed stages). */
  stage?: { n: number; of: number; name: string };
}

/** The stored first look of a running review, or null (none stored, unreadable, or the review is no longer running). */
export async function storedFirstLook(deps: Pick<CoreDeps, 'reviews'>, review: Pick<Review, 'id' | 'status'>): Promise<Threat[] | null> {
  if (!isRunning(review)) return null;
  const s = await deps.reviews.stage(review.id, FIRST_LOOK_STAGE);
  if (!s.ok || s.value?.status !== 'done') return null;
  const p = Stored.safeParse(s.value.checkpoint);
  return p.success ? p.data.threats : null;
}

/** Threatline Engine's current stage for a running review; undefined when it is not an engine review. */
export async function engineStage(deps: Pick<CoreDeps, 'reviews'>, review: Pick<Review, 'id' | 'samplesReceived' | 'samplesExpected'>): Promise<FirstLookDto['stage']> {
  const [marker, extract] = await Promise.all([deps.reviews.stage(review.id, 'engine'), deps.reviews.stage(review.id, 'extract')]);
  if (!(marker.ok && marker.value) && !(extract.ok && extract.value)) return undefined;
  const checked = extract.ok && (extract.value?.status === 'done' || extract.value?.status === 'failed');
  const n = !checked ? 2 : review.samplesReceived < review.samplesExpected ? 3 : 4;
  const name = n === 3 ? `${ENGINE_STAGES[2]}, ${review.samplesReceived} of ${review.samplesExpected} done` : ENGINE_STAGES[n - 1]!;
  return { n, of: ENGINE_STAGES.length, name };
}

/**
 * The first look as a viewer may see it: like the panel's threats, a citation of a fact this viewer cannot read is
 * dropped, and a threat left with none is counted in `hidden`, never shown. `visibleFacts` are the review's facts
 * already scoped to the viewer.
 */
export function scopeFirstLook(threats: readonly Threat[], visibleFacts: readonly Pick<ContextFact, 'id'>[]): Omit<FirstLookDto, 'stage'> {
  const ids = new Set(visibleFacts.map((f) => f.id));
  const shown: Threat[] = [];
  for (const t of threats) {
    const citations = t.citations.filter((c) => ids.has(c.factId));
    if (citations.length > 0) shown.push({ ...t, citations });
  }
  return { risks: threats.length, threats: shown, hidden: threats.length - shown.length };
}

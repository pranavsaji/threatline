import { layoutDiagram, sketchForDiagram, type DiagramInput, type DiagramModel, type DiagramSketch } from '@threatline/core';
import type { Requirement } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';

/** The data-flow diagram as a reader may see it. */
export interface DiagramDto extends DiagramModel {
  /**
   * The review has an architecture sketch, but it was left out because it rests on sources this reader cannot open:
   * the diagram then shows only the elements the reader's own threats name.
   */
  sketchHidden: boolean;
}

const CLOSED = new Set<Requirement['status']>(['Verified', 'AcceptedRisk', 'NotApplicable']);

/** Threats that have requirements, every one of them closed (verified, accepted as a risk, or not applicable). */
export function resolvedThreatIds(requirements: readonly Pick<Requirement, 'threatId' | 'status'>[]): string[] {
  const open = new Set(requirements.filter((r) => !CLOSED.has(r.status)).map((r) => r.threatId));
  return [...new Set(requirements.map((r) => r.threatId))].filter((id) => !open.has(id));
}

/** The review's sketch: the engine's extracted one, else the agent runs'. A failed read gives none (less, never more). */
async function reviewSketch(deps: Pick<CoreDeps, 'reviews'>, reviewId: string): Promise<DiagramSketch | null> {
  const [x, samples] = await Promise.all([deps.reviews.stage(reviewId, 'extract'), deps.reviews.samples(reviewId)]);
  const checkpoint = x.ok && x.value?.status === 'done' ? x.value.checkpoint : undefined;
  return sketchForDiagram(checkpoint, samples.ok ? samples.value : []);
}

/**
 * Security: the sketch was extracted from every fact of the review, so it is drawn only when `sketchVisible` (the reader
 * can open every source). Threats must already be scoped to the reader; only they place or add elements otherwise.
 */
export async function buildDiagram(
  deps: Pick<CoreDeps, 'reviews'>,
  reviewId: string,
  o: { threats: DiagramInput['threats']; requirements: readonly Pick<Requirement, 'threatId' | 'status'>[]; sketchVisible: boolean },
): Promise<DiagramDto> {
  const sketch = await reviewSketch(deps, reviewId);
  const ids = new Set(o.threats.map((t) => t.id));
  const model = layoutDiagram({
    sketch: o.sketchVisible ? sketch : null,
    threats: o.threats,
    resolvedThreatIds: resolvedThreatIds(o.requirements.filter((r) => ids.has(r.threatId))),
  });
  return { ...model, sketchHidden: !o.sketchVisible && sketch !== null };
}

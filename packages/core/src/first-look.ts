import { severityRank, type Threat } from '@threatline/shared';

/** The threat states that count: what the gate and the panel treat as a live threat (not hidden, covered or dismissed). */
const LIVE: ReadonlySet<Threat['state']> = new Set(['accepted', 'needs_human', 'proposed']);

/**
 * The first look (docs/ENGINE.md): the rule-based floor of a review that has just been gathered, before any model call.
 * From the gather's own assembly (no runs yet), so team suppression rules and earlier dismissals apply as they do in the
 * full review. Only Threatline's deterministic rule-based threats, never a threat carried from an earlier revision's AI
 * runs, most severe first. It is shown while the AI review runs and decides nothing: the gate, requirements and the
 * ledger read the review itself.
 */
export function firstLookThreats(threats: readonly Threat[]): Threat[] {
  return threats
    .filter((t) => t.origin === 'baseline' && LIVE.has(t.state))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.title.localeCompare(b.title));
}

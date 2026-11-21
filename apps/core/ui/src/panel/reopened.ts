import type { PanelDto } from '../types.js';
import { day } from '../text.js';

type ReopenedBy = NonNullable<PanelDto['history'][number]['reopenedBy']>;
const list = (xs: readonly string[]) => (xs.length <= 1 ? (xs[0] ?? '') : `${xs.slice(0, -1).join(', ')} and ${xs.at(-1)}`);

/** Why a revision exists when an incident reopened it: "Re-reviewed because PAY-9 (incident) hit component Payments API on 2026-11-21." */
export function reopenedText(c: ReopenedBy): string {
  const who = c.incidentKey ? `${c.incidentKey} (incident)` : 'an incident you cannot open';
  if (c.components.length > 0) return `Re-reviewed because ${who} hit ${c.components.length === 1 ? 'component' : 'components'} ${list(c.components)} on ${day(c.at)}.`;
  return `Re-reviewed because ${who}, linked to this work item, was raised on ${day(c.at)}.`;
}

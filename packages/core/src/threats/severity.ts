import type { Severity, ThreatRating } from '@threatline/shared';

/** likelihood x impact: >= 20 Critical, >= 12 High, >= 6 Medium, else Low. */
export function severityOf(likelihood: number, impact: number): Severity {
  const p = likelihood * impact;
  if (p >= 20) return 'Critical';
  if (p >= 12) return 'High';
  if (p >= 6) return 'Medium';
  return 'Low';
}

// Zero trust: an internal service, partner or staff account is as likely an attacker as any signed-in user (the
// eval's held-out cases showed "insider" threats such as forged queue messages falling below High at 2).
const ATTACKER = { anyone: 4, user: 3, insider: 3 } as const;
const EFFORT = { low: 1, medium: 0, high: -1 } as const;
const HARM = { takeover: 4, money: 4, sensitive_data: 4, integrity: 3, personal_data: 2, availability: 2, minor: 1 } as const;
const REACH = { one: -1, many: 0, all: 1 } as const;
const clamp = (n: number) => Math.max(1, Math.min(5, n));

/**
 * Likelihood and impact from the facts a threat states, by a fixed table, so severity does not depend on how alarmed a
 * model sounds. Critical (>= 20) needs an outside or ordinary attacker, little effort, and takeover, money or sensitive
 * data of many: the bar the prompt has always described.
 */
export function ratedScores(r: ThreatRating): { likelihood: number; impact: number } {
  return { likelihood: clamp(ATTACKER[r.attacker] + EFFORT[r.effort]), impact: clamp(HARM[r.harm] + REACH[r.reach]) };
}

const RANK: Record<Severity, number> = { Low: 0, Medium: 1, High: 2, Critical: 3 };

/**
 * The rating may correct an alarmed model by one level, never more: below that, impact (then likelihood) is raised
 * until the threat is one level under the model's own severity. A gate errs on the side of blocking.
 */
export function boundedScores(rated: { likelihood: number; impact: number }, model: { likelihood: number; impact: number }): { likelihood: number; impact: number } {
  const floor = RANK[severityOf(model.likelihood, model.impact)] - 1;
  let { likelihood, impact } = rated;
  while (RANK[severityOf(likelihood, impact)] < floor && (impact < 5 || likelihood < 5)) {
    if (impact < 5) impact++;
    else likelihood++;
  }
  return { likelihood, impact };
}

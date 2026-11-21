import { useEffect, useState } from 'react';
import Lozenge from '@atlaskit/lozenge';
import SectionMessage from '@atlaskit/section-message';
import { token } from '@atlaskit/tokens';
import { isError, type PanelApi } from '../bridge.js';
import type { DeliveryDto } from '../types.js';
import { count } from '../text.js';

type Pr = DeliveryDto['pullRequests'][number];
type Dep = DeliveryDto['deployments'][number];

/** Teamwork Graph delivery links for this work item, loaded once per panel (and again when the verdict changes). */
export function useDelivery(api: PanelApi, verdictKey: string): DeliveryDto | null {
  const [delivery, setDelivery] = useState<DeliveryDto | null>(null);
  useEffect(() => {
    if (!api.delivery) return;
    let live = true;
    api
      .delivery()
      .then((r) => {
        if (live && !isError(r)) setDelivery(r);
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [api, verdictKey]);
  return delivery;
}

const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'time unknown');

const prAppearance: Record<Pr['status'], 'success' | 'inprogress' | 'removed' | 'default'> = {
  MERGED: 'success',
  OPEN: 'inprogress',
  DRAFT: 'default',
  DECLINED: 'removed',
  UNKNOWN: 'default',
};
const depAppearance = (d: Dep): 'success' | 'inprogress' | 'removed' | 'default' =>
  d.state === 'SUCCESSFUL' ? 'success' : d.state === 'IN_PROGRESS' || d.state === 'PENDING' ? 'inprogress' : d.state === 'FAILED' || d.state === 'ROLLED_BACK' ? 'removed' : 'default';

function Linked({ url, children }: { url: string | null; children: string }) {
  return url ? (
    <a href={url} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  ) : (
    <span>{children}</span>
  );
}

/** The one alert the gates cannot raise themselves: code reached production while requirements were still open. */
export function ShippedWhileOpen({ delivery }: { delivery: DeliveryDto | null }) {
  const s = delivery?.shippedWhileOpen;
  if (!s) return null;
  const latest = s.deployments[0]!;
  return (
    <SectionMessage appearance="error" title="Shipped to production with security requirements open">
      <p style={{ margin: 0 }}>
        <Linked url={latest.url}>{latest.name}</Linked> reached <strong>{latest.environment.name}</strong> ({when(latest.at)}) while{' '}
        {count(s.openRequirements, 'security requirement')} {s.openRequirements === 1 ? 'was' : 'were'} still open
        {s.maxOpenSeverity ? ` (highest: ${s.maxOpenSeverity})` : ''}. Verify the requirements now, or accept the risk, so the
        record matches what is live.
      </p>
      {s.deployments.length > 1 && (
        <p style={{ margin: '4px 0 0', color: token('color.text.subtle') }}>{count(s.deployments.length - 1, 'earlier production deployment')} too.</p>
      )}
    </SectionMessage>
  );
}

export function DeliveryTab({ delivery }: { delivery: DeliveryDto | null }) {
  if (!delivery) return <p style={{ color: token('color.text.subtle') }}>Loading linked pull requests and deployments…</p>;
  const { pullRequests, deployments } = delivery;
  const caption = { textAlign: 'left' as const, font: token('font.heading.xsmall'), margin: '12px 0 4px' };
  const row = { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' as const, padding: '4px 0' };
  return (
    <div>
      <p style={{ margin: '4px 0', color: token('color.text.subtle') }}>
        From Atlassian Teamwork Graph: what is linked to this work item in your connected tools, as you can see it. Shown to you
        only; never stored or sent to the AI.
      </p>
      {delivery.mergedWhileOpen > 0 && (
        <SectionMessage appearance="warning">
          <p style={{ margin: 0 }}>{count(delivery.mergedWhileOpen, 'linked pull request')} merged while security requirements are open.</p>
        </SectionMessage>
      )}
      <h3 style={caption}>Pull requests ({pullRequests.length})</h3>
      {pullRequests.length === 0 ? (
        <p style={{ margin: 0 }}>None linked yet. Put the work item key (for example in the branch name) in a pull request to link it.</p>
      ) : (
        <ul aria-label="Linked pull requests" style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {pullRequests.map((p) => (
            <li key={p.id} style={row}>
              <Lozenge appearance={prAppearance[p.status]}>{p.status.toLowerCase()}</Lozenge>
              <Linked url={p.url}>{p.title}</Linked>
              <span style={{ color: token('color.text.subtle') }}>{when(p.updatedAt)}</span>
            </li>
          ))}
        </ul>
      )}
      <h3 style={caption}>Deployments ({deployments.length})</h3>
      {deployments.length === 0 ? (
        <p style={{ margin: 0 }}>No deployments linked.</p>
      ) : (
        <ul aria-label="Linked deployments" style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {deployments.map((d) => (
            <li key={d.id} style={row}>
              <Lozenge appearance={depAppearance(d)}>{d.state.toLowerCase().replace('_', ' ')}</Lozenge>
              <Linked url={d.url}>{d.name}</Linked>
              <span>
                to {d.environment.name}
                {d.environment.type === 'PRODUCTION' ? ' (production)' : ''}
              </span>
              <span style={{ color: token('color.text.subtle') }}>{when(d.at)}</span>
            </li>
          ))}
        </ul>
      )}
      {delivery.partial && (
        <p style={{ marginTop: 8, color: token('color.text.subtle') }}>
          Some links may be missing: a connected tool did not answer, or you cannot see it.
        </p>
      )}
    </div>
  );
}

/** Linked pull requests offered as one-click evidence when verifying a requirement. */
export const prSuggestions = (delivery: DeliveryDto | null): Array<{ label: string; url: string }> =>
  (delivery?.pullRequests ?? []).filter((p): p is Pr & { url: string } => p.url !== null && p.status !== 'DECLINED').slice(0, 5).map((p) => ({ label: p.title, url: p.url }));

import { useEffect, useId, useState, type MouseEvent } from 'react';
import { token } from '@atlaskit/tokens';
import { isError, type PanelApi } from '../bridge.js';
import type { SeenBeforeDto, SeenItem } from '../types.js';

/** Opens a work item from the panel (through the Forge router inside Jira; the plain link elsewhere). */
export type OpenIssue = (e: MouseEvent<HTMLAnchorElement>, key: string) => void;

/**
 * "Seen before", loaded once the review has settled (and again when its revision or verdict changes). The panel never
 * waits for it: until it arrives, or when it fails, the threats simply show no history.
 */
export function useSeenBefore(api: PanelApi, key: string | null): SeenBeforeDto | null {
  const [memory, setMemory] = useState<SeenBeforeDto | null>(null);
  useEffect(() => {
    if (!api.memory || !key) return;
    let live = true;
    api
      .memory()
      .then((r) => {
        if (live) setMemory(isError(r) ? null : r);
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [api, key]);
  return memory;
}

const link = { color: token('color.link') };

/** A work item key that opens it in Jira (target _top, as every other work item link in the panel). */
export function IssueLink({ issueKey, onOpen }: { issueKey: string; onOpen?: OpenIssue | undefined }) {
  return (
    <a href={`/browse/${issueKey}`} target="_top" onClick={onOpen ? (e) => onOpen(e, issueKey) : undefined} style={link}>
      {issueKey}
    </a>
  );
}

/** The item's text, with the evidence label ("PR #41") as a link to the evidence when there is one. */
function ItemText({ item }: { item: SeenItem }) {
  const e = item.evidence;
  const at = e ? item.text.lastIndexOf(e.label) : -1;
  if (!e || at < 0) return <>{item.text}</>;
  return (
    <>
      {item.text.slice(0, at)}
      <a href={e.url} target="_blank" rel="noopener noreferrer" style={link}>
        {e.label}
      </a>
      {item.text.slice(at + e.label.length)}
    </>
  );
}

/** Under a threat: what happened before on this site — incidents, and the same threat verified, accepted or dismissed elsewhere. */
export function SeenBeforeList({ items, onOpen, why = true }: { items: readonly SeenItem[]; onOpen?: OpenIssue | undefined; /** Each match's reason (the card shows it with its details). */ why?: boolean }) {
  const id = useId();
  if (items.length === 0) return null;
  return (
    <div style={{ display: 'grid', gap: 2, borderLeft: `2px solid ${token('color.border.discovery')}`, paddingLeft: 8 }}>
      <strong id={id} style={{ font: token('font.body.small'), color: token('color.text.subtle') }}>
        Seen before
      </strong>
      <ul aria-labelledby={id} style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 2 }}>
        {items.map((s) => (
          <li key={`${s.kind}-${s.key}`} style={{ font: token('font.body.small') }}>
            <IssueLink issueKey={s.key} onOpen={onOpen} /> · <ItemText item={s} />
            {why && <span style={{ display: 'block', color: token('color.text.subtlest') }}>Why: {s.reason}</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Headline-level: a blocking threat already happened here as an incident. */
export function HappenedBefore({ memory, onOpen }: { memory: SeenBeforeDto | null; onOpen?: OpenIssue | undefined }) {
  const h = memory?.happenedBefore;
  if (!h) return null;
  return (
    <p style={{ margin: 0 }} data-testid="threatline-happened-before">
      <strong>This happened before:</strong> <IssueLink issueKey={h.key} onOpen={onOpen} />
      {h.summary ? ` — ${h.summary}.` : '.'}
    </p>
  );
}

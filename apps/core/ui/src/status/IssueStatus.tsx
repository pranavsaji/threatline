import { useCallback, useEffect, useMemo, useState } from 'react';
import Lozenge from '@atlaskit/lozenge';
import Spinner from '@atlaskit/spinner';
import { token } from '@atlaskit/tokens';
import { isError, type PanelApi } from '../bridge.js';
import type { ApiError, StatusDto } from '../types.js';
import { statusOf, statusPollMs } from './status-view.js';

const small = { color: token('color.text.subtle'), font: token('font.body.small') } as const;

/**
 * The work item's gate status in Jira's context column (jira:issueContext): the verdict, how many items still block
 * Done, and the top reason. Everything else lives in the Threatline panel.
 */
export function IssueStatus({ api }: { api: PanelApi }) {
  const [dto, setDto] = useState<StatusDto | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    const call: Promise<StatusDto | ApiError> = api.status ? api.status() : api.get();
    const r = await call.catch((): ApiError => ({ error: 'unavailable' }));
    if (isError(r)) setError(r.error === 'not_found' ? 'You do not have access to this work item.' : 'Threatline is unavailable right now. Try again in a minute.');
    else {
      setDto(r);
      setError(null);
    }
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  const view = useMemo(() => (dto ? statusOf(dto) : null), [dto]);
  const poll = view ? statusPollMs(view) : null;
  useEffect(() => {
    if (poll === null) return;
    const t = setTimeout(() => void load(), poll);
    return () => clearTimeout(t);
  }, [poll, dto, load]);

  if (error && !view) return <p style={{ margin: 0, ...small }}>{error}</p>;
  if (!view)
    return (
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', ...small }} aria-live="polite">
        <Spinner size="small" label="Loading the Threatline gate status" /> Loading…
      </div>
    );

  return (
    <section aria-label="Threatline gate status" style={{ display: 'grid', gap: 4 }}>
      <div role="status" style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        <Lozenge appearance={view.appearance} isBold maxWidth="100%">
          {view.icon && <span aria-hidden="true">{view.icon} </span>}
          {view.label}
        </Lozenge>
        {view.open && (
          <span style={small}>
            <span aria-hidden="true">· </span>
            {view.open}
          </span>
        )}
      </div>
      {view.line && (
        <p title={view.line} style={{ margin: 0, ...small, overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' }}>
          {view.line}
        </p>
      )}
    </section>
  );
}

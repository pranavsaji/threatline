import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ApiError } from '../types.js';
import Button from '@atlaskit/button/new';
import Lozenge from '@atlaskit/lozenge';
import SectionMessage from '@atlaskit/section-message';
import Spinner from '@atlaskit/spinner';
import Tabs, { Tab, TabList, TabPanel } from '@atlaskit/tabs';
import { token } from '@atlaskit/tokens';
import { errorText, isError, type PanelApi } from '../bridge.js';
import { LicenseBanner } from '../components/LicenseBanner.js';
import type { PanelDto, Threat } from '../types.js';
import { EmptyState } from './EmptyState.js';
import { Header } from './Header.js';
import { count } from '../text.js';
import { ThreatDiff } from './ThreatDiff.js';
import { WhatIf } from './WhatIf.js';
import { StatusSteps } from './StatusSteps.js';
import { FirstLook } from './FirstLook.js';
import { ThreatCard } from './ThreatCard.js';
import { pollMs, RERUN_WAIT_MS, rerunLanded, rerunWaitOf, viewOf, type RerunWait } from './states.js';
import { useInFlight } from '../components/in-flight.js';
import { RequirementsTab } from './RequirementsTab.js';
import { AcceptancesTab } from './AcceptancesTab.js';
import { ThreatTriage } from './ThreatEditor.js';
import { ThreatModelPage } from './ThreatModelPage.js';
import { reopenedText } from './reopened.js';
import { UnhideThreat } from './UnhideThreat.js';
import { DiagramTab } from './DiagramTab.js';
import { DeliveryTab, ShippedWhileOpen, prSuggestions, useDelivery } from './DeliveryTab.js';
import { useSeenBefore, type OpenIssue } from './SeenBefore.js';

const STILL_STARTING = 'The review is still starting. Refresh the panel in a minute or two to see it.';
/** Threatline Engine runs several analyses and a verifier itself: two to four minutes, not one. */
const startedText = (mode: PanelDto['reviewMode']) =>
  mode === 'engine' ? 'Review started. Threatline Engine reviews take a few minutes.' : 'Review started. This usually takes about a minute.';
const NEEDS_EDIT = 'Someone with edit permission on this work item can re-run the review.';

const DISCARD_REASON: Record<string, string> = {
  low_votes: 'Too few agent runs agreed',
  unsupported_citation: 'Its quote is not in the sources',
  duplicate_of_dismissed: 'Matches a threat your team dismissed before',
  schema: 'The agent run was not a valid threat model',
};

export function IssuePanel({ api }: { api: PanelApi }) {
  const [dto, setDto] = useState<PanelDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** One panel-level mutation (re-run, confirm) at a time: a double click must not queue two re-runs. */
  const acting = useInFlight();
  const busy = acting.busy;
  const loadingMore = useInFlight();
  const [notice, setNotice] = useState<string | null>(null);
  const [showDiscarded, setShowDiscarded] = useState(false);
  const [more, setMore] = useState<{ threats: Threat[]; cursor: number | null } | null>(null);
  const [moreError, setMoreError] = useState<string | null>(null);
  /** Set after a re-run starts, until the new revision shows up (or the wait runs out). */
  const [waiting, setWaiting] = useState<RerunWait | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await api.get();
      if (isError(r))
        setError(
          r.error === 'not_found'
            ? 'You do not have access to this work item.'
            : 'Threatline is unavailable right now. Try again in a minute.',
        );
      else {
        setDto(r);
        setError(null);
      }
    } catch {
      setError('Threatline is unavailable right now. Try again in a minute.');
    }
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  const view = useMemo(() => (dto ? viewOf(dto) : null), [dto]);
  const delivery = useDelivery(api, dto ? `${dto.verdict?.state ?? 'none'}:${dto.verdict?.blockingCount ?? 0}` : '');
  // Seen before: once the review is ready, and again for a new revision or a changed verdict (docs/MEMORY.md).
  const memory = useSeenBefore(api, dto?.review?.status === 'ready' ? `${dto.review.id}:${dto.verdict?.state ?? 'none'}:${dto.verdict?.blockingCount ?? 0}` : null);
  useEffect(() => {
    if (waiting && dto && rerunLanded(waiting, dto)) {
      setWaiting(null);
      // The new revision is here (its progress shows below), so "Review started" no longer says anything.
      setNotice((n) => (n === startedText('engine') || n === startedText(undefined) ? null : n));
    }
  }, [dto, waiting]);
  useEffect(() => {
    const ms = view ? pollMs(view, waiting !== null) : null;
    if (!ms) return;
    let timer: ReturnType<typeof setInterval> | null = null;
    const tick = () => {
      if (waiting && Date.now() - waiting.since >= RERUN_WAIT_MS) {
        setWaiting(null);
        setNotice(STILL_STARTING);
        return;
      }
      void load();
    };
    // A hidden tab does not poll; showing it again checks at once and resumes.
    const start = () => {
      if (timer === null && !document.hidden) timer = setInterval(tick, ms);
    };
    const stop = () => {
      if (timer !== null) clearInterval(timer);
      timer = null;
    };
    const onVisibility = () => {
      if (document.hidden) return stop();
      tick();
      start();
    };
    start();
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      stop();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [view, waiting, load]);

  const rerun = () =>
    acting.run(async () => {
      const before = rerunWaitOf(dto, Date.now());
      const r = await api.rerun().catch((): ApiError => ({ error: 'unavailable' }));
      if (isError(r))
        return setNotice(
          (r.error === 'validation' || r.error === 'conflict') && r.message
            ? r.message
            : r.error === 'rate_limited'
              ? 'You have re-run reviews 10 times this hour. Try again later.'
              : r.error === 'not_found'
                ? 'You need edit permission on this work item to re-run the review.'
                : 'The re-run could not start. Try again.',
        );
      setNotice(startedText(dto?.reviewMode));
      // The new revision comes from a queued job, so keep checking until it appears (see pollMs).
      setWaiting({ ...before, since: Date.now() });
      void load();
    });

  const confirm = (kind: 'review' | 'budget') =>
    acting.run(async () => {
      if (!dto?.review) return;
      const r = await api.confirm(dto.review.id, kind).catch((): ApiError => ({ error: 'unavailable' }));
      if (isError(r)) return setNotice(errorText(r));
      setNotice(
        kind === 'budget'
          ? 'Confirmed. The confirmation is in the ledger and the admin was alerted.'
          : 'Threats confirmed. Their requirements now decide the gate.',
      );
      void load();
    });

  const showMore = (from: number) =>
    loadingMore.run(async () => {
      const r = await api.threats(from).catch((): ApiError => ({ error: 'unavailable' }));
      if (isError(r)) return setMoreError('Threatline could not load more threats. Try again.');
      setMoreError(null);
      setMore((m) => ({ threats: [...(m?.threats ?? []), ...r.threats], cursor: r.cursor }));
    });

  if (error)
    return (
      <SectionMessage appearance="error" title="Threatline">
        {error}
      </SectionMessage>
    );
  if (!dto || !view)
    return (
      <div style={{ padding: 16, display: 'flex', gap: 8, alignItems: 'center' }} aria-live="polite">
        <Spinner size="medium" label="Loading the security review" /> Loading the security review…
      </div>
    );

  const canRun = dto.roles.includes('developer');
  const champion = dto.roles.includes('champion');
  const settled =
    dto.review !== null && !['queued', 'gathering', 'awaiting_agent', 'modeling'].includes(dto.review.status);
  const humanReason = dto.verdict?.reasons.find((r) => r.code === 'needs_human' || r.code === 'injection_unconfirmed');
  const facts = new Map(dto.facts.map((f) => [f.id, f]));
  const threats = [...dto.threats, ...(more?.threats ?? [])];
  // Why the current revision exists, when an incident reopened it (docs/INCIDENTS.md).
  const latestHistory = dto.history.at(-1);
  const reopened = latestHistory?.reopenedBy && latestHistory.revision === dto.review?.revision ? latestHistory.reopenedBy : null;
  const cursor = more ? more.cursor : dto.threatsCursor;
  const injected = dto.facts.filter((f) => f.injectionSuspected);
  /** Banner actions: disabled while a re-run or confirmation is in flight; no re-run for viewers who cannot edit. */
  const action = (key: string, label: string, onClick: () => void) => (
    <Button key={key} spacing="compact" isDisabled={busy} onClick={onClick}>
      {label}
    </Button>
  );
  const rerunActions = (label: string) => (canRun ? [action('rerun', label, () => void rerun())] : []);
  const needsEdit = !canRun && <p style={{ margin: '6px 0 0', color: token('color.text.subtle') }}>{NEEDS_EDIT}</p>;
  /** Custom UI runs on Atlassian's CDN origin, so a /browse link must go through the Forge router to reach Jira. */
  const openIssue: OpenIssue | undefined = api.navigate
    ? (e, key) => {
        e.preventDefault();
        void api.navigate!(`/browse/${key}`, { newTab: e.metaKey || e.ctrlKey || e.shiftKey }).catch(() => setNotice(`Could not open ${key}. Find it in Jira search.`));
      }
    : undefined;

  return (
    <main
      style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(0, 1fr)',
        gap: 12,
        padding: 4,
        color: token('color.text'),
      }}
    >
      <div aria-live="polite">{notice && <SectionMessage appearance="information">{notice}</SectionMessage>}</div>
      {dto.licenseInactive && <LicenseBanner />}
      {view.state === 'not_reviewed' && dto.inScope === false ? (
        <SectionMessage appearance="information" title="Threatline is not on for this project or work type">
          {dto.scopeMessage ?? 'Threatline does not review this work item.'} A parent work item's review, if it has one, still applies at the gate.
        </SectionMessage>
      ) : view.state === 'not_reviewed' ? (
        <EmptyState onRun={() => void rerun()} canRun={canRun} busy={busy} />
      ) : (
        <>
          <Header
            dto={dto}
            {...(canRun ? { onRerun: () => void rerun() } : {})}
            busy={busy}
            tasks={{ api, onChanged: () => void load() }}
            memory={memory}
            {...(openIssue ? { onOpen: openIssue } : {})}
          />
          {dto.review && dto.review.modelIds.some((m) => m.startsWith('claude')) && (
            <SectionMessage appearance="discovery" title="Threatline Engine review">
              Threatline ran this review itself: independent analyses of the work item and its pages that must agree and quote their evidence word for word,
              and a verifier that checks each threat against those quotes. Models: {dto.review.modelIds.join(', ')}.
            </SectionMessage>
          )}
          {dto.review?.modelIds.some((m) => m === 'threatline-rules' || m === 'redline-rules') && (
            <SectionMessage appearance="information" title="Rule-based review">
              AI review is off on this site, so these threats come from Threatline's built-in checks only. An admin can turn on AI review under Threatline admin → Review mode: Threatline Engine needs no Rovo.
            </SectionMessage>
          )}
          {dto.review && <WhatIf api={api} />}
          {view.state === 'in_progress' && (
            <SectionMessage appearance="information" title="Review in progress">
              <StatusSteps steps={view.steps} />
            </SectionMessage>
          )}
          {/* Shown only while the review runs; the settled review replaces it (and includes the same rule checks). */}
          {view.state === 'in_progress' && dto.firstLook && <FirstLook firstLook={dto.firstLook} facts={facts} />}
          {view.state === 'failed' && (
            <SectionMessage
              appearance="error"
              title="The review failed"
              actions={rerunActions('Retry review')}
            >
              Threatline could not finish this review, so Done and merge stay blocked until it runs again.
              {dto.review?.failureReason && dto.review.failureReason !== 'budget' && (
                <p style={{ margin: '6px 0 0' }}>Cause: {dto.review.failureReason}. If retrying gives the same cause, an admin can check Threatline admin → Recent runs.</p>
              )}
              {needsEdit}
            </SectionMessage>
          )}
          {view.state === 'timeout' && (
            <SectionMessage
              appearance="error"
              title="The AI review did not arrive in time"
              actions={rerunActions('Retry review')}
            >
              {dto.samples.received} of {dto.samples.expected} agent runs arrived. A missing review counts as a failed
              one, so Done and merge stay blocked.
              {needsEdit}
            </SectionMessage>
          )}
          {view.state === 'budget' && (
            <SectionMessage
              appearance="warning"
              title="Reviews are paused at the AI budget"
              actions={champion ? [action('confirm', 'Confirm this work item', () => void confirm('budget'))] : []}
            >
              The site reached its review budget (or, in Rovo agent mode, ran out of Rovo credits). A security champion can confirm this work
              item; the confirmation is recorded in the ledger.
            </SectionMessage>
          )}
          {humanReason && (
            <SectionMessage
              appearance="warning"
              title="Threats need a security champion"
              actions={champion ? [action('confirm', 'Confirm threats', () => void confirm('review'))] : []}
            >
              {humanReason.message}
            </SectionMessage>
          )}
          {view.stale && (
            <SectionMessage
              appearance="warning"
              title="Context changed since the last review"
              actions={rerunActions('Re-run review')}
            >
              The design or linked work changed. Re-run the review before moving this work item to Done.
              {needsEdit}
            </SectionMessage>
          )}
          {view.partial && (
            <SectionMessage appearance="warning" title="Partial context">
              Some linked sources could not be read, so this review may miss threats.
            </SectionMessage>
          )}
          {injected.length > 0 && (
            <SectionMessage appearance="warning" title="Threatline ignored instructions found in this page">
              <p style={{ margin: '0 0 6px' }}>
                These sources contain text aimed at the AI. It was treated as data, and threats based on it need a
                security champion.
              </p>
              <ul
                aria-label="Sources with suspected instructions"
                style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', gap: 6, flexWrap: 'wrap' }}
              >
                {injected.map((f) => (
                  <li key={f.id}>
                    <Lozenge appearance="moved">⚠ {f.title}</Lozenge>
                  </li>
                ))}
              </ul>
            </SectionMessage>
          )}
          <ShippedWhileOpen delivery={delivery} />
          <Tabs id="threatline-tabs">
            {/* A narrow panel scrolls the tab row itself rather than the whole page sideways. */}
            <div style={{ overflowX: 'auto', minWidth: 0 }}>
              <TabList>
                <Tab>Threats ({dto.threatsTotal})</Tab>
                <Tab>Requirements ({dto.requirements.length})</Tab>
                <Tab>Acceptances ({dto.acceptances.length})</Tab>
                <Tab>History</Tab>
                <Tab>Diagram</Tab>
                {api.delivery && <Tab>Delivery{delivery ? ` (${delivery.pullRequests.length + delivery.deployments.length})` : ''}</Tab>}
              </TabList>
            </div>
            <TabPanel>
              <div style={{ display: 'grid', gap: 8, paddingTop: 8, width: '100%' }}>
                {reopened && <p style={{ margin: 0, font: token('font.body.small'), color: token('color.text.subtle') }}>{reopenedText(reopened)}</p>}
                {dto.history.length >= 2 && <ThreatDiff api={api} revisions={dto.history.map((h) => h.revision)} />}
                {threats.length === 0 && <p style={{ color: token('color.text.subtle') }}>No threats yet.</p>}
                {threats.map((t) => (
                  <ThreatCard
                    key={t.id}
                    threat={t}
                    facts={facts}
                    covers={dto.covered.filter((c) => c.coveredBy === t.id).map((c) => c.title)}
                    seenBefore={memory?.threats[t.id] ?? []}
                    onOpen={openIssue}
                    explain={async (x) => {
                      const r = await api.explain(x.reviewId, x.id).catch((): ApiError => ({ error: 'unavailable' }));
                      return isError(r) ? null : r;
                    }}
                  >
                    {champion && settled && t.state === 'suppressed' && (
                      <UnhideThreat
                        threat={t}
                        api={api}
                        onDone={() => {
                          setMore(null);
                          void load();
                        }}
                      />
                    )}
                    {champion && settled && t.state !== 'dismissed' && t.state !== 'suppressed' && (
                      <ThreatTriage
                        threat={t}
                        others={threats.filter((o) => o.id !== t.id && o.state !== 'dismissed')}
                        api={api}
                        onDone={() => {
                          setMore(null);
                          void load();
                        }}
                      />
                    )}
                  </ThreatCard>
                ))}
                {dto.hiddenThreats > 0 && (
                  <p style={{ color: token('color.text.subtlest'), font: token('font.body.small') }}>
                    {count(dto.hiddenThreats, 'threat')} {dto.hiddenThreats === 1 ? 'cites a source' : 'cite sources'} you cannot open and {dto.hiddenThreats === 1 ? 'is' : 'are'} not shown.
                  </p>
                )}
                {cursor !== null && (
                  <div style={{ display: 'grid', gap: 4, justifyItems: 'start' }}>
                    <Button isDisabled={loadingMore.busy} onClick={() => void showMore(cursor)}>
                      Show more threats
                    </Button>
                    {moreError && (
                      <p role="alert" style={{ margin: 0, color: token('color.text.danger'), font: token('font.body.small') }}>
                        {moreError}
                      </p>
                    )}
                  </div>
                )}
                {(dto.discarded.length > 0 || dto.hiddenDiscarded > 0) && (
                  <div>
                    <Button
                      appearance="subtle"
                      onClick={() => setShowDiscarded(!showDiscarded)}
                      aria-expanded={showDiscarded}
                    >
                      {showDiscarded ? 'Hide' : 'Show'} discarded threats ({dto.discarded.length + dto.hiddenDiscarded})
                    </Button>
                    {showDiscarded && (
                      <ul
                        aria-label="Discarded threats"
                        style={{ margin: '6px 0 0', paddingLeft: 18, display: 'grid', gap: 4 }}
                      >
                        {dto.discarded.map((d, i) => (
                          <li key={`${d.title}-${i}`}>
                            <s>{d.title}</s> — {DISCARD_REASON[d.reason] ?? d.reason}
                          </li>
                        ))}
                        {dto.hiddenDiscarded > 0 && <li>{dto.hiddenDiscarded} more cite sources you cannot open.</li>}
                      </ul>
                    )}
                  </div>
                )}
              </div>
            </TabPanel>
            <TabPanel>
              <RequirementsTab dto={dto} api={api} onChanged={() => void load()} prLinks={prSuggestions(delivery)} />
            </TabPanel>
            <TabPanel>
              <AcceptancesTab dto={dto} api={api} onChanged={() => void load()} />
            </TabPanel>
            <TabPanel>
              <div style={{ display: 'grid', width: '100%' }}>
                <ThreatModelPage dto={dto} api={api} />
                <div style={{ overflowX: 'auto' }} tabIndex={0} role="region" aria-label="Review history">
                  <table style={{ borderCollapse: 'collapse', marginTop: 8, width: '100%' }}>
                    <caption
                      style={{ textAlign: 'left', font: token('font.body.small'), color: token('color.text.subtle') }}
                    >
                      Review history
                    </caption>
                    <thead>
                      <tr>
                        {['Revision', 'When', 'Risk', 'Status', 'Added', 'Removed'].map((h) => (
                          <th
                            key={h}
                            scope="col"
                            style={{
                              textAlign: 'left',
                              padding: 4,
                              borderBottom: `1px solid ${token('color.border')}`,
                            }}
                          >
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {dto.history.map((h) => (
                        <tr key={h.revision}>
                          <td style={{ padding: 4 }}>{h.revision}</td>
                          <td style={{ padding: 4, whiteSpace: 'nowrap' }}>
                            {h.createdAt.slice(0, 16).replace('T', ' ')} UTC
                          </td>
                          <td style={{ padding: 4 }}>{h.riskScore}</td>
                          <td style={{ padding: 4 }}>{h.status.replace('_', ' ')}</td>
                          <td style={{ padding: 4 }}>+{h.added}</td>
                          <td style={{ padding: 4 }}>−{h.removed}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {dto.history.some((h) => h.reopenedBy) && (
                  <ul aria-label="Why these revisions exist" style={{ margin: '8px 0 0', paddingLeft: 18, font: token('font.body.small') }}>
                    {dto.history.flatMap((h) => (h.reopenedBy ? [<li key={h.revision}>{`Revision ${h.revision}: ${reopenedText(h.reopenedBy)}`}</li>] : []))}
                  </ul>
                )}
              </div>
            </TabPanel>
            <TabPanel>
              <DiagramTab diagram={dto.diagram} />
            </TabPanel>
            {api.delivery && (
              <TabPanel>
                <DeliveryTab delivery={delivery} />
              </TabPanel>
            )}
          </Tabs>
        </>
      )}
    </main>
  );
}

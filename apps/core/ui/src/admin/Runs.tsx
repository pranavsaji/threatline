import { Fragment, useEffect, useId, useState, type CSSProperties } from 'react';
import Button from '@atlaskit/button/new';
import Lozenge from '@atlaskit/lozenge';
import { token } from '@atlaskit/tokens';
import { errorText, isError, type AdminApi } from '../bridge.js';
import type { ApiError, RunDto, RunStage } from '../types.js';
import { hint, h2, sectionStyle, utc } from './policy-editor.js';

const STATUS: Record<string, { text: string; appearance: 'success' | 'removed' | 'moved' | 'inprogress' | 'default' }> = {
  ready: { text: 'Ready', appearance: 'success' },
  failed: { text: 'Failed', appearance: 'removed' },
  agent_timeout: { text: 'Timed out', appearance: 'moved' },
  queued: { text: 'Queued', appearance: 'default' },
  gathering: { text: 'Gathering', appearance: 'inprogress' },
  awaiting_agent: { text: 'Waiting for agent', appearance: 'inprogress' },
  modeling: { text: 'Modeling', appearance: 'inprogress' },
};
const PROBLEM: Record<string, string> = { budget: 'Budget reached', agent_timeout: 'Agent runs timed out', schema: 'Agent output was not valid', no_json: 'Agent returned no threat model' };
const ERROR_WORDS: Record<string, string> = { budget: 'budget reached', agent_timeout: 'timed out', schema: 'invalid output', no_json: 'no threat model' };

export const duration = (ms: number) => (ms < 60_000 ? `${Math.round(ms / 1000)} s` : `${Math.round(ms / 60_000)} min`);

function stageName(stage: string): string {
  if (stage === 'gather') return 'Gather context';
  if (stage === 'assemble') return 'Assemble';
  if (stage === 'agent') return 'Agent runs';
  if (stage === 'extract') return 'Extract';
  if (stage === 'first_look') return 'First look (rule-based)';
  if (stage === 'comment') return 'Verdict comment';
  const m = /^agent_(\d+)$/.exec(stage);
  if (m) return `Agent run ${m[1]}`;
  return stage.replace(/_/g, ' ');
}
const stageText = (s: RunStage) => `${stageName(s.stage)}: ${s.status}${s.error ? ` (${ERROR_WORDS[s.error] ?? s.error})` : ''}, ${duration(s.ms)}`;

function problemOf(r: RunDto): string {
  if (r.failureReason) return PROBLEM[r.failureReason] ?? r.failureReason;
  const failed = r.stages.find((s) => s.status === 'failed');
  if (failed?.error) return PROBLEM[failed.error] ?? failed.error;
  return r.partial ? 'Partial context' : '';
}

const cell: CSSProperties = { padding: '6px 8px', borderBottom: `1px solid ${token('color.border')}`, textAlign: 'left', verticalAlign: 'top' };

/** Observability: the last 50 reviews, newest first, with how long each stage took and why any failed. */
export function Runs({ api }: { api: AdminApi }) {
  const id = useId();
  const [runs, setRuns] = useState<RunDto[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    void api
      .runs()
      .catch((): ApiError => ({ error: 'unavailable' }))
      .then((r) => (isError(r) ? setError(errorText(r)) : setRuns(r.runs)));
  }, [api]);

  return (
    <section aria-labelledby={`${id}-h`} style={sectionStyle}>
      <h2 id={`${id}-h`} style={h2}>
        Recent runs
      </h2>
      {error && <p style={{ margin: 0 }}>{error}</p>}
      {runs && runs.length === 0 && <p style={{ margin: 0 }}>No reviews yet. They appear here as soon as one starts.</p>}
      {runs && runs.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table aria-label="Last 50 runs" style={{ borderCollapse: 'collapse', width: '100%', font: token('font.body.small') }}>
            <thead>
              <tr>
                {['Work item', 'Started', 'Status', 'Took', 'Agent runs', 'Problem', 'Stages'].map((h) => (
                  <th key={h} scope="col" style={{ ...cell, color: token('color.text.subtle'), fontWeight: token('font.weight.semibold') }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => {
                const name = `${r.issueKey} revision ${r.revision}`;
                const st = STATUS[r.status] ?? { text: r.status, appearance: 'default' as const };
                const expanded = open === r.reviewId;
                return (
                  <Fragment key={r.reviewId}>
                    <tr>
                      <td style={{ ...cell, whiteSpace: 'nowrap' }}>{`${r.issueKey} r${r.revision}`}</td>
                      <td style={{ ...cell, whiteSpace: 'nowrap' }}>{utc(r.createdAt)}</td>
                      <td style={cell}>
                        <Lozenge appearance={st.appearance}>{st.text}</Lozenge>
                      </td>
                      <td style={cell}>{r.durationMs === null ? 'Running' : duration(r.durationMs)}</td>
                      <td style={cell}>{`${r.samplesReceived} of ${r.samplesExpected}`}</td>
                      <td style={cell}>{problemOf(r)}</td>
                      <td style={cell}>
                        <Button appearance="subtle" spacing="compact" aria-expanded={expanded} aria-label={`${expanded ? 'Hide' : 'Show'} stages for ${name}`} onClick={() => setOpen(expanded ? null : r.reviewId)}>
                          {expanded ? 'Hide stages' : 'Show stages'}
                        </Button>
                      </td>
                    </tr>
                    {expanded && (
                      <tr>
                        <td colSpan={7} style={{ ...cell, background: token('elevation.surface.sunken') }}>
                          {r.stages.length === 0 ? (
                            <span>No stages recorded for this run.</span>
                          ) : (
                            <ol aria-label={`Stages of ${name}`} style={{ margin: 0, paddingLeft: 20, display: 'grid', gap: 2 }}>
                              {r.stages.map((s) => (
                                <li key={s.stage} style={{ margin: 0 }}>
                                  {stageText(s)}
                                </li>
                              ))}
                            </ol>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p style={hint}>Times are from the review starting to each stage finishing. Prompt version and samples are kept with each run for audits.</p>
    </section>
  );
}

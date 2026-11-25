import { useEffect, useRef, useState } from 'react';
import Button from '@atlaskit/button/new';
import { token } from '@atlaskit/tokens';
import { errorText, isError, type CreatedRequirements, type PanelApi } from '../bridge.js';
import { useInFlight } from '../components/in-flight.js';
import type { ApiError, PanelDto } from '../types.js';
import { IssueLink, type OpenIssue } from './SeenBefore.js';

/** Open requirements that have no Jira work item yet: what "Turn N requirements into tasks" creates. */
export const openWithoutTask = (dto: Pick<PanelDto, 'requirements'>) => dto.requirements.filter((r) => !r.subtaskKey && (r.status === 'Open' || r.status === 'InProgress'));

/**
 * What creating requirement work items did: the new keys, a line when nothing was created, and why any could not be
 * (an epic in a project without Task or Story types; Jira refusing). The Requirements tab and the header say the same.
 */
export function createdParts(r: { created: Array<{ subtaskKey: string }>; skipped: Array<{ reason: string }> }): { keys: string[]; none: string | null; notes: string[] } {
  const keys = r.created.map((c) => c.subtaskKey);
  const failed = r.skipped.filter((s) => s.reason === 'failed').length;
  const noType = r.skipped.filter((s) => s.reason === 'no_child_type').length;
  const notes: string[] = [];
  if (noType > 0)
    notes.push(
      `${noType} could not be created: Jira allows no sub-tasks under an epic, and this project has no Task or Story work type for them. Add one of those work types to the project and try again, or track the requirements here and mark them Verified with evidence.`,
    );
  if (failed > 0)
    notes.push(
      `Jira did not create ${failed}: check that you can create work items in this project and that it has a sub-task work type (on an epic: Task or Story), then try again.`,
    );
  return { keys, none: keys.length > 0 ? null : failed + noType > 0 ? 'Nothing was created.' : 'No new sub-tasks were needed.', notes };
}

type Outcome = { parts: ReturnType<typeof createdParts> } | { error: string };

/** "Created PAY-12, PAY-13." with each key a link, then any notes. */
function OutcomeText({ outcome, onOpen }: { outcome: Outcome; onOpen?: OpenIssue | undefined }) {
  if ('error' in outcome) return <>{outcome.error}</>;
  const { keys, none, notes } = outcome.parts;
  return (
    <>
      {keys.length > 0 ? (
        <>
          Created{' '}
          {keys.map((k, i) => (
            <span key={k}>
              {i > 0 && ', '}
              <IssueLink issueKey={k} onOpen={onOpen} />
            </span>
          ))}
          .
        </>
      ) : (
        none
      )}
      {notes.map((n) => ` ${n}`).join('')}
    </>
  );
}

/**
 * The panel's one positive action, under the headline: turn the open requirements into Jira work items in one click
 * (sub-tasks; on an epic, Tasks or Stories). Shown to people who can edit the work item while some open requirement has
 * no work item yet. The result is announced in a live region, and focus moves to it because the button goes away.
 */
export function TurnIntoTasks({ dto, api, onChanged, onOpen }: { dto: PanelDto; api: PanelApi; onChanged: () => void; onOpen?: OpenIssue | undefined }) {
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const creating = useInFlight();
  const status = useRef<HTMLParagraphElement>(null);
  const missing = openWithoutTask(dto);
  const canEdit = dto.roles.includes('developer');
  useEffect(() => {
    if (outcome) status.current?.focus();
  }, [outcome]);

  const create = () =>
    creating.run(async () => {
      const r: CreatedRequirements | ApiError = await api.createRequirements(missing.map((x) => x.threatId)).catch((): ApiError => ({ error: 'unavailable' }));
      if (isError(r)) return setOutcome({ error: errorText(r) });
      setOutcome({ parts: createdParts(r) });
      onChanged();
    });

  if (!canEdit) return null;
  const n = missing.length;
  return (
    <div style={{ display: 'grid', gap: 4, justifyItems: 'start' }}>
      {n > 0 && (
        <Button appearance="primary" onClick={() => void create()} isDisabled={creating.busy} testId="threatline-turn-into-tasks">
          {`Turn ${n} ${n === 1 ? 'requirement' : 'requirements'} into tasks`}
        </Button>
      )}
      <p ref={status} role="status" tabIndex={-1} style={{ margin: 0, minHeight: 0, outline: 'none', font: token('font.body.small') }}>
        {outcome && <OutcomeText outcome={outcome} onOpen={onOpen} />}
      </p>
    </div>
  );
}

import { appError, err, FixCheckRecordSchema, ok, type FixCheckRecord, type Result } from '@threatline/shared';
import type { CoreDeps } from '../deps.js';

/** Where a work item's latest fix check lives (docs/FIX_CHECK.md). */
export const fixCheckKey = (issueId: string) => `fixcheck:${issueId}`;
/** The work item's latest fix check. A read that fails or a record that does not parse is an error (fail closed). */
export async function readFixCheck(deps: Pick<CoreDeps, 'state'>, issueId: string): Promise<Result<FixCheckRecord | null>> {
  let v: unknown;
  try {
    v = await deps.state.get<unknown>(fixCheckKey(issueId));
  } catch {
    return err(appError('upstream', 'could not read the fix check'));
  }
  if (v === undefined || v === null) return ok(null);
  const p = FixCheckRecordSchema.safeParse(v);
  return p.success ? ok(p.data) : err(appError('schema', 'stored fix check does not parse'));
}


import { describe, expect, it } from 'vitest';
import { panelResolver } from '../../src/resolvers/index.js';

type Call = (req: { call: { functionKey: string; payload?: unknown }; context: unknown }) => Promise<unknown>;
const call = panelResolver as unknown as Call;

describe('resolver registry', () => {
  it.each(['admin.getPolicy', 'admin.setPolicy', 'admin.warnOnly', 'admin.warnOnlyEnd', 'admin.runs', 'admin.usage', 'admin.setNotifications', 'admin.projectStatuses', 'ledger.proof', 'ledger.treeHead'])(
    '%s is registered, and refuses a call with no signed-in user',
    async (functionKey) => {
      expect(await call({ call: { functionKey, payload: {} }, context: {} })).toMatchObject({ error: 'forbidden' });
    },
  );
  it.each(['panel.diff', 'panel.whatIf', 'inbox.list', 'attestation.check'])('%s is registered, and refuses a call with no work item or user', async (functionKey) => {
    expect(await call({ call: { functionKey, payload: {} }, context: {} })).toEqual({ error: 'not_found' });
  });
  it('an unknown call is not registered', async () => {
    await expect(call({ call: { functionKey: 'admin.nope' }, context: {} })).rejects.toThrow(/no definition/);
  });
});

import { describe, expect, it } from 'vitest';
import { adfToText, createJiraClient, type AdfDoc } from '../../src/adapters/jira.js';
import { fakeHttp, fixture, noSleep } from './fake-http.js';

const client = (routes: Parameters<typeof fakeHttp>[0]) => {
  const http = fakeHttp(routes);
  const s = noSleep();
  return { jira: createJiraClient(http.request, { sleep: s.sleep, random: () => 0 }), calls: http.calls, waits: s.waits };
};

describe('jira client: issue', () => {
  it('maps a full issue: trusted fields, links, ADF description to plain text', async () => {
    const { jira, calls } = client([[/GET \/rest\/api\/3\/issue\/PAY-7\?/, { status: 200, body: fixture('jira', 'issue') }]]);
    const r = await jira.issue('PAY-7');
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const i = r.value;
    expect(i).toMatchObject({
      id: '10042',
      key: 'PAY-7',
      summary: 'Refund webhook from the payment provider',
      issueType: { id: '10001', name: 'Story', subtask: false },
      parent: { id: '10040', key: 'PAY-5' },
      components: ['payments'],
      labels: ['pci'],
      project: { id: '10000', key: 'PAY' },
      status: { name: 'In Progress', category: 'indeterminate' },
      fixVersions: ['2026.12'],
      assignee: 'acc-1',
    });
    expect(i.links).toEqual([
      { type: 'relates to', direction: 'outward', issue: { id: '10050', key: 'PAY-9', summary: 'Payment provider incident', status: 'Done', issueType: 'Bug' } },
      { type: 'is blocked by', direction: 'inward', issue: { id: '10051', key: 'PAY-10', summary: 'Secrets rotation', status: 'To Do', issueType: 'Story' } },
    ]);
    expect(i.description).toContain('@Dana');
    expect(i.description).toContain('verify(sig, body)');
    expect(i.description).toContain('- HMAC check');
    expect(calls[0]!.path).toContain('fields=summary,description,issuetype,parent,issuelinks,components,labels,project,status,fixVersions,assignee');
  });

  it('maps a sparse issue with null description and no optional fields', async () => {
    const { jira } = client([[/GET \/rest\/api\/3\/issue\/PAY-8\?/, { status: 200, body: fixture('jira', 'issue-sparse') }]]);
    const r = await jira.issue('PAY-8');
    expect(r.ok && r.value).toMatchObject({ key: 'PAY-8', description: '', links: [], components: [], labels: [], fixVersions: [] });
    expect(r.ok && r.value.parent).toBeUndefined();
  });

  it('404 → err(not_found)', async () => {
    const { jira } = client([[/issue\/PAY-404/, { status: 404, body: fixture('jira', 'error-404') }]]);
    const r = await jira.issue('PAY-404');
    expect(!r.ok && r.error.code).toBe('not_found');
  });

  it('403 → err(forbidden)', async () => {
    const { jira } = client([[/issue\/PAY-1/, { status: 403, body: '{}' }]]);
    const r = await jira.issue('PAY-1');
    expect(!r.ok && r.error.code).toBe('forbidden');
  });

  it('429 is retried with backoff (honouring Retry-After) and then succeeds', async () => {
    const { jira, calls, waits } = client([
      [/issue\/PAY-7/, [{ status: 429, headers: { 'Retry-After': '2' } }, { status: 429 }, { status: 200, body: fixture('jira', 'issue') }]],
    ]);
    const r = await jira.issue('PAY-7');
    expect(r.ok).toBe(true);
    expect(calls).toHaveLength(3);
    expect(waits[0]).toBe(2000);
    expect(waits[1]).toBeGreaterThan(0);
  });

  it('429 that never clears → err(upstream) after the retry budget, not an endless loop', async () => {
    const { jira, calls } = client([[/issue\/PAY-7/, { status: 429 }]]);
    const r = await jira.issue('PAY-7');
    expect(!r.ok && r.error.code).toBe('upstream');
    expect(calls.length).toBe(4);
  });

  it('a 200 whose body is not JSON → err(upstream)', async () => {
    const { jira } = client([[/issue\/PAY-7/, { status: 200, body: '<html>maintenance</html>' }]]);
    const r = await jira.issue('PAY-7');
    expect(!r.ok && r.error.code).toBe('upstream');
  });

  it('a 200 with an unexpected shape → err(upstream), never a half-filled issue', async () => {
    const { jira } = client([[/issue\/PAY-7/, { status: 200, body: '{"errorMessages":["x"]}' }]]);
    const r = await jira.issue('PAY-7');
    expect(!r.ok && r.error.code).toBe('upstream');
  });

  it('rejects a crafted key that would change the route, without calling Jira', async () => {
    const { jira, calls } = client([[/GET/, { status: 404, body: '{}' }]]);
    const r = await jira.issue('../../rest/api/3/myself');
    expect(!r.ok && r.error.code).toBe('validation');
    expect(calls).toHaveLength(0);
  });
});

describe('jira client: permissions', () => {
  it('canBrowse is true when the check returns the issue id', async () => {
    const { jira, calls } = client([[/POST \/rest\/api\/3\/permissions\/check/, { status: 200, body: fixture('jira', 'permissions-allowed') }]]);
    const r = await jira.canBrowse('acc-1', '10042');
    expect(r).toEqual({ ok: true, value: true });
    expect(JSON.parse(calls[0]!.init!.body!)).toEqual({
      accountId: 'acc-1',
      projectPermissions: [{ permissions: ['BROWSE_PROJECTS'], issues: [10042] }],
    });
    expect(calls[0]!.init!.headers!['Content-Type']).toBe('application/json');
  });

  it('canBrowse is false when the issue is absent from projectPermissions[].issues', async () => {
    const { jira } = client([[/permissions\/check/, { status: 200, body: fixture('jira', 'permissions-denied') }]]);
    expect(await jira.canBrowse('acc-1', '10042')).toEqual({ ok: true, value: false });
  });

  it('canBrowse resolves an issue key to its id first', async () => {
    const { jira, calls } = client([
      [/GET \/rest\/api\/3\/issue\/PAY-7\?/, { status: 200, body: fixture('jira', 'issue') }],
      [/permissions\/check/, { status: 200, body: fixture('jira', 'permissions-allowed') }],
    ]);
    expect(await jira.canBrowse('acc-1', 'PAY-7')).toEqual({ ok: true, value: true });
    expect(JSON.parse(calls[1]!.init!.body!).projectPermissions[0].issues).toEqual([10042]);
  });

  it('canBrowse for an issue that does not exist is false (no existence leak)', async () => {
    const { jira } = client([[/GET \/rest\/api\/3\/issue\/PAY-404/, { status: 404, body: '{}' }]]);
    expect(await jira.canBrowse('acc-1', 'PAY-404')).toEqual({ ok: true, value: false });
  });

  it('canBrowse with no account id is false without calling Jira', async () => {
    const { jira, calls } = client([]);
    expect(await jira.canBrowse('', '10042')).toEqual({ ok: true, value: false });
    expect(calls).toHaveLength(0);
  });

  it('browsable checks many work items in one request per 100 and returns the allowed ids', async () => {
    const ids = Array.from({ length: 101 }, (_, i) => String(20000 + i));
    const { jira, calls } = client([
      [/permissions\/check/, { status: 200, body: JSON.stringify({ projectPermissions: [{ permission: 'BROWSE_PROJECTS', issues: [20000, 20100] }] }) }],
    ]);
    const r = await jira.browsable('acc-1', [...ids, 'not-an-id']);
    expect(r).toEqual({ ok: true, value: ['20000', '20100'] });
    expect(calls).toHaveLength(2);
    expect(JSON.parse(calls[0]!.init!.body!).projectPermissions[0].issues).toHaveLength(100);
    expect(await jira.browsable('', ids)).toEqual({ ok: true, value: [] });
    expect(calls).toHaveLength(2);
  });

  it('canEdit asks for EDIT_ISSUES', async () => {
    const { jira, calls } = client([
      [/permissions\/check/, { status: 200, body: '{"projectPermissions":[{"permission":"EDIT_ISSUES","issues":[10042]}]}' }],
    ]);
    expect(await jira.canEdit('acc-1', '10042')).toEqual({ ok: true, value: true });
    expect(JSON.parse(calls[0]!.init!.body!).projectPermissions[0].permissions).toEqual(['EDIT_ISSUES']);
  });

  it('isAdmin reads the ADMINISTER global permission', async () => {
    const { jira, calls } = client([[/permissions\/check/, { status: 200, body: fixture('jira', 'permissions-admin') }]]);
    expect(await jira.isAdmin('acc-1')).toEqual({ ok: true, value: true });
    expect(JSON.parse(calls[0]!.init!.body!)).toEqual({ accountId: 'acc-1', globalPermissions: ['ADMINISTER'] });
  });

  it('groupsOf returns group names', async () => {
    const { jira, calls } = client([[/GET \/rest\/api\/3\/user\/groups\?accountId=acc-1/, { status: 200, body: fixture('jira', 'groups') }]]);
    expect(await jira.groupsOf('acc-1')).toEqual({ ok: true, value: ['threatline-champions', 'jira-software-users'] });
    expect(calls).toHaveLength(1);
  });
});

describe('jira client: reads', () => {
  it('comments map ADF bodies to text; empty list is fine', async () => {
    const { jira } = client([
      [/issue\/10042\/comment/, { status: 200, body: fixture('jira', 'comments') }],
      [/issue\/10043\/comment/, { status: 200, body: fixture('jira', 'comments-empty') }],
    ]);
    expect(await jira.comments('10042')).toEqual({
      ok: true,
      value: [{ id: '200', body: 'Uses the shared secret', author: 'acc-2', created: '2026-11-11T09:00:00.000+0000', restricted: false }],
    });
    expect(await jira.comments('10043')).toEqual({ ok: true, value: [] });
  });

  it('remote links keep url and default a missing title to the url', async () => {
    const { jira } = client([[/remotelink/, { status: 200, body: fixture('jira', 'remotelinks') }]]);
    const r = await jira.remoteLinks('10042');
    expect(r.ok && r.value).toEqual([
      { url: 'https://one-atlas-mefc.atlassian.net/wiki/spaces/PAY/pages/98305/Refund+design', title: 'Refund design' },
      { url: 'https://example.com/x', title: 'https://example.com/x' },
    ]);
  });

  it('search pages with nextPageToken until max', async () => {
    const { jira, calls } = client([
      [/POST \/rest\/api\/3\/search\/jql/, [{ status: 200, body: fixture('jira', 'search-page1') }, { status: 200, body: fixture('jira', 'search-page2') }]],
    ]);
    const r = await jira.search('parent = 10042', ['summary'], 50);
    expect(r.ok && r.value.map((i) => i.key)).toEqual(['PAY-11', 'PAY-12']);
    expect(JSON.parse(calls[1]!.init!.body!).nextPageToken).toBe('t2');
  });

  it('search stops at max even when more pages exist', async () => {
    const { jira, calls } = client([[/search\/jql/, { status: 200, body: fixture('jira', 'search-page1') }]]);
    const r = await jira.search('project = PAY', ['summary'], 1);
    expect(r.ok && r.value).toHaveLength(1);
    expect(calls).toHaveLength(1);
  });

  it('search reads the priority name when asked for it (Seen before shows an incident’s priority)', async () => {
    const body = JSON.stringify({ issues: [{ id: '20007', key: 'INC-7', fields: { summary: 'Duplicate refunds', priority: { name: 'Highest' } } }, { id: '20008', key: 'INC-8', fields: { summary: 'No priority' } }] });
    const { jira } = client([[/search\/jql/, { status: 200, body }]]);
    const r = await jira.search('labels = incident', ['summary', 'priority'], 10);
    expect(r.ok && r.value.map((i) => [i.key, i.priority])).toEqual([['INC-7', 'Highest'], ['INC-8', undefined]]);
  });

  it('children searches by parent id', async () => {
    const { jira, calls } = client([[/search\/jql/, [{ status: 200, body: fixture('jira', 'search-page1') }, { status: 200, body: fixture('jira', 'search-page2') }]]]);
    const r = await jira.children('10042');
    expect(r.ok && r.value).toHaveLength(2);
    expect(JSON.parse(calls[0]!.init!.body!).jql).toBe('parent = 10042');
  });

  it('children rejects a non-numeric id (no JQL injection)', async () => {
    const { jira, calls } = client([]);
    const r = await jira.children('1 OR project = SECRET');
    expect(!r.ok && r.error.code).toBe('validation');
    expect(calls).toHaveLength(0);
  });
});

describe('jira client: writes', () => {
  it('setProperty PUTs JSON with an explicit content type', async () => {
    const { jira, calls } = client([[/PUT \/rest\/api\/3\/issue\/10042\/properties\/threatline\.verdict/, { status: 200, body: '' }]]);
    expect(await jira.setProperty('10042', 'threatline.verdict', { state: 'block' })).toEqual({ ok: true, value: undefined });
    expect(calls[0]!.init).toMatchObject({ method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: '{"state":"block"}' });
  });

  it('createSubtask posts project + parent + issuetype and returns id/key', async () => {
    const doc: AdfDoc = { type: 'doc', version: 1, content: [{ type: 'paragraph', content: [{ type: 'text', text: 'Given…' }] }] };
    const { jira, calls } = client([
      [/GET \/rest\/api\/3\/issue\/10042\?/, { status: 200, body: fixture('jira', 'issue') }],
      [/POST \/rest\/api\/3\/issue$/, { status: 201, body: fixture('jira', 'created') }],
    ]);
    const r = await jira.createSubtask('10042', { summary: 'Verify HMAC', description: doc, labels: ['threatline'], issueTypeId: '10002' });
    expect(r).toEqual({ ok: true, value: { id: '10070', key: 'PAY-13' } });
    expect(JSON.parse(calls[1]!.init!.body!)).toEqual({
      fields: { project: { id: '10000' }, parent: { id: '10042' }, summary: 'Verify HMAC', description: doc, labels: ['threatline'], issuetype: { id: '10002' } },
    });
  });

  it('subtaskType picks the project\'s sub-task issue type; none → not_found', async () => {
    const { jira, calls } = client([
      [/GET \/rest\/api\/3\/issuetype\/project\?projectId=10000$/, { status: 200, body: JSON.stringify([{ id: '10001', name: 'Story', subtask: false }, { id: '10003', name: 'Subtask', subtask: true }]) }],
    ]);
    expect(await jira.subtaskType('10000')).toEqual({ ok: true, value: '10003' });
    expect(calls).toHaveLength(1);
    const none = client([[/GET \/rest\/api\/3\/issuetype\/project/, { status: 200, body: JSON.stringify([{ id: '10001', name: 'Story', subtask: false }]) }]]);
    expect(await none.jira.subtaskType('10000')).toMatchObject({ ok: false, error: { code: 'not_found' } });
    expect(await none.jira.subtaskType('1 OR 1')).toMatchObject({ ok: false, error: { code: 'validation' } });
  });

  it('getProperty returns the value, null when the property is absent', async () => {
    const { jira } = client([
      [/GET \/rest\/api\/3\/issue\/PAY-7\/properties\/threatline\.verdict$/, { status: 200, body: JSON.stringify({ key: 'threatline.verdict', value: { state: 'block' } }) }],
      [/GET \/rest\/api\/3\/issue\/PAY-8\/properties\/threatline\.verdict$/, { status: 404, body: '{}' }],
    ]);
    expect(await jira.getProperty('PAY-7', 'threatline.verdict')).toEqual({ ok: true, value: { state: 'block' } });
    expect(await jira.getProperty('PAY-8', 'threatline.verdict')).toEqual({ ok: true, value: null });
    expect(await jira.getProperty('PAY 8', 'threatline.verdict')).toMatchObject({ ok: false, error: { code: 'validation' } });
  });

  it('addRemoteLink upserts by globalId', async () => {
    const { jira, calls } = client([[/POST \/rest\/api\/3\/issue\/10042\/remotelink$/, { status: 200, body: JSON.stringify({ id: 1 }) }]]);
    expect(await jira.addRemoteLink('10042', { globalId: 'threatline-threat-model-10042', url: 'https://x/wiki/pages/9', title: 'Threat model' })).toEqual({ ok: true, value: undefined });
    expect(JSON.parse(calls[0]!.init!.body!)).toEqual({ globalId: 'threatline-threat-model-10042', object: { url: 'https://x/wiki/pages/9', title: 'Threat model' } });
  });

  it('projectInfo returns the project id and its issue types', async () => {
    const { jira } = client([[/GET \/rest\/api\/3\/project\/PAY$/, { status: 200, body: JSON.stringify({ id: '10000', key: 'PAY', issueTypes: [{ id: '1', name: 'Epic', subtask: false }, { id: '4', name: 'Subtask', subtask: true }] }) }]]);
    expect(await jira.projectInfo('PAY')).toEqual({ ok: true, value: { id: '10000', key: 'PAY', issueTypes: [{ id: '1', name: 'Epic', subtask: false }, { id: '4', name: 'Subtask', subtask: true }] } });
    expect(await jira.projectInfo('pay; x')).toMatchObject({ ok: false, error: { code: 'validation' } });
  });

  it('projectStatuses lists each status name once, across issue types', async () => {
    const body = [{ name: 'Story', statuses: [{ name: 'To Do' }, { name: 'In Progress' }, { name: 'Done' }] }, { name: 'Bug', statuses: [{ name: 'To Do' }, { name: 'Closed' }] }];
    const { jira } = client([[/GET \/rest\/api\/3\/project\/PAY\/statuses$/, { status: 200, body: JSON.stringify(body) }]]);
    expect(await jira.projectStatuses('PAY')).toEqual({ ok: true, value: ['To Do', 'In Progress', 'Done', 'Closed'] });
    expect(await jira.projectStatuses('pay; x')).toMatchObject({ ok: false, error: { code: 'validation' } });
  });

  it('ensureComponent creates the component only when the project lacks it', async () => {
    const has = client([[/GET \/rest\/api\/3\/project\/PAY\/components$/, { status: 200, body: JSON.stringify([{ id: '1', name: 'support-agent' }]) }]]);
    expect(await has.jira.ensureComponent('PAY', 'support-agent')).toEqual({ ok: true, value: undefined });
    expect(has.calls).toHaveLength(1);
    const lacks = client([
      [/GET \/rest\/api\/3\/project\/PAY\/components$/, { status: 200, body: '[]' }],
      [/POST \/rest\/api\/3\/component$/, { status: 201, body: JSON.stringify({ id: '2' }) }],
    ]);
    await lacks.jira.ensureComponent('PAY', 'support-agent');
    expect(JSON.parse(lacks.calls[1]!.init!.body!)).toEqual({ name: 'support-agent', project: 'PAY' });
  });

  it('createIssue posts project, type, summary, ADF, labels, components and parent', async () => {
    const doc: AdfDoc = { type: 'doc', version: 1, content: [] };
    const { jira, calls } = client([[/POST \/rest\/api\/3\/issue$/, { status: 201, body: fixture('jira', 'created') }]]);
    expect(await jira.createIssue({ projectId: '10000', issueTypeId: '2', summary: 'S', description: doc, labels: ['threatline-demo'], components: ['support-agent'], parentId: '10042' })).toEqual({ ok: true, value: { id: '10070', key: 'PAY-13' } });
    expect(JSON.parse(calls[0]!.init!.body!)).toEqual({ fields: { project: { id: '10000' }, issuetype: { id: '2' }, summary: 'S', description: doc, labels: ['threatline-demo'], components: [{ name: 'support-agent' }], parent: { id: '10042' } } });
  });

  it('addLabel / removeLabel use the update verbs', async () => {
    const { jira, calls } = client([[/PUT \/rest\/api\/3\/issue\/10042$/, { status: 204 }]]);
    await jira.addLabel('10042', 'threatline-review');
    await jira.removeLabel('10042', 'threatline-review');
    expect(JSON.parse(calls[0]!.init!.body!)).toEqual({ update: { labels: [{ add: 'threatline-review' }] } });
    expect(JSON.parse(calls[1]!.init!.body!)).toEqual({ update: { labels: [{ remove: 'threatline-review' }] } });
  });

  it('comment posts the ADF body', async () => {
    const doc: AdfDoc = { type: 'doc', version: 1, content: [] };
    const { jira, calls } = client([[/POST \/rest\/api\/3\/issue\/10042\/comment/, { status: 201, body: '{"id":"1"}' }]]);
    expect((await jira.comment('10042', doc)).ok).toBe(true);
    expect(JSON.parse(calls[0]!.init!.body!)).toEqual({ body: doc });
  });

  it("comment returns the new comment's id and author (Threatline's own account, for comments posted as the app)", async () => {
    const doc: AdfDoc = { type: 'doc', version: 1, content: [] };
    const posted = client([[/POST \/rest\/api\/3\/issue\/10042\/comment/, { status: 201, body: '{"id":"301","author":{"accountId":"557058:app","accountType":"app"}}' }]]);
    expect(await posted.jira.comment('10042', doc)).toEqual({ ok: true, value: { id: '301', authorAccountId: '557058:app' } });
    // The comment exists even when the reply is not the expected shape: that is still a success, never a retry.
    const odd = client([[/POST \/rest\/api\/3\/issue\/10042\/comment/, { status: 201, body: '{"id":7}' }]]);
    expect(await odd.jira.comment('10042', doc)).toEqual({ ok: true, value: { id: '', authorAccountId: '' } });
  });

  it('comments reads a window wider than the 20 the gatherer keeps', async () => {
    const { jira, calls } = client([[/issue\/10042\/comment/, { status: 200, body: '{"comments":[]}' }]]);
    await jira.comments('10042');
    expect(calls[0]!.path).toMatch(/orderBy=-created&maxResults=50$/);
  });

  it('a 400 on write → err(validation) carrying Jira’s messages', async () => {
    const { jira } = client([[/PUT/, { status: 400, body: '{"errorMessages":["Field labels cannot be set"],"errors":{}}' }]]);
    const r = await jira.addLabel('10042', 'x');
    expect(!r.ok && r.error).toMatchObject({ code: 'validation', message: expect.stringContaining('Field labels cannot be set') });
  });
});

describe('adfToText', () => {
  it('handles mentions, code blocks, hard breaks, emoji, cards and nested lists', () => {
    const doc = {
      type: 'doc',
      version: 1,
      content: [
        { type: 'heading', attrs: { level: 2 }, content: [{ type: 'text', text: 'Design' }] },
        { type: 'paragraph', content: [{ type: 'text', text: 'Hi ' }, { type: 'mention', attrs: { text: '@Sam' } }, { type: 'hardBreak' }, { type: 'emoji', attrs: { shortName: ':lock:', text: '🔒' } }] },
        { type: 'codeBlock', content: [{ type: 'text', text: 'a()\nb()' }] },
        { type: 'paragraph', content: [{ type: 'inlineCard', attrs: { url: 'https://x.test/a' } }] },
        { type: 'orderedList', content: [{ type: 'listItem', content: [{ type: 'paragraph', content: [{ type: 'text', text: 'one' }] }, { type: 'bulletList', content: [{ type: 'listItem', content: [{ type: 'paragraph', content: [{ type: 'text', text: 'nested' }] }] }] }] }] },
      ],
    };
    const t = adfToText(doc);
    expect(t).toBe('Design\nHi @Sam\n🔒\na()\nb()\nhttps://x.test/a\n- one\n  - nested');
  });

  it('returns "" for null, strings pass through, and deep nesting is bounded', () => {
    expect(adfToText(null)).toBe('');
    expect(adfToText('plain')).toBe('plain');
    let deep: Record<string, unknown> = { type: 'text', text: 'bottom' };
    for (let i = 0; i < 500; i++) deep = { type: 'paragraph', content: [deep] };
    expect(() => adfToText({ type: 'doc', content: [deep] })).not.toThrow();
  });
});

describe('jira client: restricted comments (security)', () => {
  it('marks comments with a visibility restriction', async () => {
    const body = JSON.stringify({ comments: [
      { id: '1', author: { accountId: 'a' }, created: 't', body: 'open' },
      { id: '2', author: { accountId: 'a' }, created: 't', body: 'admins only', visibility: { type: 'role', value: 'Administrators' } },
    ] });
    const { jira } = client([[/comment/, { status: 200, body }]]);
    const r = await jira.comments('10042');
    expect(r.ok && r.value.map((c) => [c.id, c.restricted])).toEqual([['1', false], ['2', true]]);
  });
});

describe('jira client: permission checks as the user (impersonation)', () => {
  it('canBrowse/canEdit/isAdmin ask Jira as that user via mypermissions when a user transport is given', async () => {
    const app = fakeHttp([[/GET \/rest\/api\/3\/issue\/PAY-7\?/, { status: 200, body: fixture('jira', 'issue') }]]);
    const asUserCalls: string[] = [];
    const user = (accountId: string) =>
      fakeHttp([
        [/mypermissions\?issueId=10042&permissions=BROWSE_PROJECTS/, { status: 200, body: JSON.stringify({ permissions: { BROWSE_PROJECTS: { havePermission: accountId === 'acc-ok' } } }) }],
        [/mypermissions\?issueId=10042&permissions=EDIT_ISSUES/, { status: 200, body: '{"permissions":{"EDIT_ISSUES":{"havePermission":false}}}' }],
        [/mypermissions\?permissions=ADMINISTER/, { status: 200, body: '{"permissions":{"ADMINISTER":{"havePermission":true}}}' }],
      ]).request;
    const jira = createJiraClient(app.request, { sleep: noSleep().sleep, asUser: (a) => (asUserCalls.push(a), user(a)) });
    expect(await jira.canBrowse('acc-ok', 'PAY-7')).toEqual({ ok: true, value: true });
    expect(await jira.canBrowse('acc-no', '10042')).toEqual({ ok: true, value: false });
    expect(await jira.canEdit('acc-ok', '10042')).toEqual({ ok: true, value: false });
    expect(await jira.isAdmin('acc-ok')).toEqual({ ok: true, value: true });
    expect(asUserCalls).toEqual(['acc-ok', 'acc-no', 'acc-ok', 'acc-ok']);
    expect(app.calls.some((c) => c.path.includes('permissions/check'))).toBe(false);
  });

  it('browsable searches as the user (id in (…)), so Jira returns only what they can see; no app-level permissions/check', async () => {
    const app = fakeHttp([]);
    const bodies: string[] = [];
    const user = () => (path: string, init?: { body?: string }) => {
      bodies.push(`${path} ${init?.body ?? ''}`);
      return fakeHttp([[/POST \/rest\/api\/3\/search\/jql/, { status: 200, body: JSON.stringify({ issues: [{ id: '20001', key: 'PAY-1', fields: {} }] }) }]]).request(path, init as never);
    };
    const jira = createJiraClient(app.request, { sleep: noSleep().sleep, asUser: user as never });
    expect(await jira.browsable('acc-1', ['20001', '20002', 'x"; drop'])).toEqual({ ok: true, value: ['20001'] });
    expect(bodies).toHaveLength(1);
    expect(JSON.parse(bodies[0]!.split(' ').slice(1).join(' '))).toMatchObject({ jql: 'id in (20001,20002)', maxResults: 100 });
    expect(app.calls).toHaveLength(0);
  });

  it('a 404/403 for the user means no permission', async () => {
    const user = () => fakeHttp([[/mypermissions/, { status: 404, body: '{}' }]]).request;
    const jira = createJiraClient(fakeHttp([]).request, { sleep: noSleep().sleep, asUser: user });
    expect(await jira.canBrowse('acc', '10042')).toEqual({ ok: true, value: false });
  });
});

describe('jira client: installGate', () => {
  it('reads the project workflows and updates them as the admin, adding the gate once', async () => {
    const app = fakeHttp([[/GET \/rest\/api\/3\/project\/PAY$/, { status: 200, body: JSON.stringify({ id: '10001', key: 'PAY', issueTypes: [{ id: '1', name: 'Story' }] }) }]]);
    const read = {
      statuses: [{ statusReference: '5', name: 'Done' }],
      workflows: [{ id: 'w1', name: 'Software workflow for project PAY', isEditable: true, version: { versionNumber: 1 }, transitions: [{ name: 'Done', toStatusReference: '5', validators: [] }] }],
    };
    const user = fakeHttp([
      [/POST \/rest\/api\/3\/workflows$/, { status: 200, body: JSON.stringify(read) }, /"projectAndIssueTypes":\[\{"projectId":"10001","issueTypeId":"1"\}\]/],
      [/POST \/rest\/api\/3\/workflows\/update$/, { status: 200, body: '{}' }],
    ]);
    const jira = createJiraClient(app.request, { sleep: noSleep().sleep, asUser: () => user.request });
    const ext = 'ari:cloud:ecosystem::extension/13898a7c-6897-48d3-a512-079d9f9f5f00/511a7dd3-8745-4121-8c4d-664f8fff2fae/static/threatline-gate';
    expect(await jira.installGate('acc-admin', 'PAY', 'Done', ext)).toEqual({ ok: true, value: { added: ['Software workflow for project PAY: Done'], already: [], readOnly: [] } });
    const update = JSON.parse(user.calls.at(-1)!.init!.body!);
    expect(update.workflows[0].transitions[0].validators).toEqual([{ ruleKey: 'forge:expression-validator', parameters: { key: ext, config: '' } }]);
  });
});

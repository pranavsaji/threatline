import { describe, expect, it } from 'vitest';
import { createJiraClient } from '../../src/adapters/jira.js';
import { fakeHttp, noSleep } from './fake-http.js';

const client = (routes: Parameters<typeof fakeHttp>[0]) => {
  const http = fakeHttp(routes);
  return { jira: createJiraClient(http.request, { sleep: noSleep().sleep, random: () => 0 }), calls: http.calls };
};

describe('jira client: groupExists', () => {
  it('asks for the group by exact name and matches it exactly', async () => {
    const { jira, calls } = client([[/GET \/rest\/api\/3\/group\/bulk\?groupName=threatline-security-champions&maxResults=1/, { status: 200, body: '{"values":[{"name":"threatline-security-champions","groupId":"g1"}]}' }]]);
    expect(await jira.groupExists!('threatline-security-champions')).toEqual({ ok: true, value: true });
    expect(calls).toHaveLength(1);
  });

  it('no match, or a 404, is false; a name with spaces is encoded', async () => {
    const { jira, calls } = client([
      [/groupName=security%20champions/, { status: 200, body: '{"values":[]}' }],
      [/groupName=gone/, { status: 404, body: '{}' }],
    ]);
    expect(await jira.groupExists!('security champions')).toEqual({ ok: true, value: false });
    expect(await jira.groupExists!('gone')).toEqual({ ok: true, value: false });
    expect(calls[0]!.path).toContain('groupName=security%20champions');
  });
});

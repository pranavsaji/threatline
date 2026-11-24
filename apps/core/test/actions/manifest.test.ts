import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { allAsvs, strideDefaults } from '@threatline/frameworks';
import { StrideSchema } from '@threatline/shared';

type Mod = Record<string, unknown>;
const root = join(import.meta.dirname, '..', '..');
const m = parse(readFileSync(join(root, 'manifest.yml'), 'utf8')) as { app: Mod; modules: Record<string, Mod[]>; resources: Mod[] };
const actions = new Map(m.modules.action!.map((a) => [a.key as string, a]));

const VERBS: Record<string, string> = {
  'get-review': 'GET',
  'get-security-requirements': 'GET',
  'check-change-risk': 'GET',
  'explain-threat': 'GET',
  'release-readiness': 'GET',
  'posture-summary': 'GET',
  'get-merge-attestation': 'CREATE',
  'request-risk-acceptance': 'CREATE',
  'start-review': 'TRIGGER',
  'verify-requirement': 'UPDATE',
};
const MCP_TOOLS = ['get-review', 'get-security-requirements', 'check-change-risk', 'get-merge-attestation', 'request-risk-acceptance', 'verify-requirement', 'explain-threat', 'posture-summary'];

describe('manifest: Rovo actions, skill and MCP (Task 28)', () => {
  it('shares one installation across Jira and Confluence, so MCP, page events and the agent see Jira data', () => {
    expect(m.app.compatibility).toEqual({ jira: { required: true }, confluence: { required: false } });
  });

  it('declares every spec action with its verb, a handler, and primitive inputs only', () => {
    const fns = new Set(m.modules.function!.map((f) => f.key));
    for (const [key, verb] of Object.entries(VERBS)) {
      const a = actions.get(key);
      expect(a, key).toBeDefined();
      expect(a!.actionVerb, key).toBe(verb);
      expect(fns.has(a!.function), key).toBe(true);
      for (const [name, input] of Object.entries((a!.inputs ?? {}) as Record<string, { type: string; description?: string }>)) {
        expect(['string', 'integer', 'number', 'boolean'], `${key}.${name}`).toContain(input.type);
        expect(input.description, `${key}.${name}`).toBeTruthy();
      }
    }
  });

  it('the agent can call every action; the MCP module exposes the eight MCP actions', () => {
    const agent = m.modules['rovo:agent']![0]!;
    expect(new Set(agent.actions as string[])).toEqual(new Set([...Object.keys(VERBS), 'get-review-context', 'submit-threat-model']));
    expect(agent.skills).toEqual(['threat-model-review']);
    const mcp = m.modules['rovo:mcp'];
    expect(mcp).toHaveLength(1);
    expect((mcp![0]!.name as string).length).toBeLessThanOrEqual(30);
    expect(mcp![0]!.tools).toEqual(MCP_TOOLS);
  });

  it('the skill directory exists, SKILL.md frontmatter names it, and its tools are actions', () => {
    const skill = m.modules['rovo:skill']![0]!;
    const dir = (skill.source as { dir: string }).dir;
    expect(dir).toBe('skills/threat-model-review');
    const md = readFileSync(join(root, dir, 'SKILL.md'), 'utf8');
    const front = /^---\n([\s\S]*?)\n---\n/.exec(md);
    const meta = parse(front![1]!) as { name: string; description: string; 'allowed-tools'?: string };
    expect(meta.name).toBe('threat-model-review');
    expect(meta.description.length).toBeGreaterThanOrEqual(50);
    const tools = (skill.dependencies as { tools: string[] }).tools;
    for (const t of tools) expect(actions.has(t), t).toBe(true);
    expect(meta['allowed-tools']!.split(' ').sort()).toEqual([...tools].sort());
    expect(md.split('\n').length).toBeLessThanOrEqual(500);
    for (const ref of ['asvs-5-map.md', 'stride-checklist.md', 'agentic-top10.md']) expect(existsSync(join(root, dir, 'references', ref)), ref).toBe(true);
  });

  it('references/asvs-5-map.md matches the bundled ASVS data (every chapter, every STRIDE starting id)', () => {
    const md = readFileSync(join(root, 'skills/threat-model-review/references/asvs-5-map.md'), 'utf8');
    for (const ch of new Set(allAsvs().map((r) => r.chapter))) expect(md, ch).toContain(`### ${ch}`);
    for (const s of StrideSchema.options) for (const id of strideDefaults(s).asvs) expect(md, id).toContain(`**${id}**`);
  });

  it('ships the open-source IDE skill with the spec workflow', () => {
    const md = readFileSync(join(root, '..', '..', 'mcp-skill', 'skill.md'), 'utf8');
    expect(md).toMatch(/get-security-requirements/);
    expect(md).toMatch(/check-change-risk/);
    expect(md).toMatch(/get-merge-attestation/);
    expect(md).toMatch(/https:\/\/mcp\.atlassian\.com\/forge\//);
  });
});

describe('manifest: posture surfaces (Task 29)', () => {
  it('a global page and a dashboard gadget serve the posture view through the shared resolver', () => {
    const page = (m.modules['jira:globalPage'] ?? []).find((x) => x.key === 'threatline-posture');
    expect(page).toMatchObject({ resource: 'panel', resolver: { function: 'panelResolverFn' }, title: 'Threatline security posture' });
    const gadget = (m.modules['jira:dashboardGadget'] ?? []).find((x) => x.key === 'threatline-posture-gadget');
    expect(gadget).toMatchObject({ resource: 'panel', resolver: { function: 'panelResolverFn' } });
    expect(gadget!.description).toBeTruthy();
    expect(gadget!.thumbnail).toMatch(/^https:\/\//);
  });
});

describe('manifest: the gate status in the work item context column', () => {
  it('a jira:issueContext module serves the status view through the shared UI and resolver, with the panel icon', () => {
    const ctx = (m.modules['jira:issueContext'] ?? []).find((x) => x.key === 'threatline-status');
    const panel = (m.modules['jira:issuePanel'] ?? []).find((x) => x.key === 'threatline-panel');
    expect(ctx).toMatchObject({ resource: 'panel', resolver: { function: 'panelResolverFn' }, title: 'Threatline', icon: panel!.icon });
    // Jira requires a label (the context button's text).
    expect(ctx!.label).toBeTruthy();
  });

  it('the UI router has a view for every Custom UI module key', () => {
    const router = readFileSync(join(root, 'ui', 'src', 'router.tsx'), 'utf8');
    const keys = ['jira:issuePanel', 'jira:issueContext', 'jira:adminPage', 'jira:globalPage', 'jira:dashboardGadget'].flatMap((mod) => (m.modules[mod] ?? []).map((x) => x.key as string));
    for (const k of keys) expect(router, k).toContain(`case '${k}':`);
  });
});

describe('Marketplace readiness (Task 33)', () => {
  /**
   * Modules checked as not EAP. EAP modules can only be enabled on development environments, so one here would block
   * the Marketplace listing; Preview is supported in production. rovo:skill and rovo:mcp were checked on
   * developer.atlassian.com on 2026-11-18 (both Preview); the rest per docs/research/forge-api-notes.md. A new module
   * fails this test until its status is checked and added.
   */
  const NOT_EAP = new Set(['sql', 'trigger', 'consumer', 'scheduledTrigger', 'jira:issuePanel', 'jira:issueContext', 'jira:adminPage', 'jira:globalPage', 'jira:dashboardGadget', 'jira:workflowValidator', 'jira:entityProperty', 'action', 'rovo:skill', 'rovo:mcp', 'rovo:agent', 'function', 'llm', 'webtrigger']);
  // `webtrigger` (CI verification, docs/CI_VERIFICATION.md): a long-standing GA Forge module, no scope needed.
  // `jira:issueContext` (the gate status in the context column): listed with no EAP or Preview label in the Jira module
  // index on developer.atlassian.com, checked 2026-11-24.
  // `llm` (Forge LLMs, Threatline Engine): generally available; checked 2026-11-20 (Atlassian community: "Forge LLMs GA").
  it('uses no EAP module, so no separate production manifest is needed', () => {
    const unknown = Object.keys(m.modules).filter((k) => !NOT_EAP.has(k));
    expect(unknown).toEqual([]);
  });
  it('declares no egress, so the app can qualify for Runs on Atlassian', () => {
    // Egress is declared under permissions.external (fetch/backend/client hosts). Teamwork Graph read scopes such as
    // read:graph:pull-request:external name an object type, not a host, and send nothing out.
    const perms = ((m as unknown as { permissions?: Record<string, unknown> }).permissions ?? {}) as Record<string, unknown>;
    expect(perms.external).toBeUndefined();
    expect(Object.keys(perms).sort()).toEqual(['scopes']);
    const scopes = Object.keys((perms.scopes ?? {}) as Record<string, unknown>);
    expect(scopes.filter((s) => /fetch|backend|client/.test(s))).toEqual([]);
  });
});

describe('manifest: Paid via Atlassian licensing stays off until the February flip (docs/LICENSING.md)', () => {
  it('licensing is not enabled yet, so production can still be installed by link', () => {
    // Step 1 of the February runbook in docs/LICENSING.md changes this test in the same commit as the manifest.
    expect((m.app.licensing as { enabled?: unknown } | undefined)?.enabled).not.toBe(true);
  });

  it('the patch in docs/LICENSING.md names triggers that exist here', () => {
    const doc = readFileSync(join(root, '..', '..', 'docs', 'LICENSING.md'), 'utf8');
    const keys = new Set(m.modules.trigger!.map((t) => t.key as string));
    for (const k of ['issue-events', 'page-events']) {
      expect(keys.has(k)).toBe(true);
      expect(doc).toContain(`key: ${k}`);
    }
  });
});

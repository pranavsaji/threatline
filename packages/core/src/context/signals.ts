import type { ContextFact, DataClass, Exposure } from '@threatline/shared';

export interface Evidence {
  factId: string;
  quote: string;
}
export interface Signals {
  dataClasses: DataClass[];
  exposure: Exposure;
  llmFeatures: boolean;
  /** The AI feature can act (tools, shell, outbound actions), not only answer. */
  agentTools: boolean;
  /** Money moves (charges, refunds, transfers, payouts), not only payment data being mentioned. */
  paymentFlow: boolean;
  /** Secrets or credentials are stored, logged, embedded or shared somewhere they could leak from. */
  secretHandling: boolean;
  fileUpload: boolean;
  auth: boolean;
  payment: boolean;
  thirdParty: string[];
  /** Keys: a data class name, 'exposure', 'llmFeatures', 'agentTools', 'paymentFlow', 'secretHandling', 'fileUpload', 'auth', or `thirdParty:<name>`. */
  evidence: Record<string, Evidence>;
}

/** Keyword table (data, not logic). A trailing `*` means "word starting with". Matching is case-insensitive on word boundaries. */
export const SIGNAL_KEYWORDS = {
  pii: ['email address*', 'e-mail*', 'phone number*', 'address*', 'date of birth', 'ssn', 'social security', 'passport*', 'personal data', 'customer name*', 'pii'],
  credentials: ['password*', 'credential*', 'login details'],
  payment: ['credit card*', 'card number*', 'stripe', 'payment*', 'checkout', 'pci', 'refund*', 'billing', 'invoice*'],
  health: ['medical', 'health record*', 'diagnos*', 'patient*', 'hipaa'],
  secrets: ['api key*', 'secret key*', 'private key*', 'signing key*', 'access token*', 'secret', 'secrets', 'client secret*', 'signing secret*', 'hs256', 'hmac', 'encryption key*'],
  public: ['public', 'internet-facing', 'external customer*', 'mobile app*', 'website', 'webhook*', 'public api', 'anonymous user*'],
  partner: ['partner*', 'b2b', 'vendor portal', 'third-party integration*'],
  // "agent" alone counts unless a person is meant ("support agents", "sales agent"): see HUMAN_AGENT.
  llm: ['llm*', 'gpt*', 'claude', 'language model*', 'ai agent*', 'ai assistant*', 'agentic', 'agent', 'agents', 'rag', 'embedding*', 'tool call*', 'prompt', 'prompts', 'system prompt*', 'chatbot*', 'copilot*', 'genai', 'generative ai'],
  agentTools: ['tool', 'tools', 'tool call*', 'function call*', 'shell', 'mcp', 'plugin*', 'execut*', 'runs commands', 'run commands', 'sql', 'refund*', 'book*', 'send*', 'forward*', 'install*', 'api call*', 'calls the api', 'browse*', 'writes to', 'creates tickets', 'takes actions'],
  paymentFlow: ['refund*', 'checkout', 'charge', 'charges', 'charged', 'charging', 'payout*', 'pay out', 'transfer*', 'amount*', 'price*', 'pays', 'paid', 'payments', 'stripe', 'paypal', 'wallet*', 'store credit', 'discount*'],
  secretHandling: ['hard-coded', 'hardcoded', 'plain text', 'plaintext', 'environment variable*', 'config file*', 'stored in', 'stores passwords', 'log file*', 'log system*', 'logs full', 'logs the', 'logged to', 'written to log*', 'shared secret*', 'embedded', 'in the url', 'query string', 'api key*', 'secret key*', 'private key*', 'signing key*', 'access token*', 'refresh token*'],
  fileUpload: ['upload*', 'attachment*', 'file import*'],
  auth: ['authenticat*', 'login*', 'log in', 'sign in', 'session*', 'oauth', 'sso', 'jwt*', 'mfa', 'single sign-on'],
  thirdParty: ['stripe', 'paypal', 'twilio', 'sendgrid', 'openai', 'anthropic', 'salesforce', 'slack', 'zendesk', 'shopify', 's3', 'google'],
} as const;

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const toRegex = (kw: string): RegExp =>
  kw.endsWith('*') ? new RegExp(`\\b${escape(kw.slice(0, -1))}[a-z]*`, 'i') : new RegExp(`\\b${escape(kw)}\\b`, 'i');
/**
 * "agent" preceded by a word that makes it a person. Judged per occurrence, so extra text can never hide another
 * occurrence: signals stay monotonic.
 */
const HUMAN_AGENT = '(?<!\\b(?:support|sales|service|call[- ]cent(?:er|re)|human|travel|insurance|user|estate|booking|customer|field|leasing|ticket) )';
const keywordRegex = (kw: string): RegExp => (kw === 'agent' || kw === 'agents' ? new RegExp(`\\b${HUMAN_AGENT}${kw}\\b`, 'i') : toRegex(kw));
const COMPILED = Object.fromEntries(
  Object.entries(SIGNAL_KEYWORDS).map(([k, list]) => [k, (list as readonly string[]).map((kw) => ({ kw: kw.replace(/\*$/, ''), re: keywordRegex(kw) }))]),
) as Record<keyof typeof SIGNAL_KEYWORDS, Array<{ kw: string; re: RegExp }>>;

/** The sentence around `index`, at most 200 chars, always a verbatim substring of `text`. */
export function sentenceAround(text: string, index: number, matchLength: number): string {
  let start = index;
  while (start > 0 && !/[.!?\n]/.test(text[start - 1] ?? '')) start--;
  let end = index + matchLength;
  while (end < text.length && !/[.!?\n]/.test(text[end] ?? '')) end++;
  if (end < text.length) end++;
  let s = text.slice(start, end);
  if (s.length > 200) {
    const from = Math.max(start, Math.min(index - 80, end - 200));
    s = text.slice(from, from + 200);
  }
  return s.trim();
}

function findFirst(facts: readonly ContextFact[], key: keyof typeof SIGNAL_KEYWORDS): Evidence | undefined {
  for (const f of facts) {
    for (const { re } of COMPILED[key]) {
      const m = re.exec(f.excerpt);
      if (m) return { factId: f.id, quote: sentenceAround(f.excerpt, m.index, m[0].length) };
    }
  }
  return undefined;
}

/**
 * Deterministic, monotonic signal extraction: more text can only add signals, so a poisoned page can never lower them.
 */
export function extractSignals(facts: readonly ContextFact[]): Signals {
  const evidence: Record<string, Evidence> = {};
  const dataClasses: DataClass[] = [];
  for (const dc of ['pii', 'credentials', 'payment', 'health', 'secrets'] as const) {
    const ev = findFirst(facts, dc);
    if (ev) {
      dataClasses.push(dc);
      evidence[dc] = ev;
    }
  }
  const pub = findFirst(facts, 'public');
  const partner = pub ? undefined : findFirst(facts, 'partner');
  const exposure: Exposure = pub ? 'public' : partner ? 'partner' : 'internal';
  if (pub ?? partner) evidence.exposure = (pub ?? partner)!;
  const flag = (key: 'llm' | 'agentTools' | 'paymentFlow' | 'secretHandling' | 'fileUpload' | 'auth', name: string): boolean => {
    const ev = findFirst(facts, key);
    if (ev) evidence[name] = ev;
    return ev !== undefined;
  };
  const llmFeatures = flag('llm', 'llmFeatures');
  const agentTools = flag('agentTools', 'agentTools');
  const paymentFlow = flag('paymentFlow', 'paymentFlow');
  const secretHandling = flag('secretHandling', 'secretHandling');
  const fileUpload = flag('fileUpload', 'fileUpload');
  const auth = flag('auth', 'auth');
  const thirdParty: string[] = [];
  for (const { kw, re } of COMPILED.thirdParty) {
    for (const f of facts) {
      const m = re.exec(f.excerpt);
      if (m) {
        thirdParty.push(kw);
        evidence[`thirdParty:${kw}`] = { factId: f.id, quote: sentenceAround(f.excerpt, m.index, m[0].length) };
        break;
      }
    }
  }
  return { dataClasses, exposure, llmFeatures, agentTools, paymentFlow, secretHandling, fileUpload, auth, payment: dataClasses.includes('payment'), thirdParty, evidence };
}

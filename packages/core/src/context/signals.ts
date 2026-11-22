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
  pii: ['email address*', 'e-mail*', 'email', 'emails', 'phone', 'phones', 'phone number*', 'address*', 'date of birth', 'ssn', 'social security', 'passport*', 'personal data', 'customer name*', 'pii'],
  credentials: ['password*', 'credential*', 'login details'],
  payment: ['credit card*', 'card number*', 'stripe', 'payment*', 'checkout', 'pci', 'refund*', 'billing', 'invoice*'],
  health: ['medical', 'health record*', 'diagnos*', 'patient*', 'hipaa'],
  // `redacted:` is the marker redaction leaves (`[REDACTED:aws_key]`): a real secret in the text must still count as one.
  secrets: ['api key*', 'secret key*', 'private key*', 'signing key*', 'access token*', 'secret', 'secrets', 'client secret*', 'signing secret*', 'hs256', 'hmac', 'encryption key*', 'redacted:'],
  public: ['public', 'internet-facing', 'external customer*', 'mobile app*', 'website', 'webhook*', 'public api', 'anonymous user*'],
  partner: ['partner*', 'b2b', 'vendor portal', 'third-party integration*'],
  // "agent" alone counts unless a person is meant ("support agents", "sales agent"): see HUMAN_AGENT.
  llm: ['llm*', 'gpt*', 'claude', 'openai', 'gemini', 'mistral', 'llama', 'language model*', 'ai agent*', 'ai _ agent*', 'ai assistant*', 'agentic', 'agent', 'agents', 'rag', 'embedding*', 'tool call*', 'prompt', 'prompts', 'system prompt*', 'chatbot*', 'copilot*', 'genai', 'generative ai'],
  agentTools: ['tool', 'tools', 'tool call*', 'function call*', 'shell', 'mcp', 'plugin*', 'execut*', 'runs commands', 'run commands', 'sql', 'refund*', 'book*', 'send*', 'forward*', 'install*', 'api call*', 'calls the api', 'browse*', 'writes to', 'creates tickets', 'takes actions'],
  paymentFlow: ['refund*', 'checkout', 'charge', 'charges', 'charged', 'charging', 'payout*', 'pay out', 'transfer*', 'amount*', 'price*', 'pays', 'paid', 'payments', 'stripe', 'paypal', 'wallet*', 'store credit', 'discount*'],
  secretHandling: ['redacted:', 'hard-coded', 'hardcoded', 'plain text', 'plaintext', 'environment variable*', 'config file*', 'stored in', 'stores passwords', 'log file*', 'log system*', 'logs full', 'logs the', 'logged to', 'written to log*', 'shared secret*', 'embedded', 'in the url', 'query string', 'api key*', 'secret key*', 'private key*', 'signing key*', 'access token*', 'refresh token*'],
  fileUpload: ['upload*', 'attachment*', 'file import*'],
  auth: ['authenticat*', 'login*', 'log in', 'log-in', 'logged in', 'logged-in', 'logs in', 'sign in', 'sign-in', 'signed in', 'signed-in', 'signs in', 'sign up', 'sign-up', 'signup*', 'session*', 'oauth', 'sso', 'jwt*', 'mfa', 'single sign-on'],
  thirdParty: ['stripe', 'paypal', 'twilio', 'sendgrid', 'openai', 'anthropic', 'salesforce', 'slack', 'zendesk', 'shopify', 's3', 'google'],
} as const;

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/** `_` in a keyword stands for any one word (`ai _ agent` matches "AI support agent"); a trailing `:` needs no word end. */
const body = (kw: string) => escape(kw).replace(/ _ /g, ' \\w+ ');
const toRegex = (kw: string): RegExp =>
  kw.endsWith('*') ? new RegExp(`\\b${body(kw.slice(0, -1))}[a-z]*`, 'i') : new RegExp(`\\b${body(kw)}${kw.endsWith(':') ? '' : '\\b'}`, 'i');
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

/** A quote long enough to cite on its own (threats/grounding.ts needs 12 characters). */
const citable = (quote: string) => quote.replace(/[^a-z0-9]+/gi, '').length >= 12;

/**
 * The first match, preferring one whose sentence is long enough to cite: a one-word comment ("Session.") must not stand
 * in for the design page's sentence that says the same thing at length.
 */
function findFirst(facts: readonly ContextFact[], key: keyof typeof SIGNAL_KEYWORDS): Evidence | undefined {
  let first: Evidence | undefined;
  for (const f of facts) {
    for (const { re } of COMPILED[key]) {
      for (const m of f.excerpt.matchAll(new RegExp(re.source, 'gi'))) {
        const ev = { factId: f.id, quote: sentenceAround(f.excerpt, m.index, m[0].length) };
        if (citable(ev.quote)) return ev;
        first ??= ev;
      }
    }
  }
  return first;
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

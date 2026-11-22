import type { AgentThreat, Stride } from '@threatline/shared';
import type { Signals } from '../context/signals.js';

interface Rule {
  when: (s: Signals) => string | undefined; // returns the evidence key that triggered the rule
  threat: Omit<AgentThreat, 'evidence'>;
  /**
   * When a trusted AI threat covers this generic one: the STRIDE categories that count as the same kind of risk, and
   * the words that show it is about the same thing (matched against its title, scenario and component).
   */
  covers: { strides: Stride[]; topic: RegExp };
}

/** Deterministic STRIDE threats derived from bundle signals. They always run, so a failed or poisoned agent run still leaves a cited review. */
const RULES: Rule[] = [
  {
    when: (s) => (s.auth ? 'auth' : undefined),
    threat: {
      stride: 'Spoofing', title: 'Account takeover through weak authentication', component: 'authentication',
      scenario: 'An attacker reuses stolen or guessed credentials or a leaked session token to act as another user.',
      likelihood: 3, impact: 4, asvs: ['V6.3.1', 'V7.2.1'], cwe: ['CWE-287'],
      plainLanguage: 'Someone could log in as a customer using a stolen password or session.',
    },
    covers: { strides: ['Spoofing', 'ElevationOfPrivilege'], topic: /\b(auth\w*|log ?in|sign[- ]?in|session|credential|password|token|mfa|2fa|otp|impersonat\w*|account takeover|reset|saml|sso|single sign-on|identity provider|idp|assertion|oauth|jwt|biometric\w*|face ?id|fingerprint|forged? identit\w*)/i },
  },
  {
    when: (s) => (s.dataClasses.includes('pii') ? 'pii' : undefined),
    threat: {
      stride: 'InformationDisclosure', title: 'Personal data exposed to unauthorised users', component: 'customer data',
      scenario: 'A user or automated client requests records that belong to someone else and receives their personal data.',
      likelihood: 3, impact: 4, asvs: ['V8.2.1', 'V14.2.1'], cwe: ['CWE-359', 'CWE-639'],
      plainLanguage: 'Someone could see another customer’s personal details.',
    },
    covers: { strides: ['InformationDisclosure'], topic: /\b(personal|pii|customer (data|records?|details?)|privacy|profile|address(es)?|phone|e-?mail|idor|another (user|customer)|other (users?|customers?)|enumerat\w*)/i },
  },
  {
    // Payment data alone (an invoice PDF, card details in a log) is not a payment flow: the money has to move.
    when: (s) => (s.payment && s.paymentFlow ? 'paymentFlow' : undefined),
    threat: {
      stride: 'Tampering', title: 'Payment amount or recipient manipulated', component: 'payment flow',
      scenario: 'An attacker alters the amount, currency or recipient of a payment between request and execution.',
      likelihood: 3, impact: 5, asvs: ['V2.3.1', 'V2.2.1'], cwe: ['CWE-841'],
      plainLanguage: 'Someone could change how much money moves, or where it goes.',
    },
    covers: { strides: ['Tampering'], topic: /\b(payments?|amount|refunds?|payouts?|transfers?|charges?|price|currency|recipient|invoices?|checkout|money)\b/i },
  },
  {
    // A password the user types is not a leak; one that is stored, logged, embedded or shared can be.
    when: (s) => (s.dataClasses.includes('secrets') ? 'secrets' : s.dataClasses.includes('credentials') && s.secretHandling ? 'secretHandling' : undefined),
    threat: {
      stride: 'InformationDisclosure', title: 'Credentials or secrets leaked', component: 'secret storage',
      scenario: 'Passwords, API keys or signing keys end up in code, logs, prompts or responses where attackers can read them.',
      likelihood: 3, impact: 4, asvs: ['V13.3.1', 'V6.2.1'], cwe: ['CWE-798', 'CWE-522'],
      plainLanguage: 'Someone could find a password or key and use it to get in.',
    },
    covers: { strides: ['InformationDisclosure'], topic: /\b(secrets?|api keys?|keys?|credentials?|passwords?|tokens?|signing)\b/i },
  },
  {
    when: (s) => (s.fileUpload ? 'fileUpload' : undefined),
    threat: {
      stride: 'ElevationOfPrivilege', title: 'Malicious file upload executes code', component: 'file upload',
      scenario: 'An uploaded file with a dangerous type or crafted content is processed or served in a way that runs attacker code.',
      likelihood: 2, impact: 4, asvs: ['V5.2.1', 'V5.3.1'], cwe: ['CWE-434'],
      plainLanguage: 'Someone could upload a harmful file that runs on our servers or in other users’ browsers.',
    },
    covers: { strides: ['ElevationOfPrivilege', 'Tampering'], topic: /\b(upload\w*|files?|attachments?|images?)\b/i },
  },
  {
    when: (s) => (s.exposure === 'public' ? 'exposure' : undefined),
    threat: {
      stride: 'DenialOfService', title: 'Unauthenticated endpoint abused for resource exhaustion', component: 'public endpoint',
      scenario: 'Automated clients flood the internet-facing endpoint, exhausting compute, rate limits or paid downstream calls.',
      likelihood: 3, impact: 3, asvs: ['V2.4.1'], cwe: ['CWE-770', 'CWE-400'],
      plainLanguage: 'Someone could flood the public endpoint so real customers can’t use it, and run up our costs.',
    },
    covers: { strides: ['DenialOfService'], topic: /\b(rate|flood\w*|exhaust\w*|denial|dos|abuse\w*|throttl\w*|quota|costs?|spam\w*|brute)/i },
  },
  {
    when: (s) => (s.llmFeatures ? 'llmFeatures' : undefined),
    threat: {
      stride: 'ElevationOfPrivilege', title: 'Agent goal hijack through injected instructions', component: 'AI agent',
      scenario: 'Text the agent reads (user input, stored content, a page or a tool result) contains instructions that redirect it to act for the attacker (prompt injection).',
      likelihood: 4, impact: 4, asvs: ['V8.3.1', 'V2.2.1'], cwe: ['CWE-1427'],
      plainLanguage: 'Someone could slip instructions into what the AI reads and make it work for them.',
    },
    covers: { strides: ['ElevationOfPrivilege', 'Tampering', 'Spoofing', 'InformationDisclosure'], topic: /\b(prompt injection|inject\w*|instructions?|jailbreak\w*|hijack\w*|poison\w*|steer\w*|manipulat\w*|malicious (content|input|text|pages?|emails?|messages?)|untrusted (content|input|text))/i },
  },
  {
    // An assistant that only answers has no tools to misuse.
    when: (s) => (s.llmFeatures && s.agentTools ? 'agentTools' : undefined),
    threat: {
      stride: 'Tampering', title: 'Tool misuse by an over-privileged agent', component: 'AI agent tools',
      scenario: 'The agent calls one of its tools with attacker-chosen arguments, or does something the requesting user is not allowed to do.',
      likelihood: 3, impact: 4, asvs: ['V8.2.1', 'V8.3.1'], cwe: ['CWE-250', 'CWE-1426'],
      plainLanguage: 'The AI could be tricked into using its tools, like refunds, in ways nobody intended.',
    },
    covers: { strides: ['Tampering', 'ElevationOfPrivilege'], topic: /\b(tools?|tool calls?|function calls?|actions?|over-?privileg\w*|excessive agency|permissions?|shell|commands?|sql|queries|mcp|plugins?|refunds?|bookings?|forward\w*|exfiltrat\w*)\b/i },
  },
  {
    // Sending an order to Stripe, or files to S3, is not a disclosure by itself: personal or health data has to go.
    // S3 is the team's own storage, not another company.
    when: (s) => {
      const tp = s.thirdParty.find((x) => x !== 's3');
      return tp && (s.dataClasses.includes('pii') || s.dataClasses.includes('health')) ? `thirdParty:${tp}` : undefined;
    },
    threat: {
      stride: 'InformationDisclosure', title: 'Sensitive data sent to a third-party service', component: 'third-party integration',
      scenario: 'Data is passed to an external provider without minimisation, contract controls or encryption in transit.',
      likelihood: 2, impact: 3, asvs: ['V12.2.1', 'V14.2.1'], cwe: ['CWE-200'],
      plainLanguage: 'Customer data could leave our systems and be exposed by another company.',
    },
    covers: { strides: ['InformationDisclosure'], topic: /\b(third[- ]party|vendors?|providers?|external|integrations?|processors?|sent to|shared with)\b/i },
  },
];

/**
 * The coverage test for a rule-based threat (by title): the trusted AI threat whose kind and topic match it, if any.
 * Used to keep a generic rule-based threat from repeating a more specific one the AI already raised.
 */
export function coveredByText(baselineTitle: string, candidate: { stride: Stride; title: string; scenario: string; component: string }): boolean {
  const rule = RULES.find((r) => r.threat.title === baselineTitle);
  if (!rule) return false;
  return rule.covers.strides.includes(candidate.stride) && rule.covers.topic.test(`${candidate.title} ${candidate.scenario} ${candidate.component}`);
}

export function baselineThreats(signals: Signals): AgentThreat[] {
  const out: AgentThreat[] = [];
  for (const rule of RULES) {
    const key = rule.when(signals);
    const ev = key ? signals.evidence[key] : undefined;
    if (ev) out.push({ ...rule.threat, evidence: [{ quote: ev.quote }] });
  }
  return out;
}

import { MAX_EXCERPT, type ContextFact, type SourceType } from '@threatline/shared';
import { sha256Hex } from '@threatline/crypto';
import { INVISIBLE_CHARS, scanForInjection } from './injection.js';
import { redactSecrets } from './redact.js';

export interface RawFact {
  sourceAri: string;
  sourceType: SourceType;
  title: string;
  url: string;
  text: string;
  version: string;
  trusted: boolean;
  origin: 'rest' | 'graph';
}

// `shy` (soft hyphen) is dropped: "pass&shy;word" must read as "password" to the keyword rules.
const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#39': "'", shy: '' };
const SOFT_HYPHEN = /\u00AD/g;

/** Untrusted numeric entities must never throw: out-of-range values and lone surrogates become U+FFFD. */
function safeCodePoint(cp: number): string {
  if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return '\uFFFD';
  return String.fromCodePoint(cp);
}

/** Raw page size Threatline parses (2 MB of text); anything beyond is dropped before parsing, so no page can stall ingest. */
export const MAX_RAW_PAGE = 2_000_000;

/**
 * Drops <script> and <style> elements in one linear pass (final review I3): a regex with a lazy body and a
 * back-reference rescans to the end of the page for every unclosed opening tag, which is quadratic on hostile input.
 * An element that is never closed drops the rest of the page, as a browser would treat it.
 */
function stripScriptsAndStyles(html: string): string {
  // ASCII-only lowercase keeps every index identical to `html` (toLowerCase can lengthen text, e.g. İ → i̇).
  const lower = html.replace(/[A-Z]+/g, (c) => c.toLowerCase());
  const open = /<(script|style)\b/g;
  let out = '';
  let from = 0;
  for (let m = open.exec(lower); m; m = open.exec(lower)) {
    out += `${html.slice(from, m.index)} `;
    const close = lower.indexOf(`</${m[1]}`, open.lastIndex);
    if (close < 0) return out;
    const end = lower.indexOf('>', close);
    if (end < 0) return out;
    from = end + 1;
    open.lastIndex = from;
  }
  return out + html.slice(from);
}

export function htmlToText(html: string): string {
  return stripScriptsAndStyles(html.length > MAX_RAW_PAGE ? html.slice(0, MAX_RAW_PAGE) : html)
    .replace(/<br\s*\/?>|<\/(p|div|li|h[1-6]|tr)>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&(#\d+|#x[0-9a-f]+|[a-z]+|#39);/gi, (m, e: string) => {
      const k = e.toLowerCase();
      if (ENTITIES[k] !== undefined) return ENTITIES[k];
      if (k.startsWith('#')) return safeCodePoint(k.startsWith('#x') ? parseInt(k.slice(2), 16) : parseInt(k.slice(1), 10));
      return m;
    })
    // Linear on any input: collapse non-newline whitespace first, then one newline per run that contains one.
    .replace(/[^\S\n]+/g, ' ')
    .replace(/ ?\n[\n ]*/g, '\n')
    .trim();
}

export const factIdOf = (sourceAri: string, version: string): string => `fact_${sha256Hex(`${sourceAri}@${version}`).slice(0, 16)}`;

/** Most parts one source is split into: 12,000 characters of a long design page, beyond which the rest is dropped. */
export const MAX_PARTS = 6;

/** Splits at a line break (else a sentence end, else a space) in the second half of each window, so parts read whole. */
export function splitText(text: string, max = MAX_EXCERPT, maxParts = MAX_PARTS): string[] {
  const parts: string[] = [];
  let rest = text;
  while (rest.length > max && parts.length < maxParts - 1) {
    const window = rest.slice(0, max);
    const cut = [window.lastIndexOf('\n'), window.lastIndexOf('. ') + 1, window.lastIndexOf(' ')].find((n) => n >= max / 2) ?? max;
    parts.push(rest.slice(0, cut).trim());
    rest = rest.slice(cut).trimStart();
  }
  parts.push(rest.slice(0, max));
  return parts.filter((p, n) => n === 0 || p.length > 0);
}

/**
 * Strips HTML, scans the full text for injection, removes invisible characters, redacts secrets, and splits a long
 * source into parts of at most MAX_EXCERPT characters each (up to MAX_PARTS). Before, only the first 2,000 characters
 * of a page reached the model and the keyword rules, so a long design page lost most of what it said. The first part
 * keeps the source's fact id, so a short source is exactly what it was. Every part carries the whole source's injection
 * verdict, so splitting can never hide a directive in another part.
 */
export function normalizeFacts(raw: RawFact): ContextFact[] {
  const text = htmlToText(raw.text);
  const title = htmlToText(raw.title);
  const clean = (s: string) => redactSecrets(s.replace(INVISIBLE_CHARS, '').replace(SOFT_HYPHEN, ''));
  // Scanned twice: as written (hidden characters are themselves a reason) and exactly as the model will read it, so a
  // character the cleaning removes ("ign\u00ADore previous instructions") cannot split a directive past the scanner.
  const written = scanForInjection(`${title}\n${text}`);
  const seen = scanForInjection(`${title.replace(INVISIBLE_CHARS, '').replace(SOFT_HYPHEN, '')}\n${text.replace(INVISIBLE_CHARS, '').replace(SOFT_HYPHEN, '')}`);
  const scan = { suspected: written.suspected || seen.suspected, reasons: [...new Set([...written.reasons, ...seen.reasons])] };
  const parts = splitText(clean(text));
  const cleanTitle = clean(title).slice(0, 480);
  return parts.map((excerpt, n) => ({
    id: n === 0 ? factIdOf(raw.sourceAri, raw.version) : factIdOf(raw.sourceAri, `${raw.version}#${n + 1}`),
    sourceAri: raw.sourceAri,
    sourceType: raw.sourceType,
    title: n === 0 ? cleanTitle : `${cleanTitle} (part ${n + 1} of ${parts.length})`,
    url: raw.url,
    excerpt,
    trustLevel: raw.trusted ? 'trusted' : 'untrusted',
    version: raw.version,
    injectionSuspected: scan.suspected,
    injectionReasons: scan.reasons,
    origin: raw.origin,
  }));
}

/** One fact per source: the first part of `normalizeFacts` (graph facts and other short sources). */
export function normalizeFact(raw: RawFact): ContextFact {
  return normalizeFacts(raw)[0]!;
}

// Adversarial PRECISION suite for probeAICodeSmells, round 1.
// Every test in the main describes is a MUST-NOT-FIRE case: benign, production-quality
// code that a naive "AI code smell" detector would over-fire on. All assertions expect
// zero findings of any severity. The final describe collects genuinely ambiguous shapes
// that may fail today; failures there are calibration signal, not regressions.
//
// Authored blind: this file was written without reading the probe implementation.

import { describe, it, expect } from 'vitest';
import { probeAICodeSmells } from '../lib/probes.js';

/** Run the probe and assert zero findings, dumping any findings on failure. */
function expectClean(files) {
  const findings = probeAICodeSmells(files);
  expect(findings).toEqual([]);
}

const one = (path, content) => [{ path, content }];

/**
 * Generate n well-formed, slightly varied TypeScript functions (~5 lines each).
 * Used to build large "unremarkable production file" fixtures.
 */
function tsFiller(n, prefix = 'step') {
  const bodies = [
    (i) =>
      `export function ${prefix}Trim${i}(input: string): string {\n` +
      `  const trimmed = input.trim();\n` +
      `  return trimmed.length > 0 ? trimmed : 'fallback-${i}';\n` +
      `}\n`,
    (i) =>
      `export function ${prefix}Sum${i}(values: number[]): number {\n` +
      `  return values.reduce((acc, v) => acc + v, ${i});\n` +
      `}\n`,
    (i) =>
      `export function ${prefix}Pick${i}(record: Record<string, number>, key: string): number {\n` +
      `  const value = record[key];\n` +
      `  return typeof value === 'number' ? value : ${i};\n` +
      `}\n`,
    (i) =>
      `export function ${prefix}Label${i}(count: number): string {\n` +
      `  if (count === 1) {\n` +
      `    return '1 item';\n` +
      `  }\n` +
      `  return count + ' items (${prefix}${i})';\n` +
      `}\n`,
  ];
  let out = '';
  for (let i = 0; i < n; i++) {
    out += bodies[i % bodies.length](i) + '\n';
  }
  return out;
}

/** Same idea, plain JavaScript. */
function jsFiller(n, prefix = 'op') {
  const bodies = [
    (i) =>
      `export function ${prefix}Round${i}(value) {\n` +
      `  return Math.round(value * ${i + 1}) / ${i + 1};\n` +
      `}\n`,
    (i) =>
      `export function ${prefix}Join${i}(parts) {\n` +
      `  return parts.filter(Boolean).join('-${i}');\n` +
      `}\n`,
    (i) =>
      `export function ${prefix}Clamp${i}(n, lo, hi) {\n` +
      `  if (n < lo) return lo;\n` +
      `  if (n > hi) return hi;\n` +
      `  return n;\n` +
      `}\n`,
  ];
  let out = '';
  for (let i = 0; i < n; i++) {
    out += bodies[i % bodies.length](i) + '\n';
  }
  return out;
}

// ---------------------------------------------------------------------------
// Category 1: catch blocks that LOOK empty but are not
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: catch blocks that look empty but are not', () => {
  it('does not fire on paramless catch with a single cleanup call', () => {
    expectClean(
      one(
        'src/service.ts',
        `
export async function shutdown(pool: { end(): Promise<void> }, cleanup: () => void) {
  try {
    await pool.end();
  } catch {
    cleanup();
  }
}
`
      )
    );
  });

  it('does not fire on catch whose first token is a comment followed by real handling', () => {
    expectClean(
      one(
        'src/metrics/reporter.ts',
        `
export function report(metrics: { count(name: string): void }, send: () => void) {
  try {
    send();
  } catch (e) {
    /* intentional: see RFC-12, transport errors are counted not thrown */
    metrics.count('err');
  }
}
`
      )
    );
  });

  it('does not fire on catch that only rethrows', () => {
    expectClean(
      one(
        'src/db/tx.ts',
        `
export async function withTransaction(run: () => Promise<void>, rollback: () => Promise<void>) {
  try {
    await run();
  } catch (err) {
    await rollback();
    throw err;
  }
}

export function passthrough(fn: () => void) {
  try {
    fn();
  } catch (err) {
    throw err;
  }
}
`
      )
    );
  });

  it('does not fire on catch with a guard-and-rethrow on one dense line', () => {
    expectClean(
      one(
        'src/api/client.ts',
        `
class AbortError extends Error {}

export async function fetchProfile(load: () => Promise<string>) {
  try {
    return await load();
  } catch (e) { if (e instanceof AbortError) return null; throw e; }
}
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 2: legitimately-empty catch in idiomatic feature-detection patterns
// (bodies carry an explanatory comment; the truly-bare variants live in the
// ambiguous block at the bottom)
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: idiomatic feature-detection catch', () => {
  it('does not fire on Intl feature detection with explanatory comment and fallback', () => {
    expectClean(
      one(
        'src/i18n/segmenter.ts',
        `
let segmenter: Intl.Segmenter | null = null;
try {
  segmenter = new Intl.Segmenter('en', { granularity: 'word' });
} catch {
  /* Intl.Segmenter unsupported in this runtime; word-boundary fallback below */
}
const splitWords = segmenter
  ? (text: string) => Array.from(segmenter.segment(text), (s) => s.segment)
  : (text: string) => text.split(/\\s+/);

export { splitWords };
`
      )
    );
  });

  it('does not fire on localStorage probe with explanatory comment and boolean fallback', () => {
    expectClean(
      one(
        'src/storage/availability.ts',
        `
export function storageAvailable(): boolean {
  try {
    const key = '__probe__';
    window.localStorage.setItem(key, '1');
    window.localStorage.removeItem(key);
    return true;
  } catch {
    /* private browsing or storage quota: treated as unavailable, callers fall back to memory */
  }
  return false;
}
`
      )
    );
  });

  it('does not fire on clipboard capability check with comment and explicit fallback path', () => {
    expectClean(
      one(
        'src/ui/clipboard.ts',
        `
export async function copyText(text: string, fallback: (text: string) => void) {
  try {
    await navigator.clipboard.writeText(text);
    return;
  } catch {
    // Clipboard API blocked (permissions policy or insecure context). The
    // execCommand-based fallback below is the supported degradation path.
  }
  fallback(text);
}
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 3: the word "any" inside identifiers and prose, never a type annotation
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: "any" inside identifiers is not the any type', () => {
  it('does not fire on identifiers that start with any', () => {
    expectClean(
      one(
        'src/auth/roles.ts',
        `
interface User {
  id: string;
  roles: string[];
}

export function anyUserHasRole(users: User[], role: string): boolean {
  const anyUser = users.find((u) => u.roles.includes(role));
  return anyUser !== undefined;
}

export function anyOf(flags: boolean[]): boolean {
  return flags.some(Boolean);
}
`
      )
    );
  });

  it('does not fire on identifiers that end with or contain any (company, many, Any suffix)', () => {
    expectClean(
      one(
        'src/billing/company.ts',
        `
interface Company {
  id: string;
  seats: number;
}

export function companyAnySeatFree(company: Company, used: number): boolean {
  return used < company.seats;
}

export function howManyCompanies(companies: Company[]): number {
  return companies.length;
}

export const companyAny = (companies: Company[]) => companies.length > 0;
`
      )
    );
  });

  it('does not fire on function names and parameters spelled around any/anything', () => {
    expectClean(
      one(
        'src/search/query.ts',
        `
export function getAnyMatch(haystack: string[], needle: string): string | undefined {
  return haystack.find((h) => h.includes(needle));
}

export function describe_(anything: string): string {
  return 'query: ' + anything;
}

export function matchAnyOf(patterns: RegExp[], input: string): boolean {
  return patterns.some((p) => p.test(input));
}
`
      )
    );
  });

  it('does not fire on library-style type names containing Any as a word fragment', () => {
    expectClean(
      one(
        'src/state/actions.ts',
        `
// Redux-style action plumbing. AnyAction here is a named interface, not the any type.
export interface AnyAction {
  type: string;
  payload?: unknown;
}

export function isAnyAction(value: unknown): value is AnyAction {
  return typeof value === 'object' && value !== null && 'type' in value;
}

export function dispatchAnyAction(queue: AnyAction[], action: AnyAction): void {
  queue.push(action);
}
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 4: ": any" inside strings, comments, JSDoc, and template literals
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: ": any" only inside masked regions', () => {
  it('does not fire on string literals that contain type-annotation text', () => {
    expectClean(
      one(
        'src/lint/messages.ts',
        `
export const MESSAGES = {
  noExplicitAny: "Replace ': any' with a specific type or 'unknown'.",
  emptyCatch: 'An empty catch {} silently swallows errors.',
};

export function formatHint(name: string): string {
  return 'Avoid annotations like "value: any" in reviewed code, ' + name + '.';
}
`
      )
    );
  });

  it('does not fire on line and block comments discussing the any type', () => {
    expectClean(
      one(
        'src/typing/notes.ts',
        `
// We deliberately avoid ": any" here; unknown forces narrowing at the call site.
/*
 * History: this module once declared config: any and paid for it.
 * Every field is now typed. Do not reintroduce any-typed escape hatches.
 */
export function parseConfig(raw: string): Record<string, unknown> {
  return JSON.parse(raw) as Record<string, unknown>;
}
`
      )
    );
  });

  it('does not fire on JSDoc @param {any} docs in a JS file', () => {
    expectClean(
      one(
        'src/utils/serialize.js',
        `
/**
 * Serialize a value for logging.
 * @param {any} value - accepts any JSON-serializable value
 * @param {any} [replacer] - optional replacer, passed straight to JSON.stringify
 * @returns {string}
 */
export function serialize(value, replacer) {
  return JSON.stringify(value, replacer, 2);
}
`
      )
    );
  });

  it('does not fire on template literals embedding code samples with ": any"', () => {
    expectClean(
      one(
        'src/docs/snippets.ts',
        `
export function badExampleSnippet(varName: string): string {
  return \`
// BAD: do not write this
const \${varName}: any = load();
try { run(\${varName}); } catch {}
\`;
}

export const FIX_TEMPLATE = \`Replace "config: any" with "config: AppConfig".\`;
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 5: sparse "any" in large declaration-style files (a heavy-use smell
// should not fire on one occurrence in hundreds of lines)
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: sparse any in large files', () => {
  it('does not fire on a large .d.ts-style declaration file with a single any interop slot', () => {
    const declarations = Array.from(
      { length: 90 },
      (_, i) =>
        `export declare function query${i}(input: string, limit: number): Promise<string[]>;\n` +
        `export declare const LIMIT_${i}: number;\n` +
        `export interface Row${i} { id: string; value: number; label: string; }\n`
    ).join('\n');
    expectClean(
      one(
        'src/types/vendor-sdk.d.ts',
        declarations +
          `
// Upstream SDK callback is untyped at the boundary; single deliberate escape hatch.
export declare function onRawEvent(handler: (payload: any) => void): void;
`
      )
    );
  });

  it('does not fire on a 400+ line .ts service with one boundary any cast', () => {
    expectClean(
      one(
        'src/services/report-builder.ts',
        tsFiller(90, 'report') +
          `
// window.__legacyBridge is injected by a host page we do not control.
export function readLegacyBridge(): unknown {
  return (window as any).__legacyBridge;
}
`
      )
    );
  });

  it('does not fire on a large module where any appears once in a documented third-party shim', () => {
    expectClean(
      one(
        'src/integrations/charting.ts',
        tsFiller(80, 'chart') +
          `
interface ChartHost {
  render(el: HTMLElement, spec: object): void;
}

/**
 * The vendor bundle attaches itself as an untyped global. This is the single
 * point where its shape enters our code; everything downstream is typed.
 */
export function loadChartHost(globalObj: { VendorCharts?: any }): ChartHost | null {
  const host = globalObj.VendorCharts;
  return host && typeof host.render === 'function' ? (host as ChartHost) : null;
}
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 6: unknown, as const, generics, satisfies — near-miss type syntax
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: near-miss TypeScript type syntax', () => {
  it('does not fire on pervasive unknown usage', () => {
    expectClean(
      one(
        'src/validation/guards.ts',
        `
export function isString(value: unknown): value is string {
  return typeof value === 'string';
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function assertDefined<T>(value: T | undefined, label: string): T {
  if (value === undefined) {
    throw new Error(label + ' must be defined');
  }
  return value;
}
`
      )
    );
  });

  it('does not fire on as const assertions', () => {
    expectClean(
      one(
        'src/config/routes.ts',
        `
export const ROUTES = ['home', 'audit', 'learn', 'about'] as const;

export const THEME = {
  primary: '#0f172a',
  accent: '#38bdf8',
} as const;

export type Route = (typeof ROUTES)[number];
`
      )
    );
  });

  it('does not fire on generic-heavy utility signatures', () => {
    expectClean(
      one(
        'src/utils/collections.ts',
        `
export function groupBy<T, K extends string>(items: T[], key: (item: T) => K): Record<K, T[]> {
  const out = {} as Record<K, T[]>;
  for (const item of items) {
    const k = key(item);
    (out[k] ??= []).push(item);
  }
  return out;
}

export function mapValues<V, R>(input: Record<string, V>, fn: (v: V) => R): Record<string, R> {
  return Object.fromEntries(Object.entries(input).map(([k, v]) => [k, fn(v)]));
}

export type DeepReadonly<T> = { readonly [K in keyof T]: DeepReadonly<T[K]> };
`
      )
    );
  });

  it('does not fire on satisfies and conditional types', () => {
    expectClean(
      one(
        'src/config/limits.ts',
        `
type Limits = Record<'files' | 'bytes' | 'findings', number>;

export const LIMITS = {
  files: 2000,
  bytes: 5_000_000,
  findings: 500,
} satisfies Limits;

export type Unwrap<T> = T extends Promise<infer U> ? U : T;
export type NonEmpty<T> = T extends [] ? never : T;
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 7: empty blocks that are NOT catch blocks
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: empty blocks that are not catch', () => {
  it('does not fire on intentional noop function defaults', () => {
    expectClean(
      one(
        'src/events/emitter.ts',
        `
type Listener = (payload: string) => void;

const noop: Listener = () => {};

export function createEmitter(onEvent: Listener = noop) {
  const listeners: Listener[] = [onEvent];
  return {
    on(fn: Listener) {
      listeners.push(fn);
    },
    emit(payload: string) {
      for (const fn of listeners) fn(payload);
    },
  };
}
`
      )
    );
  });

  it('does not fire on empty if branch used for readable guard ordering', () => {
    expectClean(
      one(
        'src/render/scheduler.ts',
        `
export function schedule(pending: boolean, urgent: boolean, run: () => void) {
  if (pending && !urgent) {
    // already queued, nothing to add
  } else {
    run();
  }
}
`
      )
    );
  });

  it('does not fire on empty object literals as defaults and accumulators', () => {
    expectClean(
      one(
        'src/http/request.ts',
        `
interface RequestOptions {
  headers?: Record<string, string>;
  query?: Record<string, string>;
}

export function buildUrl(base: string, { query = {} }: RequestOptions = {}) {
  const params = new URLSearchParams(query);
  const qs = params.toString();
  return qs ? base + '?' + qs : base;
}

export function emptyState(): Record<string, never> {
  return {};
}
`
      )
    );
  });

  it('does not fire on while loops with side-effectful conditions and empty bodies', () => {
    expectClean(
      one(
        'src/parse/scanner.ts',
        `
export function drain(queue: { pop(): string | undefined }) {
  while (queue.pop() !== undefined) {}
}

export function skipSpaces(text: string, start: number): number {
  let i = start;
  while (i < text.length && text[i] === ' ') i++;
  return i;
}
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 8: catch parameter destructuring and unusual-but-valid catch forms
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: unusual catch parameter forms', () => {
  it('does not fire on catch destructuring the message', () => {
    expectClean(
      one(
        'src/telemetry/errors.ts',
        `
export function guarded(run: () => void, report: (msg: string) => void) {
  try {
    run();
  } catch ({ message }) {
    report(String(message));
  }
}
`
      )
    );
  });

  it('does not fire on catch destructuring multiple fields with a default', () => {
    expectClean(
      one(
        'src/api/errors.ts',
        `
export async function callApi(invoke: () => Promise<Response>, log: (line: string) => void) {
  try {
    return await invoke();
  } catch ({ code = 'UNKNOWN', message = 'no message' }) {
    log(code + ': ' + message);
    return null;
  }
}
`
      )
    );
  });

  it('does not fire on TypeScript catch (err: unknown) with narrowing', () => {
    expectClean(
      one(
        'src/jobs/runner.ts',
        `
export async function runJob(job: () => Promise<void>, log: (line: string) => void) {
  try {
    await job();
  } catch (err: unknown) {
    if (err instanceof Error) {
      log(err.message);
    } else {
      log(String(err));
    }
  }
}
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 9: files whose smelly-looking content lives entirely in comments
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: comment-only smelly content', () => {
  it('does not fire on a file that is one large doc comment containing catch {} and : any', () => {
    expectClean(
      one(
        'src/lint/rule-notes.ts',
        `
/*
 * Rule design notes.
 *
 * We flag two shapes:
 *   1. catch {} and catch (e) {} with no statements — swallowed errors.
 *   2. Heavy use of ": any" annotations — const data: any = fetchStuff();
 *
 * Neither shape appears in this file as code; these are the patterns the
 * rule targets, documented for the next maintainer.
 */
export const RULE_NOTES_VERSION = 3;
`
      )
    );
  });

  it('does not fire on markdown-ish doc strings held in a constant', () => {
    expectClean(
      one(
        'src/docs/guide.ts',
        `
export const GUIDE_MD = [
  '## Common review flags',
  '',
  '- \`catch {}\` with no handler body',
  '- \`let state: any = {}\` broad typing',
  '- Certainly! Here is the complete implementation (pasted-chat tell)',
  '',
  'Each flag links to a fix pattern.',
].join('\\n');
`
      )
    );
  });

  it('does not fire on JSDoc example blocks demonstrating the anti-pattern', () => {
    expectClean(
      one(
        'src/utils/safe-json.js',
        `
/**
 * Parse JSON without throwing.
 *
 * @example
 * // Instead of:
 * // let parsed: any;
 * // try { parsed = JSON.parse(raw); } catch {}
 * // write:
 * const parsed = safeJson(raw, null);
 *
 * @param {string} raw
 * @param {*} fallback
 */
export function safeJson(raw, fallback) {
  try {
    return JSON.parse(raw);
  } catch (err) {
    return fallback;
  }
}
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 10: minified-looking but legitimate one-liner utilities
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: dense one-liner utilities', () => {
  it('does not fire on compact arrow utility exports', () => {
    expectClean(
      one(
        'src/utils/math.ts',
        `export const clamp=(n:number,a:number,b:number):number=>Math.min(Math.max(n,a),b);
export const lerp=(a:number,b:number,t:number):number=>a+(b-a)*t;
export const sum=(xs:number[]):number=>xs.reduce((a,x)=>a+x,0);
`
      )
    );
  });

  it('does not fire on a dense single-line memoize helper', () => {
    expectClean(
      one(
        'src/utils/memo.js',
        `export const memo=(fn)=>{const c=new Map();return (k)=>{if(!c.has(k))c.set(k,fn(k));return c.get(k);};};
`
      )
    );
  });

  it('does not fire on chained one-line string helpers', () => {
    expectClean(
      one(
        'src/utils/strings.js',
        `export const slug=(s)=>s.toLowerCase().trim().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
export const cap=(s)=>s?s[0].toUpperCase()+s.slice(1):s;
export const pad2=(n)=>String(n).padStart(2,'0');
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 11: regex literals whose SOURCE TEXT looks like the smell
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: regex literals containing catch/any text', () => {
  it('does not fire on a lint-style regex matching empty catch', () => {
    expectClean(
      one(
        'src/lint/patterns.ts',
        String.raw`
export const EMPTY_CATCH = /catch\s*(\([^)]*\))?\s*\{\s*\}/g;

export function countEmptyCatches(source: string): number {
  return (source.match(EMPTY_CATCH) ?? []).length;
}
`
      )
    );
  });

  it('does not fire on a regex matching explicit any annotations', () => {
    expectClean(
      one(
        'src/lint/any-rule.ts',
        String.raw`
export const EXPLICIT_ANY = /:\s*any\b/g;

export function flagExplicitAny(line: string): boolean {
  return EXPLICIT_ANY.test(line);
}
`
      )
    );
  });

  it('does not fire on RegExp constructor strings holding the same patterns', () => {
    expectClean(
      one(
        'src/lint/dynamic-rules.ts',
        String.raw`
const RULES: Record<string, RegExp> = {
  emptyCatch: new RegExp('catch\\s*\\{\\s*\\}'),
  anyType: new RegExp(':\\s*any\\b'),
  todoLeft: new RegExp('TODO: implement', 'i'),
};

export function ruleNames(): string[] {
  return Object.keys(RULES);
}
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 12: AI-signature-sounding PROSE confined to comments
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: AI-sounding prose inside comments', () => {
  it('does not fire on "robust implementation" phrasing in a doc comment', () => {
    expectClean(
      one(
        'src/net/retry.ts',
        `
/**
 * Retry with exponential backoff. Reviewers keep calling this "a robust
 * implementation"; the robustness is the jitter, documented below.
 */
export async function withRetry<T>(fn: () => Promise<T>, attempts = 3): Promise<T> {
  let lastErr: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      const base = 2 ** i * 100;
      await new Promise((r) => setTimeout(r, base + Math.random() * base));
    }
  }
  throw lastErr;
}
`
      )
    );
  });

  it('does not fire on tutorial-voice comments like "Here\'s how"', () => {
    expectClean(
      one(
        'src/onboarding/steps.ts',
        `
// Here's how the wizard advances: each step validates, then commits, then
// the index moves. Certainly not the only design, but it keeps undo simple.
export function nextStep(index: number, valid: boolean, total: number): number {
  if (!valid) return index;
  return Math.min(index + 1, total - 1);
}
`
      )
    );
  });

  it('does not fire on changelog-style comments with assistant-sounding phrases', () => {
    expectClean(
      one(
        'src/store/history.ts',
        `
/*
 * v3 notes: "I've updated the code to handle edge cases" was the entire PR
 * description we received. This comment exists so the next author writes a
 * real one. The actual edge cases handled: empty history, duplicate push.
 */
export function pushHistory(stack: string[], entry: string): string[] {
  if (stack[stack.length - 1] === entry) return stack;
  return [...stack, entry];
}
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 13: generated-code banners on otherwise clean files
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: generated-file banners over clean code', () => {
  it('does not fire on an eslint-disable banner', () => {
    expectClean(
      one(
        'src/generated/routes-manifest.ts',
        `/* eslint-disable */
// prettier-ignore
export const ROUTE_MANIFEST: Record<string, string> = {
  home: '/',
  audit: '/audit',
  learn: '/learn',
  about: '/about',
};
`
      )
    );
  });

  it('does not fire on an autogenerated DO NOT EDIT notice', () => {
    expectClean(
      one(
        'src/generated/build-info.ts',
        `// AUTOGENERATED FILE - DO NOT EDIT.
// Regenerate with: npm run gen:build-info
export const BUILD_INFO = {
  version: '0.5.0',
  commit: 'abcdef1',
  builtAt: '2026-07-25T00:00:00Z',
};
`
      )
    );
  });

  it('does not fire on a protoc-style @generated header', () => {
    expectClean(
      one(
        'src/generated/events.ts',
        `// @generated by protoc-gen-ts v2.1.0
// source: events.proto
export interface EventEnvelope {
  id: string;
  kind: string;
  occurredAt: string;
}

export function isEnvelope(value: unknown): value is EventEnvelope {
  return typeof value === 'object' && value !== null && 'id' in value && 'kind' in value;
}
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 14: framework-idiom .ts files a naive matcher confuses
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: Vue/Svelte-adjacent framework idioms', () => {
  it('does not fire on Vue composition-API style composable', () => {
    expectClean(
      one(
        'src/composables/useCounter.ts',
        `
interface Ref<T> {
  value: T;
}

declare function ref<T>(initial: T): Ref<T>;
declare function computed<T>(fn: () => T): Ref<T>;
declare function watch<T>(source: Ref<T>, cb: (next: T, prev: T) => void, options?: {}): void;

export function useCounter(start = 0) {
  const count = ref(start);
  const doubled = computed(() => count.value * 2);
  watch(count, (next, prev) => {
    if (next < prev) count.value = prev;
  }, {});
  return { count, doubled };
}
`
      )
    );
  });

  it('does not fire on Svelte store contract implemented by hand', () => {
    expectClean(
      one(
        'src/stores/session.ts',
        `
type Subscriber<T> = (value: T) => void;
type Unsubscriber = () => void;

export function writable<T>(initial: T) {
  let value = initial;
  const subs = new Set<Subscriber<T>>();
  return {
    subscribe(fn: Subscriber<T>): Unsubscriber {
      subs.add(fn);
      fn(value);
      return () => subs.delete(fn);
    },
    set(next: T) {
      value = next;
      for (const fn of subs) fn(value);
    },
    update(fn: (current: T) => T) {
      this.set(fn(value));
    },
  };
}
`
      )
    );
  });

  it('does not fire on defineComponent-style options object with empty hooks object', () => {
    expectClean(
      one(
        'src/components/badge.ts',
        `
interface ComponentOptions {
  name: string;
  props: Record<string, { type: unknown; required: boolean }>;
  emits: string[];
  watch: {};
}

export const BadgeOptions: ComponentOptions = {
  name: 'ScoreBadge',
  props: {
    score: { type: Number, required: true },
  },
  emits: ['click'],
  watch: {},
};
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Category 15: large, clean, unremarkable production files end-to-end
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: large clean files produce zero findings', () => {
  it('does not fire anywhere in a 400+ line TypeScript utility module', () => {
    expectClean(one('src/utils/text-tools.ts', tsFiller(90, 'text')));
  });

  it('does not fire anywhere in a 300+ line plain JavaScript module', () => {
    expectClean(one('src/utils/format-lib.js', jsFiller(80, 'fmt')));
  });

  it('does not fire on a large service file with realistic try/catch handling throughout', () => {
    const handlers = Array.from(
      { length: 25 },
      (_, i) =>
        `export async function handler${i}(load: () => Promise<string>, log: (m: string) => void) {\n` +
        `  try {\n` +
        `    const value = await load();\n` +
        `    return value.trim();\n` +
        `  } catch (err) {\n` +
        `    log('handler${i} failed: ' + String(err));\n` +
        `    return null;\n` +
        `  }\n` +
        `}\n`
    ).join('\n');
    expectClean(one('src/services/pipeline.ts', tsFiller(40, 'stage') + handlers));
  });

  it('does not fire across a multi-file corpus of clean production modules', () => {
    expectClean([
      { path: 'src/utils/dates.ts', content: tsFiller(30, 'date') },
      { path: 'src/utils/currency.ts', content: tsFiller(30, 'money') },
      { path: 'src/utils/paths.js', content: jsFiller(30, 'path') },
    ]);
  });
});

// ---------------------------------------------------------------------------
// Mixed-shape spot checks (multi-category collisions in one file)
// ---------------------------------------------------------------------------
describe('probeAICodeSmells precision: combined collision shapes', () => {
  it('does not fire when identifier-any, comment-any, and handled catch share a file', () => {
    expectClean(
      one(
        'src/inventory/service.ts',
        `
// Migration note: fields were once typed ": any" across this module. Fixed in v2.
interface Item {
  sku: string;
  qty: number;
}

export function anyItemLow(items: Item[], threshold: number): boolean {
  return items.some((i) => i.qty < threshold);
}

export async function reserve(items: Item[], commit: () => Promise<void>, log: (m: string) => void) {
  try {
    await commit();
    return true;
  } catch (err) {
    log('reserve failed: ' + String(err));
    return false;
  }
}
`
      )
    );
  });

  it('does not fire on a lint-tooling file that mentions every smell it detects', () => {
    expectClean(
      one(
        'src/lint/smell-registry.ts',
        String.raw`
export interface SmellRule {
  id: string;
  pattern: RegExp;
  message: string;
}

export const SMELL_RULES: SmellRule[] = [
  {
    id: 'empty-catch',
    pattern: /catch\s*(\([^)]*\))?\s*\{\s*\}/,
    message: 'Empty catch {} swallows errors silently.',
  },
  {
    id: 'explicit-any',
    pattern: /:\s*any\b/,
    message: "Explicit ': any' defeats the type checker.",
  },
  {
    id: 'todo-scaffold',
    pattern: /\/\/\s*TODO: implement/i,
    message: 'Left-over TODO scaffolding from generated code.',
  },
];

export function match(rule: SmellRule, source: string): boolean {
  return rule.pattern.test(source);
}
`
      )
    );
  });

  it('does not fire on a README-generator embedding smelly code samples in template literals', () => {
    expectClean(
      one(
        'src/docs/readme-gen.ts',
        `
export function renderBadPractices(): string {
  const sample = \`
function loadUser(id: string): any {
  try {
    return db.get(id);
  } catch {}
}
\`;
  return '## What not to ship\\n\\n\` \` \`ts' + sample + '\` \` \`';
}
`
      )
    );
  });
});

// ---------------------------------------------------------------------------
// Edge cases where benign-vs-smell is genuinely ambiguous.
// Each test is flagged: these MAY fail against today's calibration, and a
// failure here is signal about where the threshold sits, not a regression.
// ---------------------------------------------------------------------------
describe('edge cases where benign-vs-smell is genuinely ambiguous', () => {
  // AMBIGUOUS: truly bare catch {} — idiomatic feature detection, but
  // indistinguishable from a swallowed error without reading the next line.
  // ADJUDICATED round 1: kept firing. The Pattern page's contract: a bare
  // empty catch fires; documented intent means writing the comment, which
  // suppresses. Feature detection earns quiet with one comment.
  it.skip('bare catch {} feature detection with fallback assignment on the next line', () => {
    expectClean(
      one(
        'src/i18n/plural.ts',
        `
let rules: Intl.PluralRules | null = null;
try {
  rules = new Intl.PluralRules('en');
} catch {}
const select = rules ? (n: number) => rules.select(n) : (n: number) => (n === 1 ? 'one' : 'other');
export { select };
`
      )
    );
  });

  // AMBIGUOUS: catch (e) {} that is genuinely intentional (best-effort cache
  // warm) but carries no comment; a reviewer could read it either way.
  // ADJUDICATED round 1: kept firing. Same contract: best-effort swallowing
  // is fine once it says so in a comment.
  it.skip('bare catch (e) {} in a best-effort cache warm loop', () => {
    expectClean(
      one(
        'src/cache/warm.ts',
        `
export async function warmCache(keys: string[], fetchOne: (k: string) => Promise<void>) {
  for (const key of keys) {
    try {
      await fetchOne(key);
    } catch (e) {}
  }
}
`
      )
    );
  });

  // AMBIGUOUS: catch whose only content is an eslint-disable comment. After
  // comment masking this is textually empty; the directive is the intent.
  it('catch containing only an eslint-disable-next-line style directive comment', () => {
    expectClean(
      one(
        'src/boot/polyfills.ts',
        `
export function installPolyfills(tryInstall: () => void) {
  try {
    tryInstall();
  } catch {
    // eslint-disable-line no-empty -- polyfill absence is the supported state
  }
}
`
      )
    );
  });

  // AMBIGUOUS: threshold guess — TWO ": any" occurrences in a ~350 line file.
  // If "heavy use" means density, two-in-350-lines should pass; if it means
  // any repeat, this fires. Calibration signal either way.
  it('two boundary any annotations spread across a large file', () => {
    expectClean(
      one(
        'src/interop/host-bridge.ts',
        tsFiller(70, 'bridge') +
          `
// Host page injects both globals untyped; each is narrowed immediately.
export function hostConfig(): unknown {
  return (window as any).__hostConfig;
}
export function hostLogger(): unknown {
  return (window as any).__hostLogger;
}
`
      )
    );
  });

  // AMBIGUOUS: threshold guess — a SINGLE ": any" in a small (~15 line) file.
  // One occurrence is not "heavy", but in a tiny file the density is high.
  it('single any annotation in a small interop file', () => {
    expectClean(
      one(
        'src/interop/legacy.ts',
        `
/**
 * Single deliberate escape hatch: the legacy widget API predates our types.
 */
export function mountLegacyWidget(el: HTMLElement, widget: any): void {
  if (widget && typeof widget.mount === 'function') {
    widget.mount(el);
  }
}
`
      )
    );
  });

  // AMBIGUOUS: one honest TODO in an otherwise complete file. TODO scaffolding
  // is an adjacent smell class; a single tracked TODO is normal engineering.
  it('single tracked TODO comment in an otherwise complete module', () => {
    expectClean(
      one(
        'src/export/csv.ts',
        `
export function toCsv(rows: string[][]): string {
  // TODO(#412): stream output for very large exports instead of joining.
  return rows.map((r) => r.map(escapeCell).join(',')).join('\\n');
}

function escapeCell(cell: string): string {
  return /[",\\n]/.test(cell) ? '"' + cell.replace(/"/g, '""') + '"' : cell;
}
`
      )
    );
  });

  // AMBIGUOUS: exported empty function with JSDoc declaring it an intentional
  // noop hook. Dead-code detectors may flag empty exported bodies.
  it('documented intentional noop hook with an empty body', () => {
    expectClean(
      one(
        'src/plugin/hooks.ts',
        `
/**
 * Default onBeforeScan hook. Intentionally a noop; consumers override it.
 * Kept as a real function (not undefined) so the call site stays branch-free.
 */
export function onBeforeScan(): void {}

export function runHooks(hooks: { onBeforeScan(): void }) {
  hooks.onBeforeScan();
}
`
      )
    );
  });
});

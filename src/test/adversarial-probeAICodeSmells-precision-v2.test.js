/**
 * Adversarial PRECISION tests for probeAICodeSmells.
 *
 * Calibration: probeAICodeSmells is INFORMATIONAL. Any finding fired on
 * benign, intentional, idiomatic code is noise that trains users to ignore
 * the panel entirely. These tests assert ZERO findings on legitimate code
 * that merely contains the SHAPES the probe tries to flag.
 *
 * Threshold: expect(findings).toEqual([])
 *
 * Categories tested:
 *  1. Intentional empty catches with explanatory comments
 *  2. Catches whose single statement IS the handling (log)
 *  3. Catches that rethrow without other statements
 *  4. Catches in test files
 *  5. Catches narrowed to a known recoverable error class
 *  6. try/finally with no catch at all
 *  7. `catch {}` inside a string literal
 *  8. `catch (e) {}` inside a block comment
 *  9. `catch {}` inside a line comment
 * 10. catch text inside a template literal as a code sample
 * 11. Fenced markdown sample assigned to a variable
 * 12. Promise.catch(() => {})
 * 13. `: any` in catch clauses
 * 14. `: any` in .d.ts files
 * 15. `: any[]` array type in generic helpers
 * 16. Record<string, any> bag-of-properties
 * 17. <T = any> generic default
 * 18. `as any` in test setup or migrations
 * 19. The word `any` as identifier or English comment
 * 20. `any` in JSDoc inside .js files
 * 21. Pure .js / .jsx with no TypeScript
 * 22. `: unknown` handler params
 * 23. Zod-validated handlers using payload: unknown
 * 24. TS overloads where implementation signature uses `any`
 * 25. Suppressive utility wrappers (tryCatch)
 * 26. TypeScript class field declarations
 * 27. anyOf / oneOf JSON Schema fragments in strings or comments
 */

import { describe, it, expect } from 'vitest';
import { probeAICodeSmells } from '../lib/probes.js';

const file = (path, content) => ({ path, content });
const scan = (path, content) => probeAICodeSmells([file(path, content)]);

// ---------------------------------------------------------------------------
// Category 1: Intentional empty catches with explanatory comments
// ---------------------------------------------------------------------------
describe('benign: intentional empty catches with explanatory comments', () => {
  it('does not flag empty catch with best-effort cleanup comment', () => {
    const src = `
      function cleanup() {
        try {
          fs.unlinkSync(tmpPath);
        } catch (e) {
          // best-effort cleanup; file may not exist
        }
      }
    `;
    expect(scan('src/utils/cleanup.js', src)).toEqual([]);
  });

  it('does not flag empty catch documenting why swallowing is correct', () => {
    const src = `
      try {
        navigator.clipboard.writeText(value);
      } catch (e) {
        // clipboard API rejected by browser policy. Fallback is no-op by design.
      }
    `;
    expect(scan('src/utils/clipboard.js', src)).toEqual([]);
  });

  it('does not flag intentional empty catch (no binding) with note', () => {
    const src = `
      try {
        JSON.parse(input);
      } catch {
        // input was not JSON. Caller handles the non-JSON branch.
      }
    `;
    expect(scan('src/utils/parse.js', src)).toEqual([]);
  });

  it('does not flag empty catch with multi-line rationale comment', () => {
    const src = `
      try {
        localStorage.setItem('k', v);
      } catch (e) {
        /*
         * QuotaExceededError or SecurityError in private-browsing.
         * Persistence is a nice-to-have here, not a requirement.
         */
      }
    `;
    expect(scan('src/utils/storage.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 2: Catches that log and that single statement IS the handling
// ---------------------------------------------------------------------------
describe('benign: log-only catches', () => {
  it('does not flag a single log.warn handler', () => {
    const src = `
      try {
        await retry(fn);
      } catch (e) {
        log.warn('non-fatal', { e });
      }
    `;
    expect(scan('src/jobs/retry.js', src)).toEqual([]);
  });

  it('does not flag a single console.error handler', () => {
    const src = `
      try {
        flushMetrics();
      } catch (err) {
        console.error('metrics flush failed', err);
      }
    `;
    expect(scan('src/metrics/flush.js', src)).toEqual([]);
  });

  it('does not flag a single logger.debug handler', () => {
    const src = `
      try {
        cache.evict(key);
      } catch (e) {
        logger.debug('cache evict skipped', e);
      }
    `;
    expect(scan('src/cache/evict.js', src)).toEqual([]);
  });

  it('does not flag a single reportError(e) handler', () => {
    const src = `
      try {
        runPlugin(plugin);
      } catch (e) {
        reportError(e);
      }
    `;
    expect(scan('src/plugins/run.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 3: Catches that rethrow without any other statement
// ---------------------------------------------------------------------------
describe('benign: rethrow-only catches', () => {
  it('does not flag bare rethrow', () => {
    const src = `
      try {
        doWork();
      } catch (e) {
        throw e;
      }
    `;
    expect(scan('src/work.js', src)).toEqual([]);
  });

  it('does not flag rethrow used to mark a boundary intentionally', () => {
    const src = `
      async function boundary() {
        try {
          return await inner();
        } catch (e) {
          throw e; // explicit re-raise for boundary instrumentation hook
        }
      }
    `;
    expect(scan('src/boundary.js', src)).toEqual([]);
  });

  it('does not flag rethrow wrapped in a custom error', () => {
    const src = `
      try {
        return parse(input);
      } catch (cause) {
        throw new ParseError('bad input', { cause });
      }
    `;
    expect(scan('src/parser.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 4: Catches inside test files
// ---------------------------------------------------------------------------
describe('benign: catches in test files', () => {
  it('does not flag empty catch in *.test.ts', () => {
    const src = `
      it('handles missing key', () => {
        try {
          throw new Error('expected');
        } catch (e) {}
        expect(true).toBe(true);
      });
    `;
    expect(scan('src/foo.test.ts', src)).toEqual([]);
  });

  it('does not flag empty catch in *.spec.ts', () => {
    const src = `
      it('throws', () => {
        try { mayThrow(); } catch {}
      });
    `;
    expect(scan('src/foo.spec.ts', src)).toEqual([]);
  });

  it('does not flag empty catch in __tests__/ directory', () => {
    const src = `
      describe('x', () => {
        it('y', () => {
          try { mayThrow(); } catch (e) {}
        });
      });
    `;
    expect(scan('src/__tests__/x.test.js', src)).toEqual([]);
  });

  it('does not flag empty catch in tests/ directory', () => {
    const src = `
      try { mayThrow(); } catch {}
    `;
    expect(scan('tests/integration.js', src)).toEqual([]);
  });

  it('does not flag fixture file with empty catch', () => {
    const src = `
      // fixture for parser tests
      try { JSON.parse('x'); } catch {}
    `;
    expect(scan('src/test/fixtures/bad-json.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 5: Catches narrowed to a recoverable known error class
// ---------------------------------------------------------------------------
describe('benign: catches narrowed to a known recoverable error', () => {
  it('does not flag catch that branches on instanceof and rethrows other', () => {
    const src = `
      try {
        await fetchThing();
      } catch (e) {
        if (e instanceof NotFoundError) return null;
        throw e;
      }
    `;
    expect(scan('src/fetcher.js', src)).toEqual([]);
  });

  it('does not flag catch with code-based recoverable error check', () => {
    const src = `
      try {
        fs.mkdirSync(p);
      } catch (e) {
        if (e.code !== 'EEXIST') throw e;
      }
    `;
    expect(scan('src/fs-helpers.js', src)).toEqual([]);
  });

  it('does not flag catch with AbortError recovery', () => {
    const src = `
      try {
        await fetchWithSignal(url, ctrl.signal);
      } catch (e) {
        if (e.name === 'AbortError') return;
        throw e;
      }
    `;
    expect(scan('src/net.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 6: try/finally with no catch at all
// ---------------------------------------------------------------------------
describe('benign: try/finally with no catch', () => {
  it('does not flag try/finally', () => {
    const src = `
      function withLock(fn) {
        acquire();
        try {
          return fn();
        } finally {
          release();
        }
      }
    `;
    expect(scan('src/lock.js', src)).toEqual([]);
  });

  it('does not flag async try/finally with timer cleanup', () => {
    const src = `
      async function timed(fn) {
        const t = startTimer();
        try {
          return await fn();
        } finally {
          stopTimer(t);
        }
      }
    `;
    expect(scan('src/timed.js', src)).toEqual([]);
  });

  it('does not flag try/finally that releases a resource', () => {
    const src = `
      function withFd(path, fn) {
        const fd = openSync(path);
        try { return fn(fd); } finally { closeSync(fd); }
      }
    `;
    expect(scan('src/fd.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 7: `catch {}` text inside a string literal
// ---------------------------------------------------------------------------
describe('benign: catch text inside string literals', () => {
  it('does not flag catch {} inside a double-quoted string', () => {
    const src = `
      const explainer = "Beginners often write try { ... } catch {} which silently swallows errors.";
      export default explainer;
    `;
    expect(scan('src/docs/explainer.js', src)).toEqual([]);
  });

  it('does not flag catch {} inside a single-quoted string', () => {
    const src = `
      const tip = 'Avoid catch {} without a comment.';
      module.exports = tip;
    `;
    expect(scan('src/tips.js', src)).toEqual([]);
  });

  it('does not flag catch (e) {} as a substring of a docstring', () => {
    const src = `
      const HELP = "The pattern \\\"catch (e) {}\\\" with no comment is an antipattern.";
    `;
    expect(scan('src/help.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 8: `catch (e) {}` inside a block comment
// ---------------------------------------------------------------------------
describe('benign: catch text inside block comments', () => {
  it('does not flag catch (e) {} inside a /* */ block comment', () => {
    const src = `
      /*
       * Historically this used catch (e) {} but we replaced it with
       * a proper logger.warn call below.
       */
      try { mayThrow(); } catch (e) { logger.warn(e); }
    `;
    expect(scan('src/historic.js', src)).toEqual([]);
  });

  it('does not flag JSDoc that mentions catch (e) {}', () => {
    const src = `
      /**
       * Wraps the supplied fn. Do NOT use catch (e) {} inside fn.
       * @param {Function} fn
       */
      function wrap(fn) { return fn; }
    `;
    expect(scan('src/wrap.js', src)).toEqual([]);
  });

  it('does not flag a multi-line comment that quotes catch shapes', () => {
    const src = `
      /*
        Examples of bad shapes:
          catch (e) {}
          catch {}
          Promise.reject().catch(() => {})
        The codebase below uses none of them.
      */
      export const ok = true;
    `;
    expect(scan('src/examples-of-bad.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 9: `catch {}` inside a // line comment
// ---------------------------------------------------------------------------
describe('benign: catch text inside line comments', () => {
  it('does not flag catch {} in a single-line // comment', () => {
    const src = `
      // The classic antipattern is catch {} with no comment.
      try { mayThrow(); } catch (e) { logger.warn(e); }
    `;
    expect(scan('src/lint-note.js', src)).toEqual([]);
  });

  it('does not flag two adjacent // lines that together quote catch (e) {}', () => {
    const src = `
      // Never write code like this:
      //   try { x(); } catch (e) {}
      export const ok = true;
    `;
    expect(scan('src/never-do.js', src)).toEqual([]);
  });

  it('does not flag inline // comment after a statement', () => {
    const src = `
      const ANTIPATTERN = 'catch {}'; // we do not do this here
      export default ANTIPATTERN;
    `;
    expect(scan('src/anti.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 10: catch text inside a template literal used as a code sample
// ---------------------------------------------------------------------------
describe('benign: catch text inside template literal samples', () => {
  it('does not flag a backtick code sample variable', () => {
    const src = `
      const sample = \`
        try {
          doWork();
        } catch {}
      \`;
      export default sample;
    `;
    expect(scan('src/learn/samples.js', src)).toEqual([]);
  });

  it('does not flag a template-literal explainer with catch (e) {}', () => {
    const src = `
      export const note = \`
        Common antipattern:
          try { x(); } catch (e) {}
        Use a comment or log.
      \`;
    `;
    expect(scan('src/learn/notes.js', src)).toEqual([]);
  });

  it('does not flag a tagged template literal documenting catch shapes', () => {
    const src = `
      export const html = dedent\`
        <pre>try { x(); } catch {}</pre>
      \`;
    `;
    expect(scan('src/learn/html.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 11: Fenced markdown-style sample assigned to a variable
// ---------------------------------------------------------------------------
describe('benign: fenced markdown sample assigned to a variable', () => {
  it('does not flag fenced ```js block embedded in a string', () => {
    const src = `
      export const md = \`
\\\`\\\`\\\`js
try {
  thing();
} catch {}
\\\`\\\`\\\`
      \`;
    `;
    expect(scan('src/learn/md-sample.js', src)).toEqual([]);
  });

  it('does not flag fenced ```ts block with : any sample', () => {
    const src = `
      export const md = \`
\\\`\\\`\\\`ts
function handler(req: any, res: any) {}
\\\`\\\`\\\`
      \`;
    `;
    expect(scan('src/learn/md-any.js', src)).toEqual([]);
  });

  it('does not flag a curriculum file that quotes both shapes', () => {
    const src = `
      export const lesson = {
        title: 'Catches and any',
        body: \`Examples:\\n  try { f(); } catch {}\\n  function h(req: any) {}\`,
      };
    `;
    expect(scan('src/learn/lesson.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 12: Promise.catch(() => {})
// ---------------------------------------------------------------------------
describe('benign: Promise.catch with intentional no-op', () => {
  it('does not flag fire-and-forget Promise.catch with comment', () => {
    const src = `
      // best-effort telemetry; never blocks the UI
      sendBeacon(url, data).catch(() => {});
    `;
    expect(scan('src/telemetry.js', src)).toEqual([]);
  });

  it('does not flag .catch(() => null) with explanatory comment', () => {
    const src = `
      // missing entry is the success path for this lookup
      const v = await store.get(key).catch(() => null);
    `;
    expect(scan('src/store.js', src)).toEqual([]);
  });

  it('does not flag .catch(noop) where noop is named explicitly', () => {
    const src = `
      const noop = () => {};
      // metrics emission is fire-and-forget by design
      emitMetric('hit').catch(noop);
    `;
    expect(scan('src/metrics.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 13: `: any` in catch clauses (TS 3.x default before useUnknownInCatch)
// ---------------------------------------------------------------------------
describe('benign: : any in catch clauses', () => {
  it('does not flag catch (e: any) when the body inspects the error', () => {
    const src = `
      try {
        await doWork();
      } catch (e: any) {
        if (e?.code === 'EEXIST') return;
        throw e;
      }
    `;
    expect(scan('src/ts-catch.ts', src)).toEqual([]);
  });

  it('does not flag catch (err: any) with logger', () => {
    const src = `
      try { run(); } catch (err: any) { logger.warn('non-fatal', { msg: err?.message }); }
    `;
    expect(scan('src/ts-log.ts', src)).toEqual([]);
  });

  it('does not flag catch (e: any) with rethrow', () => {
    const src = `
      try { run(); } catch (e: any) { throw e; }
    `;
    expect(scan('src/ts-rethrow.ts', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 14: `: any` in .d.ts declaration files (third-party shims)
// ---------------------------------------------------------------------------
describe('benign: : any in .d.ts declaration files', () => {
  it('does not flag any usage in an ambient module declaration', () => {
    const src = `
      declare module 'untyped-lib' {
        export function configure(opts: any): any;
        export const VERSION: string;
      }
    `;
    expect(scan('src/types/untyped-lib.d.ts', src)).toEqual([]);
  });

  it('does not flag global augmentation with any types', () => {
    const src = `
      declare global {
        interface Window { __DEVTOOLS__?: any }
      }
      export {};
    `;
    expect(scan('src/types/window.d.ts', src)).toEqual([]);
  });

  it('does not flag any in a vendor.d.ts shim', () => {
    const src = `
      declare module '*.svg' { const content: any; export default content; }
    `;
    expect(scan('src/types/vendor.d.ts', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 15: `: any[]` array type in generic helpers
// ---------------------------------------------------------------------------
describe('benign: : any[] in generic helpers', () => {
  it('does not flag any[] in a debounce signature with rationale', () => {
    const src = `
      // any[] is correct here: debounce passes args through opaquely
      export function debounce<F extends (...args: any[]) => void>(fn: F, ms: number): F {
        let t: any;
        return ((...args: any[]) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); }) as F;
      }
    `;
    expect(scan('src/utils/debounce.ts', src)).toEqual([]);
  });

  it('does not flag any[] inside a generic memoize helper', () => {
    const src = `
      export function memoize<F extends (...args: any[]) => unknown>(fn: F): F {
        const cache = new Map();
        return ((...args: any[]) => {
          const key = JSON.stringify(args);
          if (!cache.has(key)) cache.set(key, fn(...args));
          return cache.get(key);
        }) as F;
      }
    `;
    expect(scan('src/utils/memoize.ts', src)).toEqual([]);
  });

  it('does not flag any[] in a throttle helper', () => {
    const src = `
      export function throttle<F extends (...args: any[]) => void>(fn: F, ms: number): F {
        let last = 0;
        return ((...args: any[]) => {
          const now = Date.now();
          if (now - last >= ms) { last = now; fn(...args); }
        }) as F;
      }
    `;
    expect(scan('src/utils/throttle.ts', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 16: Record<string, any> bag-of-properties
// ---------------------------------------------------------------------------
describe('benign: Record<string, any> bag-of-properties', () => {
  it('does not flag Record<string, any> on an opaque config blob', () => {
    const src = `
      export function merge(a: Record<string, any>, b: Record<string, any>): Record<string, any> {
        return { ...a, ...b };
      }
    `;
    expect(scan('src/utils/merge.ts', src)).toEqual([]);
  });

  it('does not flag Record<string, any> in a JSON-passthrough sink', () => {
    const src = `
      export function toJSON(o: Record<string, any>): string {
        return JSON.stringify(o);
      }
    `;
    expect(scan('src/utils/to-json.ts', src)).toEqual([]);
  });

  it('does not flag Record<string, any> on extras param', () => {
    const src = `
      export function log(event: string, extras: Record<string, any> = {}): void {
        console.log(event, extras);
      }
    `;
    expect(scan('src/utils/log.ts', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 17: <T = any> generic default
// ---------------------------------------------------------------------------
describe('benign: <T = any> generic default', () => {
  it('does not flag T = any default on a fetch helper', () => {
    const src = `
      export async function getJSON<T = any>(url: string): Promise<T> {
        const r = await fetch(url);
        return (await r.json()) as T;
      }
    `;
    expect(scan('src/net/get-json.ts', src)).toEqual([]);
  });

  it('does not flag T = any default on event emitter', () => {
    const src = `
      export class Emitter<T = any> {
        listeners: Array<(v: T) => void> = [];
        emit(v: T): void { for (const l of this.listeners) l(v); }
      }
    `;
    expect(scan('src/utils/emitter.ts', src)).toEqual([]);
  });

  it('does not flag T = any in a Result type', () => {
    const src = `
      export type Result<T = any, E = Error> = { ok: true; value: T } | { ok: false; error: E };
    `;
    expect(scan('src/types/result.ts', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 18: `as any` in test setup / migrations with comments
// ---------------------------------------------------------------------------
describe('benign: as any in test setup or migrations', () => {
  it('does not flag as any in a test mock with comment', () => {
    const src = `
      // jest mock; intentionally untyped
      const mock = { user: { id: 'u1' } } as any;
      it('runs', () => { expect(mock.user.id).toBe('u1'); });
    `;
    expect(scan('src/foo.test.ts', src)).toEqual([]);
  });

  it('does not flag as any in a migration that mutates schema', () => {
    const src = `
      // migration: column added before TS types regenerate
      const row = result as any;
      await db.exec('ALTER TABLE x ADD c TEXT');
      console.log(row.c);
    `;
    expect(scan('src/migrations/2026-01-01-add-c.ts', src)).toEqual([]);
  });

  it('does not flag as any in a vitest spy', () => {
    const src = `
      import { vi } from 'vitest';
      // private API spied for test only
      const spy = vi.spyOn(obj as any, '_privateMethod');
      expect(spy).toBeDefined();
    `;
    expect(scan('src/foo.spec.ts', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 19: The word `any` as identifier / English comment
// ---------------------------------------------------------------------------
describe('benign: any as identifier or English text', () => {
  it('does not flag isAny / hasAny identifiers', () => {
    const src = `
      export const isAny = (xs) => xs.length > 0;
      export const hasAnyValue = (o) => Object.values(o).some(Boolean);
    `;
    expect(scan('src/utils/predicates.js', src)).toEqual([]);
  });

  it('does not flag English use of "any" in comments', () => {
    const src = `
      // returns any one of the matching items
      export function pickOne(xs) { return xs[0]; }
    `;
    expect(scan('src/utils/pick-one.js', src)).toEqual([]);
  });

  it('does not flag the literal string "any" in user-facing text', () => {
    const src = `
      export const label = 'Filter: any match';
    `;
    expect(scan('src/ui/filter-label.js', src)).toEqual([]);
  });

  it('does not flag identifier anyOf in a JSON-schema variable', () => {
    const src = `
      export const anyOfShape = { anyOf: [{ type: 'string' }, { type: 'number' }] };
    `;
    expect(scan('src/schemas/any-of.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 20: `any` in JSDoc inside .js files
// ---------------------------------------------------------------------------
describe('benign: any in JSDoc inside .js', () => {
  it('does not flag @param {any}', () => {
    const src = `
      /**
       * @param {any} input
       * @returns {string}
       */
      export function stringify(input) { return String(input); }
    `;
    expect(scan('src/utils/stringify.js', src)).toEqual([]);
  });

  it('does not flag @returns {any}', () => {
    const src = `
      /**
       * @param {string} k
       * @returns {any}
       */
      export function get(k) { return store[k]; }
    `;
    expect(scan('src/utils/get.js', src)).toEqual([]);
  });

  it('does not flag @typedef with any property', () => {
    const src = `
      /**
       * @typedef {Object} Bag
       * @property {any} extras
       */
      export const x = 1;
    `;
    expect(scan('src/types/bag.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 21: Pure .js / .jsx with no TypeScript at all
// ---------------------------------------------------------------------------
describe('benign: pure JS/JSX with no TypeScript', () => {
  it('does not flag a typical React functional component', () => {
    const src = `
      import React from 'react';
      export default function Hello({ name }) {
        return <div>Hello {name}</div>;
      }
    `;
    expect(scan('src/components/Hello.jsx', src)).toEqual([]);
  });

  it('does not flag a plain utility module', () => {
    const src = `
      export const add = (a, b) => a + b;
      export const sub = (a, b) => a - b;
    `;
    expect(scan('src/utils/math.js', src)).toEqual([]);
  });

  it('does not flag a class with methods', () => {
    const src = `
      export class Counter {
        constructor() { this.n = 0; }
        inc() { this.n += 1; }
        get value() { return this.n; }
      }
    `;
    expect(scan('src/utils/counter.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 22: `: unknown` handler parameters (the recommended fix)
// ---------------------------------------------------------------------------
describe('benign: : unknown handler parameters', () => {
  it('does not flag a webhook handler typed as unknown', () => {
    const src = `
      export function handleWebhook(payload: unknown) {
        if (typeof payload !== 'object' || payload === null) throw new Error('bad');
        return (payload as { id: string }).id;
      }
    `;
    expect(scan('src/api/webhook.ts', src)).toEqual([]);
  });

  it('does not flag an event handler typed as unknown', () => {
    const src = `
      export function onEvent(e: unknown) {
        if (e instanceof CustomEvent) return e.detail;
      }
    `;
    expect(scan('src/events/handler.ts', src)).toEqual([]);
  });

  it('does not flag a queue worker typed as unknown', () => {
    const src = `
      export async function processJob(job: unknown) {
        if (!isJob(job)) return;
        await run(job);
      }
    `;
    expect(scan('src/queue/worker.ts', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 23: Already-Zod-validated handlers using payload: unknown
// ---------------------------------------------------------------------------
describe('benign: zod-validated handlers using payload: unknown', () => {
  it('does not flag a zod-validated post handler', () => {
    const src = `
      import { z } from 'zod';
      const Body = z.object({ id: z.string() });
      export function post(payload: unknown) {
        const parsed = Body.parse(payload);
        return parsed.id;
      }
    `;
    expect(scan('src/api/post.ts', src)).toEqual([]);
  });

  it('does not flag a zod-validated stripe webhook adapter', () => {
    const src = `
      import { z } from 'zod';
      const Event = z.object({ type: z.string(), data: z.unknown() });
      export function handleStripe(raw: unknown) {
        const evt = Event.parse(raw);
        return evt.type;
      }
    `;
    expect(scan('src/api/stripe-webhook.ts', src)).toEqual([]);
  });

  it('does not flag a zod-validated CLI command parser', () => {
    const src = `
      import { z } from 'zod';
      const Args = z.object({ cmd: z.string(), flags: z.record(z.string()) });
      export function dispatch(argv: unknown) {
        const { cmd } = Args.parse(argv);
        return cmd;
      }
    `;
    expect(scan('src/cli/dispatch.ts', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 24: TS function overloads — `any` mechanical for impl signature
// ---------------------------------------------------------------------------
describe('benign: TS overloads with any in implementation signature', () => {
  it('does not flag overloads with any in the impl line', () => {
    const src = `
      export function pick(x: string): string;
      export function pick(x: number): number;
      export function pick(x: any): any {
        return x;
      }
    `;
    expect(scan('src/utils/pick.ts', src)).toEqual([]);
  });

  it('does not flag overloads on an emit() impl signature', () => {
    const src = `
      export function emit(event: 'open'): void;
      export function emit(event: 'data', payload: string): void;
      export function emit(event: string, payload?: any): void {
        bus.dispatch(event, payload);
      }
    `;
    expect(scan('src/bus/emit.ts', src)).toEqual([]);
  });

  it('does not flag overloads in a select() signature', () => {
    const src = `
      export function select(q: { id: string }): User;
      export function select(q: { email: string }): User;
      export function select(q: any): User {
        return db.query(q);
      }
    `;
    expect(scan('src/db/select.ts', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 25: Suppressive utility wrappers (tryCatch)
// ---------------------------------------------------------------------------
describe('benign: suppressive utility wrappers', () => {
  it('does not flag a tryCatch helper that returns a Result', () => {
    const src = `
      export function tryCatch(fn) {
        try {
          return { ok: true, value: fn() };
        } catch (e) {
          return { ok: false, error: e };
        }
      }
    `;
    expect(scan('src/utils/try-catch.js', src)).toEqual([]);
  });

  it('does not flag an asyncTryCatch wrapper', () => {
    const src = `
      export async function asyncTryCatch(fn) {
        try { return { ok: true, value: await fn() }; }
        catch (e) { return { ok: false, error: e }; }
      }
    `;
    expect(scan('src/utils/async-try-catch.js', src)).toEqual([]);
  });

  it('does not flag a Go-style tuple helper', () => {
    const src = `
      export async function to(p) {
        try { return [null, await p]; }
        catch (e) { return [e, undefined]; }
      }
    `;
    expect(scan('src/utils/to.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 26: TypeScript class field declarations: `config: any = default`
// ---------------------------------------------------------------------------
describe('benign: TS class field declarations with any', () => {
  it('does not flag a class field initialized with an opaque default', () => {
    const src = `
      const defaultConfig = { mode: 'auto' };
      export class App {
        config: any = defaultConfig;
        init() { return this.config; }
      }
    `;
    expect(scan('src/app.ts', src)).toEqual([]);
  });

  it('does not flag a class with multiple any fields', () => {
    const src = `
      export class Bag {
        meta: any = {};
        extras: any[] = [];
        tag: any;
      }
    `;
    expect(scan('src/bag.ts', src)).toEqual([]);
  });

  it('does not flag a class field constrained later by getters', () => {
    const src = `
      export class Holder {
        private _v: any = null;
        get v(): string { return String(this._v); }
        set v(x: string) { this._v = x; }
      }
    `;
    expect(scan('src/holder.ts', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Category 27: anyOf / oneOf JSON Schema fragments
// ---------------------------------------------------------------------------
describe('benign: anyOf / oneOf JSON Schema fragments', () => {
  it('does not flag an anyOf schema literal', () => {
    const src = `
      export const schema = {
        type: 'object',
        properties: {
          id: { anyOf: [{ type: 'string' }, { type: 'number' }] },
        },
      };
    `;
    expect(scan('src/schemas/id.js', src)).toEqual([]);
  });

  it('does not flag a oneOf schema literal', () => {
    const src = `
      export const schema = {
        oneOf: [
          { type: 'object', properties: { kind: { const: 'a' } } },
          { type: 'object', properties: { kind: { const: 'b' } } },
        ],
      };
    `;
    expect(scan('src/schemas/kind.js', src)).toEqual([]);
  });

  it('does not flag anyOf in a comment doc-block', () => {
    const src = `
      /**
       * Use anyOf when you want at least one branch to match.
       * Use oneOf when exactly one must match.
       */
      export const x = 1;
    `;
    expect(scan('src/schemas/notes.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Edge cases where benign-vs-smell is genuinely ambiguous
// ---------------------------------------------------------------------------
describe('edge cases where benign-vs-smell is genuinely ambiguous', () => {
  // AMBIGUOUS: empty catch with only a TODO. Strictly speaking the engineer
  // signaled "I'll come back" rather than "this is fine," but most teams
  // ship TODOs and we should not nag in INFO.
  it('does not flag empty catch annotated only with TODO', () => {
    const src = `
      try { thing(); } catch (e) { /* TODO: route to telemetry */ }
    `;
    expect(scan('src/todo.js', src)).toEqual([]);
  });

  // AMBIGUOUS: catch (e) { void e; } pattern used to silence
  // no-unused-vars lints while signaling intentional swallow.
  it('does not flag catch (e) { void e; } lint-silencing pattern', () => {
    const src = `
      try { f(); } catch (e) { void e; }
    `;
    expect(scan('src/void-e.js', src)).toEqual([]);
  });

  // AMBIGUOUS: : any deliberately used in event-bus dispatch where
  // payload genuinely varies per event type. Could be Record<string, unknown>,
  // but : any is widely accepted here.
  it('does not flag : any on an event-bus dispatch helper', () => {
    const src = `
      export function dispatch(event: string, payload: any): void {
        bus.emit(event, payload);
      }
    `;
    expect(scan('src/bus/dispatch.ts', src)).toEqual([]);
  });

  // AMBIGUOUS: a single string-literal that contains both shapes near
  // actual code. The probe should isolate string vs code context.
  it('does not flag a learn module that puts both shapes in one string', () => {
    const src = `
      export const lesson = "Avoid catch (e) {} and function h(req: any) { return req; }";
      export function ok() { return true; }
    `;
    expect(scan('src/learn/combined.js', src)).toEqual([]);
  });
});

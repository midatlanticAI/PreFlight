// Adversarial precision tests for probeAICodeSmells.
//
// Threshold: ZERO findings. probeAICodeSmells is INFORMATIONAL; any info-level
// finding on the legitimate code below is noise. Every test here is a MUST NOT
// FIRE case. Heavy emphasis on multi-line block/template/JSDoc comment cases
// (categories 10, 11, 12) where a per-line scanner would mistake quoted shapes
// for real code.

import { describe, it, expect } from 'vitest';
import { probeAICodeSmells } from '../lib/probes.js';

const file = (path, content) => ({ path, content });
const noFindings = (path, src) => expect(probeAICodeSmells([file(path, src)])).toEqual([]);

// ---------------------------------------------------------------------------
// 1. Intentional empty catches with explanatory comments INSIDE the catch body.
// ---------------------------------------------------------------------------
describe('intentional empty catches with explanatory comment inside', () => {
  it('storage write best-effort', () => {
    const src = `
      function persist(key, value) {
        try {
          localStorage.setItem(key, JSON.stringify(value));
        } catch (e) {
          // Storage quota or privacy mode: degrade to in-memory only.
        }
      }
    `;
    noFindings('src/util/persist.js', src);
  });

  it('cleanup on already-closed socket', () => {
    const src = `
      function closeSocket(ws) {
        try { ws.close(); } catch {
          // Socket already closed during teardown; nothing to do.
        }
      }
    `;
    noFindings('src/net/socket.js', src);
  });

  it('optional dependency probe', () => {
    const src = `
      let chalk;
      try {
        chalk = require('chalk');
      } catch (e) {
        // chalk is optional. We fall back to identity coloring below.
      }
    `;
    noFindings('src/cli/color.js', src);
  });

  it('JSON parse with documented fallback', () => {
    const src = `
      function readMaybeJSON(raw) {
        try {
          return JSON.parse(raw);
        } catch (err) {
          // raw is not JSON. The caller treats null as "not JSON" by contract.
        }
        return null;
      }
    `;
    noFindings('src/util/json.js', src);
  });
});

// ---------------------------------------------------------------------------
// 2. Catches that log and the single statement IS the handling.
// ---------------------------------------------------------------------------
describe('log-only catches where logging IS the handling', () => {
  it('console.error one-liner', () => {
    const src = `
      try { doWork(); } catch (e) { console.error('work failed', e); }
    `;
    noFindings('src/work.js', src);
  });

  it('structured logger', () => {
    const src = `
      try {
        processBatch(items);
      } catch (err) {
        logger.warn({ err, items: items.length }, 'batch processing failed');
      }
    `;
    noFindings('src/batch.js', src);
  });

  it('reportError telemetry', () => {
    const src = `
      try { render(); } catch (e) { reportError(e); }
    `;
    noFindings('src/render.js', src);
  });
});

// ---------------------------------------------------------------------------
// 3. Catches that rethrow only.
// ---------------------------------------------------------------------------
describe('rethrowing catches', () => {
  it('plain rethrow', () => {
    const src = `
      try { mightThrow(); } catch (e) { throw e; }
    `;
    noFindings('src/r1.js', src);
  });

  it('rethrow wrapped', () => {
    const src = `
      try {
        await loadConfig();
      } catch (cause) {
        throw new Error('config load failed', { cause });
      }
    `;
    noFindings('src/r2.js', src);
  });

  it('rethrow with cleanup', () => {
    const src = `
      try {
        await begin();
      } catch (e) {
        await rollback();
        throw e;
      }
    `;
    noFindings('src/r3.js', src);
  });
});

// ---------------------------------------------------------------------------
// 4. Catches in test/fixtures files.
// ---------------------------------------------------------------------------
describe('catches inside test or fixture files', () => {
  it('empty catch inside a .test.js', () => {
    const src = `
      it('does not throw', () => {
        try { fn(); } catch {}
      });
    `;
    noFindings('src/feature/__tests__/feature.test.js', src);
  });

  it('empty catch inside spec file', () => {
    const src = `
      describe('x', () => {
        it('y', () => {
          try { fn(); } catch (e) {}
        });
      });
    `;
    noFindings('src/feature/feature.spec.ts', src);
  });

  it('catch inside fixtures dir', () => {
    const src = `
      export function brokenOnPurpose() {
        try { JSON.parse('{'); } catch {}
      }
    `;
    noFindings('src/fixtures/broken-json.js', src);
  });
});

// ---------------------------------------------------------------------------
// 5. Catches narrowed to a known recoverable error class.
// ---------------------------------------------------------------------------
describe('narrowed-to-recoverable catches', () => {
  it('AbortError ignored', () => {
    const src = `
      try {
        await fetch(url, { signal });
      } catch (e) {
        if (e.name !== 'AbortError') throw e;
      }
    `;
    noFindings('src/net/fetch.js', src);
  });

  it('ENOENT ignored', () => {
    const src = `
      try {
        fs.unlinkSync(path);
      } catch (e) {
        if (e.code !== 'ENOENT') throw e;
      }
    `;
    noFindings('src/fs/cleanup.js', src);
  });

  it('SyntaxError narrowed', () => {
    const src = `
      try {
        return JSON.parse(text);
      } catch (e) {
        if (!(e instanceof SyntaxError)) throw e;
        return null;
      }
    `;
    noFindings('src/util/parse.js', src);
  });
});

// ---------------------------------------------------------------------------
// 6. try/finally with no catch at all.
// ---------------------------------------------------------------------------
describe('try/finally with no catch', () => {
  it('lock release', () => {
    const src = `
      async function withLock(fn) {
        await lock.acquire();
        try {
          return await fn();
        } finally {
          lock.release();
        }
      }
    `;
    noFindings('src/sync/lock.js', src);
  });

  it('timer cleanup', () => {
    const src = `
      function timed(fn) {
        const t = startTimer();
        try { return fn(); } finally { t.stop(); }
      }
    `;
    noFindings('src/perf/timed.js', src);
  });

  it('file handle close', () => {
    const src = `
      async function readAll(handle) {
        try {
          return await handle.readFile();
        } finally {
          await handle.close();
        }
      }
    `;
    noFindings('src/fs/handle.js', src);
  });
});

// ---------------------------------------------------------------------------
// 7. catch {} text inside SINGLE-LINE string literals.
// ---------------------------------------------------------------------------
describe('catch shapes in single-line string literals', () => {
  it('double-quoted string', () => {
    const src = `
      const msg = "the pattern catch {} is a smell";
      export default msg;
    `;
    noFindings('src/copy.js', src);
  });

  it('single-quoted string', () => {
    const src = `
      const advice = 'avoid writing catch (e) {} in your code';
      console.log(advice);
    `;
    noFindings('src/advice.js', src);
  });

  it('template literal single line', () => {
    const src = `
      const t = \`see also: catch {} as an antipattern\`;
      export { t };
    `;
    noFindings('src/templ.js', src);
  });
});

// ---------------------------------------------------------------------------
// 8. catch (e) {} text inside SINGLE-LINE block comments.
// ---------------------------------------------------------------------------
describe('catch shapes in single-line /* */ block comments', () => {
  it('single-line block comment with catch (e) {}', () => {
    const src = `
      /* avoid catch (e) {} */
      export const X = 1;
    `;
    noFindings('src/single-block-1.js', src);
  });

  it('comment with catch {}', () => {
    const src = `
      const y = 2; /* historically: catch {} was the default */
      export { y };
    `;
    noFindings('src/single-block-2.js', src);
  });

  it('trailing block comment with shape', () => {
    const src = `
      export const Z = 3; /* TODO: refactor "catch (err) {}" usages */
    `;
    noFindings('src/single-block-3.js', src);
  });
});

// ---------------------------------------------------------------------------
// 9. catch {} text inside // line comments.
// ---------------------------------------------------------------------------
describe('catch shapes in // line comments', () => {
  it('plain line comment', () => {
    const src = `
      // never write catch {} without a reason
      export const A = 1;
    `;
    noFindings('src/line-1.js', src);
  });

  it('trailing line comment', () => {
    const src = `
      const v = 1; // legacy code used catch (e) {} here, fixed in #421
      export { v };
    `;
    noFindings('src/line-2.js', src);
  });

  it('two consecutive line comments', () => {
    const src = `
      // step 1: try
      // step 2: catch {} would be wrong
      export const B = 2;
    `;
    noFindings('src/line-3.js', src);
  });
});

// ---------------------------------------------------------------------------
// 10. MULTI-LINE /* ... */ block comments quoting catch shapes (4+).
//     The case the per-line fix did not handle.
// ---------------------------------------------------------------------------
describe('multi-line /* */ block comments quoting catch shapes', () => {
  it('multi-line block comment quoting catch {}', () => {
    const src = `
      /*
       * Historical note. Before v2, the implementation used:
       *   try { doWork(); } catch {}
       * which dropped errors. We now narrow to known classes.
       */
      export function doWork() { return 1; }
    `;
    noFindings('src/multi-block-1.js', src);
  });

  it('multi-line block comment with catch (e) {}', () => {
    const src = `
      /*
       * Anti-pattern reference:
       *
       *   try {
       *     mightThrow();
       *   } catch (e) {}
       *
       * Do not copy this shape. It hides bugs.
       */
      export const A = 1;
    `;
    noFindings('src/multi-block-2.js', src);
  });

  it('multi-line block comment with multiple catch variants', () => {
    const src = `
      /*
       * The following shapes are all equivalent and all bad:
       *   catch {}
       *   catch (e) {}
       *   catch (err) {}
       *   catch (_) {}
       * Use a narrowed catch with explicit recovery instead.
       */
      export const B = 2;
    `;
    noFindings('src/multi-block-3.js', src);
  });

  it('multi-line block comment with full try/catch quoted', () => {
    const src = `
      /*
       * Before:
       *   try {
       *     parse(input);
       *   } catch (err) {
       *   }
       *
       * After:
       *   try {
       *     parse(input);
       *   } catch (err) {
       *     if (!(err instanceof SyntaxError)) throw err;
       *     return null;
       *   }
       */
      export function parse(x) { return JSON.parse(x); }
    `;
    noFindings('src/multi-block-4.js', src);
  });

  it('multi-line block comment with prose plus catch shape', () => {
    const src = `
      /*
       * Discussion: empty catches are not always wrong. The form
       *
       *     try { localStorage.setItem(k, v); } catch (e) {}
       *
       * is fine in browser code because quota errors are recoverable
       * by simply not persisting. The lint rule recognizes this idiom.
       */
      export function persist(k, v) {
        try { localStorage.setItem(k, v); } catch (e) {
          // best effort
        }
      }
    `;
    noFindings('src/multi-block-5.js', src);
  });

  it('multi-line block comment with catch in middle line only', () => {
    const src = `
      /*
       * Section one talks about try blocks generally.
       *
       *   catch (e) {}
       *
       * Section two talks about finally.
       */
      export const C = 3;
    `;
    noFindings('src/multi-block-6.js', src);
  });
});

// ---------------------------------------------------------------------------
// 11. MULTI-LINE TEMPLATE-LITERAL docstrings (backtick strings spanning
//     lines) containing catch shapes (4+).
// ---------------------------------------------------------------------------
describe('multi-line template literals containing catch shapes', () => {
  it('docstring constant', () => {
    const src = `
      export const ANTI_PATTERN_DOC = \`
        Empty catches are an antipattern:

          try {
            doWork();
          } catch (e) {}

        Always narrow.
      \`;
    `;
    noFindings('src/docs/empty-catch.js', src);
  });

  it('multiline help text', () => {
    const src = `
      const HELP = \`
        Usage:
          tool [options]

        Note: the legacy implementation contained
          try { fn(); } catch {}
        which we have removed.
      \`;
      console.log(HELP);
    `;
    noFindings('src/cli/help.js', src);
  });

  it('codegen template', () => {
    const src = `
      export function emitWrapper(name) {
        return \`
          export function \${name}(arg) {
            try {
              return inner(arg);
            } catch (e) {
              // generated handler keeps this catch intentional
              return null;
            }
          }
        \`;
      }
    `;
    noFindings('src/codegen/wrapper.js', src);
  });

  it('markdown content stored in a template literal', () => {
    const src = `
      export const PATTERN_MD = \`
        ## Empty catch

        The shape

        \\\`\\\`\\\`
        try {
          x();
        } catch (e) {}
        \\\`\\\`\\\`

        is informational only.
      \`;
    `;
    noFindings('src/learn/empty-catch.md.js', src);
  });

  it('error message template across lines', () => {
    const src = `
      function buildMsg(name) {
        return \`
          The function \${name} used the shape
          catch (err) {}
          which was rewritten to a narrowed handler.
        \`;
      }
      export { buildMsg };
    `;
    noFindings('src/diag/msg.js', src);
  });
});

// ---------------------------------------------------------------------------
// 12. JSDoc blocks (/** ... */) describing the pattern.
// ---------------------------------------------------------------------------
describe('JSDoc blocks describing catch shapes', () => {
  it('JSDoc on a function', () => {
    const src = `
      /**
       * Run a function safely.
       *
       * This used to be implemented as:
       *   try { fn(); } catch (e) {}
       * which we now consider an antipattern.
       *
       * @param {Function} fn
       * @returns {boolean}
       */
      export function runSafe(fn) {
        try {
          fn();
          return true;
        } catch (e) {
          return false;
        }
      }
    `;
    noFindings('src/run-safe.js', src);
  });

  it('JSDoc with multiple shapes', () => {
    const src = `
      /**
       * Antipatterns to avoid:
       *
       *   catch {}
       *   catch (e) {}
       *   catch (_) {}
       *
       * Use a narrowed catch instead.
       */
      export const NOTE = 1;
    `;
    noFindings('src/notes.js', src);
  });

  it('JSDoc on a class method', () => {
    const src = `
      export class Cache {
        /**
         * Read a key.
         *
         * The naive implementation:
         *   try { return this.map.get(k); } catch {}
         * was replaced by an explicit Map.has guard.
         *
         * @param {string} k
         */
        read(k) {
          return this.map.has(k) ? this.map.get(k) : undefined;
        }
      }
    `;
    noFindings('src/cache.js', src);
  });

  it('JSDoc @example with catch shape', () => {
    const src = `
      /**
       * @example
       * // Bad:
       * try { fn(); } catch (e) {}
       *
       * @example
       * // Good:
       * try { fn(); } catch (e) { log(e); throw e; }
       */
      export function example() {}
    `;
    noFindings('src/example.js', src);
  });
});

// ---------------------------------------------------------------------------
// 13. Promise.catch(() => {}) chain form.
// ---------------------------------------------------------------------------
describe('Promise.catch chain forms', () => {
  it('fire-and-forget telemetry beacon', () => {
    const src = `
      // Best-effort beacon: failure is not actionable.
      navigator.sendBeacon('/log', payload);
      fetch('/log', { method: 'POST', body: payload }).catch(() => {});
    `;
    noFindings('src/log-beacon.js', src);
  });

  it('prewarm cache', () => {
    const src = `
      function prewarm(urls) {
        urls.forEach((u) => fetch(u).catch(() => {}));
      }
      export { prewarm };
    `;
    noFindings('src/prewarm.js', src);
  });

  it('analytics flush on unload', () => {
    const src = `
      window.addEventListener('beforeunload', () => {
        flushQueue().catch(() => {});
      });
    `;
    noFindings('src/unload.js', src);
  });
});

// ---------------------------------------------------------------------------
// 14. : any in catch clauses (legitimate TS 3.x default).
// ---------------------------------------------------------------------------
describe(': any in TS catch clauses', () => {
  it('plain TS catch any', () => {
    const src = `
      export function safeJson(s: string) {
        try {
          return JSON.parse(s);
        } catch (e: any) {
          return { error: e?.message };
        }
      }
    `;
    noFindings('src/json.ts', src);
  });

  it('TS catch any with rethrow on unexpected', () => {
    const src = `
      export async function run() {
        try {
          await work();
        } catch (e: any) {
          if (e?.code !== 'ENOENT') throw e;
        }
      }
    `;
    noFindings('src/run.ts', src);
  });

  it('TS catch any in middleware', () => {
    const src = `
      export function mw(handler: Function) {
        return async (req, res) => {
          try {
            await handler(req, res);
          } catch (err: any) {
            res.status(500).send(err?.message ?? 'internal error');
          }
        };
      }
    `;
    noFindings('src/mw.ts', src);
  });
});

// ---------------------------------------------------------------------------
// 15. : any in .d.ts declaration files.
// ---------------------------------------------------------------------------
describe(': any in .d.ts declaration files', () => {
  it('module shim', () => {
    const src = `
      declare module 'untyped-pkg' {
        export const config: any;
        export function init(opts: any): any;
      }
    `;
    noFindings('src/types/untyped-pkg.d.ts', src);
  });

  it('global augmentation', () => {
    const src = `
      declare global {
        interface Window {
          __DEV_HOOKS__?: any;
        }
      }
      export {};
    `;
    noFindings('src/types/global.d.ts', src);
  });

  it('vendor types', () => {
    const src = `
      declare const __VENDOR__: { sdk: any; meta: any };
      export {};
    `;
    noFindings('src/types/vendor.d.ts', src);
  });
});

// ---------------------------------------------------------------------------
// 16. : any[] in generic helpers.
// ---------------------------------------------------------------------------
describe(': any[] in generic helpers', () => {
  it('flatten utility', () => {
    const src = `
      export function flatten(xs: any[]): any[] {
        return xs.reduce((a, b) => a.concat(Array.isArray(b) ? flatten(b) : b), []);
      }
    `;
    noFindings('src/util/flatten.ts', src);
  });

  it('memoization key', () => {
    const src = `
      export function memoize<F extends (...args: any[]) => unknown>(fn: F): F {
        const cache = new Map<string, unknown>();
        return ((...args: any[]) => {
          const k = JSON.stringify(args);
          if (!cache.has(k)) cache.set(k, fn(...args));
          return cache.get(k);
        }) as F;
      }
    `;
    noFindings('src/util/memoize.ts', src);
  });

  it('event bus', () => {
    const src = `
      type Listener = (...args: any[]) => void;
      export class Bus {
        private listeners: Listener[] = [];
        on(l: Listener) { this.listeners.push(l); }
      }
    `;
    noFindings('src/bus.ts', src);
  });
});

// ---------------------------------------------------------------------------
// 17. Record<string, any> bag-of-properties.
// ---------------------------------------------------------------------------
describe('Record<string, any> bag types', () => {
  it('config bag', () => {
    const src = `
      export type AppConfig = Record<string, any>;
      export const defaultConfig: AppConfig = {};
    `;
    noFindings('src/config.ts', src);
  });

  it('JSON-ish payload', () => {
    const src = `
      export function merge(a: Record<string, any>, b: Record<string, any>) {
        return { ...a, ...b };
      }
    `;
    noFindings('src/merge.ts', src);
  });

  it('env vars', () => {
    const src = `
      export function readEnv(): Record<string, any> {
        return { ...process.env };
      }
    `;
    noFindings('src/env.ts', src);
  });
});

// ---------------------------------------------------------------------------
// 18. <T = any> generic default.
// ---------------------------------------------------------------------------
describe('<T = any> generic defaults', () => {
  it('Result type', () => {
    const src = `
      export type Result<T = any> = { ok: true; value: T } | { ok: false; error: Error };
    `;
    noFindings('src/result.ts', src);
  });

  it('Box class', () => {
    const src = `
      export class Box<T = any> {
        constructor(public value: T) {}
      }
    `;
    noFindings('src/box.ts', src);
  });

  it('store factory', () => {
    const src = `
      export function createStore<T = any>(initial: T) {
        let state = initial;
        return {
          get: () => state,
          set: (next: T) => { state = next; },
        };
      }
    `;
    noFindings('src/store.ts', src);
  });
});

// ---------------------------------------------------------------------------
// 19. as any casts in test setup / migrations.
// ---------------------------------------------------------------------------
describe('as any casts in test setup or migrations', () => {
  it('test mock cast', () => {
    const src = `
      import { vi } from 'vitest';
      const fakeFetch = vi.fn().mockResolvedValue({ json: async () => ({}) });
      (globalThis as any).fetch = fakeFetch;
    `;
    noFindings('src/test/setup.test.ts', src);
  });

  it('migration cast for legacy shape', () => {
    const src = `
      export function migrateV1(row: unknown) {
        const r = row as any;
        return { id: r.id, name: r.name ?? r.title };
      }
    `;
    noFindings('src/migrations/v1.ts', src);
  });

  it('private field reach in test', () => {
    const src = `
      it('uses internal state', () => {
        const c = new Cache();
        (c as any)._raw.set('k', 1);
        expect(c.get('k')).toBe(1);
      });
    `;
    noFindings('src/cache.test.ts', src);
  });
});

// ---------------------------------------------------------------------------
// 20. The word "any" as identifier / string / English.
// ---------------------------------------------------------------------------
describe('"any" as identifier or English', () => {
  it('Array.prototype.some via any', () => {
    const src = `
      export function hasAny(xs, pred) {
        return xs.some(pred);
      }
      const message = 'do you have any feedback?';
      console.log(message);
    `;
    noFindings('src/has-any.js', src);
  });

  it('variable named anyMatched', () => {
    const src = `
      function check(items) {
        let anyMatched = false;
        for (const it of items) if (it.ok) anyMatched = true;
        return anyMatched;
      }
      export { check };
    `;
    noFindings('src/check.js', src);
  });

  it('English prose in comments', () => {
    const src = `
      // If there are any items left, finalize them.
      export function finalize(items) { return items.map((x) => x.id); }
    `;
    noFindings('src/finalize.js', src);
  });
});

// ---------------------------------------------------------------------------
// 21. any in JSDoc inside .js files (@param {any}).
// ---------------------------------------------------------------------------
describe('@param {any} in JSDoc inside .js files', () => {
  it('utility taking unknown shape', () => {
    const src = `
      /**
       * @param {any} value
       * @returns {string}
       */
      export function describe(value) {
        return typeof value;
      }
    `;
    noFindings('src/jsdoc-any-1.js', src);
  });

  it('event payload', () => {
    const src = `
      /**
       * @param {string} event
       * @param {any} payload
       */
      export function emit(event, payload) {
        bus.emit(event, payload);
      }
    `;
    noFindings('src/jsdoc-any-2.js', src);
  });

  it('typedef with any', () => {
    const src = `
      /**
       * @typedef {Object} Bag
       * @property {string} key
       * @property {any} value
       */
      export const noop = () => {};
    `;
    noFindings('src/jsdoc-any-3.js', src);
  });
});

// ---------------------------------------------------------------------------
// 22. Pure .js/.jsx files with no TypeScript at all.
// ---------------------------------------------------------------------------
describe('plain .js / .jsx files with no TS', () => {
  it('plain util', () => {
    const src = `
      export function add(a, b) { return a + b; }
      export const PI = 3.14159;
    `;
    noFindings('src/util/math.js', src);
  });

  it('plain React component', () => {
    const src = `
      import React from 'react';
      export function Hello({ name }) {
        return <div>Hello, {name}</div>;
      }
    `;
    noFindings('src/components/Hello.jsx', src);
  });

  it('plain reducer', () => {
    const src = `
      export function reducer(state, action) {
        switch (action.type) {
          case 'inc': return { ...state, n: state.n + 1 };
          default: return state;
        }
      }
    `;
    noFindings('src/reducer.js', src);
  });
});

// ---------------------------------------------------------------------------
// 23. : unknown handler parameters (the recommended fix).
// ---------------------------------------------------------------------------
describe(': unknown handler parameters', () => {
  it('catch unknown then narrow', () => {
    const src = `
      export function safe(s: string) {
        try {
          return JSON.parse(s);
        } catch (e: unknown) {
          if (e instanceof SyntaxError) return null;
          throw e;
        }
      }
    `;
    noFindings('src/safe-unknown.ts', src);
  });

  it('event handler with unknown', () => {
    const src = `
      export function onEvent(payload: unknown) {
        if (typeof payload === 'object' && payload !== null && 'type' in payload) {
          return (payload as { type: string }).type;
        }
        return 'unknown';
      }
    `;
    noFindings('src/on-event.ts', src);
  });

  it('reducer with unknown action', () => {
    const src = `
      export function reducer(state: { n: number }, action: unknown) {
        if (typeof action === 'object' && action && (action as any).type === 'inc') {
          return { n: state.n + 1 };
        }
        return state;
      }
    `;
    noFindings('src/reducer.ts', src);
  });
});

// ---------------------------------------------------------------------------
// 24. Zod-validated handlers using payload: unknown.
// ---------------------------------------------------------------------------
describe('Zod-validated handlers using payload: unknown', () => {
  it('schema-guarded handler', () => {
    const src = `
      import { z } from 'zod';
      const Msg = z.object({ id: z.string(), n: z.number() });
      export function handle(payload: unknown) {
        const msg = Msg.parse(payload);
        return msg.id + ':' + msg.n;
      }
    `;
    noFindings('src/handle-zod.ts', src);
  });

  it('safeParse pattern', () => {
    const src = `
      import { z } from 'zod';
      const Cfg = z.object({ host: z.string() });
      export function loadConfig(raw: unknown) {
        const r = Cfg.safeParse(raw);
        if (!r.success) throw new Error('bad config');
        return r.data;
      }
    `;
    noFindings('src/zod-config.ts', src);
  });

  it('router validator', () => {
    const src = `
      import { z } from 'zod';
      const Q = z.object({ q: z.string().min(1) });
      export function search(query: unknown) {
        const { q } = Q.parse(query);
        return q.toLowerCase();
      }
    `;
    noFindings('src/search.ts', src);
  });
});

// ---------------------------------------------------------------------------
// 25. TypeScript function overloads with any in implementation signature.
// ---------------------------------------------------------------------------
describe('TS overloads with any in impl signature', () => {
  it('overloaded format', () => {
    const src = `
      export function format(n: number): string;
      export function format(s: string): string;
      export function format(x: any): string {
        return typeof x === 'number' ? x.toFixed(2) : String(x);
      }
    `;
    noFindings('src/format.ts', src);
  });

  it('overloaded get', () => {
    const src = `
      export function get(key: 'name'): string;
      export function get(key: 'age'): number;
      export function get(key: any): any {
        return (globalThis as any)[key];
      }
    `;
    noFindings('src/get.ts', src);
  });

  it('overloaded reducer', () => {
    const src = `
      export function reduce<T>(xs: T[], fn: (a: T, b: T) => T): T;
      export function reduce<T, U>(xs: T[], fn: (a: U, b: T) => U, seed: U): U;
      export function reduce(xs: any[], fn: any, seed?: any): any {
        return seed === undefined ? xs.reduce(fn) : xs.reduce(fn, seed);
      }
    `;
    noFindings('src/reduce.ts', src);
  });
});

// ---------------------------------------------------------------------------
// 26. Suppressive utility wrappers (tryCatch(fn) returning { ok, value, error }).
// ---------------------------------------------------------------------------
describe('suppressive utility wrappers', () => {
  it('tryCatch returns Result', () => {
    const src = `
      export function tryCatch(fn) {
        try { return { ok: true, value: fn() }; }
        catch (error) { return { ok: false, error }; }
      }
    `;
    noFindings('src/try-catch.js', src);
  });

  it('async tryCatch', () => {
    const src = `
      export async function tryAsync(fn) {
        try { return { ok: true, value: await fn() }; }
        catch (error) { return { ok: false, error }; }
      }
    `;
    noFindings('src/try-async.js', src);
  });

  it('typed Result wrapper', () => {
    const src = `
      type Result<T> = { ok: true; value: T } | { ok: false; error: unknown };
      export function attempt<T>(fn: () => T): Result<T> {
        try { return { ok: true, value: fn() }; }
        catch (error) { return { ok: false, error }; }
      }
    `;
    noFindings('src/attempt.ts', src);
  });
});

// ---------------------------------------------------------------------------
// 27. TS class field declarations: class X { config: any = defaultConfig }.
// ---------------------------------------------------------------------------
describe('TS class fields typed as any', () => {
  it('field with default', () => {
    const src = `
      const defaultConfig = { mode: 'dev' };
      export class App {
        config: any = defaultConfig;
        constructor(overrides?: Record<string, any>) {
          this.config = { ...this.config, ...overrides };
        }
      }
    `;
    noFindings('src/app.ts', src);
  });

  it('plugin slot field', () => {
    const src = `
      export class Host {
        plugin: any = null;
        register(p: any) { this.plugin = p; }
      }
    `;
    noFindings('src/host.ts', src);
  });

  it('legacy storage field', () => {
    const src = `
      export class LegacyStore {
        data: any[] = [];
        meta: Record<string, any> = {};
      }
    `;
    noFindings('src/legacy-store.ts', src);
  });
});

// ---------------------------------------------------------------------------
// 28. anyOf / oneOf JSON Schema fragments in strings or comments.
// ---------------------------------------------------------------------------
describe('anyOf / oneOf JSON Schema fragments', () => {
  it('JSON schema object literal', () => {
    const src = `
      export const schema = {
        anyOf: [{ type: 'string' }, { type: 'number' }],
        oneOf: [{ const: 'a' }, { const: 'b' }],
      };
    `;
    noFindings('src/schema.js', src);
  });

  it('schema embedded in template', () => {
    const src = `
      export const schemaJson = \`{
        "anyOf": [{"type":"string"},{"type":"number"}],
        "oneOf": [{"const":"a"},{"const":"b"}]
      }\`;
    `;
    noFindings('src/schema-str.js', src);
  });

  it('comment describing anyOf', () => {
    const src = `
      // The payload uses { anyOf: [string, number] } and { oneOf: [a, b] }.
      export const NOTE = 1;
    `;
    noFindings('src/anyof-note.js', src);
  });
});

// ---------------------------------------------------------------------------
// EDGE CASES — genuinely ambiguous patterns. Each is flagged.
// ---------------------------------------------------------------------------
describe('edge cases (genuinely ambiguous, but should still not fire)', () => {
  // EDGE: mixed real catch + multi-line block comment quoting another catch
  // in the same file. A naive scanner that strips comments per-line would
  // still leave the comment-quoted shape visible.
  it('real narrowed catch alongside multi-line block comment with empty catch', () => {
    const src = `
      /*
       * The old code looked like:
       *   try { x(); } catch (e) {}
       * The new code is below.
       */
      export function x(value) {
        try {
          return JSON.parse(value);
        } catch (e) {
          if (!(e instanceof SyntaxError)) throw e;
          return null;
        }
      }
    `;
    noFindings('src/edge-1.js', src);
  });

  // EDGE: backtick string containing catch shape adjacent to a real
  // try/finally (no catch). Confusable with a real catch.
  it('template-literal catch shape next to try/finally', () => {
    const src = `
      const NOTE = \`legacy: try { x(); } catch (e) {}\`;
      export function run(fn) {
        const t = startTimer();
        try { return fn(); } finally { t.stop(); }
      }
      export { NOTE };
    `;
    noFindings('src/edge-2.js', src);
  });

  // EDGE: TS function parameter named `any` (identifier, not type).
  it('parameter named any in TS', () => {
    const src = `
      export function pick<T>(xs: T[], any: (x: T) => boolean): T | undefined {
        return xs.find(any);
      }
    `;
    noFindings('src/edge-3.ts', src);
  });

  // EDGE: `: any` appearing inside a string literal that documents a type.
  it('type signature quoted in a string', () => {
    const src = `
      const example = "function id(x: any): any { return x; }";
      export { example };
    `;
    noFindings('src/edge-4.js', src);
  });

  // EDGE: a catch whose body is a single comment line. Behaviorally empty
  // but intentional and documented.
  it('catch body is exactly one comment line, no code', () => {
    const src = `
      function bestEffort() {
        try {
          localStorage.removeItem('legacy');
        } catch (e) {
          // private mode or no storage; nothing to clean up
        }
      }
      export { bestEffort };
    `;
    noFindings('src/edge-5.js', src);
  });

  // EDGE: nested template literal containing a catch shape.
  it('nested template literal with catch shape', () => {
    const src = `
      export function wrap(name) {
        const inner = \`
          // body
          try { \${name}(); } catch (e) {}
        \`;
        return \`function gen() {\\n\${inner}\\n}\`;
      }
    `;
    noFindings('src/edge-6.js', src);
  });
});

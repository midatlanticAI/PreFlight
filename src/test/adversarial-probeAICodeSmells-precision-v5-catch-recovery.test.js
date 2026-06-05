/**
 * Adversarial precision tests for probeAICodeSmells: catch-block recovery patterns.
 *
 * Mission: A regex-based "empty catch" detector tends to mis-flag catch bodies that
 * are short but ARE legitimate recovery (reset-to-known-good-state, default return,
 * wrapped rethrow, etc.). Every test below is a "must NOT fire" assertion against
 * defensible patterns, plus a small positive-control set proving truly empty
 * catches DO still fire (so we don't accidentally suppress real findings).
 *
 * Real-world FP class motivating this suite:
 *   try { chassisEntries = JSON.parse(raw); }
 *   catch (e) { chassisEntries = []; }   // single-line reset; this MUST NOT fire.
 *
 * Calibration: probe is INFORMATIONAL. Threshold for noise is ZERO findings.
 *
 * NOTE: This suite only asserts the AI-code-smells probe's behavior on these
 * snippets. Other probes (e.g. broad correctness) may legitimately surface
 * other findings on the same fixtures; we filter to probeAICodeSmells output
 * by calling the function directly.
 */

import { describe, it, expect } from 'vitest';
import { probeAICodeSmells } from '../lib/probes.js';

// --- helpers ----------------------------------------------------------------

/** Convenience: build a single-file input and run the probe. */
function scan(content, path = 'src/app.js') {
  return probeAICodeSmells([{ path, content }]);
}

/** True if any finding looks like an "empty catch" / silent-swallow signal. */
function hasEmptyCatchFinding(findings) {
  if (!Array.isArray(findings) || findings.length === 0) return false;
  return findings.some((f) => {
    const blob = JSON.stringify(f).toLowerCase();
    return (
      blob.includes('empty catch') ||
      blob.includes('empty-catch') ||
      blob.includes('silent') ||
      blob.includes('swallow') ||
      blob.includes('catch')
    );
  });
}

// =============================================================================
// Category 1: catch assigns to the SAME variable read in try
// (the canonical real-world FP class)
// =============================================================================

describe('Category 1: catch assigns to same variable read in try (canonical FP)', () => {
  it('chassisEntries = JSON.parse / chassisEntries = [] reset', () => {
    const code = `
      let chassisEntries;
      const raw = localStorage.getItem('chassis');
      try {
        chassisEntries = JSON.parse(raw);
      } catch (e) {
        chassisEntries = [];
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('state = JSON.parse / state = {} reset', () => {
    const code = `
      let state;
      try {
        state = JSON.parse(localStorage.getItem('app-state'));
      } catch (err) {
        state = {};
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('user = JSON.parse / user = null reset', () => {
    const code = `
      let user;
      try {
        user = JSON.parse(sessionStorage.getItem('user'));
      } catch (e) {
        user = null;
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('config = JSON.parse / config = DEFAULTS reset (named default)', () => {
    const code = `
      const DEFAULTS = { theme: 'light' };
      let config;
      try {
        config = JSON.parse(raw);
      } catch (e) {
        config = DEFAULTS;
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('count = parseInt / count = 0 reset (number primitive)', () => {
    const code = `
      let count;
      try {
        count = parseInt(localStorage.getItem('count'), 10);
      } catch (e) {
        count = 0;
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('items = parsed / items = [] inside a function', () => {
    const code = `
      function loadItems() {
        let items;
        try {
          items = JSON.parse(localStorage.getItem('items'));
        } catch (e) {
          items = [];
        }
        return items;
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('settings = parsed / settings = {...defaults} spread reset', () => {
    const code = `
      const defaults = { volume: 50 };
      let settings;
      try {
        settings = JSON.parse(raw);
      } catch (e) {
        settings = { ...defaults };
      }
    `;
    expect(scan(code)).toEqual([]);
  });
});

// =============================================================================
// Category 2: catch returns a default value
// =============================================================================

describe('Category 2: catch returns a default value', () => {
  it('catch { return null; }', () => {
    const code = `
      function safeParse(s) {
        try {
          return JSON.parse(s);
        } catch {
          return null;
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('catch { return []; }', () => {
    const code = `
      function safeList(raw) {
        try {
          return JSON.parse(raw);
        } catch {
          return [];
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('catch (e) { return undefined; }', () => {
    const code = `
      function lookup(k) {
        try {
          return store.get(k);
        } catch (e) {
          return undefined;
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('catch (e) { return {}; }', () => {
    const code = `
      function parseHeaders(raw) {
        try {
          return JSON.parse(raw);
        } catch (e) {
          return {};
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('catch { return DEFAULT_CONFIG; }', () => {
    const code = `
      const DEFAULT_CONFIG = Object.freeze({ retries: 3 });
      function loadConfig() {
        try {
          return JSON.parse(localStorage.getItem('cfg'));
        } catch {
          return DEFAULT_CONFIG;
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('catch { return false; } (boolean default)', () => {
    const code = `
      function isValid(s) {
        try {
          return schema.parse(s) != null;
        } catch {
          return false;
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });
});

// =============================================================================
// Category 3: catch logs AND returns
// =============================================================================

describe('Category 3: catch logs and returns', () => {
  it('console.warn + return null', () => {
    const code = `
      function safeParse(s) {
        try { return JSON.parse(s); }
        catch (e) {
          console.warn(e);
          return null;
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('console.error + return []', () => {
    const code = `
      function safeList(raw) {
        try { return JSON.parse(raw); }
        catch (e) {
          console.error('list parse failed', e);
          return [];
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('console.warn + return default object', () => {
    const code = `
      function safeConfig() {
        try { return JSON.parse(localStorage.getItem('cfg')); }
        catch (err) {
          console.warn('config load failed, using defaults', err);
          return { theme: 'light' };
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('console.warn + assign reset variable', () => {
    const code = `
      let chassisEntries;
      try {
        chassisEntries = JSON.parse(localStorage.getItem('chassis'));
      } catch (e) {
        console.warn('chassis corrupted, resetting', e);
        chassisEntries = [];
      }
    `;
    expect(scan(code)).toEqual([]);
  });
});

// =============================================================================
// Category 4: catch rethrows wrapped
// =============================================================================

describe('Category 4: catch rethrows wrapped', () => {
  it('throw new MyError("failed", { cause: e })', () => {
    const code = `
      class MyError extends Error {}
      function load() {
        try { return JSON.parse(raw); }
        catch (e) {
          throw new MyError('failed', { cause: e });
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('throw new Error with original message embedded', () => {
    const code = `
      function load() {
        try { return JSON.parse(raw); }
        catch (e) {
          throw new Error('load failed: ' + e.message);
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('throw wrapped TypeError with cause', () => {
    const code = `
      function validate(x) {
        try { return schema.parse(x); }
        catch (e) {
          throw new TypeError('validation failed', { cause: e });
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });
});

// =============================================================================
// Category 5: catch only rethrows (pass-through)
// =============================================================================

describe('Category 5: catch only rethrows', () => {
  it('catch (e) { throw e; }', () => {
    const code = `
      function load() {
        try { return JSON.parse(raw); }
        catch (e) { throw e; }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('catch (err) { throw err; } with cleanup comment', () => {
    const code = `
      function load() {
        try { return JSON.parse(raw); }
        catch (err) {
          // bubble up to caller, intentional
          throw err;
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('catch (e) { throw e; } inside async function', () => {
    const code = `
      async function load() {
        try { return await fetchJson(); }
        catch (e) { throw e; }
      }
    `;
    expect(scan(code)).toEqual([]);
  });
});

// =============================================================================
// Category 6: catch with explanatory comment + single recovery statement
// =============================================================================

describe('Category 6: catch with explanatory comment + single recovery statement', () => {
  it('block comment + state = []', () => {
    const code = `
      let state;
      try {
        state = JSON.parse(localStorage.getItem('state'));
      } catch (e) {
        /* localStorage corrupted, reset */
        state = [];
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('line comment + state = {}', () => {
    const code = `
      let state;
      try {
        state = JSON.parse(raw);
      } catch (e) {
        // raw was malformed; reset to empty
        state = {};
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('block comment + return default', () => {
    const code = `
      function safeParse(s) {
        try { return JSON.parse(s); }
        catch (e) {
          /* fallback to null on parse failure */
          return null;
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('multi-line comment + reset', () => {
    const code = `
      let chassisEntries;
      try {
        chassisEntries = JSON.parse(raw);
      } catch (e) {
        /*
         * localStorage entry corrupted (possibly cross-version).
         * Reset to empty list; the next save will overwrite cleanly.
         */
        chassisEntries = [];
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('JSDoc-style comment + reset', () => {
    const code = `
      let cache;
      try {
        cache = JSON.parse(raw);
      } catch (e) {
        /** Corrupted entry; drop and rebuild lazily. */
        cache = null;
      }
    `;
    expect(scan(code)).toEqual([]);
  });
});

// =============================================================================
// Category 7: catch with explanatory comment ONLY (no statements)
// SPEC AMBIGUITY: this is the fuzzy line. The catch body is empty in terms of
// executed statements but the comment documents intent. We assert it should NOT
// fire because the explanatory comment is the documented "intentional swallow"
// signal recognized by many style guides (and required by some linters via
// /* noop */). Flag in comment.
// =============================================================================

describe('Category 7: catch with explanatory comment only (spec ambiguous)', () => {
  it('catch (e) { /* swallowed by design, see issue #1234 */ }', () => {
    // AMBIGUOUS: empty-statement-wise, but the comment is the documented
    // signal of intent. We assert no-fire. If the probe fires, that is a
    // defensible product call but should be explicit, not regex incidental.
    const code = `
      try {
        someRiskyFireAndForget();
      } catch (e) {
        /* swallowed by design, see issue #1234 */
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('catch { /* intentional no-op: cleanup is best-effort */ }', () => {
    // AMBIGUOUS — same class as above.
    const code = `
      try {
        tempFile.unlink();
      } catch {
        /* intentional no-op: cleanup is best-effort */
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('catch (e) { // noop, see ADR-007 }', () => {
    // AMBIGUOUS — same class as above.
    const code = `
      try {
        notifyAnalytics();
      } catch (e) {
        // noop, see ADR-007
      }
    `;
    expect(scan(code)).toEqual([]);
  });
});

// =============================================================================
// Category 8: catch records error to a logger module
// =============================================================================

describe('Category 8: catch records error to logger module', () => {
  it('logger.error("parse failed", e)', () => {
    const code = `
      import { logger } from './log.js';
      function load() {
        try { return JSON.parse(raw); }
        catch (e) {
          logger.error('parse failed', e);
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('log.warn(e)', () => {
    const code = `
      function save() {
        try { writeFile(path, data); }
        catch (e) { log.warn(e); }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('reportError(e) (Web platform global)', () => {
    const code = `
      function tick() {
        try { schedule(); }
        catch (e) { reportError(e); }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('Sentry.captureException(e)', () => {
    const code = `
      function load() {
        try { return JSON.parse(raw); }
        catch (e) { Sentry.captureException(e); }
      }
    `;
    expect(scan(code)).toEqual([]);
  });
});

// =============================================================================
// Category 9: catch uses void operator to assert ignore
// SPEC AMBIGUOUS: `void e` is the documented ESLint pattern for "intentionally
// ignored". We assert no-fire (matches the documented convention).
// =============================================================================

describe('Category 9: catch uses void operator (spec ambiguous)', () => {
  it('catch (e) { void e; }', () => {
    // AMBIGUOUS — documented ESLint convention for intentional ignore.
    const code = `
      try { optional(); } catch (e) { void e; }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('catch (err) { void err; } with context', () => {
    // AMBIGUOUS — same.
    const code = `
      function bestEffort() {
        try { teardown(); } catch (err) { void err; }
      }
    `;
    expect(scan(code)).toEqual([]);
  });
});

// =============================================================================
// Category 10: TRULY EMPTY catches that DO deserve to fire (positive control)
// We assert >= 1 finding. If these stop firing, our must-not-fire suite would
// be hiding a regression in the probe.
// =============================================================================

describe('Category 10: truly empty catches (positive control — MUST fire)', () => {
  it('try { x(); } catch {} fires', () => {
    const code = `
      function f() {
        try { x(); } catch {}
      }
    `;
    const findings = scan(code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(hasEmptyCatchFinding(findings)).toBe(true);
  });

  it('try { x(); } catch (e) {} fires', () => {
    const code = `
      function f() {
        try { x(); } catch (e) {}
      }
    `;
    const findings = scan(code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(hasEmptyCatchFinding(findings)).toBe(true);
  });

  it('catch with only a newline body fires', () => {
    const code = ['function f() {', '  try { x(); } catch (e) {', '  }', '}'].join('\n');
    const findings = scan(code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(hasEmptyCatchFinding(findings)).toBe(true);
  });

  it('catch with only whitespace body fires', () => {
    const code = `
      function f() {
        try { x(); } catch (e) {     }
      }
    `;
    const findings = scan(code);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(hasEmptyCatchFinding(findings)).toBe(true);
  });
});

// =============================================================================
// Category 11: truly empty catches inside test/fixture files (must NOT fire)
// Per the file-filter convention, test code is excluded.
// =============================================================================

describe('Category 11: truly empty catches in test/fixture paths must NOT fire', () => {
  const trulyEmpty = `
    function f() {
      try { x(); } catch (e) {}
    }
  `;

  it('*.test.js path', () => {
    expect(scan(trulyEmpty, 'src/components/foo.test.js')).toEqual([]);
  });

  it('*.spec.js path', () => {
    expect(scan(trulyEmpty, 'src/lib/bar.spec.js')).toEqual([]);
  });

  it('__tests__/ directory', () => {
    expect(scan(trulyEmpty, 'src/__tests__/baz.js')).toEqual([]);
  });

  it('tests/ directory', () => {
    expect(scan(trulyEmpty, 'tests/integration/qux.js')).toEqual([]);
  });

  it('fixtures/ directory', () => {
    expect(scan(trulyEmpty, 'src/lib/probes/v05/fixtures/sample.js')).toEqual([]);
  });

  it('*.test.jsx path', () => {
    expect(scan(trulyEmpty, 'src/components/Comp.test.jsx')).toEqual([]);
  });
});

// =============================================================================
// Category 12: chained recovery + side effect (multiple meaningful statements)
// =============================================================================

describe('Category 12: catch with chained recovery + side effect', () => {
  it('onError(e) + setState', () => {
    const code = `
      function handler() {
        try { doWork(); }
        catch (e) {
          onError(e);
          setState(prev => ({ ...prev, error: e.message }));
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('metric increment + fallback assign', () => {
    const code = `
      let result;
      try {
        result = computeExpensive();
      } catch (e) {
        metrics.increment('compute.fail');
        result = cachedFallback;
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('dispatch + return default', () => {
    const code = `
      function loadUser(id) {
        try { return api.getUser(id); }
        catch (e) {
          dispatch({ type: 'USER_LOAD_FAIL', payload: e });
          return null;
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });
});

// =============================================================================
// Category 13: Promise.catch() chain form
// SPEC AMBIGUOUS: this is .catch() callback shape, not try/catch. We assert
// no-fire because the probe is documented around `catch` blocks, not promise
// chain callbacks. Flag in comment.
// =============================================================================

describe('Category 13: Promise.catch() chain (spec ambiguous)', () => {
  it('promise.catch(() => {}) does not fire', () => {
    // AMBIGUOUS — different syntactic shape than try/catch. Probe focus is
    // try/catch blocks. If this fires, scope has crept beyond spec.
    const code = `
      promise.catch(() => {});
    `;
    expect(scan(code)).toEqual([]);
  });

  it('promise.catch((e) => {}) does not fire', () => {
    // AMBIGUOUS — same class.
    const code = `
      promise.catch((e) => {});
    `;
    expect(scan(code)).toEqual([]);
  });

  it('promise.catch(() => fallback) does not fire (recovery callback)', () => {
    const code = `
      const result = await promise.catch(() => fallbackValue);
    `;
    expect(scan(code)).toEqual([]);
  });
});

// =============================================================================
// Category 14: nested try/catch where outer catch propagates
// =============================================================================

describe('Category 14: nested try/catch with bodies', () => {
  it('inner fallback + outer log+rethrow', () => {
    const code = `
      function complex() {
        try {
          try { dangerousOp(); }
          catch (inner) { fallback(); }
        } catch (outer) {
          criticalLog(outer);
          throw outer;
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('inner assign-reset + outer rethrow wrapped', () => {
    const code = `
      function load() {
        let data;
        try {
          try { data = JSON.parse(raw); }
          catch (inner) { data = []; }
          return data;
        } catch (outer) {
          throw new Error('load failed', { cause: outer });
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('three-level nest, all catches recover', () => {
    const code = `
      function deep() {
        try {
          try {
            try { riskA(); }
            catch (a) { recoverA(); }
          } catch (b) { recoverB(); }
        } catch (c) {
          recoverC();
          throw c;
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });
});

// =============================================================================
// Category 15: catch with conditional rethrow
// =============================================================================

describe('Category 15: catch with conditional rethrow', () => {
  it('instanceof check + return default or throw', () => {
    const code = `
      class RecoverableError extends Error {}
      function safeRun(fn, defaultValue) {
        try { return fn(); }
        catch (e) {
          if (e instanceof RecoverableError) return defaultValue;
          throw e;
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('code-property check + reset or rethrow', () => {
    const code = `
      let data;
      try {
        data = JSON.parse(raw);
      } catch (e) {
        if (e.code === 'CORRUPT') {
          data = [];
        } else {
          throw e;
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('message check + log+return or throw', () => {
    const code = `
      function load() {
        try { return JSON.parse(raw); }
        catch (e) {
          if (e.message && e.message.includes('Unexpected token')) {
            console.warn('parse glitch, returning empty');
            return [];
          }
          throw e;
        }
      }
    `;
    expect(scan(code)).toEqual([]);
  });
});

// =============================================================================
// Edge-cases / fuzzy line between empty and intentional
// =============================================================================

describe('Edge cases where empty-vs-intentional is fuzzy', () => {
  it('catch with only a semicolon-only "empty statement"', () => {
    // AMBIGUOUS — `;` is an empty statement; arguably this is the same as
    // truly empty. Listed for visibility. We do not assert a direction here.
    const code = `
      try { x(); } catch (e) { ; }
    `;
    // We only assert the probe does not crash; direction is fuzzy.
    expect(() => scan(code)).not.toThrow();
  });

  it('catch with debugger; statement only', () => {
    // AMBIGUOUS — `debugger;` is a recovery-ish dev-time hook but not
    // production-defensible. We assert no-fire (single statement; not empty
    // by AST), and flag the ambiguity.
    const code = `
      try { x(); } catch (e) { debugger; }
    `;
    expect(scan(code)).toEqual([]);
  });

  it('catch whose only statement is a no-op identifier expression', () => {
    // AMBIGUOUS — `e;` reads the binding to satisfy "used" lint rules but
    // does not act on it. We assert no-fire (non-empty AST body).
    const code = `
      try { x(); } catch (e) { e; }
    `;
    expect(scan(code)).toEqual([]);
  });
});

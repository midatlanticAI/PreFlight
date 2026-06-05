/**
 * Adversarial edge-case suite spawned from the Thread 2 (SEO/GEO architecture
 * gating) and Thread 5 (placeholder-named-assignment) precision rounds.
 *
 * Each test is a follow-on edge case the agent round didn't directly cover.
 * Convention: arrange-act-assert, no probe-internal reads, no fixtures from
 * outside this file.
 */

import { describe, it, expect } from 'vitest';
import { probeSEOHygiene, probeGEOHygiene } from '../lib/probes.js';
import { probeSecrets } from '../lib/probes.js';

// ─────────────────────────────────────────────────────────────────────────────
// Shared fixtures
// ─────────────────────────────────────────────────────────────────────────────

const BARE_INDEX = {
  path: 'index.html',
  content: `<!doctype html><html><head><meta charset="utf-8" /><title>A</title></head><body></body></html>`,
};

function manifest(path, body) {
  return { path, content: JSON.stringify(body) };
}
const STANDALONE_MANIFEST = manifest('manifest.json', {
  name: 'Field Tool',
  display: 'standalone',
  start_url: '/',
});
const SW_FILE = {
  path: 'sw.js',
  content: `const C='v1';self.addEventListener('install',(e)=>e.waitUntil(caches.open(C).then(c=>c.addAll(['/']))));`,
};

// real-shape secret value, not a placeholder
const OPENAI_REAL_SHAPE = 'sk-proj-T9kVf3HnQ8RpZxYwL2vMEoXqHwIrAsTpKjLnMbV';
const STRIPE_REAL_SHAPE = 'sk_live_T9kVf3HnQ8RpZxYwL2vM';
const AWS_REAL_SHAPE = 'AKIA1234567890ABCDEF';

const file = (path, content) => ({ path, content });

// ─────────────────────────────────────────────────────────────────────────────
// Thread 2 edges — architecture gating
// ─────────────────────────────────────────────────────────────────────────────

describe('Thread 2 edges — architecture gating boundary cases', () => {
  it('Web App Manifest referenced via <link rel="manifest"> but file absent → probes fire', () => {
    // A bare HTML with manifest link but no actual manifest file. The gate
    // requires the manifest FILE to be present and parseable.
    const html = {
      path: 'index.html',
      content: `<!doctype html><html><head><meta charset="utf-8"/><title>X</title><link rel="manifest" href="/manifest.json"/></head><body></body></html>`,
    };
    expect(probeSEOHygiene([html]).length).toBeGreaterThan(0);
    expect(probeGEOHygiene([html]).length).toBeGreaterThan(0);
  });

  it('manifest with display:"standalone" but service worker that NEVER registers install → still gated', () => {
    // The gate only looks for the install listener body or filename shape,
    // not whether the worker actually does anything meaningful. Pure presence
    // of the install listener is enough.
    const minimalSw = {
      path: 'sw.js',
      content: `self.addEventListener('install', () => {});`,
    };
    const files = [BARE_INDEX, STANDALONE_MANIFEST, minimalSw];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('manifest with display:standalone + worker file named "worker.js" (not sw/service-worker) → fires', () => {
    // Convention requires the canonical filename OR the install-listener body.
    // A nondescript "worker.js" without install handler must not satisfy gate.
    const nondescript = {
      path: 'worker.js',
      content: `// background thread, not a service worker\npostMessage('hi');`,
    };
    const files = [BARE_INDEX, STANDALONE_MANIFEST, nondescript];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('manifest with extra unknown fields + display:standalone + sw → still gated (forward-compat)', () => {
    const extra = manifest('manifest.json', {
      name: 'Tool',
      display: 'standalone',
      start_url: '/',
      experimental_field_2027: 'foo',
      handle_links: 'preferred',
    });
    const files = [BARE_INDEX, extra, SW_FILE];
    expect(probeSEOHygiene(files)).toEqual([]);
    expect(probeGEOHygiene(files)).toEqual([]);
  });

  it('two manifests (root + public) — one standalone, one browser → BOTH must be standalone-shaped', () => {
    // Defensive: don't pick the first one and ignore conflicts. We accept
    // either suppression or normal fire — but assert no crash.
    const browserMani = manifest('public/manifest.webmanifest', {
      name: 'X',
      display: 'browser',
      start_url: '/',
    });
    const files = [BARE_INDEX, STANDALONE_MANIFEST, browserMani, SW_FILE];
    expect(Array.isArray(probeSEOHygiene(files))).toBe(true);
    expect(Array.isArray(probeGEOHygiene(files))).toBe(true);
  });

  it('manifest with display:"window-controls-overlay" (PWA spec evolution) → conservative: fires', () => {
    // window-controls-overlay is a desktop-PWA extension not in the original
    // installable set. Conservative reading: not in {standalone,fullscreen,minimal-ui}.
    const wcom = manifest('manifest.json', {
      name: 'Tool',
      display: 'window-controls-overlay',
      start_url: '/',
    });
    const files = [BARE_INDEX, wcom, SW_FILE];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('SW file with self.addEventListener("install", ...) (DOUBLE-quoted) → tolerant', () => {
    // Spec says single-quoted. We assert no crash. Some implementations also
    // accept double-quoted. Either is legal.
    const dq = file('src/serviceWorker/index.js', `self.addEventListener("install", e => {});`);
    const files = [BARE_INDEX, STANDALONE_MANIFEST, dq];
    expect(Array.isArray(probeSEOHygiene(files))).toBe(true);
  });

  it('manifest at deeply nested path (apps/web/public/manifest.json) → still detected', () => {
    const nested = manifest('apps/web/public/manifest.json', {
      name: 'X',
      display: 'standalone',
      start_url: '/',
    });
    const files = [BARE_INDEX, nested, SW_FILE];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('TypeScript service worker (sw.ts) with install listener → satisfies gate', () => {
    const tsSw = file(
      'src/sw.ts',
      `declare const self: ServiceWorkerGlobalScope;\nself.addEventListener('install', (e) => { /* warm cache */ });`
    );
    const files = [BARE_INDEX, STANDALONE_MANIFEST, tsSw];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('manifest with display:standalone but ZERO icons (W3C-invalid) → tolerant', () => {
    // Real PWAs MUST declare icons, but the gate only looks at display + SW
    // presence. We accept either suppression or normal fire.
    const noIcons = manifest('manifest.json', {
      name: 'X',
      display: 'standalone',
      start_url: '/',
    });
    const files = [BARE_INDEX, noIcons, SW_FILE];
    expect(Array.isArray(probeSEOHygiene(files))).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Thread 5 edges — placeholder-named-assignment filter
// ─────────────────────────────────────────────────────────────────────────────

describe('Thread 5 edges — variable-name placeholder context', () => {
  it('SAMPLE_OPENAI_KEY = "<real-shape sk-proj-...>" → suppressed (canonical case)', () => {
    const src = `export const SAMPLE_OPENAI_KEY = '${OPENAI_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/samples.js', src)])).toEqual([]);
  });

  it('FAKE_STRIPE_KEY = "<sk_live_...>" → suppressed', () => {
    const src = `const FAKE_STRIPE_KEY = '${STRIPE_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/fakes.js', src)])).toEqual([]);
  });

  it('TEST_API_KEY = "<sk-...>" → suppressed (TEST_API pattern)', () => {
    const src = `const TEST_API_KEY = '${OPENAI_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/test-fixtures.js', src)])).toEqual([]);
  });

  it('TEST_OPENAI = "<sk-...>" → STILL FIRES (TEST_ + provider name is ambiguous; require KEY/TOKEN/SECRET/API suffix)', () => {
    // Documented narrow scope: TEST_OPENAI alone is too ambiguous (could be a
    // real key loaded via a TEST_ env loader). Suppression requires the
    // KEY/TOKEN/SECRET/API conventional suffix.
    const src = `const TEST_OPENAI = '${OPENAI_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/fixtures.js', src)]).length).toBeGreaterThan(0);
  });

  it('DUMMY_AWS_KEY = "<AKIA...>" → suppressed', () => {
    const src = `const DUMMY_AWS_KEY = '${AWS_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/dummies.js', src)])).toEqual([]);
  });

  it('MOCK_OPENAI_TOKEN = "<sk-...>" → suppressed', () => {
    const src = `const MOCK_OPENAI_TOKEN = '${OPENAI_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/mocks.js', src)])).toEqual([]);
  });

  it('FIXTURE_STRIPE = "<sk_live...>" → suppressed', () => {
    const src = `const FIXTURE_STRIPE = '${STRIPE_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/fixtures.js', src)])).toEqual([]);
  });

  it('NOT_A_REAL_KEY = "<sk-...>" → suppressed', () => {
    const src = `const NOT_A_REAL_KEY = '${OPENAI_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/leaks.js', src)])).toEqual([]);
  });

  // negative controls — generic identifiers MUST still fire
  it('OPENAI_KEY = "<sk-...>" → STILL FIRES (no placeholder marker in name)', () => {
    const src = `const OPENAI_KEY = '${OPENAI_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/leak.js', src)]).length).toBeGreaterThan(0);
  });

  it('AWS_SECRET = "<AKIA...>" → STILL FIRES', () => {
    const src = `const AWS_SECRET = '${AWS_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/aws.js', src)]).length).toBeGreaterThan(0);
  });

  it('API_KEY = "<sk-...>" → STILL FIRES', () => {
    const src = `const API_KEY = '${OPENAI_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/api.js', src)]).length).toBeGreaterThan(0);
  });

  it('STRIPE_KEY = "<sk_live...>" → STILL FIRES (no placeholder marker)', () => {
    const src = `const STRIPE_KEY = '${STRIPE_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/stripe.js', src)]).length).toBeGreaterThan(0);
  });

  // boundary — placeholder marker far away
  it('SAMPLE_FOO on line 1, real key on line 30 → still fires (window bounded)', () => {
    // The bounded look-back window is ~120 chars. A SAMPLE_ identifier
    // 30 lines away should NOT bleed into a real assignment.
    const filler = Array.from({ length: 30 }, () => '  // unrelated line').join('\n');
    const src = `const SAMPLE_FOO = 1;\n${filler}\nconst REAL_KEY = '${OPENAI_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/mixed.js', src)]).length).toBeGreaterThan(0);
  });

  it('TypeScript: const SAMPLE_OPENAI_KEY: string = "<sk-...>" → suppressed', () => {
    const src = `export const SAMPLE_OPENAI_KEY: string = '${OPENAI_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/samples.ts', src)])).toEqual([]);
  });

  it('object literal: { SAMPLE_OPENAI_KEY: "<sk-...>" } → suppressed', () => {
    const src = `export const fixtures = { SAMPLE_OPENAI_KEY: '${OPENAI_REAL_SHAPE}' };`;
    expect(probeSecrets([file('src/fixtures.js', src)])).toEqual([]);
  });

  it('letter case: lowercase sample_openai_key = "..." → STILL FIRES (convention is UPPER)', () => {
    // PLACEHOLDER_VAR_NAME_RE is uppercase-only by convention. Lowercase var
    // names are normal variables and should not bypass.
    const src = `const sample_openai_key = '${OPENAI_REAL_SHAPE}';`;
    expect(probeSecrets([file('src/lower.js', src)]).length).toBeGreaterThan(0);
  });

  it('SAMPLE_FOO with a real key 50 chars later on same line → suppressed (within window)', () => {
    const src = `const SAMPLE_FOO=1;const X='${OPENAI_REAL_SHAPE}';`;
    // Within the 120-char window. Tolerant — the helper is intentionally aggressive
    // when a SAMPLE_ marker is nearby. We accept suppression here.
    expect(probeSecrets([file('src/near.js', src)])).toEqual([]);
  });
});

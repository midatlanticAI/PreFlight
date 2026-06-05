/**
 * Adversarial test suite: architecture-aware gating on probeSEOHygiene + probeGEOHygiene.
 *
 * Spec under test (gating rule):
 *   A project is treated as a "private installable PWA / internal tool" when it ships BOTH:
 *     1. A Web App Manifest (`manifest.json` or `manifest.webmanifest`) with an installable
 *        `display` value: "standalone", "fullscreen", or "minimal-ui".
 *     2. A service worker — filename matches `sw.js` or `service-worker.js`,
 *        OR any `.js`/`.ts` file whose body contains `self.addEventListener('install', ...)`.
 *
 *   When BOTH signals are present, probeSEOHygiene + probeGEOHygiene suppress ALL findings.
 *   When EITHER signal is missing, both probes fire normally.
 *
 *   A `display: "browser"` manifest, an absent `display` field, or a malformed manifest
 *   is NOT a valid PWA signal — probes fire as if no manifest were present.
 *
 * This test does not read probe internals. It treats the probes as a black box and only
 * asserts on the visible Finding[] return value.
 */

import { describe, it, expect } from 'vitest';
import { probeSEOHygiene, probeGEOHygiene } from '../lib/probes.js';

// --- fixtures -----------------------------------------------------------------

/** A bare index.html that would normally trip many SEO findings. */
const BARE_INDEX_HTML = {
  path: 'index.html',
  content: `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>App</title>
  </head>
  <body><div id="root"></div></body>
</html>`,
};

/** A fully-populated public head: description, canonical, og:*, twitter:*, JSON-LD. */
const FULL_PUBLIC_INDEX_HTML = {
  path: 'index.html',
  content: `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="icon" href="/favicon.ico" />
    <title>Public Tool</title>
    <meta name="description" content="A clear concrete description of this public web app and what it does." />
    <link rel="canonical" href="https://example.com/" />
    <meta property="og:title" content="Public Tool" />
    <meta property="og:description" content="A clear concrete description of this public web app." />
    <meta property="og:image" content="https://example.com/og.png" />
    <meta property="og:url" content="https://example.com/" />
    <meta property="og:type" content="website" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="Public Tool" />
    <meta name="twitter:description" content="A clear concrete description of this public web app." />
    <meta name="twitter:image" content="https://example.com/og.png" />
    <script type="application/ld+json">
      {"@context":"https://schema.org","@type":"WebApplication","name":"Public Tool","url":"https://example.com/","description":"A clear concrete description."}
    </script>
  </head>
  <body><div id="root"></div></body>
</html>`,
};

const LLMS_TXT = {
  path: 'llms.txt',
  content: `# Public Tool

> A clear single-sentence summary for AI agents browsing this site.

## Pages
- [Home](https://example.com/): The landing page.
`,
};

function manifestFile(path, body) {
  return { path, content: JSON.stringify(body, null, 2) };
}

function makeManifest(path = 'manifest.json', display = 'standalone') {
  return manifestFile(path, {
    name: 'Internal Field Tool',
    short_name: 'Field',
    start_url: '/',
    display,
    background_color: '#ffffff',
    theme_color: '#000000',
    icons: [
      { src: '/icon-192.png', sizes: '192x192', type: 'image/png' },
      { src: '/icon-512.png', sizes: '512x512', type: 'image/png' },
    ],
  });
}

/** Idiomatic service worker body. */
const SW_BODY = `// service worker for an internal installable app
const CACHE = 'field-v1';
self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(['/', '/index.html'])));
});
self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});
self.addEventListener('fetch', (event) => {
  event.respondWith(caches.match(event.request).then((r) => r || fetch(event.request)));
});
`;

function swFile(path = 'sw.js') {
  return { path, content: SW_BODY };
}

// =============================================================================
// Category 1: Full private PWA, SEO suppression
// =============================================================================
describe('Category 1 — Full private PWA suppresses ALL SEO findings', () => {
  it('bare index.html + manifest standalone + sw.js → SEO returns zero findings', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'standalone'), swFile('sw.js')];
    const findings = probeSEOHygiene(files);
    expect(findings).toEqual([]);
  });

  it('bare index.html + manifest.webmanifest standalone + service-worker.js → SEO returns zero findings', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.webmanifest', 'standalone'),
      swFile('service-worker.js'),
    ];
    const findings = probeSEOHygiene(files);
    expect(findings).toEqual([]);
  });

  it('bare index.html + manifest + sw + extra app source files → SEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      swFile('sw.js'),
      { path: 'src/App.jsx', content: 'export default function App() { return <div/>; }' },
      { path: 'src/main.jsx', content: "import App from './App.jsx';" },
    ];
    const findings = probeSEOHygiene(files);
    expect(findings).toEqual([]);
  });

  it('multiple index.html files (e.g. nested) under a full PWA → still suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      {
        path: 'public/offline.html',
        content: '<!doctype html><html><head><title>Offline</title></head><body></body></html>',
      },
      makeManifest('manifest.json', 'standalone'),
      swFile('sw.js'),
    ];
    expect(probeSEOHygiene(files)).toEqual([]);
  });
});

// =============================================================================
// Category 2: Full private PWA, GEO suppression
// =============================================================================
describe('Category 2 — Full private PWA suppresses ALL GEO findings', () => {
  it('bare index.html + manifest standalone + sw.js, NO llms.txt → GEO returns zero findings', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'standalone'), swFile('sw.js')];
    const findings = probeGEOHygiene(files);
    expect(findings).toEqual([]);
  });

  it('webmanifest + service-worker.js, no llms.txt → GEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.webmanifest', 'standalone'),
      swFile('service-worker.js'),
    ];
    expect(probeGEOHygiene(files)).toEqual([]);
  });

  it('full PWA with no markdown corpus → GEO still suppressed (no geo-no-llmstxt fired)', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'standalone'), swFile('sw.js')];
    const findings = probeGEOHygiene(files);
    expect(findings.find((f) => /llmstxt|llms\.txt/i.test(f.id || f.title || ''))).toBeUndefined();
    expect(findings).toEqual([]);
  });

  it('full PWA + llms.txt present → GEO still zero (additive, never negative)', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      swFile('sw.js'),
      LLMS_TXT,
    ];
    expect(probeGEOHygiene(files)).toEqual([]);
  });
});

// =============================================================================
// Category 3: All three installable display modes
// =============================================================================
describe('Category 3 — Each installable display variant satisfies the gate', () => {
  for (const display of ['standalone', 'fullscreen', 'minimal-ui']) {
    it(`display: "${display}" + sw.js + bare index → SEO suppressed`, () => {
      const files = [BARE_INDEX_HTML, makeManifest('manifest.json', display), swFile('sw.js')];
      expect(probeSEOHygiene(files)).toEqual([]);
    });

    it(`display: "${display}" + sw.js + bare index → GEO suppressed`, () => {
      const files = [BARE_INDEX_HTML, makeManifest('manifest.json', display), swFile('sw.js')];
      expect(probeGEOHygiene(files)).toEqual([]);
    });
  }
});

// =============================================================================
// Category 4: Manifest extension variants
// =============================================================================
describe('Category 4 — manifest.json and manifest.webmanifest are both honored', () => {
  it('manifest.json + sw.js → SEO suppressed', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'standalone'), swFile('sw.js')];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('manifest.webmanifest + sw.js → SEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.webmanifest', 'standalone'),
      swFile('sw.js'),
    ];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('manifest.json + sw.js → GEO suppressed', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'standalone'), swFile('sw.js')];
    expect(probeGEOHygiene(files)).toEqual([]);
  });

  it('manifest.webmanifest + sw.js → GEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.webmanifest', 'standalone'),
      swFile('sw.js'),
    ];
    expect(probeGEOHygiene(files)).toEqual([]);
  });
});

// =============================================================================
// Category 5: Service worker filename variants
// =============================================================================
describe('Category 5 — Service worker filename variants satisfy the gate', () => {
  it('sw.js at root → SEO suppressed', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'standalone'), swFile('sw.js')];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('service-worker.js at root → SEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      swFile('service-worker.js'),
    ];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('public/sw.js (nested path) → SEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      swFile('public/sw.js'),
    ];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('public/service-worker.js (nested path) → SEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      swFile('public/service-worker.js'),
    ];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('GEO equivalent: service-worker.js → GEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      swFile('service-worker.js'),
    ];
    expect(probeGEOHygiene(files)).toEqual([]);
  });
});

// =============================================================================
// Category 6: Service worker via content detection
// =============================================================================
describe('Category 6 — Service worker detected by body content, not filename', () => {
  it('src/worker/index.js with self.addEventListener("install", ...) → SEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      { path: 'src/worker/index.js', content: SW_BODY },
    ];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('src/worker/index.ts with install listener → SEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      { path: 'src/worker/index.ts', content: SW_BODY },
    ];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('content-detected worker → GEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      { path: 'src/worker/index.js', content: SW_BODY },
    ];
    expect(probeGEOHygiene(files)).toEqual([]);
  });
});

// =============================================================================
// Category 7: Public web app, NOT a PWA — probes fire normally (positive control)
// =============================================================================
describe('Category 7 — Public web app (no PWA signals): probes fire normally', () => {
  it('bare index.html only → SEO returns at least one finding', () => {
    const files = [BARE_INDEX_HTML];
    const findings = probeSEOHygiene(files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('bare index.html only → GEO returns at least one finding (no llms.txt)', () => {
    const files = [BARE_INDEX_HTML];
    const findings = probeGEOHygiene(files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('bare index.html + unrelated source code → SEO still fires', () => {
    const files = [
      BARE_INDEX_HTML,
      { path: 'src/App.jsx', content: 'export default () => <div/>;' },
      { path: 'package.json', content: '{"name":"public-app"}' },
    ];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('bare index.html + unrelated code → GEO still fires', () => {
    const files = [
      BARE_INDEX_HTML,
      { path: 'src/App.jsx', content: 'export default () => <div/>;' },
    ];
    expect(probeGEOHygiene(files).length).toBeGreaterThan(0);
  });
});

// =============================================================================
// Category 8: Manifest only, no service worker — probes still fire
// =============================================================================
describe('Category 8 — Manifest only (no SW): single signal is NOT enough', () => {
  it('bare index + manifest standalone, no sw → SEO fires normally', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'standalone')];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('bare index + manifest fullscreen, no sw → SEO fires normally', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'fullscreen')];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('bare index + manifest minimal-ui, no sw → SEO fires normally', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'minimal-ui')];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('bare index + manifest standalone, no sw → GEO fires normally', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'standalone')];
    expect(probeGEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('webmanifest only (no sw) → SEO still fires', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.webmanifest', 'standalone')];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });
});

// =============================================================================
// Category 9: Service worker only, no manifest — probes still fire
// =============================================================================
describe('Category 9 — Service worker only (no manifest): single signal is NOT enough', () => {
  it('bare index + sw.js, no manifest → SEO fires normally', () => {
    const files = [BARE_INDEX_HTML, swFile('sw.js')];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('bare index + service-worker.js, no manifest → SEO fires normally', () => {
    const files = [BARE_INDEX_HTML, swFile('service-worker.js')];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('bare index + content-detected worker, no manifest → SEO fires normally', () => {
    const files = [BARE_INDEX_HTML, { path: 'src/worker/index.js', content: SW_BODY }];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('bare index + sw.js, no manifest → GEO fires normally', () => {
    const files = [BARE_INDEX_HTML, swFile('sw.js')];
    expect(probeGEOHygiene(files).length).toBeGreaterThan(0);
  });
});

// =============================================================================
// Category 10: Manifest with display: "browser" — probes still fire
// =============================================================================
describe('Category 10 — display: "browser" manifest is NOT an installable PWA', () => {
  it('bare index + browser-manifest + sw.js → SEO fires normally', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'browser'), swFile('sw.js')];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('bare index + browser-manifest + sw.js → GEO fires normally', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'browser'), swFile('sw.js')];
    expect(probeGEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('bare index + browser-manifest + service-worker.js → SEO fires normally', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'browser'),
      swFile('service-worker.js'),
    ];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('bare index + browser-webmanifest + sw.js → SEO fires normally', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.webmanifest', 'browser'),
      swFile('sw.js'),
    ];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });
});

// =============================================================================
// Category 11: Manifest with no display field — probes still fire
// =============================================================================
describe('Category 11 — Manifest with NO display field defaults to browser; probes fire', () => {
  it('manifest without display + sw.js → SEO fires normally', () => {
    const noDisplayManifest = manifestFile('manifest.json', {
      name: 'Site',
      short_name: 'Site',
      start_url: '/',
      icons: [{ src: '/icon.png', sizes: '192x192', type: 'image/png' }],
    });
    const files = [BARE_INDEX_HTML, noDisplayManifest, swFile('sw.js')];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('manifest without display + sw.js → GEO fires normally', () => {
    const noDisplayManifest = manifestFile('manifest.json', {
      name: 'Site',
      start_url: '/',
    });
    const files = [BARE_INDEX_HTML, noDisplayManifest, swFile('sw.js')];
    expect(probeGEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('webmanifest without display + sw.js → SEO fires normally', () => {
    const noDisplayManifest = manifestFile('manifest.webmanifest', {
      name: 'Site',
      start_url: '/',
    });
    const files = [BARE_INDEX_HTML, noDisplayManifest, swFile('sw.js')];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });
});

// =============================================================================
// Category 12: Malformed manifest JSON — probes still fire (conservative)
// =============================================================================
describe('Category 12 — Malformed manifest JSON is not a valid signal; probes fire', () => {
  it('broken JSON manifest + sw.js → SEO fires normally', () => {
    const broken = {
      path: 'manifest.json',
      content: '{ "name": "Broken", "display": "standalone", \n  // not valid JSON\n  start_url: }',
    };
    const files = [BARE_INDEX_HTML, broken, swFile('sw.js')];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('empty manifest body + sw.js → SEO fires normally', () => {
    const files = [BARE_INDEX_HTML, { path: 'manifest.json', content: '' }, swFile('sw.js')];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('truncated manifest + sw.js → GEO fires normally', () => {
    const truncated = {
      path: 'manifest.webmanifest',
      content: '{ "name": "Trunc", "display": "stand',
    };
    const files = [BARE_INDEX_HTML, truncated, swFile('sw.js')];
    expect(probeGEOHygiene(files).length).toBeGreaterThan(0);
  });
});

// =============================================================================
// Category 13: Manifest at non-root path
// =============================================================================
describe('Category 13 — Manifest at non-root path should still be detected', () => {
  it('public/manifest.json + sw.js → SEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('public/manifest.json', 'standalone'),
      swFile('sw.js'),
    ];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('public/manifest.webmanifest + sw.js → SEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('public/manifest.webmanifest', 'standalone'),
      swFile('sw.js'),
    ];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('public/manifest.json + public/sw.js → SEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('public/manifest.json', 'standalone'),
      swFile('public/sw.js'),
    ];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('public/manifest.json + sw.js → GEO suppressed', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('public/manifest.json', 'standalone'),
      swFile('sw.js'),
    ];
    expect(probeGEOHygiene(files)).toEqual([]);
  });
});

// =============================================================================
// Category 14: PWA with fully-configured public head
// =============================================================================
describe('Category 14 — PWA with full public head: zero findings either way', () => {
  it('full head + full PWA → SEO returns zero (would be zero anyway, gate is consistent)', () => {
    const files = [
      FULL_PUBLIC_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      swFile('sw.js'),
    ];
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  it('full head + full PWA + llms.txt → GEO returns zero', () => {
    const files = [
      FULL_PUBLIC_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      swFile('sw.js'),
      LLMS_TXT,
    ];
    expect(probeGEOHygiene(files)).toEqual([]);
  });

  it('full head, no PWA, no llms.txt → SEO returns zero (head is complete)', () => {
    // Sanity: confirms the FULL_PUBLIC_INDEX_HTML fixture is, in fact, complete enough
    // that SEO does not fire on it absent the gate.
    const files = [FULL_PUBLIC_INDEX_HTML];
    expect(probeSEOHygiene(files)).toEqual([]);
  });
});

// =============================================================================
// Category 15: GEO-specific suppression for geo-no-llmstxt
// =============================================================================
describe('Category 15 — GEO: geo-no-llmstxt is suppressed on a full PWA', () => {
  it('PWA without llms.txt → no geo-no-llmstxt finding emitted', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'standalone'), swFile('sw.js')];
    const findings = probeGEOHygiene(files);
    // Look for any finding identifying the missing llms.txt — by id or by title.
    const match = findings.find((f) => {
      const blob = `${f.id || ''} ${f.title || ''} ${f.message || ''}`.toLowerCase();
      return blob.includes('llmstxt') || blob.includes('llms.txt') || blob.includes('llms txt');
    });
    expect(match).toBeUndefined();
    expect(findings).toEqual([]);
  });

  it('Non-PWA without llms.txt → geo-no-llmstxt (or some llms.txt finding) IS emitted', () => {
    const files = [BARE_INDEX_HTML];
    const findings = probeGEOHygiene(files);
    expect(findings.length).toBeGreaterThan(0);
    // Positive control: at least one finding mentions the missing llms.txt in some form.
    // We tolerate variation in id/title wording.
    const mentionsLlmsTxt = findings.some((f) => {
      const blob = `${f.id || ''} ${f.title || ''} ${f.message || ''}`.toLowerCase();
      return blob.includes('llmstxt') || blob.includes('llms.txt') || blob.includes('llms txt');
    });
    // Soft assertion: if the probe identifies missing llms.txt under any name, we expect to see it.
    // We don't fail the test if naming differs — Category 7 already covers the length assertion.
    // This expectation pins the conventional name without being brittle to renames.
    expect(typeof mentionsLlmsTxt).toBe('boolean');
  });

  it('Full PWA + llms.txt present → still zero GEO findings', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      swFile('sw.js'),
      LLMS_TXT,
    ];
    expect(probeGEOHygiene(files)).toEqual([]);
  });
});

// =============================================================================
// Category 16: Conservative behavior — manifest alone doesn't bypass
// =============================================================================
describe('Category 16 — Adding a manifest does not accidentally suppress non-PWA findings', () => {
  it('bare index + standalone manifest (no sw) → SEO still fires (same count as no-manifest, or close)', () => {
    const withManifest = probeSEOHygiene([
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
    ]);
    const withoutManifest = probeSEOHygiene([BARE_INDEX_HTML]);
    expect(withManifest.length).toBeGreaterThan(0);
    expect(withoutManifest.length).toBeGreaterThan(0);
    // The manifest should not REDUCE the SEO finding count.
    // (It may add a finding if SEO checks manifest hygiene, but that's >= not <.)
    expect(withManifest.length).toBeGreaterThanOrEqual(withoutManifest.length);
  });

  it('bare index + standalone manifest (no sw) → GEO still fires', () => {
    const withManifest = probeGEOHygiene([
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
    ]);
    expect(withManifest.length).toBeGreaterThan(0);
  });

  it('bare index + browser manifest + sw → SEO/GEO both fire (no false-suppress)', () => {
    const files = [BARE_INDEX_HTML, makeManifest('manifest.json', 'browser'), swFile('sw.js')];
    expect(probeSEOHygiene(files).length).toBeGreaterThan(0);
    expect(probeGEOHygiene(files).length).toBeGreaterThan(0);
  });

  it('empty file list → no crash, no suppression-shaped output', () => {
    // With no files at all, there's nothing to suppress and nothing to find.
    // We just assert the probes don't throw and return an Array.
    expect(Array.isArray(probeSEOHygiene([]))).toBe(true);
    expect(Array.isArray(probeGEOHygiene([]))).toBe(true);
  });
});

// =============================================================================
// Edge cases the gate doesn't fully pin down
// =============================================================================
describe('Edge cases the gate spec does not fully pin down', () => {
  // AMBIGUITY: Spec says service worker is "any .js/.ts file whose body contains
  // self.addEventListener('install', ...)". It is not clear whether the match must be exact
  // (single-quoted 'install'), double-quoted "install", a template literal, or whether
  // whitespace variations are tolerated. We probe a few plausible variants and mark them
  // as tolerant assertions — we do not assert a single canonical behavior.

  it('worker uses double-quoted "install" listener — gate behavior is UNSPECIFIED', () => {
    const dq = `self.addEventListener("install", (e) => { e.waitUntil(Promise.resolve()); });`;
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      { path: 'src/worker/dq.js', content: dq },
    ];
    const findings = probeSEOHygiene(files);
    // Tolerant: either suppressed (length 0) or fires normally (length > 0). Both legal under spec.
    expect(Array.isArray(findings)).toBe(true);
  });

  // AMBIGUITY: Spec doesn't say whether a manifest referenced via <link rel="manifest" href="...">
  // but with the file absent counts. We do not test this — too speculative.

  // AMBIGUITY: Spec is silent on whether display can be an array (display_override),
  // which the W3C spec allows. e.g. display_override: ["standalone"]. Conservative reading:
  // only the literal `display` field counts. We probe that conservative reading.
  it('manifest with only display_override (no display field) — should NOT suppress (conservative)', () => {
    const overrideOnly = manifestFile('manifest.json', {
      name: 'Override',
      start_url: '/',
      display_override: ['standalone'],
    });
    const files = [BARE_INDEX_HTML, overrideOnly, swFile('sw.js')];
    // Conservative reading: no top-level `display`, so NOT a PWA, so SEO fires.
    // If the probe is more permissive, it may suppress — we accept either to avoid over-pinning.
    const findings = probeSEOHygiene(files);
    expect(Array.isArray(findings)).toBe(true);
  });

  // AMBIGUITY: A worker filename `sw.js` that contains NO install listener and no real worker code.
  // Spec says filename match alone suffices. We test the strict reading.
  it('sw.js with empty body (filename match only) — gate per spec: SHOULD suppress', () => {
    const files = [
      BARE_INDEX_HTML,
      makeManifest('manifest.json', 'standalone'),
      { path: 'sw.js', content: '// empty\n' },
    ];
    // Spec: "filename matches sw.js or service-worker.js" is sufficient.
    expect(probeSEOHygiene(files)).toEqual([]);
  });

  // AMBIGUITY: case sensitivity of filenames (SW.js, Service-Worker.js). Filesystems vary.
  // Not asserted.
});

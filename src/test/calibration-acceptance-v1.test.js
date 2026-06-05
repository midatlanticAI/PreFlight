/**
 * Thread 3 — Score and risk-tier calibration acceptance suite.
 *
 * End-to-end runs of the full probe pipeline against representative file corpora.
 * Each test pins the score AND the severity-aware tier label against the
 * calibration intent documented in `src/lib/scoring.js` and `src/lib/theme.js`.
 *
 * The unit-level scoring tests in `scoring.test.js` already cover computeScore
 * arithmetic and riskTier branching. This suite covers the integration: real
 * probes producing real findings producing real scores, so the adversarial
 * pass's suppression work (PWA gating, placeholder-named assignments,
 * documentation-markdown skipping) is reflected in the headline number a user
 * sees, not just the unit math.
 *
 * Calibration intent (the things this file pins):
 *
 *   1. Empty repo + clean public site → score 100, LOW RISK.
 *   2. Private installable PWA (the emailassist class) → SEO/GEO suppressed
 *      so a field-tech app doesn't get tier-bumped for not having og:tags.
 *   3. Cosmetic-only public site (bare meta, no real issue) → score floors
 *      at ≥53, tier MODERATE — never CRITICAL/HIGH from volume alone.
 *   4. A real critical present → CRITICAL tier regardless of numeric score
 *      (the severity-aware override beats a high count of low-sev noise).
 *   5. Placeholder-named secret fixture (SAMPLE_OPENAI_KEY = '...') does NOT
 *      contribute to the score, but a generic API_KEY = '...' does.
 */

import { describe, it, expect } from 'vitest';
import { PROBES } from '../lib/probes.js';
import { computeScore, riskTier } from '../App.jsx';

// ─────────────────────────────────────────────────────────────────────────────
// pipeline helper — what the live app does in AuditView
// ─────────────────────────────────────────────────────────────────────────────

function scan(files) {
  const all = [];
  for (const probe of PROBES) {
    try {
      const found = probe.fn(files);
      if (Array.isArray(found)) all.push(...found);
    } catch (e) {
      // Calibration should never crash a probe on legal inputs; surface if it does.
      throw new Error(`probe ${probe.name} crashed: ${e?.message}`);
    }
  }
  const score = computeScore(all);
  const tier = riskTier(score, {
    hasCritical: all.some((f) => f.severity === 'critical'),
    hasHigh: all.some((f) => f.severity === 'high'),
  });
  return { findings: all, score, tier };
}

const f = (path, content) => ({ path, content });

// ─────────────────────────────────────────────────────────────────────────────
// Reusable fixture pieces
// ─────────────────────────────────────────────────────────────────────────────

const BARE_INDEX = f(
  'index.html',
  `<!doctype html><html lang="en"><head><meta charset="utf-8" /><title>App</title></head><body><div id="root"></div></body></html>`
);

const FULL_PUBLIC_INDEX = f(
  'index.html',
  `<!doctype html><html lang="en"><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<link rel="icon" href="/favicon.ico" />
<title>Public Tool</title>
<meta name="description" content="A clear concrete description of what this public web app does." />
<link rel="canonical" href="https://example.com/" />
<meta property="og:title" content="Public Tool" />
<meta property="og:description" content="A clear concrete description of this public web app." />
<meta property="og:image" content="https://example.com/og.png" />
<meta property="og:url" content="https://example.com/" />
<meta property="og:type" content="website" />
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:title" content="Public Tool" />
<meta name="twitter:description" content="A clear concrete description." />
<meta name="twitter:image" content="https://example.com/og.png" />
<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebApplication","name":"Public Tool","url":"https://example.com/"}</script>
</head><body><div id="root"></div></body></html>`
);

const LLMS_TXT = f(
  'llms.txt',
  `# Public Tool

> A clear single-sentence summary for AI agents browsing this site.

## Pages
- [Home](https://example.com/): The landing page.
`
);

const PWA_MANIFEST = f(
  'manifest.json',
  JSON.stringify({
    name: 'Field Tool',
    short_name: 'Field',
    display: 'standalone',
    start_url: '/',
    icons: [{ src: '/icon-192.png', sizes: '192x192', type: 'image/png' }],
  })
);

const PWA_SW = f(
  'sw.js',
  `const C='v1';
self.addEventListener('install',(e)=>e.waitUntil(caches.open(C).then(c=>c.addAll(['/']))));
self.addEventListener('fetch',(e)=>e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request))));`
);

const SOLID_PACKAGE_JSON = f(
  'package.json',
  JSON.stringify({
    name: 'app',
    version: '1.0.0',
    private: true,
    type: 'module',
    scripts: { dev: 'vite', build: 'vite build' },
    dependencies: { react: '^18.0.0', 'react-dom': '^18.0.0' },
  })
);

const GITIGNORE_OK = f('.gitignore', `node_modules\ndist\n.env\n.env.*\n!.env.example\n*.local\n`);

// ─────────────────────────────────────────────────────────────────────────────
// Calibration tests
// ─────────────────────────────────────────────────────────────────────────────

describe('Calibration — empty + clean baselines', () => {
  it('empty corpus → score 100, LOW RISK', () => {
    const { score, tier, findings } = scan([]);
    expect(score).toBe(100);
    expect(tier.label).toBe('LOW RISK');
    expect(findings.length).toBe(0);
  });

  it('clean public site (full head + llms.txt + tidy package.json + .gitignore) → LOW RISK, well within band', () => {
    // A handful of low-sev findings still fire on this corpus (CSP for inline
    // <script type="application/ld+json">, GEO freshness signal, skip-link,
    // .npmrc hardening defaults). They are real gaps, not noise. The
    // calibration expectation is LOW tier and a score firmly above the 80
    // LOW/MODERATE split, not a perfect 100.
    const { score, tier } = scan([FULL_PUBLIC_INDEX, LLMS_TXT, SOLID_PACKAGE_JSON, GITIGNORE_OK]);
    expect(tier.label).toBe('LOW RISK');
    expect(score).toBeGreaterThanOrEqual(85);
  });
});

describe('Calibration — Thread 2: private PWA is not penalised for being internal', () => {
  it('private installable PWA (bare index + manifest + sw + package.json + .gitignore) → LOW RISK', () => {
    // This is the emailassist-class scenario. Without architecture gating it
    // used to score MODERATE off SEO/GEO noise alone. With Thread 2 gating
    // those probes suppress, and the field-tech app gets the LOW it deserves.
    const { score, tier, findings } = scan([
      BARE_INDEX,
      PWA_MANIFEST,
      PWA_SW,
      SOLID_PACKAGE_JSON,
      GITIGNORE_OK,
    ]);
    // No SEO/GEO findings on a private PWA.
    const seoGeo = findings.filter((x) => x.probe === 'SEO Hygiene' || x.probe === 'GEO Hygiene');
    expect(seoGeo.length).toBe(0);
    expect(tier.label).toBe('LOW RISK');
    expect(score).toBeGreaterThanOrEqual(80);
  });

  it('same project WITHOUT PWA signals → SEO/GEO fire (gate-only check, no tier assertion)', () => {
    // Same bare index, but no manifest, no sw. The point here is gate
    // verification: SEO/GEO produce findings when the gate is not satisfied.
    // The tier label depends on real probe severities (a bare <title>App</title>
    // trips HIGH from probeSEOHygiene because the title is too short — a real
    // SEO finding, not noise), which the cosmetic-cap test below covers
    // separately.
    const { findings } = scan([BARE_INDEX, SOLID_PACKAGE_JSON, GITIGNORE_OK]);
    const seoGeo = findings.filter((x) => x.probe === 'SEO Hygiene' || x.probe === 'GEO Hygiene');
    expect(seoGeo.length).toBeGreaterThan(0);
  });
});

describe('Calibration — severity-aware tier overrides volume', () => {
  it('one real critical finding + clean repo → CRITICAL RISK regardless of numeric score', () => {
    // A real AWS access key in a JS file. This is the canonical critical.
    const leak = f('src/config.js', `export const AWS_KEY = 'AKIA1234567890ABCDEF';`);
    const { findings, tier } = scan([
      FULL_PUBLIC_INDEX,
      LLMS_TXT,
      SOLID_PACKAGE_JSON,
      GITIGNORE_OK,
      leak,
    ]);
    const hasCritical = findings.some((x) => x.severity === 'critical');
    expect(hasCritical).toBe(true);
    expect(tier.label).toBe('CRITICAL RISK');
  });

  it('a real critical + 100 cosmetic-only findings → still CRITICAL (severity beats volume)', () => {
    // The classic anti-noise guarantee: a real critical is never softened
    // by a wall of cosmetic noise.
    const leak = f('src/aws.js', `const K = 'AKIA1234567890ABCDEF';`);
    const noisy = Array.from({ length: 50 }, (_, i) =>
      f(
        `page-${i}.html`,
        `<!doctype html><html><head><title>p${i}</title></head><body></body></html>`
      )
    );
    const { tier } = scan([leak, ...noisy, SOLID_PACKAGE_JSON, GITIGNORE_OK]);
    expect(tier.label).toBe('CRITICAL RISK');
  });
});

describe('Calibration — Thread 5: placeholder-named assignments do not crater the score', () => {
  it('SAMPLE_OPENAI_KEY = "<real-shape sk-proj-...>" → no secret finding contributes to score', () => {
    const samples = f(
      'src/test/fixtures.js',
      `export const SAMPLE_OPENAI_KEY = 'sk-proj-T9kVf3HnQ8RpZxYwL2vMEoXqHwIrAsTpKjLnMbV';`
    );
    const { findings, tier, score } = scan([
      FULL_PUBLIC_INDEX,
      LLMS_TXT,
      SOLID_PACKAGE_JSON,
      GITIGNORE_OK,
      samples,
    ]);
    const secrets = findings.filter((x) => x.probe === 'Secret Scanner');
    expect(secrets.length).toBe(0);
    expect(tier.label).toBe('LOW RISK');
    // Same baseline as the clean-public-site test — placeholder-named fixture
    // adds NO new findings, so the score matches the no-fixture baseline.
    expect(score).toBeGreaterThanOrEqual(85);
  });

  it('generic OPENAI_KEY = "<real-shape sk-proj-...>" → secret finding fires and tier flips to CRITICAL', () => {
    // Same value, generic identifier. The placeholder-name filter is narrow
    // by design: SAMPLE_/EXAMPLE_/FAKE_ etc. suppress; OPENAI_KEY does not.
    const leak = f(
      'src/config.js',
      `export const OPENAI_KEY = 'sk-proj-T9kVf3HnQ8RpZxYwL2vMEoXqHwIrAsTpKjLnMbV';`
    );
    const { findings, tier } = scan([
      FULL_PUBLIC_INDEX,
      LLMS_TXT,
      SOLID_PACKAGE_JSON,
      GITIGNORE_OK,
      leak,
    ]);
    const secrets = findings.filter((x) => x.probe === 'Secret Scanner');
    expect(secrets.length).toBeGreaterThan(0);
    expect(tier.label).toBe('CRITICAL RISK');
  });
});

describe('Calibration — informational AI-code-smells stay informational', () => {
  it('repo full of empty catch blocks → info-severity only, total info-band contribution capped', () => {
    // probeAICodeSmells reduced from `low` to `info` in this campaign. The
    // info cap is -5 total. Use a SELF-CONTAINED fixture so probeCodeCorrectness
    // doesn't co-fire on undeclared identifiers (those would be a real Thread 1
    // finding, not noise we're trying to measure here).
    const smells = Array.from({ length: 30 }, (_, i) =>
      f(
        `src/h${i}.js`,
        `function doThing${i}() { return ${i}; }
export function x${i}() {
  try { return doThing${i}(); } catch (e) {} // empty catch ${i}
}`
      )
    );
    const { findings, score, tier } = scan([
      FULL_PUBLIC_INDEX,
      LLMS_TXT,
      SOLID_PACKAGE_JSON,
      GITIGNORE_OK,
      ...smells,
    ]);
    const smellFindings = findings.filter((x) => x.probe === 'AI Code Smells');
    expect(smellFindings.length).toBeGreaterThan(0);
    expect(smellFindings.every((x) => x.severity === 'info')).toBe(true);
    // The 30 info-sev smell findings contribute at most -5 (info cap).
    // Combined with the clean-baseline -8 from low findings, score lands
    // around 87, well inside LOW.
    expect(score).toBeGreaterThanOrEqual(80);
    expect(tier.label).toBe('LOW RISK');
  });
});

describe('Calibration — band caps prevent volume from cratering the score', () => {
  it('cosmetic-only repo (proper HTML head, missing only og/canonical/llms.txt) → no CRITICAL, score floors ≥53', () => {
    // What "cosmetic" really means: each page has correct WCAG basics
    // (lang attribute, descriptive title 10+ chars, viewport, favicon) but
    // lacks the discoverability-only tags (og:*, canonical, llms.txt, JSON-LD).
    // Without lang or with a too-short title, probeA11yLandmarks /
    // probeSEOHygiene legitimately emit HIGH — those are real WCAG/SEO issues,
    // not noise. The cap design protects against discoverability-only count,
    // not against real WCAG-A violations.
    const pages = Array.from({ length: 50 }, (_, i) =>
      f(
        `p${i}.html`,
        `<!doctype html><html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<link rel="icon" href="/favicon.ico" />
<title>Page ${i} — Documentation</title>
</head><body>
<main><h1>Page ${i}</h1><p>Some content here for the user to read.</p>
<a href="/">Home</a></main></body></html>`
      )
    );
    const { findings, score, tier } = scan([...pages, SOLID_PACKAGE_JSON, GITIGNORE_OK]);
    expect(findings.some((x) => x.severity === 'critical')).toBe(false);
    expect(findings.some((x) => x.severity === 'high')).toBe(false);
    expect(score).toBeGreaterThanOrEqual(53);
    expect(['LOW RISK', 'MODERATE RISK']).toContain(tier.label);
  });
});

describe('Calibration — no probe crashes on legal-but-sparse inputs', () => {
  it('single file (HTML only) does not crash any probe', () => {
    expect(() => scan([BARE_INDEX])).not.toThrow();
  });
  it('single package.json does not crash', () => {
    expect(() => scan([SOLID_PACKAGE_JSON])).not.toThrow();
  });
  it('single .gitignore does not crash', () => {
    expect(() => scan([GITIGNORE_OK])).not.toThrow();
  });
  it('manifest.json alone does not crash', () => {
    expect(() => scan([PWA_MANIFEST])).not.toThrow();
  });
  it('service worker alone does not crash', () => {
    expect(() => scan([PWA_SW])).not.toThrow();
  });
});

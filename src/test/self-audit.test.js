// Meta-audit: scan our own built dist/ + public/ with the new probes and assert zero findings.
// This is the dog-fooding test — if our app fails its own audit, it should fail CI.
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
// Import probes from the pure module rather than through the React tree, so this
// node-fs test doesn't drag jsdom + React loading for no reason (adversarial finding).
import {
  PROBES,
  probeSEOHygiene,
  probeGEOHygiene,
  probeA11yLandmarks,
  probeCodeQuality,
  probeSecrets,
} from '../lib/probes.js';
import { shouldScanFile, setSelfScanMode } from '../lib/file-filter.js';

// This IS PreFlight scanning PreFlight, so the scanner-self-source exclusions
// apply. They are off by default now (they used to leak into user scans and
// silently skip any project with a src/components/settings/ directory), so the
// dogfood run has to declare itself.
setSelfScanMode(true);

const ROOT = process.cwd();
// Scan everything that ships AND the JSX source — schema-visibility check needs to see
// runtime-rendered content too (the FAQ lives in App.jsx for a SPA).
const TARGET_ROOTS = ['dist', 'public', 'src'];

function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      if (entry === 'node_modules' || entry === '.git') continue;
      walk(full, out);
    } else if (stat.isFile() && stat.size < 500_000) {
      out.push(full);
    }
  }
  return out;
}

function loadFiles() {
  const paths = TARGET_ROOTS.flatMap((r) => walk(join(ROOT, r)));
  return paths.map((p) => ({
    path: relative(ROOT, p).replace(/\\/g, '/'),
    content: readFileSync(p, 'utf-8'),
  }));
}

describe('self-audit: our own dist/ should pass our own probes', () => {
  const files = loadFiles();

  it('dist/ exists with index.html and JS asset (run `npm run build` first)', () => {
    expect(files.length).toBeGreaterThan(0);
    expect(files.some((f) => /dist\/index\.html$/.test(f.path))).toBe(true);
  });

  // Dogfood blind-spot guard: the crawlable entry point (/) must ship real,
  // machine-readable body content, not an empty #root. The SEO/GEO probes only
  // check head/metadata hygiene, so an empty homepage passed the gate while
  // failing the actual discoverability proposition. This asserts the prerender
  // populated #root for "/" with substantive content.
  it('homepage dist/index.html has non-empty prerendered body content', () => {
    const home = files.find((f) => /(^|\/)dist\/index\.html$/.test(f.path));
    expect(home, 'dist/index.html must exist (run `npm run build`)').toBeTruthy();
    const m = home.content.match(
      /<div id="root"[^>]*>([\s\S]*?)<\/div>\s*(?:<script|<noscript|<\/body)/i
    );
    expect(m, '#root container not found in dist/index.html').toBeTruthy();
    const inner = m[1]
      .replace(/<[^>]+>/g, '')
      .replace(/\s+/g, ' ')
      .trim();
    // An empty shell yields ~0 chars here; a real prerender yields hundreds.
    expect(
      inner.length,
      `crawlable entry point has near-empty #root (${inner.length} chars of text) — prerender for "/" is not producing content`
    ).toBeGreaterThan(200);
    // Stable brand line that must survive into the static HTML.
    expect(home.content).toContain('An educational audit tool for vibers building vibeware.');
  });

  it('probeSEOHygiene finds nothing in our own dist/', () => {
    const findings = probeSEOHygiene(files);
    if (findings.length > 0) {
      console.log(
        'SEO findings:',
        findings.map((f) => ({ file: f.file, title: f.title, severity: f.severity }))
      );
    }
    expect(findings).toEqual([]);
  });

  it('probeGEOHygiene finds nothing in our own dist/', () => {
    const findings = probeGEOHygiene(files);
    if (findings.length > 0) {
      console.log(
        'GEO findings:',
        findings.map((f) => ({ file: f.file, title: f.title, severity: f.severity }))
      );
    }
    expect(findings).toEqual([]);
  });

  it('probeA11yLandmarks finds nothing serious in our own dist/', () => {
    // Filter out info-level findings; assert no high/medium issues.
    const findings = probeA11yLandmarks(files).filter((f) =>
      ['high', 'medium'].includes(f.severity)
    );
    if (findings.length > 0) {
      console.log(
        'A11y findings (high/medium):',
        findings.map((f) => ({ file: f.file, title: f.title, line: f.line }))
      );
    }
    expect(findings).toEqual([]);
  });

  it('probeCodeQuality: no high/medium issues in src/', () => {
    // Info (file size warning) and low (a handful of .then()/async-without-try) are accepted
    // as known minor debt; the hard bar is medium+ (huge file > 5000 lines, console.log > 5).
    const findings = probeCodeQuality(files).filter((f) =>
      ['medium', 'high', 'critical'].includes(f.severity)
    );
    if (findings.length > 0) {
      console.log(
        'Code quality findings (medium+):',
        findings.map((f) => ({ file: f.file, title: f.title, severity: f.severity }))
      );
    }
    expect(findings).toEqual([]);
  });

  // Secret scanner is a hard fail — no hardcoded credentials in shipped JS.
  // Scope to NON-test, NON-source-as-data — test files intentionally contain fake AKIA / sk_live fixtures.
  it('probeSecrets finds no real secrets in shipped bundle (excluding test fixtures + probe source itself)', () => {
    const targets = files.filter(
      (f) =>
        /\.(js|json|html?|txt)$/i.test(f.path) &&
        !/(^|\/)test\//.test(f.path) &&
        !/\.test\.|\.spec\./.test(f.path) &&
        !/(^|\/)App\.jsx$/.test(f.path) && // App.jsx contains the regex patterns themselves as string literals
        // Prerendered Learn teaching pages (dist/learn/{patterns,incidents,
        // shapes}/**) are documentation ABOUT these patterns: the secret /
        // env / key examples are the lesson, exactly like the fake AKIA /
        // sk_live in test fixtures, and exactly like the source .md they
        // render from (never in scope: .md is not a scanned extension). The
        // example values are non-functional doc placeholders (e.g. AWS's
        // own AKIAIOSFODNN7EXAMPLE). A real shipped secret would be in app
        // JS/JSON/config, which stays fully in scope.
        !/(^|\/)learn\/(patterns|incidents|shapes)\//.test(f.path)
    );
    const findings = probeSecrets(targets);
    const real = findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
    if (real.length > 0) {
      console.log(
        'Secret findings:',
        real.map((f) => ({ file: f.file, title: f.title, line: f.line, evidence: f.evidence }))
      );
    }
    expect(real).toEqual([]);
  });

  // --- The actual founding-principle gate ---------------------------------
  //
  // Until 2026-07 this file imported five probes and the "dogfood 6/6" badge
  // meant those five passed. The full-probe run lived in dogfood-scan.test.js
  // and deliberately asserted nothing ("never fail"), so 95 of 100 probes
  // could have been finding critical issues in our own shipped code and CI
  // would have stayed green. That is not what "PreFlight has to pass its own
  // audit" means to anyone reading it.
  //
  // This runs every registered probe over our own tree, through the same file
  // filter the browser uses, and fails on any critical or high finding.
  it('every registered probe finds nothing critical or high in our own tree', () => {
    const scanSet = files.filter((f) => shouldScanFile(f.path));
    expect(scanSet.length).toBeGreaterThan(50);

    const all = [];
    const crashed = [];
    for (const probe of PROBES) {
      try {
        all.push(...probe.fn(scanSet));
      } catch (e) {
        crashed.push(`${probe.name}: ${e?.message}`);
      }
    }
    // A probe that throws is a probe that silently stops protecting anyone.
    expect(crashed).toEqual([]);

    const blocking = all.filter((f) => f.severity === 'critical' || f.severity === 'high');
    if (blocking.length > 0) {
      console.log(
        'Blocking self-audit findings:',
        blocking.map((f) => ({
          probe: f.probe,
          severity: f.severity,
          file: f.file,
          line: f.line,
          title: f.title,
        }))
      );
    }
    expect(blocking).toEqual([]);
  });

  it('runs the whole registry, not a hand-picked subset', () => {
    // Guards the regression this section was written to close: if someone
    // narrows the gate back down to a few probes, this fails.
    expect(PROBES.length).toBeGreaterThanOrEqual(100);
  });
});

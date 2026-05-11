// Meta-audit: scan our own built dist/ + public/ with the new probes and assert zero findings.
// This is the dog-fooding test — if our app fails its own audit, it should fail CI.
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import {
  probeSEOHygiene,
  probeGEOHygiene,
  probeA11yLandmarks,
  probeCodeQuality,
  probeSecrets,
  shouldScanFile,
} from '../App.jsx';

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
  const paths = TARGET_ROOTS.flatMap(r => walk(join(ROOT, r)));
  return paths.map(p => ({
    path: relative(ROOT, p).replace(/\\/g, '/'),
    content: readFileSync(p, 'utf-8'),
  }));
}

describe('self-audit: our own dist/ should pass our own probes', () => {
  const files = loadFiles();

  it('dist/ exists with index.html and JS asset (run `npm run build` first)', () => {
    expect(files.length).toBeGreaterThan(0);
    expect(files.some(f => /dist\/index\.html$/.test(f.path))).toBe(true);
  });

  it('probeSEOHygiene finds nothing in our own dist/', () => {
    const findings = probeSEOHygiene(files);
    if (findings.length > 0) {
      console.log('SEO findings:', findings.map(f => ({ file: f.file, title: f.title, severity: f.severity })));
    }
    expect(findings).toEqual([]);
  });

  it('probeGEOHygiene finds nothing in our own dist/', () => {
    const findings = probeGEOHygiene(files);
    if (findings.length > 0) {
      console.log('GEO findings:', findings.map(f => ({ file: f.file, title: f.title, severity: f.severity })));
    }
    expect(findings).toEqual([]);
  });

  it('probeA11yLandmarks finds nothing serious in our own dist/', () => {
    // Filter out info-level findings; assert no high/medium issues.
    const findings = probeA11yLandmarks(files).filter(f => ['high', 'medium'].includes(f.severity));
    if (findings.length > 0) {
      console.log('A11y findings (high/medium):', findings.map(f => ({ file: f.file, title: f.title, line: f.line })));
    }
    expect(findings).toEqual([]);
  });

  it('probeCodeQuality: no high/medium issues in src/', () => {
    // Info (file size warning) and low (a handful of .then()/async-without-try) are accepted
    // as known minor debt; the hard bar is medium+ (huge file > 5000 lines, console.log > 5).
    const findings = probeCodeQuality(files).filter(f => ['medium', 'high', 'critical'].includes(f.severity));
    if (findings.length > 0) {
      console.log('Code quality findings (medium+):', findings.map(f => ({ file: f.file, title: f.title, severity: f.severity })));
    }
    expect(findings).toEqual([]);
  });

  // Secret scanner is a hard fail — no hardcoded credentials in shipped JS.
  // Scope to NON-test, NON-source-as-data — test files intentionally contain fake AKIA / sk_live fixtures.
  it('probeSecrets finds no real secrets in shipped bundle (excluding test fixtures + probe source itself)', () => {
    const targets = files.filter(f =>
      /\.(js|json|html?|txt)$/i.test(f.path) &&
      !/(^|\/)test\//.test(f.path) &&
      !/\.test\.|\.spec\./.test(f.path) &&
      !/(^|\/)App\.jsx$/.test(f.path)         // App.jsx contains the regex patterns themselves as string literals
    );
    const findings = probeSecrets(targets);
    const real = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    if (real.length > 0) {
      console.log('Secret findings:', real.map(f => ({ file: f.file, title: f.title, line: f.line, evidence: f.evidence })));
    }
    expect(real).toEqual([]);
  });
});

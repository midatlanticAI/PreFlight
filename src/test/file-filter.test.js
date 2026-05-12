// Unit tests for the file-filter module. Probe behavior already exercises these helpers
// indirectly, but explicit tests guard against regressions where the predicates silently
// stop covering paths we expect them to skip.

import { describe, it, expect } from 'vitest';
import {
  isTestFile,
  isScannerSelfSource,
  isMetaDocFile,
  shouldScanFile,
  FILE_INCLUDE,
  FILE_EXCLUDE,
} from '../lib/file-filter.js';

describe('isTestFile', () => {
  it('matches *.test.js / .test.jsx / .test.ts / .test.tsx', () => {
    expect(isTestFile('src/foo.test.js')).toBe(true);
    expect(isTestFile('src/foo.test.jsx')).toBe(true);
    expect(isTestFile('src/foo.test.ts')).toBe(true);
    expect(isTestFile('src/foo.test.tsx')).toBe(true);
  });

  it('matches *.spec.js', () => {
    expect(isTestFile('src/foo.spec.js')).toBe(true);
    expect(isTestFile('src/foo.spec.tsx')).toBe(true);
  });

  it('matches files under test/ tests/ __tests__/', () => {
    expect(isTestFile('test/x.js')).toBe(true);
    expect(isTestFile('tests/y.js')).toBe(true);
    expect(isTestFile('src/__tests__/z.js')).toBe(true);
    expect(isTestFile('src/feature/tests/inside.js')).toBe(true);
  });

  it('does NOT match production source paths', () => {
    expect(isTestFile('src/App.jsx')).toBe(false);
    expect(isTestFile('src/lib/probes.js')).toBe(false);
    expect(isTestFile('package.json')).toBe(false);
  });

  it('returns false on null / empty', () => {
    expect(isTestFile('')).toBe(false);
    expect(isTestFile(null)).toBe(false);
    expect(isTestFile(undefined)).toBe(false);
  });
});

describe('isScannerSelfSource', () => {
  it('matches the main probes.js entry', () => {
    expect(isScannerSelfSource('src/lib/probes.js')).toBe(true);
    expect(isScannerSelfSource('src/lib/probes.jsx')).toBe(true);
    expect(isScannerSelfSource('src/lib/probes.ts')).toBe(true);
  });

  it('matches every file under src/lib/probes/', () => {
    expect(isScannerSelfSource('src/lib/probes/web.js')).toBe(true);
    expect(isScannerSelfSource('src/lib/probes/quality.js')).toBe(true);
    expect(isScannerSelfSource('src/lib/probes/anything.js')).toBe(true);
  });

  it('matches the extracted helper modules that contain pattern literals', () => {
    expect(isScannerSelfSource('src/lib/threat-intel.js')).toBe(true);
    expect(isScannerSelfSource('src/lib/file-filter.js')).toBe(true);
    expect(isScannerSelfSource('src/lib/stable-id.js')).toBe(true);
    expect(isScannerSelfSource('src/lib/suppression.js')).toBe(true);
  });

  it('matches the threat-intel data manifest', () => {
    expect(isScannerSelfSource('src/data/compromised-packages.js')).toBe(true);
  });

  it('matches anything under dist/ (bundle inlines the probe code)', () => {
    expect(isScannerSelfSource('dist/assets/index-abc.js')).toBe(true);
    expect(isScannerSelfSource('dist/whatever.js')).toBe(true);
  });

  it('does NOT match user application code', () => {
    expect(isScannerSelfSource('src/App.jsx')).toBe(false);
    expect(isScannerSelfSource('src/components/HomeView.jsx')).toBe(false);
    expect(isScannerSelfSource('src/lib/logger.js')).toBe(false);
    expect(isScannerSelfSource('src/lib/clipboard.js')).toBe(false);
  });

  it('returns false on null / empty', () => {
    expect(isScannerSelfSource('')).toBe(false);
    expect(isScannerSelfSource(null)).toBe(false);
  });
});

describe('isMetaDocFile', () => {
  it('matches llms.txt / robots.txt / sitemap.xml / .preflight.yml / .preflight.json', () => {
    expect(isMetaDocFile('public/llms.txt')).toBe(true);
    expect(isMetaDocFile('public/robots.txt')).toBe(true);
    expect(isMetaDocFile('public/sitemap.xml')).toBe(true);
    expect(isMetaDocFile('.preflight.yml')).toBe(true);
    expect(isMetaDocFile('.preflight.yaml')).toBe(true);
    expect(isMetaDocFile('.preflight.json')).toBe(true);
  });

  it('does NOT match user docs that share substrings', () => {
    expect(isMetaDocFile('docs/llms-internal.txt')).toBe(false);
    expect(isMetaDocFile('robots-config.json')).toBe(false);
    expect(isMetaDocFile('public/myrobots.txt')).toBe(false);
  });

  it('returns false on null / empty', () => {
    expect(isMetaDocFile('')).toBe(false);
    expect(isMetaDocFile(null)).toBe(false);
  });
});

describe('shouldScanFile', () => {
  it('includes common source extensions', () => {
    expect(shouldScanFile('src/foo.js')).toBe(true);
    expect(shouldScanFile('src/foo.ts')).toBe(true);
    expect(shouldScanFile('src/foo.jsx')).toBe(true);
    expect(shouldScanFile('app.py')).toBe(true);
    expect(shouldScanFile('main.go')).toBe(true);
    expect(shouldScanFile('index.html')).toBe(true);
  });

  it('includes the discoverability + Pre-Flight config files', () => {
    expect(shouldScanFile('public/llms.txt')).toBe(true);
    expect(shouldScanFile('public/robots.txt')).toBe(true);
    expect(shouldScanFile('public/sitemap.xml')).toBe(true);
    expect(shouldScanFile('.preflight.yml')).toBe(true);
  });

  it('includes AI-tool configs (cursor / windsurf / CLAUDE.md / MCP)', () => {
    expect(shouldScanFile('.cursorrules')).toBe(true);
    expect(shouldScanFile('.cursor/rules/foo.md')).toBe(true);
    expect(shouldScanFile('.windsurfrules')).toBe(true);
    expect(shouldScanFile('CLAUDE.md')).toBe(true);
    expect(shouldScanFile('.mcp.json')).toBe(true);
    expect(shouldScanFile('mcp.json')).toBe(true);
    expect(shouldScanFile('claude_desktop_config.json')).toBe(true);
  });

  it('includes Mini Shai-Hulud post-infection drop-files in the scan set', () => {
    expect(shouldScanFile('.claude/router_runtime.js')).toBe(true);
    expect(shouldScanFile('.claude/setup.mjs')).toBe(true);
    expect(shouldScanFile('.vscode/setup.mjs')).toBe(true);
    expect(shouldScanFile('.claude/settings.json')).toBe(true);
    expect(shouldScanFile('.vscode/tasks.json')).toBe(true);
    expect(shouldScanFile('tanstack_runner.js')).toBe(true);
    expect(shouldScanFile('router_init.js')).toBe(true);
  });

  it('excludes node_modules / .git / dist / build / .next', () => {
    expect(shouldScanFile('node_modules/foo/index.js')).toBe(false);
    expect(shouldScanFile('.git/HEAD')).toBe(false);
    expect(shouldScanFile('dist/index.js')).toBe(false);
    expect(shouldScanFile('build/main.js')).toBe(false);
    expect(shouldScanFile('.next/cache/foo.js')).toBe(false);
  });

  it('returns false for files with no extension match', () => {
    expect(shouldScanFile('README')).toBe(false);
    expect(shouldScanFile('LICENSE')).toBe(false);
    expect(shouldScanFile('src/foo.unknown')).toBe(false);
  });
});

describe('FILE_INCLUDE / FILE_EXCLUDE shapes', () => {
  it('exposes arrays of RegExp', () => {
    expect(Array.isArray(FILE_INCLUDE)).toBe(true);
    expect(Array.isArray(FILE_EXCLUDE)).toBe(true);
    expect(FILE_INCLUDE.every((p) => p instanceof RegExp)).toBe(true);
    expect(FILE_EXCLUDE.every((p) => p instanceof RegExp)).toBe(true);
  });

  it('FILE_INCLUDE is non-empty (probes need targets)', () => {
    expect(FILE_INCLUDE.length).toBeGreaterThan(10);
  });
});

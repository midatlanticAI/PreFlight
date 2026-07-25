// Unit tests for the file-filter module. Probe behavior already exercises these helpers
// indirectly, but explicit tests guard against regressions where the predicates silently
// stop covering paths we expect them to skip.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  isTestFile,
  isScannerSelfSource,
  setSelfScanMode,
  isSelfScanMode,
  isMetaDocFile,
  isEnvTemplateFile,
  shouldScanFile,
  FILE_INCLUDE,
  FILE_EXCLUDE,
} from '../lib/file-filter.js';

describe('isEnvTemplateFile', () => {
  it.each([
    '.env.example',
    '.env-example',
    '.env_example',
    '.env.sample',
    '.env.template',
    '.env.dist',
    '.env.defaults',
    '.env.tpl',
    '.env.placeholder',
    '.env.local.example',
    'env.example',
    'config/.env-example',
  ])('treats %s as a template', (p) => {
    expect(isEnvTemplateFile(p)).toBe(true);
  });

  it.each(['.env', '.env.local', '.env.production', 'app/.env', 'envoy.yaml', '', null])(
    'does not treat %s as a template',
    (p) => {
      expect(isEnvTemplateFile(p)).toBe(false);
    }
  );
});

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

  // FP triage 2026-07 (gemini-cli-fork scan): compound test-dir names and
  // eval fixtures were invisible to the literal alternation.
  it('matches compound test/fixture dirs and eval files', () => {
    expect(isTestFile('integration-tests/hooks-system.test.ts')).toBe(true);
    expect(isTestFile('integration-tests/test-fixtures/dynamic.html')).toBe(true);
    expect(isTestFile('memory-tests/case.ts')).toBe(true);
    expect(isTestFile('perf-tests/bench.ts')).toBe(true);
    expect(isTestFile('evals/calendar-all-day.eval.ts')).toBe(true);
    expect(isTestFile('src/foo/fixtures/sample.html')).toBe(true);
    expect(isTestFile('src/__mocks__/api.js')).toBe(true);
  });

  it('does NOT match production source paths', () => {
    expect(isTestFile('src/App.jsx')).toBe(false);
    expect(isTestFile('src/lib/probes.js')).toBe(false);
    expect(isTestFile('package.json')).toBe(false);
    // "contests" is not "tests"; compound match requires a -_ separator
    expect(isTestFile('src/contests/leaderboard.js')).toBe(false);
    expect(isTestFile('src/attests/verify.js')).toBe(false);
  });

  it('returns false on null / empty', () => {
    expect(isTestFile('')).toBe(false);
    expect(isTestFile(null)).toBe(false);
    expect(isTestFile(undefined)).toBe(false);
  });
});

// The scanner-self-source exclusions are identity-based as of 2026-07: they
// apply only when a scan declares itself to be PreFlight scanning PreFlight.
// The block below asserts the exclusion list; the block after it asserts the
// default, which is the part that protects users.
describe('isScannerSelfSource (self-scan mode ON)', () => {
  beforeEach(() => setSelfScanMode(true));
  afterEach(() => setSelfScanMode(false));

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

  it('includes the discoverability + PreFlight config files', () => {
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

// --- The user-facing guarantee this refactor exists to create ---------------
//
// Before 2026-07 the exclusions were applied on path alone, to every scan. A
// user whose project happened to contain src/components/settings/, src/learn/,
// src/lib/probes/ or a built dist/ had those files silently skipped by every
// pattern-matching probe, including the Secret Scanner and Auth Weakness. A
// settings directory is where API keys and auth config live, so this was a
// false negative in one of the highest-value places in a typical app.
describe('isScannerSelfSource defaults OFF so user scans are never blinded', () => {
  it('does not skip any scanner-shaped path when self-scan mode is off', () => {
    for (const p of [
      'src/lib/probes.js',
      'src/lib/probes/supply-chain.js',
      'src/lib/threat-intel.js',
      'src/lib/file-filter.js',
      'src/lib/stable-id.js',
      'src/lib/breakers.js',
      'src/learn/onboarding.js',
      'src/components/learn/Course.jsx',
      'src/components/settings/Account.jsx',
      'dist/app.js',
    ]) {
      expect(isScannerSelfSource(p)).toBe(false);
    }
  });

  it('reports its own mode', () => {
    expect(isSelfScanMode()).toBe(false);
    setSelfScanMode(true);
    expect(isSelfScanMode()).toBe(true);
    setSelfScanMode(false);
    expect(isSelfScanMode()).toBe(false);
  });
});

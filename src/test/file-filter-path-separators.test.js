// Directory rules have to survive native Windows paths.
//
// Every directory rule in file-filter.js is written with `/`, because that is
// what a repo path looks like. A caller that walks the filesystem with
// path.join on Windows hands over backslashes, and before 2026-07-26 that made
// all of them silently miss: not the test directories, not the fixture
// directories, not the vendor directories, not the scanner's own source.
// shouldScanFile still returned true, so the file was scanned with every
// protection switched off and no signal that anything had been skipped.
//
// The visible symptom, reported by an outside review of a real scan: a project
// with a genuine SSRF test suite scoring worse than one with no tests at all.
// The fixtures exist to prove the app blocks 169.254.169.254 and
// 127.0.0.1.evil.com. Strip the exclusion and they read as production code
// reaching for link-local metadata over plain HTTP, so writing the test suite
// lowers the score.
//
// PreFlight is developed on Windows, which is what makes this worth a
// dedicated file: the wrong behaviour is one path.join away at every call site.

import { describe, it, expect } from 'vitest';
import {
  isTestFile,
  isMetaDocFile,
  isEnvTemplateFile,
  isScannerSelfSource,
  shouldScanFile,
  setSelfScanMode,
} from '../lib/file-filter.js';
import { probeCodeQuality } from '../lib/probes/quality.js';

const bothWays = (posix) => [posix, posix.replace(/\//g, '\\')];

describe('isTestFile is separator-agnostic', () => {
  it.each([
    'test/security.mjs',
    'tests/adversarial.mjs',
    'src/__tests__/thing.js',
    'packages/app/test-fixtures/payload.js',
    'e2e/checkout.spec.ts',
    'integration-tests/api.js',
  ])('%s matches in both spellings', (posix) => {
    const [p, win] = bothWays(posix);
    expect(isTestFile(p)).toBe(true);
    expect(isTestFile(win)).toBe(true);
  });

  it('handles a leading ./ and .\\ prefix', () => {
    expect(isTestFile('./test/a.js')).toBe(true);
    expect(isTestFile('.\\test\\a.js')).toBe(true);
  });

  it('handles an absolute Windows path', () => {
    expect(isTestFile('C:\\Users\\dev\\proj\\test\\security.mjs')).toBe(true);
  });

  it('still says no to a source file in either spelling', () => {
    expect(isTestFile('src/lib/app.js')).toBe(false);
    expect(isTestFile('src\\lib\\app.js')).toBe(false);
  });
});

describe('the other path predicates too', () => {
  it('isMetaDocFile', () => {
    expect(isMetaDocFile('public\\robots.txt')).toBe(true);
    expect(isMetaDocFile('public/robots.txt')).toBe(true);
  });

  it('isEnvTemplateFile', () => {
    expect(isEnvTemplateFile('config\\.env.example')).toBe(true);
    expect(isEnvTemplateFile('config/.env.example')).toBe(true);
  });

  it('isScannerSelfSource, which gates the dogfood run', () => {
    setSelfScanMode(true);
    try {
      expect(isScannerSelfSource('src\\lib\\probes\\web.js')).toBe(true);
      expect(isScannerSelfSource('src/lib/probes/web.js')).toBe(true);
    } finally {
      setSelfScanMode(false);
    }
  });

  it('shouldScanFile excludes vendor directories in both spellings', () => {
    expect(shouldScanFile('node_modules/pkg/index.js')).toBe(false);
    expect(shouldScanFile('node_modules\\pkg\\index.js')).toBe(false);
  });
});

describe('the symptom that surfaced it', () => {
  // A probe that guards on isTestFile has to stay quiet on a test file no
  // matter which separator the harness used to build the path.
  const suite = `// proves the SSRF guard rejects link-local metadata
const BLOCKED = ['http://169.254.169.254/latest/meta-data/', 'http://127.0.0.1.evil.com/'];
export async function run() {
  for (const url of BLOCKED) {
    await fetch('/api/preview/target?u=' + encodeURIComponent(url));
  }
}`;

  it('stays quiet on a test file given a POSIX path', () => {
    expect(probeCodeQuality([{ path: 'test/security.mjs', content: suite }])).toEqual([]);
  });

  it('stays quiet on the same file given a Windows path', () => {
    expect(probeCodeQuality([{ path: 'test\\security.mjs', content: suite }])).toEqual([]);
  });
});

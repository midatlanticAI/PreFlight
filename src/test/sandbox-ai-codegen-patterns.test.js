// src/test/sandbox-ai-codegen-patterns.test.js
//
// AI-codegen and tech-debt pattern coverage for the sandbox runner. Two
// sections:
//
//   1) "Currently caught" — patterns we already detect via the wired v0.4
//      probes (probeCodeQuality, probeAICodeSmells, probeAuthWeakness, plus
//      probeSecrets which is on the same probes.js surface). These are
//      regular it() assertions; a regression in any one of them fails CI.
//
//   2) "Planned coverage (drift detectors)" — patterns from the Phase B
//      Top 10 in preflight-v2-spec.md §1.6 that we intend to catch but
//      don't yet. Each test asserts the *current* state (no finding fires)
//      using it.fails(). it.fails passes today because the inner assertion
//      fails as expected. The moment a future probe starts catching the
//      pattern, the inner assertion will pass and it.fails will FAIL,
//      forcing a maintainer to convert the test to a regular it() with
//      the new positive assertion. This pattern doubles as a forward-
//      pointer for which v2 probes are queued and gives us an automated
//      reminder when one quietly lands via a side effect of another probe.
//
// The point of this file: when we come back to extend the sandbox runner
// with v2 probes, the test surface already documents what should fire.

import { describe, it, expect } from 'vitest';
import { runSandboxScan } from '../lib/sandbox/runner.js';

// Quick predicate: did the runner emit a finding whose title or evidence
// includes the given pattern (case-insensitive)?
const has = (findings, pattern) =>
  findings.some(
    (f) =>
      new RegExp(pattern, 'i').test(f.title || '') ||
      new RegExp(pattern, 'i').test(f.evidence || '')
  );

// ============================================================================
// SECTION 1 — Currently caught (regression suite)
// ============================================================================

describe('AI-codegen patterns: currently caught by the sandbox runner', () => {
  it('eval() literal', () => {
    const findings = runSandboxScan(`const out = eval("1 + 1");`);
    expect(has(findings, 'eval')).toBe(true);
  });

  it('dangerouslySetInnerHTML in JSX', () => {
    const code = `function X({ html }) { return <div dangerouslySetInnerHTML={{ __html: html }} />; }`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'dangerouslysetinnerhtml')).toBe(true);
  });

  it('JWT algorithm "none"', () => {
    const code = `jwt.sign(payload, '', { algorithm: 'none' });`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'algorithm')).toBe(true);
  });

  it('console.log left in non-test code (tech-debt low/info finding)', () => {
    // probeCodeQuality flags console statements; verify at least one is
    // surfaced. Single occurrence is low/info; the gate's tolerance for
    // info findings is documented in self-audit.test.js.
    const code = `function greet() { console.log('hello'); return 'hello'; }`;
    const findings = runSandboxScan(code);
    expect(findings.some((f) => /console/i.test(f.title))).toBe(true);
  });
});

// ============================================================================
// SECTION 2 — Planned coverage (Phase B Top 10 drift detectors)
// ============================================================================
//
// Each it.fails asserts the CURRENT state: the runner does NOT yet emit a
// matching finding. When a probe lands that catches the pattern, the inner
// assertion stops failing and it.fails reports a failure, surfacing the new
// coverage so the test gets converted to a regular it().

describe('AI-codegen patterns: planned coverage (Phase B Top 10 drift detectors)', () => {
  // Item 4 from spec §1.6 — top of the React hygiene family per StackInsight.
  it.fails('useEffect addEventListener with no cleanup return is not yet caught', () => {
    const code = `useEffect(() => { window.addEventListener('resize', onResize); }, []);`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'cleanup|removeEventListener|listener')).toBe(true);
  });

  // Item 5 — fetch without r.ok check.
  it.fails('fetch().then(r => r.json()) with no r.ok check is not yet caught', () => {
    const code = `fetch('/api/x').then((r) => r.json()).then(setData);`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'r\\.ok|response\\.ok|status check')).toBe(true);
  });

  // Item 7 — setState in render body.
  it.fails('setState called synchronously in component body is not yet caught', () => {
    const code = `function C({ user }) {
      const [name, setName] = useState('');
      setName(user.name);
      return null;
    }`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'setstate|set state|state-in-render')).toBe(true);
  });

  // Item 9 — full lodash import for a single helper.
  it.fails('full lodash import is not yet caught', () => {
    const code = `import _ from 'lodash'; const a = _.cloneDeep(x);`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'lodash|tree.?shake|bundle')).toBe(true);
  });

  // Item 10 — @ts-ignore without explanation.
  it.fails('@ts-ignore without an explanatory comment is not yet caught', () => {
    const code = `// @ts-ignore\nconst x: number = 'hi';`;
    const findings = runSandboxScan(code);
    expect(has(findings, '@?ts-ignore|ts-expect-error')).toBe(true);
  });

  // Item 2 — broad catch that swallows.
  it.fails('try/catch with only console.log of the error is not yet caught', () => {
    const code = `try { doThing(); } catch (e) { console.log(e); }`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'catch|swallow|broad')).toBe(true);
  });

  // Item 3 — hallucinated npm import.
  it.fails('import from an unknown npm package name is not yet caught', () => {
    const code = `import { magic } from 'totally-not-real-npm-package-xyz-12345';`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'hallucinat|unknown.?package|slopsquat')).toBe(true);
  });

  // Item 8 — img with no alt.
  it.fails('<img> JSX without an alt attribute is not yet caught', () => {
    const code = `function Pic({ src }) { return <img src={src} />; }`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'alt|accessib|a11y')).toBe(true);
  });
});

// ============================================================================
// SECTION 3 — General tech-debt drift detectors
// ============================================================================

describe('General tech-debt patterns: planned coverage', () => {
  it.fails('floating promise from a locally declared async function is not yet caught', () => {
    const code = `async function save() {}; save();`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'floating.?promise|unhandled.?promise|await|void')).toBe(true);
  });

  it.fails('await inside a for loop with IO is not yet caught (N+1)', () => {
    const code = `for (const id of ids) { const r = await fetchOne(id); results.push(r); }`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'n\\+1|await.?in.?loop|promise\\.all')).toBe(true);
  });

  it.fails('Promise.all over unbounded user input is not yet caught', () => {
    const code = `await Promise.all(userIds.map((id) => fetchOne(id)));`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'promise\\.all|unbounded|concurren')).toBe(true);
  });

  it.fails('variant/backup file naming (component_v2.tsx, page-old.jsx) is not yet caught', () => {
    // The runner sees only the file content, not the file name; the v7
    // version of this probe will need a filename input. This drift detector
    // documents that gap. When the runner takes a filename param, this
    // test gets converted to a positive assertion.
    const code = `// see component.tsx for the canonical version\nexport default function ComponentV2() {}`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'variant|backup|old|v2')).toBe(true);
  });

  it.fails('eslint-disable comment without justification is not yet caught', () => {
    const code = `// eslint-disable-next-line\nconst x = unsafeThing();`;
    const findings = runSandboxScan(code);
    expect(has(findings, 'eslint.?disable|justification')).toBe(true);
  });
});

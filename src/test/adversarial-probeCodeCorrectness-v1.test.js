// Adversarial RECALL tests for probeCodeCorrectness.
// Written from the spec in src/learn/patterns/code-correctness.md.
// No implementation files were read while authoring this suite.

import { describe, it, expect } from 'vitest';
import { probeCodeCorrectness } from '../lib/probes.js';

// ---------- helpers ----------

const FILE = (path, content) => ({ path, content });

/** Run the probe and return findings (always an array). */
const run = (files) => {
  const out = probeCodeCorrectness(files);
  return Array.isArray(out) ? out : [];
};

/** Filter findings to those that reference a given identifier in evidence. */
const mentioning = (findings, name) =>
  findings.filter((f) => f && typeof f.evidence === 'string' && f.evidence.includes(name));

const CANONICAL_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

// =====================================================================
// POSITIVE: probe MUST fire on these (undeclared identifier references)
// =====================================================================

describe('positive: bare undeclared identifier references fire', () => {
  it('flags a bare undeclared identifier used as a statement', () => {
    const f = run([FILE('a.js', 'totallyUndeclaredName;\n')]);
    expect(mentioning(f, 'totallyUndeclaredName').length).toBeGreaterThan(0);
  });

  it('flags a typo of console (concole.log) when only console is a global', () => {
    const src = "concole.log('hi');\n";
    const f = run([FILE('typo.js', src)]);
    expect(mentioning(f, 'concole').length).toBeGreaterThan(0);
  });

  it('flags a function call to an undeclared name', () => {
    const f = run([FILE('call.js', 'doTheThing(1, 2, 3);\n')]);
    expect(mentioning(f, 'doTheThing').length).toBeGreaterThan(0);
  });

  it('flags an undeclared identifier on the right-hand side of an assignment', () => {
    const src = 'let x;\nx = mysteryValue;\n';
    const f = run([FILE('rhs.js', src)]);
    expect(mentioning(f, 'mysteryValue').length).toBeGreaterThan(0);
  });

  it('flags an undeclared identifier used as the predicate of an if', () => {
    const src = 'if (notDefinedAnywhere) { }\n';
    const f = run([FILE('if.js', src)]);
    expect(mentioning(f, 'notDefinedAnywhere').length).toBeGreaterThan(0);
  });

  it('flags an undeclared identifier nested in a callback', () => {
    const src = '[1,2,3].map((n) => transformer(n));\n';
    const f = run([FILE('cb.js', src)]);
    expect(mentioning(f, 'transformer').length).toBeGreaterThan(0);
  });

  it('flags an undeclared identifier as the object of a member expression', () => {
    const src = 'const z = ghostObject.prop;\n';
    const f = run([FILE('mem.js', src)]);
    expect(mentioning(f, 'ghostObject').length).toBeGreaterThan(0);
  });

  it('flags an undeclared uppercase JSX component reference', () => {
    // No React import or declaration of GhostComponent.
    const src = 'function App() { return <GhostComponent />; }\nexport default App;\n';
    const f = run([FILE('App.jsx', src)]);
    expect(mentioning(f, 'GhostComponent').length).toBeGreaterThan(0);
  });

  it('flags an undeclared identifier passed as an argument', () => {
    const src = 'console.log(secretToken);\n';
    const f = run([FILE('arg.js', src)]);
    expect(mentioning(f, 'secretToken').length).toBeGreaterThan(0);
  });

  it('flags an undeclared identifier used inside a template literal expression', () => {
    const src = 'const s = `value=${missingThing}`;\n';
    const f = run([FILE('tpl.js', src)]);
    expect(mentioning(f, 'missingThing').length).toBeGreaterThan(0);
  });

  it('flags multiple distinct undeclared references in the same file', () => {
    const src = 'foo(); bar(); baz();\n';
    const f = run([FILE('many.js', src)]);
    // At least one of these undeclared names must surface.
    const hits =
      mentioning(f, 'foo').length + mentioning(f, 'bar').length + mentioning(f, 'baz').length;
    expect(hits).toBeGreaterThan(0);
  });

  it('flags an undeclared identifier in a return statement', () => {
    const src = 'function go() { return phantomValue; }\n';
    const f = run([FILE('ret.js', src)]);
    expect(mentioning(f, 'phantomValue').length).toBeGreaterThan(0);
  });

  it('flags an undeclared identifier in a binary expression', () => {
    const src = 'const total = 1 + missingAddend;\n';
    const f = run([FILE('bin.js', src)]);
    expect(mentioning(f, 'missingAddend').length).toBeGreaterThan(0);
  });

  it('flags an undeclared identifier used in throw', () => {
    const src = 'function bad() { throw mysteryError; }\n';
    const f = run([FILE('throw.js', src)]);
    expect(mentioning(f, 'mysteryError').length).toBeGreaterThan(0);
  });
});

// =====================================================================
// NEGATIVE: probe MUST NOT fire on legitimate bindings + allowed globals
// =====================================================================

describe('negative: declared bindings are recognized', () => {
  it('does not flag a const binding used later', () => {
    const src = 'const greeting = "hi";\nconsole.log(greeting);\n';
    const f = run([FILE('const.js', src)]);
    expect(mentioning(f, 'greeting')).toHaveLength(0);
  });

  it('does not flag a let binding used later', () => {
    const src = 'let counter = 0;\ncounter += 1;\n';
    const f = run([FILE('let.js', src)]);
    expect(mentioning(f, 'counter')).toHaveLength(0);
  });

  it('does not flag a var binding used later', () => {
    const src = 'var legacy = 1;\nconsole.log(legacy);\n';
    const f = run([FILE('var.js', src)]);
    expect(mentioning(f, 'legacy')).toHaveLength(0);
  });

  it('does not flag a function declaration referenced elsewhere', () => {
    const src = 'function helper() { return 1; }\nhelper();\n';
    const f = run([FILE('fn.js', src)]);
    expect(mentioning(f, 'helper')).toHaveLength(0);
  });

  it('does not flag a class declaration referenced elsewhere', () => {
    const src = 'class Widget {}\nconst w = new Widget();\nconsole.log(w);\n';
    const f = run([FILE('class.js', src)]);
    expect(mentioning(f, 'Widget')).toHaveLength(0);
  });

  it('does not flag a function parameter used inside the body', () => {
    const src = 'function id(x) { return x; }\nid(1);\n';
    const f = run([FILE('param.js', src)]);
    expect(mentioning(f, 'x')).toHaveLength(0);
  });

  it('does not flag an imported named binding used later', () => {
    const src = "import { useState } from 'react';\nuseState(0);\n";
    const f = run([FILE('imp.js', src)]);
    expect(mentioning(f, 'useState')).toHaveLength(0);
  });

  it('does not flag a default-imported binding used later', () => {
    const src = "import React from 'react';\nconsole.log(React);\n";
    const f = run([FILE('def.js', src)]);
    expect(mentioning(f, 'React')).toHaveLength(0);
  });

  it('does not flag a namespace import used later', () => {
    const src = "import * as utils from './u.js';\nutils.go();\n";
    const f = run([FILE('ns.js', src)]);
    expect(mentioning(f, 'utils')).toHaveLength(0);
  });

  it('does not flag identifiers introduced by object destructuring', () => {
    const src = 'const obj = { a: 1, b: 2 };\nconst { a, b } = obj;\nconsole.log(a, b);\n';
    const f = run([FILE('dest-obj.js', src)]);
    expect(mentioning(f, 'a')).toHaveLength(0);
    expect(mentioning(f, 'b')).toHaveLength(0);
  });

  it('does not flag identifiers introduced by array destructuring', () => {
    const src = 'const arr = [1, 2];\nconst [first, second] = arr;\nconsole.log(first, second);\n';
    const f = run([FILE('dest-arr.js', src)]);
    expect(mentioning(f, 'first')).toHaveLength(0);
    expect(mentioning(f, 'second')).toHaveLength(0);
  });

  it('does not flag a catch clause parameter used in the catch body', () => {
    const src = 'try { JSON.parse("{"); } catch (err) { console.log(err.message); }\n';
    const f = run([FILE('catch.js', src)]);
    expect(mentioning(f, 'err')).toHaveLength(0);
  });

  it('does not flag a re-export source identifier', () => {
    const src = "export { foo } from './x.js';\n";
    const f = run([FILE('reexport.js', src)]);
    expect(mentioning(f, 'foo')).toHaveLength(0);
  });
});

describe('negative: built-in globals are recognized', () => {
  const builtins = [
    'console',
    'Math',
    'JSON',
    'Date',
    'Promise',
    'Symbol',
    'Proxy',
    'Reflect',
    'Object',
    'Array',
    'String',
    'Number',
    'Boolean',
  ];

  it.each(builtins)('does not flag built-in global %s', (name) => {
    const src = `const x = ${name};\nconsole.log(x);\n`;
    const f = run([FILE(`b-${name}.js`, src)]);
    // Filter to findings whose evidence/title literally contains this name as a bare reference.
    const hits = f.filter(
      (finding) =>
        typeof finding.evidence === 'string' &&
        // strict-ish: must be the exact bare name flagged
        new RegExp(`\\b${name}\\b`).test(finding.evidence) &&
        // and not the `x` binding
        !/\bx\b/.test(finding.title || '')
    );
    // We assert the well-known global was not surfaced as undeclared.
    // (Other findings unrelated to `name` are tolerated.)
    expect(hits.filter((h) => (h.title || '').includes(name))).toHaveLength(0);
  });
});

describe('negative: browser globals are recognized', () => {
  const browser = [
    'window',
    'document',
    'navigator',
    'localStorage',
    'sessionStorage',
    'fetch',
    'URL',
    'URLSearchParams',
    'FormData',
    'Headers',
    'Request',
    'Response',
    'Blob',
    'File',
    'FileReader',
    'WebSocket',
    'EventSource',
    'IntersectionObserver',
    'MutationObserver',
    'ResizeObserver',
    'AbortController',
  ];

  it.each(browser)('does not flag browser global %s', (name) => {
    const src = `const x = ${name};\nconsole.log(x);\n`;
    const f = run([FILE(`br-${name}.js`, src)]);
    const titled = f.filter((finding) => (finding.title || '').includes(name));
    expect(titled).toHaveLength(0);
  });
});

describe('negative: Node globals are recognized', () => {
  const node = [
    'process',
    'Buffer',
    '__dirname',
    '__filename',
    'require',
    'module',
    'exports',
    'global',
    'globalThis',
    'setImmediate',
    'clearImmediate',
  ];

  it.each(node)('does not flag Node global %s', (name) => {
    const src = `const x = ${name};\nconsole.log(x);\n`;
    const f = run([FILE(`n-${name}.js`, src)]);
    const titled = f.filter((finding) => (finding.title || '').includes(name));
    expect(titled).toHaveLength(0);
  });
});

describe('negative: test runner globals are recognized', () => {
  const runners = [
    'describe',
    'it',
    'test',
    'expect',
    'beforeAll',
    'afterAll',
    'beforeEach',
    'afterEach',
    'vi',
  ];

  it.each(runners)('does not flag test runner global %s', (name) => {
    const src = `${name};\n`;
    const f = run([FILE(`t-${name}.js`, src)]);
    const titled = f.filter((finding) => (finding.title || '').includes(name));
    expect(titled).toHaveLength(0);
  });
});

describe('negative: React is recognized when JSX appears', () => {
  it('does not flag bare React reference in a file that contains JSX', () => {
    // No explicit React import; JSX should cause React to be allowed.
    const src = 'function App() { return <div>hi</div>; }\nexport default App;\n';
    const f = run([FILE('JsxReact.jsx', src)]);
    const titled = f.filter((finding) => (finding.title || '').includes('React'));
    expect(titled).toHaveLength(0);
  });
});

// =====================================================================
// STRUCTURAL: finding shape, severity set, TS skip, JSX intrinsics
// =====================================================================

describe('structural: finding shape conformance', () => {
  it('every finding has the expected probe identity and fields', () => {
    const f = run([FILE('shape.js', 'undeclaredHere;\n')]);
    expect(f.length).toBeGreaterThan(0);
    for (const finding of f) {
      expect(finding.probe).toBe('Code Correctness');
      expect(typeof finding.id).toBe('string');
      expect(finding.id.length).toBeGreaterThan(0);
      expect(typeof finding.title).toBe('string');
      expect(finding.title.length).toBeGreaterThan(0);
      expect(CANONICAL_SEVERITIES.has(String(finding.severity).toLowerCase())).toBe(true);
      expect(typeof finding.category).toBe('string');
      expect(typeof finding.cwe).toBe('string');
      expect(finding.cwe.length).toBeGreaterThan(0);
      expect(finding.file).toBe('shape.js');
      expect(typeof finding.line).toBe('number');
      expect(finding.line).toBeGreaterThan(0);
      expect(typeof finding.evidence).toBe('string');
      expect(finding.evidence.length).toBeGreaterThan(0);
      expect(typeof finding.remediation).toBe('string');
      expect(finding.remediation.length).toBeGreaterThan(0);
    }
  });
});

describe('structural: TypeScript files are skipped in v1', () => {
  it('returns no findings for a .ts file even with obviously undeclared refs', () => {
    const src = 'const x: number = mysteryTSName;\n';
    const f = run([FILE('skip.ts', src)]);
    expect(mentioning(f, 'mysteryTSName')).toHaveLength(0);
  });

  it('returns no findings for a .tsx file even with obviously undeclared refs', () => {
    const src = 'const x: number = mysteryTSXName;\n';
    const f = run([FILE('skip.tsx', src)]);
    expect(mentioning(f, 'mysteryTSXName')).toHaveLength(0);
  });
});

describe('structural: JSX intrinsic lowercase tags are not checked as identifiers', () => {
  const lowers = ['div', 'span', 'input'];
  it.each(lowers)('does not flag intrinsic <%s>', (tag) => {
    const src = `function App() { return <${tag} />; }\nexport default App;\n`;
    const f = run([FILE(`I-${tag}.jsx`, src)]);
    const titled = f.filter((finding) => (finding.title || '').includes(tag));
    expect(titled).toHaveLength(0);
  });
});

// =====================================================================
// EDGE CASES called out by the spec
// =====================================================================

describe('edge cases the spec pins down', () => {
  it('does not flag `meta` in `import.meta.url`', () => {
    const src = 'const u = import.meta.url;\nconsole.log(u);\n';
    const f = run([FILE('meta1.js', src)]);
    const titled = f.filter((finding) => (finding.title || '').includes('meta'));
    expect(titled).toHaveLength(0);
  });

  it('does not flag `meta` in `import.meta.env.VITE_FOO`', () => {
    const src = 'const v = import.meta.env.VITE_FOO;\nconsole.log(v);\n';
    const f = run([FILE('meta2.js', src)]);
    const titled = f.filter((finding) => (finding.title || '').includes('meta'));
    expect(titled).toHaveLength(0);
  });

  it('flags an undeclared computed-property key (obj[someVar])', () => {
    const src = 'const obj = {};\nconst v = obj[someVar];\nconsole.log(v);\n';
    const f = run([FILE('comp.js', src)]);
    expect(mentioning(f, 'someVar').length).toBeGreaterThan(0);
  });

  it('does not flag the parameter of an implicit-return arrow', () => {
    const src = 'const f = (x) => x;\nconsole.log(f(1));\n';
    const f = run([FILE('arrow.js', src)]);
    expect(mentioning(f, 'x')).toHaveLength(0);
  });
});

// =====================================================================
// Ambiguous corners — spec does not explicitly pin these down.
// Documented here as constraint-tests; loosen assertions to "the probe
// returns an array and does not crash".
// =====================================================================

describe('edge cases the spec does not pin down', () => {
  it('handles an empty input array without throwing', () => {
    // Spec does not say what an empty input returns; require: array, no throw.
    const f = run([]);
    expect(Array.isArray(f)).toBe(true);
  });

  it('handles a file with empty content without throwing', () => {
    const f = run([FILE('empty.js', '')]);
    expect(Array.isArray(f)).toBe(true);
  });

  it('handles a syntactically-broken file without throwing', () => {
    // Spec mentions acorn parsing; does not pin down recovery behavior.
    const f = run([FILE('broken.js', 'function (((')]);
    expect(Array.isArray(f)).toBe(true);
  });

  it('handles a .mjs file (spec lists .mjs as covered)', () => {
    const f = run([FILE('m.mjs', 'mysteryMJS;\n')]);
    // Should at least return an array. Whether it fires is implied by spec.
    expect(Array.isArray(f)).toBe(true);
  });

  it('handles a .cjs file (spec lists .cjs as covered)', () => {
    const f = run([FILE('c.cjs', 'mysteryCJS;\n')]);
    expect(Array.isArray(f)).toBe(true);
  });

  it('does not double-flag the same undeclared name used many times (best-effort)', () => {
    // Spec does not commit to dedupe semantics; we just assert it does not return an absurd number.
    const src = Array.from({ length: 20 }, () => 'mysteryX();').join('\n') + '\n';
    const f = run([FILE('dup.js', src)]);
    const hits = mentioning(f, 'mysteryX');
    // Loose ceiling: should not blow up to e.g. 200 findings for 20 refs.
    expect(hits.length).toBeLessThanOrEqual(20);
  });
});

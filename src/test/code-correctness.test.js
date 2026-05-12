// Tests for probeCodeCorrectness — the AST-based undeclared-identifier check.
//
// Coverage goals:
//   - Reports a clearly-undeclared identifier
//   - Recognizes imports as declarations
//   - Recognizes var/let/const, function decls, class decls, params, destructuring
//   - Doesn't false-positive on built-ins / browser / Node / test globals
//   - Handles JSX (uppercase components are references, lowercase tags are intrinsic)
//   - Skips test files and scanner-self-source per file-filter rules
//   - Skips .ts/.tsx (v1 limitation)
//   - Doesn't crash on syntax errors

import { describe, it, expect } from 'vitest';
import { probeCodeCorrectness } from '../lib/probes/code-correctness.js';

const file = (path, content) => ({ path, content });

describe('probeCodeCorrectness', () => {
  it('flags a clearly-undeclared identifier', () => {
    const f = probeCodeCorrectness([file('src/app.js', `function go() { return urlHighlight; }`)]);
    expect(f).toHaveLength(1);
    expect(f[0].title).toMatch(/urlHighlight/);
    expect(f[0].probe).toBe('Code Correctness');
    expect(f[0].severity).toBe('low');
  });

  it('does NOT flag imported names', () => {
    const f = probeCodeCorrectness([file('src/app.js', `import { foo } from './lib.js'; foo();`)]);
    expect(f).toEqual([]);
  });

  it('does NOT flag default imports', () => {
    const f = probeCodeCorrectness([file('src/app.js', `import bar from './lib.js'; bar();`)]);
    expect(f).toEqual([]);
  });

  it('does NOT flag namespace imports', () => {
    const f = probeCodeCorrectness([
      file('src/app.js', `import * as utils from './lib.js'; utils.x();`),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag const/let/var declarations', () => {
    const f = probeCodeCorrectness([
      file('src/a.js', `const x = 1; let y = 2; var z = 3; console.log(x + y + z);`),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag function declaration name or params', () => {
    const f = probeCodeCorrectness([
      file('src/a.js', `function greet(name) { return name; } greet('hi');`),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag arrow function params', () => {
    const f = probeCodeCorrectness([file('src/a.js', `const fn = (x, y) => x + y; fn(1, 2);`)]);
    expect(f).toEqual([]);
  });

  it('does NOT flag class declaration', () => {
    const f = probeCodeCorrectness([file('src/a.js', `class Foo {} new Foo();`)]);
    expect(f).toEqual([]);
  });

  it('does NOT flag destructuring patterns', () => {
    const f = probeCodeCorrectness([
      file('src/a.js', `const { a, b: c, ...rest } = obj; const [x, y] = arr;`),
    ]);
    // `obj` and `arr` are undeclared, but the destructured names a/c/rest/x/y are bindings
    const declared = f.filter(
      (finding) => /a|c|rest|x|y/.test(finding.title) && !/obj|arr/.test(finding.title)
    );
    expect(declared.length).toBe(0);
  });

  it('does NOT flag catch clause binding', () => {
    const f = probeCodeCorrectness([file('src/a.js', `try {} catch (err) { console.log(err); }`)]);
    expect(f).toEqual([]);
  });

  it('does NOT flag built-in globals (console, Math, JSON, Promise)', () => {
    const f = probeCodeCorrectness([
      file('src/a.js', `console.log(Math.PI); JSON.stringify({}); Promise.resolve(1);`),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag browser globals (window, document, localStorage, fetch)', () => {
    const f = probeCodeCorrectness([
      file(
        'src/a.js',
        `window.location.href; document.title; localStorage.getItem('k'); fetch('/');`
      ),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag Node globals (process, Buffer, __dirname)', () => {
    const f = probeCodeCorrectness([
      file('src/a.js', `process.env.X; Buffer.from('a'); console.log(__dirname);`),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag test runner globals (describe, it, expect, vi)', () => {
    // Note: test files are skipped by isTestFile() anyway, but if non-test code references
    // these globals it shouldn't false-positive.
    const f = probeCodeCorrectness([
      file('src/maybe-shared.js', `function makeTest() { return [describe, it, expect, vi]; }`),
    ]);
    expect(f).toEqual([]);
  });

  it('handles JSX: uppercase tag is a reference (flagged if undeclared)', () => {
    const f = probeCodeCorrectness([
      file('src/c.jsx', `export default function App() { return <UndeclaredComponent />; }`),
    ]);
    expect(f.find((x) => x.title.includes('UndeclaredComponent'))).toBeDefined();
  });

  it('handles JSX: lowercase tag is intrinsic (NOT flagged)', () => {
    const f = probeCodeCorrectness([
      file('src/c.jsx', `export default function App() { return <div><span>hi</span></div>; }`),
    ]);
    expect(f).toEqual([]);
  });

  it('handles JSX: imported component is fine', () => {
    const f = probeCodeCorrectness([
      file(
        'src/c.jsx',
        `import Foo from './Foo.jsx';\nexport default function App() { return <Foo />; }`
      ),
    ]);
    expect(f).toEqual([]);
  });

  it('skips test files entirely (isTestFile rule)', () => {
    const f = probeCodeCorrectness([file('src/test/some.test.js', `definitelyUndeclaredThing();`)]);
    expect(f).toEqual([]);
  });

  it('skips .ts files in v1', () => {
    // .ts files have type annotations acorn doesn't parse; skip until v0.5 typescript-parser.
    const f = probeCodeCorrectness([file('src/foo.ts', `definitelyUndeclaredThing();`)]);
    expect(f).toEqual([]);
  });

  it('skips .tsx files in v1', () => {
    const f = probeCodeCorrectness([file('src/foo.tsx', `definitelyUndeclaredThing();`)]);
    expect(f).toEqual([]);
  });

  it('does NOT crash on syntax errors (returns no findings for that file)', () => {
    // acorn-loose fallback catches malformed JS; we just skip the file
    expect(() =>
      probeCodeCorrectness([file('src/broken.js', `const x = { a: 1, b: ,`)])
    ).not.toThrow();
  });

  it('reports each undeclared identifier only once per file (first location)', () => {
    const f = probeCodeCorrectness([
      file('src/a.js', `function go() {\n  return urlHighlight + urlHighlight + urlHighlight;\n}`),
    ]);
    const urlHits = f.filter((x) => x.title.includes('urlHighlight'));
    expect(urlHits.length).toBe(1);
    expect(urlHits[0].line).toBe(2);
  });

  it('does NOT flag the function name from a function expression assigned to const', () => {
    const f = probeCodeCorrectness([file('src/a.js', `const fn = function namedFn() {}; fn();`)]);
    expect(f).toEqual([]);
  });

  it('does NOT flag React when classic JSX runtime imports it', () => {
    const f = probeCodeCorrectness([
      file(
        'src/c.jsx',
        `import React from 'react';\nexport default function() { return <div />; }`
      ),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag React when JSX runtime makes it global (modern build)', () => {
    // React is in the GLOBALS allowlist for the modern JSX automatic runtime
    const f = probeCodeCorrectness([
      file(
        'src/c.jsx',
        `export default function() { return <React.Fragment><div/></React.Fragment>; }`
      ),
    ]);
    expect(f).toEqual([]);
  });
});

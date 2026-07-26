// F7 precision fixes from a real project scan, 2026-07.
//
// The scan reported 105 health findings on a working cockpit. Broken out, the
// number was inflated rather than earned:
//
//   33 repeated string literals, most of them HTTP header names and DOM ids
//   19 cyclomatic complexity, dominated by handlers that were charged for the
//      branches inside their own callbacks
//
// Both are precision bugs, not threshold arguments. Lowering a threshold would
// have hidden real findings alongside the noise; these fix the classification
// so the real ones survive.

import { describe, it, expect } from 'vitest';
import { probeAICodegenBloat } from '../lib/probes/v2/bloat.js';

const run = (content, path = 'src/a.js') => probeAICodegenBloat([{ path, content }]);
const titles = (fs) => fs.map((f) => f.title);
const magic = (content) => titles(run(content)).filter((t) => /is repeated/.test(t));
const complexity = (content) => run(content).filter((f) => /cyclomatic complexity/.test(f.title));

describe('magic strings: protocol constants are not magic values', () => {
  it('does not flag a repeated HTTP header name', () => {
    const src = [
      "a.setHeader('content-type', j);",
      "b.setHeader('content-type', j);",
      "c.setHeader('content-type', j);",
    ].join('\n');
    expect(magic(src)).toHaveLength(0);
  });

  it('does not flag a repeated custom x- header', () => {
    const src = [
      'send("x-atlan-token", t);',
      'send("x-atlan-token", t);',
      'send("x-atlan-token", t);',
    ].join('\n');
    expect(magic(src)).toHaveLength(0);
  });
});

describe('magic strings: markup references are not magic values', () => {
  it('does not flag an element id used through a DOM query', () => {
    const src = ["$('buildBtn').x();", "$('buildBtn').y();", "$('buildBtn').z();"].join('\n');
    expect(magic(src)).toHaveLength(0);
  });

  it('does not flag an id that reaches the DOM through a helper', () => {
    // The id is a selector at least once, which makes it an element name for
    // the whole file even where it is passed to addRow() or rowsOf().
    const src = [
      "addRow('fieldRows', FIELD_ROW);",
      "addRow('fieldRows', FIELD_ROW, f);",
      "const v = rowsOf('fieldRows');",
      "$('fieldRows').innerHTML = '';",
    ].join('\n');
    expect(magic(src)).toHaveLength(0);
  });

  it('does not flag a class name assigned via className', () => {
    const src = [
      "a.className = 'sessline';",
      "b.className = 'sessline';",
      "c.className = 'sessline' + extra;",
    ].join('\n');
    expect(magic(src)).toHaveLength(0);
  });

  it('still flags an app-defined storage key', () => {
    // This is the case the check exists for: the key is defined nowhere but in
    // these three literals, so a rename has to find all three.
    const src = [
      "const t = localStorage.getItem('atlanTemplate');",
      "localStorage.setItem('atlanTemplate', t);",
      "localStorage.removeItem('atlanTemplate');",
    ].join('\n');
    expect(magic(src)).toHaveLength(1);
  });

  it('still flags a repeated cookie name', () => {
    const src = [
      "const a = cookies.get('app_session_v2');",
      "const b = cookies.set('app_session_v2', t);",
      "const c = cookies.del('app_session_v2');",
    ].join('\n');
    expect(magic(src)).toHaveLength(1);
  });

  it('still flags a repeated app state value', () => {
    const src = [
      "if (run.status === 'halted-budget') a();",
      "if (job.status === 'halted-budget') b();",
      "set(x, 'halted-budget');",
    ].join('\n');
    expect(magic(src)).toHaveLength(1);
  });
});

describe('cyclomatic complexity: a function is not charged for its callbacks', () => {
  it('does not inherit branches nested deep inside a callback', () => {
    // The handler itself has one branch. Everything else belongs to the
    // callback, two levels down, where the previous implementation could not
    // see it was nested.
    const inner = Array.from({ length: 24 }, (_, i) => `      if (x === ${i}) run(${i});`).join(
      '\n'
    );
    const src = [
      'function handler(req, res) {',
      '  if (!req.ok) return;',
      '  load().then((rows) => {',
      '    rows.forEach((x) => {',
      inner,
      '    });',
      '  });',
      '}',
    ].join('\n');
    const found = complexity(src);
    expect(found.map((f) => f.title).join(' ')).not.toMatch(/"handler"/);
  });

  it('still charges the callback itself for its own branches', () => {
    const inner = Array.from({ length: 24 }, (_, i) => `    if (x === ${i}) run(${i});`).join('\n');
    const src = [
      'function handler() {',
      '  load().then(function inner(x) {',
      inner,
      '  });',
      '}',
    ].join('\n');
    expect(
      complexity(src)
        .map((f) => f.title)
        .join(' ')
    ).toMatch(/"inner"/);
  });

  it('still charges a genuinely tangled function', () => {
    const body = Array.from({ length: 20 }, (_, i) => `  if (a === ${i} && b) return ${i};`).join(
      '\n'
    );
    const src = `function tangled(a, b) {\n${body}\n  return 0;\n}`;
    expect(
      complexity(src)
        .map((f) => f.title)
        .join(' ')
    ).toMatch(/"tangled"/);
  });
});

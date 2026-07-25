/**
 * Adversarial RECALL suite for probeAICodegenBloat.
 *
 * Every test in this file is derived from the pattern page
 * `src/learn/patterns/ai-codegen-bloat.md`, which is the spec. The probe
 * implementation was deliberately not read while writing these tests.
 *
 * Spec promises under test ("What PreFlight looks for"):
 *   1. Backup / variant files by name: .backup. .old. .orig. -copy -v2 _final
 *   2. Commented-out code: ten or more consecutive comment lines that parse as code
 *   3. Assistant narration left in comments
 *   4. Functions over 100 lines, and functions whose cyclomatic complexity passes 10
 *   5. Pass-through wrappers
 *   6. Dead imports, and files carrying more than 20 imported bindings
 *   7. Repeated string literals (3+), skipping paths, URLs, sentence-shaped copy
 *   8. eslint-disable with no stated reason (same line or line above)
 *   9. TODO / FIXME with no ticket reference
 *
 * Spec promises of SILENCE:
 *   - Generic variable names (data, result, item) are never flagged
 *   - File length and stray console calls belong to the Code Quality probe
 *   - "this probe never rates them above medium"
 *
 * Positive fixtures are kept minimal on purpose: each one contains exactly one
 * spec-flaggable condition, so a non-empty result can only have come from the
 * condition under test.
 */

import { describe, it, expect } from 'vitest';
import { probeAICodegenBloat } from '../lib/probes.js';

// --- helpers ---------------------------------------------------------------

const one = (path, content) => probeAICodegenBloat([{ path, content }]);

const lineOf = (content, needle) => content.split('\n').findIndex((l) => l.includes(needle)) + 1;

/** A function body of `n` plain statement lines, no strings, no branches. */
const longFunction = (n) => {
  const body = Array.from({ length: n }, (_, i) => `  const step${i} = ${i} + 1;`).join('\n');
  return `export function buildReport(input) {\n${body}\n  return input;\n}\n`;
};

/** A function with `n` independent if-branches. McCabe complexity = n + 1. */
const branchyFunction = (n) => {
  const body = Array.from({ length: n }, (_, i) => `  if (input.flag${i}) { total += ${i}; }`).join(
    '\n'
  );
  return `export function score(input) {\n  let total = 0;\n${body}\n  return total;\n}\n`;
};

/** A file importing exactly `n` bindings, every one of them referenced. */
const importsFile = (n) => {
  const names = Array.from({ length: n }, (_, i) => `binding${i}`);
  const chunk = Math.ceil(n / 3);
  const groups = [names.slice(0, chunk), names.slice(chunk, chunk * 2), names.slice(chunk * 2)];
  const imports = groups
    .filter((g) => g.length > 0)
    .map((g, i) => `import { ${g.join(', ')} } from './toolkit-${i}.js';`)
    .join('\n');
  return `${imports}\nexport function useAll() {\n  return [${names.join(', ')}];\n}\n`;
};

const commentRun = (n) =>
  Array.from({ length: n }, (_, i) => `// const value${i} = compute(${i});`).join('\n');

const KITCHEN_SINK = [
  {
    path: 'src/components/Dashboard.backup.tsx',
    content: 'export const Dashboard = () => null;\n',
  },
  {
    path: 'src/lib/queue-service.js',
    content: 'export function run() {\n  // TODO: handle the empty case\n  return 1;\n}\n',
  },
  {
    path: 'src/lib/builder.js',
    content:
      "export function build() {\n  // Here's a complete implementation of the builder.\n  return 2;\n}\n",
  },
  {
    path: 'src/lib/flags.js',
    content:
      '// eslint-disable-next-line no-unused-vars\nexport function noop(a) {\n  return 3;\n}\n',
  },
];

// --- 1. Backup and variant files -------------------------------------------

describe('backup and variant files', () => {
  it('flags a .backup. file', () => {
    const findings = one(
      'src/components/Dashboard.backup.tsx',
      'export const Dashboard = () => null;\n'
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags a .old. file', () => {
    const findings = one('src/lib/api.old.js', 'export const get = (u) => u;\n');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags a .orig. file', () => {
    const findings = one('src/lib/parser.orig.js', 'export const parse = (s) => s;\n');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags a -copy file', () => {
    const findings = one('src/utils/helpers-copy.js', 'export const noop = () => 0;\n');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags a -v2 file', () => {
    const findings = one('src/pages/page-v2.tsx', 'export const Page = () => null;\n');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags a _final file', () => {
    const findings = one('src/lib/config_final.js', 'export const config = {};\n');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags a variant file nested deep in the source tree', () => {
    const findings = one(
      'src/features/billing/components/InvoiceRow.backup.tsx',
      'export const InvoiceRow = () => null;\n'
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags on the name alone even when the file content is spotless', () => {
    const clean = 'export function add(a, b) {\n  return a + b;\n}\n';
    expect(one('src/lib/math.old.js', clean).length).toBeGreaterThan(0);
    // control: identical content under a normal name is silent
    expect(one('src/lib/math.js', clean)).toHaveLength(0);
  });

  it('is silent on an ordinary source file name', () => {
    expect(one('src/lib/service.ts', 'export const run = () => 1;\n')).toHaveLength(0);
  });

  it('does not treat "copyright" as a -copy variant', () => {
    expect(one('src/lib/copyright.js', 'export const year = 2026;\n')).toHaveLength(0);
  });

  it('does not treat "oldest" as a .old. variant', () => {
    expect(one('src/lib/oldest.js', 'export const first = (xs) => xs[0];\n')).toHaveLength(0);
  });

  it('skips a variant file under a fixtures path', () => {
    expect(
      one('src/test/fixtures/Dashboard.backup.tsx', 'export const D = () => null;\n')
    ).toHaveLength(0);
  });

  it('skips a variant file under __tests__', () => {
    expect(one('src/__tests__/api.old.js', 'export const get = (u) => u;\n')).toHaveLength(0);
  });

  it('skips a .spec. variant file', () => {
    expect(one('src/components/Panel-v2.spec.tsx', 'export const P = () => null;\n')).toHaveLength(
      0
    );
  });
});

// --- 2. Commented-out code --------------------------------------------------

describe('commented-out code', () => {
  it('flags ten consecutive comment lines that parse as code', () => {
    const content = `export function run() {\n${commentRun(10)}\n  return 1;\n}\n`;
    expect(one('src/app.js', content).length).toBeGreaterThan(0);
  });

  it('is silent at nine consecutive commented-out lines (just under the threshold)', () => {
    const content = `export function run() {\n${commentRun(9)}\n  return 1;\n}\n`;
    expect(one('src/app.js', content)).toHaveLength(0);
  });

  it('flags a long commented-out block in a .ts file', () => {
    const content = `export function run(): number {\n${commentRun(15)}\n  return 1;\n}\n`;
    expect(one('src/lib/service.ts', content).length).toBeGreaterThan(0);
  });

  it('is silent on a twelve-line block of prose comments', () => {
    const prose = [
      '// This module owns the retry policy for the upstream billing calls.',
      '// The upstream returns 502 for roughly ten seconds after a cold start,',
      '// so the first attempt is expected to fail during a deploy window.',
      '// Backoff is linear rather than exponential because the cold start is',
      '// bounded and the caller is a background worker with no user waiting.',
      '// Anything past the third attempt is treated as a real outage and is',
      '// surfaced to the operator rather than retried again in the same run.',
      '// The policy is intentionally shared with the invoice worker so both',
      '// paths degrade the same way during a deploy.',
      '// Changing the attempt count changes the worst case latency budget,',
      '// which the scheduler assumes is under one minute.',
      '// Keep the two in step.',
    ].join('\n');
    const content = `${prose}\nexport function retry(fn) {\n  return fn();\n}\n`;
    expect(one('src/lib/retry.js', content)).toHaveLength(0);
  });

  it('is silent when a run of commented-out lines is broken before reaching ten', () => {
    const content = `export function run() {\n${commentRun(6)}\n  const live = 1;\n${commentRun(6)}\n  return live;\n}\n`;
    expect(one('src/app.js', content)).toHaveLength(0);
  });
});

// --- 3. Assistant narration in comments -------------------------------------

describe('assistant narration in comments', () => {
  it('flags "Here\'s a complete implementation"', () => {
    const content =
      "export function build() {\n  // Here's a complete implementation of the builder.\n  return 1;\n}\n";
    const findings = one('src/lib/builder.js', content);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags "I\'ve updated the function"', () => {
    const content =
      "export function build() {\n  // I've updated the function to handle the null case.\n  return 1;\n}\n";
    expect(one('src/lib/builder.js', content).length).toBeGreaterThan(0);
  });

  it('flags "feel free to adjust"', () => {
    const content =
      'export function build() {\n  // Feel free to adjust the threshold below.\n  return 1;\n}\n';
    expect(one('src/lib/builder.js', content).length).toBeGreaterThan(0);
  });

  it('flags "let me know if"', () => {
    const content =
      'export function build() {\n  // Let me know if you want this split into two modules.\n  return 1;\n}\n';
    expect(one('src/lib/builder.js', content).length).toBeGreaterThan(0);
  });

  it('flags narration inside a JSDoc block in a .tsx component', () => {
    const content =
      "/**\n * Here's a complete implementation of the settings panel.\n */\nexport function Panel() {\n  return null;\n}\n";
    expect(one('src/components/Panel.tsx', content).length).toBeGreaterThan(0);
  });

  it('flags narration on a trailing same-line comment', () => {
    const content =
      "export function build() {\n  return 1; // I've updated the function to return the count\n}\n";
    expect(one('src/lib/builder.js', content).length).toBeGreaterThan(0);
  });

  it('is silent on a comment that explains why', () => {
    const content =
      'export function fetchOnce(fn) {\n  // Retries twice because the upstream returns 502 on cold start.\n  return fn();\n}\n';
    expect(one('src/lib/fetch-once.js', content)).toHaveLength(0);
  });

  it('is silent on an ordinary JSDoc block', () => {
    const content =
      '/**\n * Adds two numbers.\n * @param {number} a\n * @param {number} b\n * @returns {number}\n */\nexport function add(a, b) {\n  return a + b;\n}\n';
    expect(one('src/lib/math.js', content)).toHaveLength(0);
  });
});

// --- 4. Oversized and over-complex functions --------------------------------

describe('function size and cyclomatic complexity', () => {
  it('flags a function well over 100 lines', () => {
    expect(one('src/lib/report.js', longFunction(140)).length).toBeGreaterThan(0);
  });

  it('is silent on an 80-line function (comfortably under the threshold)', () => {
    expect(one('src/lib/report.js', longFunction(80))).toHaveLength(0);
  });

  // Round-1 adjudication: structural checks are .js/.jsx/.mjs/.cjs only.
  // acorn has no TypeScript grammar and its loose-parser fallback invents
  // bindings (`import type {X}` reads as a default import named "type"), so
  // the pattern page now states the scope and these fixtures moved to .js.
  it('flags an oversized arrow function', () => {
    const body = Array.from({ length: 130 }, (_, i) => `  const step${i} = ${i} + 1;`).join('\n');
    const content = `export const buildReport = (input) => {\n${body}\n  return input;\n};\n`;
    expect(one('src/lib/report.js', content).length).toBeGreaterThan(0);
  });

  it('does not run structural checks on a .ts file (documented scope)', () => {
    const body = Array.from({ length: 130 }, (_, i) => `  const step${i} = ${i} + 1;`).join('\n');
    const content = `export const buildReport = (input) => {\n${body}\n  return input;\n};\n`;
    expect(one('src/lib/report.ts', content)).toHaveLength(0);
  });

  // Threshold raised from >10 to >15 after the 2026-07 cockpit scan: the check
  // produced 47 mediums there and was the largest contributor to that band, on
  // code its author considered deliberate. Complexity is a judgement call, and
  // a judgement call does not belong beside a missing auth check. Now reported
  // at low severity as well.
  it('flags a function with twenty branches (complexity 21)', () => {
    expect(one('src/lib/score.js', branchyFunction(20)).length).toBeGreaterThan(0);
  });

  it('is silent at fourteen branches (complexity 15, at the bar)', () => {
    expect(one('src/lib/score.js', branchyFunction(14))).toHaveLength(0);
  });

  it('is silent on a function with eight branches (complexity 9)', () => {
    expect(one('src/lib/score.js', branchyFunction(8))).toHaveLength(0);
  });

  // Round-1 adjudication: switch ARMS no longer score. A flat dispatch is
  // readable and the probe's own advice recommends it, so the fixture now
  // carries its complexity in branches and logical operators instead.
  it('flags complexity accumulated from mixed constructs, not just if statements', () => {
    const content = [
      'export function classify(input) {',
      '  let total = 0;',
      '  if (input.a) total += 1;',
      '  if (input.b) total += 1;',
      '  while (input.c > total) total += 1;',
      '  for (let i = 0; i < input.d; i += 1) total += 1;',
      '  for (const k of input.keys) if (k) total += 1;',
      '  do { total += 1; } while (total < input.min);',
      '  try { total += input.parse(); } catch (e) { total = 0; }',
      '  if (input.i && input.j) total += 1;',
      '  if (input.k || input.l) total += 1;',
      '  switch (input.kind) {',
      '    case 1:',
      '      total += 1;',
      '      break;',
      '    case 2:',
      '      total += 1;',
      '      break;',
      '    case 3:',
      '      total += 1;',
      '      break;',
      '    default:',
      '      break;',
      '  }',
      '  total += input.e && input.f ? 1 : 0;',
      '  total += input.g || input.h ? 1 : 0;',
      '  return total;',
      '}',
      '',
    ].join('\n');
    expect(one('src/lib/classify.js', content).length).toBeGreaterThan(0);
  });

  it('is silent on a short, simple function', () => {
    const content =
      'export function clamp(n, lo, hi) {\n  if (n < lo) return lo;\n  if (n > hi) return hi;\n  return n;\n}\n';
    expect(one('src/lib/clamp.js', content)).toHaveLength(0);
  });
});

// --- 5. Pass-through wrappers -----------------------------------------------

describe('pass-through wrappers', () => {
  it('flags a named function that forwards all parameters unchanged', () => {
    const content =
      "import { fetchUser } from './api-client.js';\nexport function getUser(id, opts) {\n  return fetchUser(id, opts);\n}\n";
    expect(one('src/lib/users.js', content).length).toBeGreaterThan(0);
  });

  // Round-1 adjudication: concise arrows are NOT wrappers. `const isFoo =
  // (c) => LIST.includes(c)` is the idiom for an alias, and flagging it fired
  // on ordinary predicates and thunks three times in the precision suite. The
  // smell is ceremony: a full body whose only statement forwards.
  it('does not flag a concise arrow alias', () => {
    const content =
      "import { sendEvent } from './bus.js';\nexport const emit = (name, payload) => sendEvent(name, payload);\n";
    expect(one('src/lib/emit.js', content)).toHaveLength(0);
  });

  it('flags a block-bodied arrow wrapper', () => {
    const content =
      "import { sendEvent } from './bus.js';\nexport const emit = (name, payload) => {\n  return sendEvent(name, payload);\n};\n";
    expect(one('src/lib/emit.js', content).length).toBeGreaterThan(0);
  });

  it('flags a plain pass-through wrapper (JS scope)', () => {
    const content =
      "import { loadRow } from './db.js';\nexport function getRow(table, id) {\n  return loadRow(table, id);\n}\n";
    expect(one('src/lib/service.js', content).length).toBeGreaterThan(0);
  });

  it('is silent when the wrapper transforms an argument', () => {
    const content =
      "import { fetchUser } from './api-client.js';\nexport function getUser(id, opts) {\n  const merged = { ...opts, include: 'profile' };\n  return fetchUser(id, merged);\n}\n";
    expect(one('src/lib/users.js', content)).toHaveLength(0);
  });

  it('is silent when the function does real work before forwarding', () => {
    const content = [
      "import { fetchUser } from './api-client.js';",
      'export function getUser(id, opts) {',
      '  if (!id) {',
      "    throw new Error('id is required');",
      '  }',
      '  return fetchUser(id, opts);',
      '}',
      '',
    ].join('\n');
    expect(one('src/lib/users.js', content)).toHaveLength(0);
  });
});

// --- 6. Dead imports and import count ---------------------------------------

describe('dead imports and import count', () => {
  it('flags an unused named import', () => {
    const content =
      "import { formatDate } from './format.js';\nexport function run() {\n  return 1;\n}\n";
    const findings = one('src/app.js', content);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags an unused default import', () => {
    const content = "import logger from './logger.js';\nexport function run() {\n  return 1;\n}\n";
    expect(one('src/app.js', content).length).toBeGreaterThan(0);
  });

  it('flags an unused namespace import', () => {
    const content =
      "import * as helpers from './helpers.js';\nexport function run() {\n  return 1;\n}\n";
    expect(one('src/app.js', content).length).toBeGreaterThan(0);
  });

  it('flags the unused binding when a sibling binding is used', () => {
    const content = [
      "import { formatDate, parseDate } from './format.js';",
      'export function run(value) {',
      '  return parseDate(value);',
      '}',
      '',
    ].join('\n');
    const findings = one('src/lib/service.js', content);
    expect(findings.length).toBeGreaterThan(0);
  });

  // Round-1 adjudication: the import-count check was removed. A composition
  // root imports many things and uses every one; counting bindings measures
  // the file's job, not its health. Dead imports carry that signal instead.
  it('does not flag a file for import count alone, at any size', () => {
    expect(one('src/lib/service.js', importsFile(21))).toHaveLength(0);
    expect(one('src/lib/service.js', importsFile(20))).toHaveLength(0);
  });

  it('is silent when every import is referenced', () => {
    const content = [
      "import { formatDate } from './format.js';",
      "import base from './base.js';",
      'export function run(value) {',
      '  return base(formatDate(value));',
      '}',
      '',
    ].join('\n');
    expect(one('src/app.js', content)).toHaveLength(0);
  });

  it('is silent on a side-effect import, which binds nothing', () => {
    const content = "import './styles.css';\nexport function run() {\n  return 1;\n}\n";
    expect(one('src/components/Panel.tsx', content)).toHaveLength(0);
  });
});

// --- 7. Repeated string literals --------------------------------------------

describe('repeated string literals', () => {
  it('flags a literal appearing three times', () => {
    const content = [
      'export function classify(record) {',
      "  if (record.state === 'PENDING_REVIEW') return 1;",
      "  if (record.next === 'PENDING_REVIEW') return 2;",
      "  if (record.prev === 'PENDING_REVIEW') return 3;",
      '  return 0;',
      '}',
      '',
    ].join('\n');
    expect(one('src/lib/classify.js', content).length).toBeGreaterThan(0);
  });

  it('is silent at two occurrences (just under the threshold)', () => {
    const content = [
      'export function classify(record) {',
      "  if (record.state === 'PENDING_REVIEW') return 1;",
      "  if (record.next === 'PENDING_REVIEW') return 2;",
      '  return 0;',
      '}',
      '',
    ].join('\n');
    expect(one('src/lib/classify.js', content)).toHaveLength(0);
  });

  it('flags a literal appearing four times in a .tsx component', () => {
    const content = [
      'export function Badge({ mode }) {',
      "  if (mode.a === 'AMBER_ALERT') return null;",
      "  if (mode.b === 'AMBER_ALERT') return null;",
      "  if (mode.c === 'AMBER_ALERT') return null;",
      "  if (mode.d === 'AMBER_ALERT') return null;",
      '  return null;',
      '}',
      '',
    ].join('\n');
    expect(one('src/components/Badge.jsx', content).length).toBeGreaterThan(0);
  });

  it('skips repeated path-shaped literals', () => {
    const content = [
      'export function paths() {',
      "  const a = './config/settings.json';",
      "  const b = './config/settings.json';",
      "  const c = './config/settings.json';",
      '  return [a, b, c];',
      '}',
      '',
    ].join('\n');
    expect(one('src/lib/paths.js', content)).toHaveLength(0);
  });

  it('skips repeated URL literals', () => {
    const content = [
      'export function endpoints() {',
      "  const a = 'https://api.example.com/v1/users';",
      "  const b = 'https://api.example.com/v1/users';",
      "  const c = 'https://api.example.com/v1/users';",
      '  return [a, b, c];',
      '}',
      '',
    ].join('\n');
    expect(one('src/lib/endpoints.js', content)).toHaveLength(0);
  });

  it('skips repeated sentence-shaped display copy', () => {
    const content = [
      'export function messages() {',
      "  const a = 'Your changes have been saved.';",
      "  const b = 'Your changes have been saved.';",
      "  const c = 'Your changes have been saved.';",
      '  return [a, b, c];',
      '}',
      '',
    ].join('\n');
    expect(one('src/lib/messages.js', content)).toHaveLength(0);
  });
});

// --- 8. eslint-disable without a reason -------------------------------------

describe('eslint-disable without a stated reason', () => {
  it('flags a bare eslint-disable-next-line', () => {
    const content =
      '// eslint-disable-next-line no-unused-vars\nexport function noop(a) {\n  return 1;\n}\n';
    const findings = one('src/lib/noop.js', content);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags a bare trailing eslint-disable-line', () => {
    const content =
      'export function noop(a) {\n  return a; // eslint-disable-line no-unused-vars\n}\n';
    expect(one('src/lib/noop.js', content).length).toBeGreaterThan(0);
  });

  it('is silent when the disable carries a -- reason on the same line', () => {
    const content = [
      '// eslint-disable-next-line no-restricted-syntax -- vendor types are wrong, see PROJ-482',
      'export function noop(a) {',
      '  return a;',
      '}',
      '',
    ].join('\n');
    expect(one('src/lib/noop.js', content)).toHaveLength(0);
  });

  it('is silent when the reason is stated on the line above the disable', () => {
    const content = [
      '// Vendor types declare this parameter optional but the runtime requires it.',
      '// eslint-disable-next-line no-restricted-syntax',
      'export function noop(a) {',
      '  return a;',
      '}',
      '',
    ].join('\n');
    expect(one('src/lib/noop.js', content)).toHaveLength(0);
  });
});

// --- 9. TODO / FIXME without a ticket ---------------------------------------

describe('TODO and FIXME without a ticket reference', () => {
  it('flags a bare TODO', () => {
    const content = 'export function run() {\n  // TODO: handle the empty case\n  return 1;\n}\n';
    expect(one('src/app.js', content).length).toBeGreaterThan(0);
  });

  it('flags a bare FIXME', () => {
    const content = 'export function run() {\n  // FIXME broken on Safari\n  return 1;\n}\n';
    expect(one('src/lib/service.ts', content).length).toBeGreaterThan(0);
  });

  it('flags a TODO on a trailing same-line comment', () => {
    const content = 'export function run() {\n  return 1; // TODO tighten this up\n}\n';
    expect(one('src/components/Panel.tsx', content).length).toBeGreaterThan(0);
  });

  it('is silent on a TODO carrying a PROJ-style ticket', () => {
    const content =
      'export function run() {\n  // TODO(PROJ-123): handle the empty case\n  return 1;\n}\n';
    expect(one('src/app.js', content)).toHaveLength(0);
  });

  it('is silent on a FIXME carrying a #number reference', () => {
    const content = 'export function run() {\n  // FIXME: see #456\n  return 1;\n}\n';
    expect(one('src/app.js', content)).toHaveLength(0);
  });

  it('is silent on a TODO carrying a tracker link', () => {
    const content = [
      'export function run() {',
      '  // TODO: https://github.com/example/repo/issues/12',
      '  return 1;',
      '}',
      '',
    ].join('\n');
    expect(one('src/app.js', content)).toHaveLength(0);
  });
});

// --- 10. Things the spec says this probe deliberately does not flag ----------

describe('deliberate non-detections', () => {
  it('does not flag generic variable names', () => {
    const content = [
      'export function transform(input) {',
      '  const data = input.data;',
      '  const result = data.map((item) => item.value);',
      '  return result;',
      '}',
      '',
    ].join('\n');
    expect(one('src/app.js', content)).toHaveLength(0);
  });

  it('does not flag file length (that belongs to the Code Quality probe)', () => {
    const content = Array.from(
      { length: 160 },
      (_, i) => `export function calc${i}(x) {\n  return x + ${i};\n}\n`
    ).join('\n');
    expect(one('src/lib/calcs.js', content)).toHaveLength(0);
  });

  it('does not flag console calls (that belongs to the Code Quality probe)', () => {
    const content = [
      'export function report(items) {',
      '  console.log(items.length);',
      '  console.warn(items.length);',
      '  console.error(items.length);',
      '  return items.length;',
      '}',
      '',
    ].join('\n');
    expect(one('src/app.js', content)).toHaveLength(0);
  });

  it('stays silent on a long file full of generic names and console calls', () => {
    const body = Array.from({ length: 120 }, (_, i) =>
      [
        `export function step${i}(input) {`,
        '  const data = input;',
        '  console.log(data);',
        '  return data;',
        '}',
      ].join('\n')
    ).join('\n');
    expect(one('src/lib/steps.js', body)).toHaveLength(0);
  });
});

// --- 11. Structural guarantees ----------------------------------------------

describe('finding structure', () => {
  it('stamps every finding with the probe name', () => {
    const findings = probeAICodegenBloat(KITCHEN_SINK);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.probe).toBe('AI Codegen Bloat');
    }
  });

  it('never rates a finding above medium', () => {
    const findings = probeAICodegenBloat(KITCHEN_SINK);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(['info', 'low', 'medium']).toContain(String(f.severity).toLowerCase());
    }
  });

  it('never emits critical or high for any detection in the family', () => {
    const corpus = [
      ...KITCHEN_SINK,
      { path: 'src/lib/report.js', content: longFunction(140) },
      { path: 'src/lib/score.js', content: branchyFunction(14) },
      { path: 'src/lib/big.ts', content: importsFile(21) },
      {
        path: 'src/lib/wrap.js',
        content:
          "import { fetchUser } from './api-client.js';\nexport function getUser(id, opts) {\n  return fetchUser(id, opts);\n}\n",
      },
    ];
    const findings = probeAICodegenBloat(corpus);
    expect(findings.length).toBeGreaterThan(0);
    const loud = findings.filter((f) =>
      ['critical', 'high'].includes(String(f.severity).toLowerCase())
    );
    expect(loud).toHaveLength(0);
  });

  it('gives every finding a non-empty id', () => {
    const findings = probeAICodegenBloat(KITCHEN_SINK);
    for (const f of findings) {
      expect(typeof f.id).toBe('string');
      expect(f.id.length).toBeGreaterThan(0);
    }
  });

  it('gives every finding a title, a category and a CWE', () => {
    const findings = probeAICodegenBloat(KITCHEN_SINK);
    for (const f of findings) {
      expect(typeof f.title).toBe('string');
      expect(f.title.trim().length).toBeGreaterThan(0);
      expect(typeof f.category).toBe('string');
      expect(f.category.trim().length).toBeGreaterThan(0);
      expect(String(f.cwe)).toMatch(/\d{3,4}/);
    }
  });

  it('gives every finding non-empty evidence', () => {
    const findings = probeAICodegenBloat(KITCHEN_SINK);
    for (const f of findings) {
      expect(typeof f.evidence).toBe('string');
      expect(f.evidence.trim().length).toBeGreaterThan(0);
    }
  });

  it('gives every finding non-empty remediation', () => {
    const findings = probeAICodegenBloat(KITCHEN_SINK);
    for (const f of findings) {
      expect(typeof f.remediation).toBe('string');
      expect(f.remediation.trim().length).toBeGreaterThan(0);
    }
  });

  it('reports the file path it was given', () => {
    const findings = probeAICodegenBloat(KITCHEN_SINK);
    const paths = KITCHEN_SINK.map((f) => f.path);
    for (const f of findings) {
      expect(paths).toContain(f.file);
    }
  });

  it('reports a positive integer line number', () => {
    const findings = probeAICodegenBloat(KITCHEN_SINK);
    for (const f of findings) {
      expect(Number.isInteger(f.line)).toBe(true);
      expect(f.line).toBeGreaterThan(0);
    }
  });

  it('points the line number at the TODO, not at line 1', () => {
    const filler = Array.from({ length: 11 }, (_, i) => `const pad${i} = ${i};`).join('\n');
    const content = `${filler}\n// TODO: handle the empty case\nexport const run = () => 1;\n`;
    const expected = lineOf(content, 'TODO');
    const findings = one('src/app.js', content);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.line === expected)).toBe(true);
    expect(findings.every((f) => f.line !== 1)).toBe(true);
  });

  it('points the line number at the narration comment, not at line 1', () => {
    const filler = Array.from({ length: 14 }, (_, i) => `const pad${i} = ${i};`).join('\n');
    const content = `${filler}\n// Here's a complete implementation of the parser.\nexport const parse = (s) => s;\n`;
    const expected = lineOf(content, "Here's a complete");
    const findings = one('src/lib/parse.js', content);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.line === expected)).toBe(true);
  });

  it('points the line number at the bare eslint-disable, not at line 1', () => {
    const filler = Array.from({ length: 9 }, (_, i) => `const pad${i} = ${i};`).join('\n');
    const content = `${filler}\n// eslint-disable-next-line no-unused-vars\nexport function noop(a) {\n  return 1;\n}\n`;
    const expected = lineOf(content, 'eslint-disable-next-line');
    const findings = one('src/lib/noop.js', content);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.line === expected)).toBe(true);
  });

  it('returns an array of plain finding objects', () => {
    const findings = probeAICodegenBloat(KITCHEN_SINK);
    expect(Array.isArray(findings)).toBe(true);
    for (const f of findings) {
      expect(typeof f).toBe('object');
      expect(f).not.toBeNull();
    }
  });
});

// --- 12. Multi-file attribution ---------------------------------------------

describe('multi-file attribution', () => {
  it('attributes findings to the dirty file, not the clean one', () => {
    const files = [
      { path: 'src/lib/clean.js', content: 'export function add(a, b) {\n  return a + b;\n}\n' },
      {
        path: 'src/lib/dirty.js',
        content: 'export function run() {\n  // TODO: handle the empty case\n  return 1;\n}\n',
      },
    ];
    const findings = probeAICodegenBloat(files);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.file).toBe('src/lib/dirty.js');
    }
  });

  it('reports both files when both are dirty', () => {
    const files = [
      {
        path: 'src/lib/first.js',
        content: 'export function run() {\n  // TODO: handle the empty case\n  return 1;\n}\n',
      },
      {
        path: 'src/lib/second.js',
        content: 'export function run() {\n  // FIXME broken on Safari\n  return 1;\n}\n',
      },
    ];
    const files2 = probeAICodegenBloat(files).map((f) => f.file);
    expect(new Set(files2)).toEqual(new Set(['src/lib/first.js', 'src/lib/second.js']));
  });

  it('analyses files independently: a batch equals the sum of its parts', () => {
    const a = { path: 'src/lib/first.js', content: longFunction(140) };
    const b = {
      path: 'src/components/Panel.backup.tsx',
      content: 'export const Panel = () => null;\n',
    };
    const solo = probeAICodegenBloat([a]).length + probeAICodegenBloat([b]).length;
    expect(probeAICodegenBloat([a, b])).toHaveLength(solo);
  });

  it('does not leak a dirty file findings onto a skipped test file', () => {
    const files = [
      {
        path: 'src/test/fixtures/sample.js',
        content: 'export function run() {\n  // TODO: handle the empty case\n  return 1;\n}\n',
      },
      {
        path: 'src/lib/real.js',
        content: 'export function run() {\n  // TODO: handle the empty case\n  return 1;\n}\n',
      },
    ];
    const findings = probeAICodegenBloat(files);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.file).toBe('src/lib/real.js');
    }
  });
});

// --- 13. Input robustness ---------------------------------------------------

describe('input robustness', () => {
  it('returns an empty array for an empty corpus', () => {
    expect(probeAICodegenBloat([])).toEqual([]);
  });

  it('returns an empty array for an empty file', () => {
    expect(one('src/app.js', '')).toHaveLength(0);
  });

  it('returns an empty array for a whitespace-only file', () => {
    expect(one('src/app.js', '\n\n   \n\t\n')).toHaveLength(0);
  });
});

// --- 14. Edge cases the spec does not pin down ------------------------------

describe('edge cases the spec does not pin down', () => {
  it('treats a function of exactly 100 lines as under the bar', () => {
    // AMBIGUOUS: the page says "functions over 100 lines". It does not say whether
    // the count is body lines or signature-to-close, nor whether 100 itself trips.
    // Read literally, "over 100" excludes exactly 100.
    const content = longFunction(97); // signature + 97 body lines + return + close = 100
    expect(one('src/lib/report.js', content)).toHaveLength(0);
  });

  it('treats cyclomatic complexity of exactly 16 as over the bar', () => {
    // "complexity passes 15" reads as strictly greater than 15. Fifteen
    // independent if-branches gives McCabe 16.
    expect(one('src/lib/score.js', branchyFunction(15)).length).toBeGreaterThan(0);
  });

  it('treats cyclomatic complexity of exactly 15 as under the bar', () => {
    expect(one('src/lib/score.js', branchyFunction(14))).toHaveLength(0);
  });

  it('counts a block comment holding twelve code lines as commented-out code', () => {
    // AMBIGUOUS: the page says "ten or more consecutive comment lines". It does not
    // say whether a single /* */ block counts as N comment lines or as one comment.
    const inner = Array.from({ length: 12 }, (_, i) => ` * const value${i} = compute(${i});`).join(
      '\n'
    );
    const content = `/*\n${inner}\n */\nexport const run = () => 1;\n`;
    expect(one('src/app.js', content).length).toBeGreaterThan(0);
  });

  it('does not treat a directory named v2 as a variant file', () => {
    // AMBIGUOUS: the page lists the marker as "-v2", a name fragment. A versioned
    // directory is a deliberate API layout, not a leftover copy.
    expect(one('src/v2/index.js', 'export const run = () => 1;\n')).toHaveLength(0);
  });

  it('handles an unused type-only import without throwing', () => {
    // AMBIGUOUS: `import type` is erased at build time, so it cannot execute a module
    // on load. Whether it still counts as a dead import is not stated.
    const content =
      "import type { User } from './types.js';\nexport function run() {\n  return 1;\n}\n";
    const findings = one('src/lib/service.ts', content);
    expect(Array.isArray(findings)).toBe(true);
  });

  it('does not double-report a wrapper that is also the only export', () => {
    // AMBIGUOUS: the page allows a load-bearing seam to keep its indirection if a
    // comment says so, but does not say the comment silences the finding.
    const content = [
      "import { fetchUser } from './api-client.js';",
      '// Deliberate seam: the test suite swaps this module.',
      'export function getUser(id, opts) {',
      '  return fetchUser(id, opts);',
      '}',
      '',
    ].join('\n');
    const findings = one('src/lib/users.js', content);
    expect(findings.length).toBeLessThanOrEqual(1);
  });
});

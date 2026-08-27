// Cross-file taint: a source in one file reaching a sink in another.
//
// The precision cases matter more than the detection ones here. A taint probe
// that reports correct parameterised SQL teaches people to ignore it, and an
// ignored probe is worth less than no probe, because it still costs attention.

import { describe, it, expect } from 'vitest';
import {
  probeCrossFileTaint,
  resolveRelativeImport,
  summariseModule,
} from '../lib/probes/taint-cross-file.js';
import { parseFile } from '../lib/probes/taint-engine.js';
import { PROBES } from '../lib/probes.js';

const db = (body) => ({ path: 'src/db.js', content: body });
const route = (body) => ({ path: 'src/routes/user.js', content: body });

describe('cross-file taint: the flow it exists for', () => {
  it('reports a source in one file reaching a sink in another', () => {
    const findings = probeCrossFileTaint([
      db('export function runQuery(sql) {\n  return db.query(sql);\n}\n'),
      route(
        "import { runQuery } from '../db.js';\n" +
          'export async function GET(req) {\n' +
          '  return runQuery(`SELECT * FROM users WHERE id = ${req.query.id}`);\n' +
          '}\n'
      ),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].probe).toBe('Cross-File Taint');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].cwe).toBe('CWE-89');
  });

  it('names both files, because neither is wrong on its own', () => {
    const [f] = probeCrossFileTaint([
      db('export function runQuery(sql) {\n  return db.query(sql);\n}\n'),
      route(
        "import { runQuery } from '../db.js';\n" +
          'export async function GET(req) {\n' +
          '  return runQuery(`SELECT * FROM users WHERE id = ${req.query.id}`);\n' +
          '}\n'
      ),
    ]);
    expect(f.taintPath.sourceFile).toBe('src/routes/user.js');
    expect(f.taintPath.sinkFile).toBe('src/db.js');
    expect(f.taintPath.via).toMatch(/runQuery/);
    expect(f.evidence).toMatch(/req\.query\.id/);
    // The fix belongs in the helper, where every caller benefits.
    expect(f.remediation).toMatch(/src\/db\.js/);
  });

  it('follows a default export too', () => {
    const findings = probeCrossFileTaint([
      {
        path: 'src/run.js',
        // A qualified sink. The engine deliberately does not treat a bare
        // exec() as one: the name is too common to assume it is the shell.
        content: 'export default function (cmd) {\n  child_process.exec(cmd);\n}\n',
      },
      route(
        "import run from '../run.js';\n" +
          'export function GET(req) {\n  return run(req.query.cmd);\n}\n'
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('cross-file taint: precision', () => {
  it('does NOT report correct parameterised SQL', () => {
    // The bound-parameter argument is the FIX. Reporting it is how a taint
    // probe teaches people that its findings are noise.
    const findings = probeCrossFileTaint([
      db('export function runQuery(sql, params) {\n  return db.query(sql, params);\n}\n'),
      route(
        "import { runQuery } from '../db.js';\n" +
          'export async function GET(req) {\n' +
          "  return runQuery('SELECT * FROM users WHERE id = ?', [req.query.id]);\n" +
          '}\n'
      ),
    ]);
    expect(findings).toEqual([]);
  });

  it('does NOT report a constant argument', () => {
    const findings = probeCrossFileTaint([
      db('export function runQuery(sql) {\n  return db.query(sql);\n}\n'),
      route(
        "import { runQuery } from '../db.js';\n" +
          "export function GET() {\n  return runQuery('SELECT 1');\n}\n"
      ),
    ]);
    expect(findings).toEqual([]);
  });

  it('does NOT invent a link between files that are not imported', () => {
    const findings = probeCrossFileTaint([
      db('export function runQuery(sql) {\n  return db.query(sql);\n}\n'),
      route('export function GET(req) {\n  return other(`SELECT ${req.query.id}`);\n}\n'),
    ]);
    expect(findings).toEqual([]);
  });

  it('does nothing with a single file (that is the other engine job)', () => {
    expect(
      probeCrossFileTaint([
        route('export function GET(req) {\n  return db.query(`SELECT ${req.query.id}`);\n}\n'),
      ])
    ).toEqual([]);
  });

  it('ignores bare package specifiers', () => {
    // A package internals are not the author code to fix, and resolving one
    // would mean guessing at a file the scan never saw.
    const findings = probeCrossFileTaint([
      db('export function runQuery(sql) {\n  return db.query(sql);\n}\n'),
      route(
        "import { runQuery } from 'some-package';\n" +
          'export function GET(req) {\n  return runQuery(`SELECT ${req.query.id}`);\n}\n'
      ),
    ]);
    expect(findings).toEqual([]);
  });

  it('emits one finding per call site, not one per matching rule', () => {
    const findings = probeCrossFileTaint([
      db('export function runQuery(sql) {\n  return db.query(sql);\n}\n'),
      route(
        "import { runQuery } from '../db.js';\n" +
          'export function GET(req) {\n  return runQuery(`SELECT ${req.query.id}`);\n}\n'
      ),
    ]);
    expect(findings).toHaveLength(1);
  });
});

describe('cross-file taint: module resolution', () => {
  const known = new Set(['src/db.js', 'src/lib/index.ts', 'src/util.ts']);

  it('resolves ../ and ./ against the importing file', () => {
    expect(resolveRelativeImport('src/routes/user.js', '../db.js', known)).toBe('src/db.js');
    expect(resolveRelativeImport('src/routes/user.js', '../db', known)).toBe('src/db.js');
    expect(resolveRelativeImport('src/a.js', './util', known)).toBe('src/util.ts');
  });

  it('resolves a directory import to its index file', () => {
    expect(resolveRelativeImport('src/a.js', './lib', known)).toBe('src/lib/index.ts');
  });

  it('returns null for a bare specifier or an unknown path', () => {
    expect(resolveRelativeImport('src/a.js', 'react', known)).toBeNull();
    expect(resolveRelativeImport('src/a.js', './nope', known)).toBeNull();
  });
});

describe('cross-file taint: summaries', () => {
  it('summarises a parameter that reaches a sink', () => {
    const ast = parseFile('export function runQuery(sql) {\n  return db.query(sql);\n}\n', '.js');
    const s = summariseModule(ast);
    expect(s.get('runQuery').paramToSink[0].index).toBe(0);
  });

  it('summarises an exported arrow function', () => {
    const ast = parseFile('export const runQuery = (sql) => db.query(sql);\n', '.js');
    expect(s0(summariseModule(ast))).toBe(0);
    function s0(map) {
      return map.get('runQuery')?.paramToSink?.[0]?.index;
    }
  });

  it('records nothing for a function with neither a sink nor a source', () => {
    const ast = parseFile('export function add(a, b) {\n  return a + b;\n}\n', '.js');
    expect(summariseModule(ast).has('add')).toBe(false);
  });
});

describe('cross-file taint: registration', () => {
  it('is a registered probe', () => {
    expect(PROBES.some((p) => p.name === 'Cross-File Taint')).toBe(true);
  });
});

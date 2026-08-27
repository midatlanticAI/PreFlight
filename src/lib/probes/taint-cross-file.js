// src/lib/probes/taint-cross-file.js
//
// Cross-file taint. The intra-procedural engine in taint-engine.js tracks a
// tainted value through one function in one file and stops at the module
// boundary, where "imports are treated as untainted". That boundary is exactly
// where generated code puts the interesting half.
//
// The shape this exists for:
//
//   // db.js
//   export function runQuery(sql) { return db.query(sql); }
//
//   // routes/user.js
//   import { runQuery } from '../db.js';
//   export async function GET(req) {
//     return runQuery(`SELECT * FROM users WHERE id = ${req.query.id}`);
//   }
//
// Neither file is reportable on its own. db.js has a sink with no source, and
// user.js has a source flowing into what looks like an ordinary local call.
// Factoring the query helper out is good practice and it is what a model does
// when asked to tidy up, so the pattern is common rather than exotic.
//
// Approach: FUNCTION SUMMARIES, computed in one pass and applied in a second.
//
//   Pass 1  For every exported function, answer two questions.
//           (a) Does a parameter reach a sink? Then a caller who passes a
//               tainted value into that parameter has completed a flow.
//           (b) Does it return a value derived from a source? Then a caller who
//               assigns its result is holding tainted data.
//
//   Pass 2  Re-walk each file. At a call to an imported function, look up the
//           summary and decide.
//
// This is deliberately a summary-based approximation, not a whole-program
// analysis. What it does NOT do is stated in the limits below rather than left
// for a reader to discover, because a taint tool that overstates its reach is
// worse than one that does less and says so.

import { parseFile, SOURCES, SINKS, readDottedName } from './taint-engine.js';
import { isTestFile, isScannerSelfSource } from '../file-filter.js';

const JS_RE = /\.[jt]sx?$/;

// ---------------------------------------------------------------------------
// Module resolution
// ---------------------------------------------------------------------------

// Relative specifiers only. A bare specifier is a package, and a package's
// internals are not the author's code to fix; a tsconfig path alias needs the
// tsconfig, which the scanner does not read. Both are silently skipped, which
// costs recall and never invents a link between two unrelated files.
const RELATIVE_RE = /^\.{1,2}\//;

const CANDIDATE_SUFFIXES = [
  '',
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '/index.ts',
  '/index.tsx',
  '/index.js',
  '/index.jsx',
];

/**
 * Resolve a relative import to a path in the scanned set.
 * @param {string} fromPath  the importing file
 * @param {string} spec      the specifier as written
 * @param {Set<string>} known  every path in the scan
 * @returns {string|null}
 */
export function resolveRelativeImport(fromPath, spec, known) {
  if (typeof spec !== 'string' || !RELATIVE_RE.test(spec)) return null;
  const fromDir = fromPath.replace(/\\/g, '/').replace(/\/[^/]*$/, '');
  const parts = (fromDir + '/' + spec).split('/');
  const stack = [];
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (part === '..') stack.pop();
    else stack.push(part);
  }
  const base = stack.join('/');
  for (const suffix of CANDIDATE_SUFFIXES) {
    // An import written with an extension already resolves on the '' suffix.
    const candidate = suffix.startsWith('/')
      ? base + suffix
      : base.replace(/\.[jt]sx?$/, '') + suffix;
    if (known.has(candidate)) return candidate;
  }
  return known.has(base) ? base : null;
}

// ---------------------------------------------------------------------------
// Pass 1: summarise exported functions
// ---------------------------------------------------------------------------

function paramNames(fn) {
  const out = [];
  for (const p of fn.params || []) {
    if (p.type === 'Identifier') out.push(p.name);
    else if (p.type === 'AssignmentPattern' && p.left?.type === 'Identifier') out.push(p.left.name);
    else if (p.type === 'RestElement' && p.argument?.type === 'Identifier')
      out.push(p.argument.name);
    else out.push(null); // destructured: not tracked, position still counts
  }
  return out;
}

function eachNode(node, visit, seen = new Set()) {
  if (!node || typeof node !== 'object' || seen.has(node)) return;
  seen.add(node);
  if (typeof node.type === 'string') visit(node);
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'range' || key === 'parent') continue;
    const child = node[key];
    if (Array.isArray(child)) for (const c of child) eachNode(c, visit, seen);
    else if (child && typeof child === 'object') eachNode(child, visit, seen);
  }
}

function matchSink(node) {
  if (node.type !== 'CallExpression') return null;
  for (const sink of SINKS) {
    const hit = sink.matches ? sink.matches(node) : null;
    if (hit) return { sink, hit };
  }
  return null;
}

function matchSource(node) {
  for (const src of SOURCES) {
    const hit = src.matches ? src.matches(node) : null;
    if (hit) return hit;
  }
  return null;
}

/**
 * Does an expression read one of these names, directly or through a member
 * access or a template literal? Deliberately shallow: it answers "is this
 * parameter involved", not "how".
 */
function readsAnyName(node, names) {
  let found = null;
  eachNode(node, (n) => {
    if (found) return;
    if (n.type === 'Identifier' && names.has(n.name)) found = n.name;
  });
  return found;
}

/**
 * Summarise one function.
 * @returns {{paramToSink: Array<{param:string,index:number,sink:object,line:number}>,
 *           returnsSource: {detail:string,line:number}|null}}
 */
function summariseFunction(fn) {
  const names = paramNames(fn);
  const nameSet = new Set(names.filter(Boolean));
  const paramToSink = [];
  let returnsSource = null;

  eachNode(fn.body, (node) => {
    // (a) a parameter reaching a sink argument
    const sinkHit = matchSink(node);
    if (sinkHit) {
      // ONLY the first argument. db.query(sql, params), exec(cmd, opts),
      // res.redirect(url, status) and fs.readFile(path, cb) all put the
      // dangerous value first and the safe machinery after it. Treating every
      // argument as dangerous reports correct parameterised SQL as injection,
      // which is the single fastest way to make a taint probe worth ignoring:
      //   runQuery('SELECT * FROM t WHERE id = ?', [req.query.id])
      // is the FIX, not the bug.
      const dangerousArgs = (node.arguments || []).slice(0, 1);
      for (const arg of dangerousArgs) {
        const name = readsAnyName(arg, nameSet);
        if (!name) continue;
        const index = names.indexOf(name);
        if (paramToSink.some((p) => p.index === index && p.sink.id === sinkHit.sink.id)) continue;
        paramToSink.push({
          param: name,
          index,
          sink: sinkHit.sink,
          detail: sinkHit.hit?.detail || sinkHit.sink.id,
          line: node.loc?.start?.line || 1,
        });
      }
    }
    // (b) returning something derived from a source
    if (!returnsSource && node.type === 'ReturnStatement' && node.argument) {
      let hit = null;
      eachNode(node.argument, (n) => {
        if (hit) return;
        const s = matchSource(n);
        if (s) hit = s;
      });
      if (hit) {
        returnsSource = { detail: hit.detail || hit.kind, line: node.loc?.start?.line || 1 };
      }
    }
  });

  return { paramToSink, returnsSource };
}

/**
 * Collect { exportedName -> summary } for one parsed module.
 * Handles `export function f(){}`, `export const f = () => {}`, and
 * `export default function f(){}`.
 */
export function summariseModule(ast) {
  const summaries = new Map();
  const record = (name, fn) => {
    if (!name || !fn) return;
    const s = summariseFunction(fn);
    if (s.paramToSink.length || s.returnsSource) summaries.set(name, s);
  };

  for (const node of ast.body || []) {
    if (node.type === 'ExportNamedDeclaration' && node.declaration) {
      const d = node.declaration;
      if (d.type === 'FunctionDeclaration') record(d.id?.name, d);
      if (d.type === 'VariableDeclaration') {
        for (const decl of d.declarations || []) {
          const init = decl.init;
          if (
            decl.id?.type === 'Identifier' &&
            init &&
            (init.type === 'ArrowFunctionExpression' || init.type === 'FunctionExpression')
          ) {
            record(decl.id.name, init);
          }
        }
      }
    }
    if (node.type === 'ExportDefaultDeclaration') {
      const d = node.declaration;
      if (d && (d.type === 'FunctionDeclaration' || d.type === 'ArrowFunctionExpression')) {
        record('default', d);
      }
    }
  }
  return summaries;
}

/**
 * Local name -> { module, exported } for every relative import in a module.
 */
export function collectImports(ast, fromPath, known) {
  const map = new Map();
  for (const node of ast.body || []) {
    if (node.type !== 'ImportDeclaration') continue;
    const target = resolveRelativeImport(fromPath, node.source?.value, known);
    if (!target) continue;
    for (const spec of node.specifiers || []) {
      if (spec.type === 'ImportSpecifier') {
        map.set(spec.local.name, {
          module: target,
          exported: spec.imported?.name || spec.local.name,
        });
      } else if (spec.type === 'ImportDefaultSpecifier') {
        map.set(spec.local.name, { module: target, exported: 'default' });
      }
    }
  }
  return map;
}

// ---------------------------------------------------------------------------
// Pass 2: apply summaries at call sites
// ---------------------------------------------------------------------------

/**
 * Cross-file taint probe. Emits a finding when a source in one file reaches a
 * sink in another through an imported function.
 *
 * LIMITS, stated rather than discovered:
 * - Relative imports only. Package internals and tsconfig path aliases are out.
 * - One hop. A -> B is followed; A -> B -> C is not.
 * - Summaries are per exported function, so a re-export chain is not followed.
 * - Destructured parameters count for position but are not tracked by name.
 *
 * @param {Array<{path:string,content:string}>} files
 * @returns {object[]} findings
 */
export function probeCrossFileTaint(files) {
  const scanned = (files || []).filter(
    (f) => f && JS_RE.test(f.path) && !isTestFile(f.path) && !isScannerSelfSource(f.path)
  );
  if (scanned.length < 2) return []; // cross-file needs at least two files

  const known = new Set(scanned.map((f) => f.path.replace(/\\/g, '/')));
  const parsed = new Map();
  for (const f of scanned) {
    const ast = parseFile(f.content, f.path.match(JS_RE)?.[0] || '.js');
    if (ast) parsed.set(f.path.replace(/\\/g, '/'), { ast, file: f });
  }

  // Pass 1
  const moduleSummaries = new Map();
  for (const [path, { ast }] of parsed) moduleSummaries.set(path, summariseModule(ast));

  // Pass 2
  const findings = [];
  const seen = new Set();
  for (const [path, { ast, file }] of parsed) {
    const imports = collectImports(ast, path, known);
    if (imports.size === 0) continue;

    eachNode(ast, (node) => {
      if (node.type !== 'CallExpression') return;
      const calleeName =
        node.callee?.type === 'Identifier' ? node.callee.name : readDottedName(node.callee);
      if (!calleeName) return;
      const imported = imports.get(calleeName.split('.')[0]);
      if (!imported) return;
      const summary = moduleSummaries.get(imported.module)?.get(imported.exported);
      if (!summary || !summary.paramToSink.length) return;

      // Does any argument at a sink-reaching position carry a source?
      for (const p of summary.paramToSink) {
        const arg = node.arguments?.[p.index];
        if (!arg) continue;
        let sourceHit = null;
        eachNode(arg, (n) => {
          if (sourceHit) return;
          const s = matchSource(n);
          if (s) sourceHit = s;
        });
        if (!sourceHit) continue;

        const line = node.loc?.start?.line || 1;
        const key = `${file.path}:${line}:${imported.module}:${p.sink.id}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push({
          id: `xtaint-${p.sink.id}-${file.path}-${line}`,
          probe: 'Cross-File Taint',
          title: `${p.sink.title} (across files)`,
          severity: p.sink.severity,
          category: 'Injection',
          cwe: p.sink.cwe,
          file: file.path,
          line,
          evidence:
            `Source: ${sourceHit.kind} (${sourceHit.detail}) at ${file.path}:${line} ` +
            `-> passed to ${imported.exported}() in ${imported.module} ` +
            `-> Sink: ${p.detail} at ${imported.module}:${p.line}`,
          remediation:
            `${p.sink.remediation} The sink is in ${imported.module} at line ${p.line}, so neither file ` +
            `looks wrong on its own: the helper trusts its caller and the caller trusts the helper. ` +
            `Fix it in the helper, where every caller benefits, rather than at this one call site.`,
          taintPath: {
            sourceFile: file.path,
            sourceLine: line,
            source: sourceHit.detail,
            via: `${imported.exported}() param #${p.index + 1}`,
            sinkFile: imported.module,
            sinkLine: p.line,
            sink: p.detail,
          },
        });
      }
    });
  }
  return findings;
}

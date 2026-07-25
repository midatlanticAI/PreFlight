// src/lib/probes/v2/bloat.js
//
// F7: AI Codegen Bloat (v2 spec, docs/preflight-v2-spec.md). The family the
// spec calls the novel surface: no existing linter row in the tool-coverage
// matrix covers it. These are not vulnerabilities. They are the tells of code
// that was generated and shipped without a read-through, and the spec's whole
// argument is that those tells co-locate with the real defects.
//
// Severity ceiling for the family is MEDIUM by design. Nothing here is an
// exploit; the expected response is "go read this file", not "patch now".
//
// Two roster entries from the spec are deliberately NOT implemented:
//   - "generic name pollution (data/result/temp/item)" — spec §1.8 separately
//     declines exactly this as unfixable-FP ("no deterministic signal separates
//     AI laziness from a callback parameter in a documented API"). The §1.8
//     reasoning wins over the roster line.
//   - "file over 500 lines" / "console statements in non-test" — already owned
//     by the Code Quality probe's file-size ladder and console check. Emitting
//     them here would double-report the same line.

import { parseModule, walk } from './context.js';
import { isTestFile, isScannerSelfSource } from '../../file-filter.js';
import { maskCommentsAndStringsFromContent } from '../_internal/masking.js';

const FN_TYPES = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']);

// Thresholds. Named so the Learn page and the tests read from one place.
export const BLOAT_FN_LINES = 100;
export const BLOAT_CYCLOMATIC = 10;
export const BLOAT_IMPORT_COUNT = 20;
export const BLOAT_COMMENTED_CODE_LINES = 10;
export const BLOAT_MAGIC_STRING_REPEATS = 3;

const finding = (o) => ({
  probe: 'AI Codegen Bloat',
  category: 'Maintainability',
  severity: 'low',
  ...o,
});

// A function's declared name, for readable finding titles.
function fnName(node, parent) {
  if (node.id?.name) return node.id.name;
  if (parent?.type === 'VariableDeclarator' && parent.id?.name) return parent.id.name;
  if (parent?.type === 'Property' && parent.key?.name) return parent.key.name;
  if (parent?.type === 'MethodDefinition' && parent.key?.name) return parent.key.name;
  return '(anonymous)';
}

// Cyclomatic complexity: 1 + one per branch point. Counts only nodes inside
// THIS function, not nested function bodies (those get their own score).
function cyclomaticOf(fnNode) {
  let score = 1;
  const seen = new Set();
  walk(fnNode, (n, parent) => {
    if (n !== fnNode && FN_TYPES.has(n.type)) {
      seen.add(n);
      return;
    }
    // Skip anything inside an already-seen nested function.
    let p = parent;
    while (p) {
      if (seen.has(p)) return;
      p = null; // walk() gives immediate parent only; one level is enough here
    }
    if (
      n.type === 'IfStatement' ||
      n.type === 'ForStatement' ||
      n.type === 'ForInStatement' ||
      n.type === 'ForOfStatement' ||
      n.type === 'WhileStatement' ||
      n.type === 'DoWhileStatement' ||
      n.type === 'CatchClause' ||
      n.type === 'ConditionalExpression'
    )
      score++;
    else if (n.type === 'SwitchCase' && n.test) score++;
    else if (n.type === 'LogicalExpression' && ['&&', '||', '??'].includes(n.operator)) score++;
  });
  return score;
}

export function probeAICodegenBloat(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    const content = file.content || '';
    if (!content.trim()) return;

    // --- 1. Backup / variant files left in the tree. Path-only, no parse.
    // The single most visible symptom of generate-until-it-works: the old
    // attempt is still shipping. Extension-anchored so `v2/` directories and
    // legitimately-named modules do not match.
    if (
      /(?:\.(?:backup|bak|old|orig|copy|tmp)\.[jt]sx?$)|(?:[-_](?:backup|old|copy|final|new|v\d+|\d+)\.[jt]sx?$)|(?:\s|^|\/)copy(?:\s|_|-)of/i.test(
        file.path
      )
    ) {
      findings.push(
        finding({
          id: `bloat-backup-file-${file.path}`,
          title: `Backup or variant file left in the source tree: ${file.path.split('/').pop()}`,
          severity: 'medium',
          cwe: 'CWE-1164',
          file: file.path,
          line: 1,
          evidence: file.path,
          remediation:
            'Superseded attempts left beside the real file get imported by mistake, get edited instead of the live one, and keep old logic (including old auth checks) alive in the bundle. Version control already holds the history. Delete the variant and let git remember it.',
        })
      );
    }

    if (!/\.[jt]sx?$/i.test(file.path)) return;
    if (/\.min\.[jt]sx?$/i.test(file.path)) return;

    const lines = content.split('\n');
    // Comment-stripped view, used so a repeated literal quoted inside a
    // commented-out block is not counted as a live magic string.
    const codeOnly = maskCommentsAndStringsFromContent(content)
      .split('\n')
      .map((l, i) => (/^\s*(?:\/\/|\*|\/\*)/.test(lines[i] || '') ? '' : lines[i] || ''))
      .join('\n');

    // --- 2. Commented-out code blocks. Consecutive comment lines that parse
    // as code rather than prose. AI-generated code is a draft; the draft's
    // discarded attempts get commented rather than deleted.
    let runStart = -1;
    let runCodeish = 0;
    const flushRun = (endIdx) => {
      if (runStart >= 0 && endIdx - runStart + 1 >= BLOAT_COMMENTED_CODE_LINES && runCodeish >= 3) {
        findings.push(
          finding({
            id: `bloat-commented-code-${file.path}-${runStart + 1}`,
            title: `${endIdx - runStart + 1} consecutive lines of commented-out code`,
            cwe: 'CWE-1164',
            file: file.path,
            line: runStart + 1,
            evidence: (lines[runStart] || '').trim().slice(0, 120),
            remediation:
              'A commented-out block is code that no reader can trust: it is not running, not tested, and not obviously wrong. Delete it. If it might come back, the commit history is the right place for it, and git blame will find it.',
          })
        );
      }
      runStart = -1;
      runCodeish = 0;
    };
    lines.forEach((raw, idx) => {
      const m = raw.match(/^\s*\/\/\s?(.*)$/);
      if (!m) {
        flushRun(idx - 1);
        return;
      }
      const body = m[1];
      if (runStart < 0) runStart = idx;
      // Code-shaped: ends in a statement terminator, or contains an
      // assignment / call / declaration / control keyword.
      if (
        /[;{}]\s*$/.test(body) ||
        /\b(?:const|let|var|function|return|if|else|for|while|import|export|await|class)\b/.test(
          body
        ) ||
        /\w\s*\([^)]*\)\s*[;{]?\s*$/.test(body) ||
        /^\s*[\w.[\]'"]+\s*=[^=]/.test(body)
      )
        runCodeish++;
    });
    flushRun(lines.length - 1);

    // --- 3. AI signature phrases in comments. The model narrating its own
    // work, left in the file. Info-only: it is a tell, not a defect.
    const SIGNATURE_RE =
      /(?:here'?s?\s+(?:a|an|the)\s+(?:robust|complete|simple|basic|updated|improved|corrected|comprehensive|full|working)\b|(?:i|i've|i have)\s+(?:updated|added|implemented|created|fixed|refactored|modified)\s+the\b|feel free to\s+(?:adjust|modify|customize|change)\b|(?:note|remember)\s+that you(?:'ll| will| may| might)\s+need to\b|this (?:implementation|function|code) (?:assumes|should|provides)\b|(?:let me know if|hope this helps)\b|(?:certainly|sure)[,!]\s+(?:here|i)\b|as an ai\b|replace this with your (?:actual|real)\b)/i;
    lines.forEach((raw, idx) => {
      const cm = raw.match(/(?:\/\/|\/\*|^\s*\*)\s?(.+)$/);
      if (!cm) return;
      if (!SIGNATURE_RE.test(cm[1])) return;
      findings.push(
        finding({
          id: `bloat-ai-signature-${file.path}-${idx + 1}`,
          title: 'Assistant narration left in a code comment',
          severity: 'info',
          cwe: 'CWE-1164',
          file: file.path,
          line: idx + 1,
          evidence: raw.trim().slice(0, 120),
          remediation:
            'A comment addressed to the person who pasted the prompt is not documentation for the next reader. It also marks the spot where generated code was accepted without a read-through, which is worth a second look at the logic underneath it. Rewrite the comment to say why the code does what it does, or delete it.',
        })
      );
    });

    // --- 4. eslint-disable with no justification on the same or previous line.
    lines.forEach((raw, idx) => {
      const dm = raw.match(/eslint-disable(?:-next-line|-line)?\s+([\w@/-]+(?:\s*,\s*[\w@/-]+)*)/);
      if (!dm) return;
      const after = raw.slice(raw.indexOf(dm[0]) + dm[0].length);
      const hasReason = /--\s*\S/.test(after) || /\/\/\s*\S/.test(after);
      const prev = (lines[idx - 1] || '').trim();
      const prevIsComment = /^(?:\/\/|\*|\/\*)\s*\S/.test(prev) && !/eslint-disable/.test(prev);
      if (hasReason || prevIsComment) return;
      findings.push(
        finding({
          id: `bloat-eslint-disable-${file.path}-${idx + 1}`,
          title: `eslint-disable for "${dm[1]}" with no stated reason`,
          cwe: 'CWE-1164',
          file: file.path,
          line: idx + 1,
          evidence: raw.trim().slice(0, 120),
          remediation:
            'Turning a rule off is a decision, and the next reader needs to know whether it still applies. Add the reason inline (eslint-disable-next-line rule -- the vendor types are wrong here) or fix the underlying issue. An unexplained disable is indistinguishable from silencing a real warning to make the build pass.',
        })
      );
    });

    // --- 5. TODO / FIXME with no ticket reference.
    lines.forEach((raw, idx) => {
      if (!/(?:\/\/|\/\*|^\s*\*|#)\s*(?:TODO|FIXME|HACK|XXX)\b/.test(raw)) return;
      // A ticket reference: JIRA-123, #123, GH-123, or a tracker URL.
      if (/(?:[A-Z][A-Z0-9]+-\d+|#\d+|https?:\/\/\S+)/.test(raw)) return;
      findings.push(
        finding({
          id: `bloat-todo-no-ticket-${file.path}-${idx + 1}`,
          title: 'TODO or FIXME with no ticket reference',
          severity: 'info',
          cwe: 'CWE-1164',
          file: file.path,
          line: idx + 1,
          evidence: raw.trim().slice(0, 120),
          remediation:
            'An untracked TODO is a note to a person who will not read it again. Either link the ticket that will get it done, or do the work now, or delete the comment and accept the code as it stands. Undated TODOs accumulate until nobody knows which ones still matter.',
        })
      );
    });

    // --- AST-backed checks below this point.
    const ast = parseModule(content);
    if (!ast) return;

    // --- 6. Oversized functions and 7. high cyclomatic complexity.
    const importedNames = new Map(); // local name -> line
    const seenFns = new Set();
    walk(ast, (node, parent) => {
      if (node.type === 'ImportDeclaration') {
        for (const spec of node.specifiers || []) {
          if (spec.local?.name) importedNames.set(spec.local.name, node.loc?.start?.line ?? 1);
        }
        return;
      }
      if (!FN_TYPES.has(node.type) || seenFns.has(node)) return;
      seenFns.add(node);
      const startLine = node.loc?.start?.line;
      const endLine = node.loc?.end?.line;
      const name = fnName(node, parent);
      if (startLine && endLine && endLine - startLine + 1 > BLOAT_FN_LINES) {
        findings.push(
          finding({
            id: `bloat-fn-long-${file.path}-${startLine}`,
            title: `Function "${name}" is ${endLine - startLine + 1} lines`,
            severity: 'medium',
            cwe: 'CWE-1121',
            file: file.path,
            line: startLine,
            evidence: `${endLine - startLine + 1} lines exceeds the ${BLOAT_FN_LINES}-line threshold`,
            remediation: `A function this long is doing several jobs, and no reviewer holds all of it in their head at once. Find the seams (the comment headers inside it are usually the boundaries the generator already saw) and extract each one into a named function. The names become the documentation.`,
          })
        );
      }
      const cc = cyclomaticOf(node);
      if (cc > BLOAT_CYCLOMATIC) {
        findings.push(
          finding({
            id: `bloat-cyclomatic-${file.path}-${startLine}`,
            title: `Function "${name}" has cyclomatic complexity ${cc}`,
            severity: 'medium',
            cwe: 'CWE-1121',
            file: file.path,
            line: startLine ?? 1,
            evidence: `${cc} independent paths exceeds the ${BLOAT_CYCLOMATIC} threshold`,
            remediation: `Complexity ${cc} means ${cc} paths a test suite would need to cover to actually exercise this function. Pull the branch bodies into named functions, replace flag arguments with separate entry points, and use early returns to flatten nesting. Fewer paths is fewer places for a missed case to hide.`,
          })
        );
      }
      // --- 8. Wrapper function that only forwards to another call.
      const body = node.body;
      if (body?.type === 'BlockStatement' && body.body?.length === 1) {
        const only = body.body[0];
        const call =
          only.type === 'ReturnStatement' && only.argument?.type === 'CallExpression'
            ? only.argument
            : only.type === 'ExpressionStatement' && only.expression?.type === 'CallExpression'
              ? only.expression
              : null;
        const params = node.params || [];
        if (
          call &&
          params.length > 0 &&
          params.every((p) => p.type === 'Identifier') &&
          call.arguments.length === params.length &&
          call.arguments.every((a, i) => a.type === 'Identifier' && a.name === params[i].name) &&
          name !== '(anonymous)'
        ) {
          const calleeName =
            call.callee.type === 'Identifier'
              ? call.callee.name
              : call.callee.property?.name || 'the wrapped function';
          if (calleeName !== name) {
            findings.push(
              finding({
                id: `bloat-wrapper-${file.path}-${startLine}`,
                title: `"${name}" only forwards its arguments to ${calleeName}`,
                severity: 'info',
                cwe: 'CWE-1164',
                file: file.path,
                line: startLine ?? 1,
                evidence: `${name}(${params.map((p) => p.name).join(', ')}) => ${calleeName}(...)`,
                remediation: `A pass-through adds a name to learn and a file to open without changing behaviour. If the indirection is deliberate (a seam for testing, a planned API boundary), say so in a comment. Otherwise call ${calleeName} directly and delete the wrapper.`,
              })
            );
          }
        }
      }
    });

    // --- 9. Dead imports: bound but never referenced anywhere else.
    if (importedNames.size) {
      const used = new Set();
      walk(ast, (node, parent) => {
        if (node.type !== 'Identifier') return;
        if (parent?.type === 'ImportSpecifier' || parent?.type === 'ImportDefaultSpecifier') return;
        if (parent?.type === 'ImportNamespaceSpecifier') return;
        if (parent?.type === 'MemberExpression' && parent.property === node && !parent.computed)
          return;
        if (parent?.type === 'Property' && parent.key === node && !parent.computed) return;
        used.add(node.name);
      });
      // JSX component references resolve through JSXIdentifier nodes.
      walk(ast, (node) => {
        if (node.type === 'JSXIdentifier' && node.name) used.add(node.name);
      });
      for (const [name, line] of importedNames) {
        if (used.has(name)) continue;
        findings.push(
          finding({
            id: `bloat-dead-import-${file.path}-${name}`,
            title: `Imported "${name}" is never used`,
            cwe: 'CWE-1164',
            file: file.path,
            line,
            evidence: `import binding "${name}" has no reference in this file`,
            remediation:
              'An unused import still costs a module resolution, can still run the imported module for its side effects, and tells the next reader this file depends on something it does not. Delete the binding. If the import is there purely for a side effect, use the bare form (import "./styles.css") so the intent is explicit.',
          })
        );
      }
      if (importedNames.size > BLOAT_IMPORT_COUNT) {
        findings.push(
          finding({
            id: `bloat-import-count-${file.path}`,
            title: `${importedNames.size} imported bindings in one file`,
            severity: 'info',
            cwe: 'CWE-1121',
            file: file.path,
            line: 1,
            evidence: `${importedNames.size} bindings exceeds the ${BLOAT_IMPORT_COUNT} threshold`,
            remediation:
              'A file that needs this many imports is usually holding several responsibilities that want to be separate modules. Group the imports by what they serve, and each group is a candidate file. This is a shape signal, not a rule.',
          })
        );
      }
    }

    // --- 10. Repeated magic string literals. Uses masked content to find the
    // literals, then counts. Short and obviously-safe values are skipped.
    const strCounts = new Map();
    for (const m of codeOnly.matchAll(/(['"])((?:(?!\1)[^\\\n]|\\.){8,60})\1/g)) {
      const v = m[2];
      if (/^[\s\W]*$/.test(v)) continue; // punctuation-only
      if (/^(?:https?:\/\/|\.\/|\.\.\/|\/)/.test(v)) continue; // paths and URLs
      if (/^[A-Z][a-z]+(?: [a-z]+)+[.!?]?$/.test(v)) continue; // sentence-shaped UI copy
      strCounts.set(v, (strCounts.get(v) || 0) + 1);
    }
    for (const [v, count] of strCounts) {
      if (count < BLOAT_MAGIC_STRING_REPEATS) continue;
      const idx = lines.findIndex((l) => l.includes(v));
      findings.push(
        finding({
          id: `bloat-magic-string-${file.path}-${v.slice(0, 24).replace(/\W/g, '_')}`,
          title: `String "${v.slice(0, 32)}${v.length > 32 ? '…' : ''}" is repeated ${count} times`,
          cwe: 'CWE-1164',
          file: file.path,
          line: idx >= 0 ? idx + 1 : 1,
          evidence: `${count} occurrences of the same literal`,
          remediation:
            'The same literal in several places is the same decision made several times. When it changes, every copy has to be found. Name it once as a const and reference the name. If the copies are meant to be independent, the shared spelling is a coincidence worth making obvious.',
        })
      );
    }
  });
  return findings;
}

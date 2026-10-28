// src/lib/probes/v2/async.js
//
// F2: Async and Promise correctness (docs/preflight-v2-spec.md §F2, 16-probe
// roster). AI models treat `await` as an incantation that makes a promise
// synchronous; when the abstraction leaks you get serialized loops that
// wanted to be parallel, rejections nobody handles, and fetch chains that
// crash on the first 500.
//
// Severity ceiling: MEDIUM — deliberately matching F7. The risk TIER takes
// the worst severity present, and a correctness finding must not brand a
// repo HIGH RISK (pinned by calibration-acceptance-v1). Whether health-axis
// findings should ever reach high is the parked class-ceiling decision;
// until it is made, these families teach at medium and below.
//
// Roster entries deliberately not built, with reasons:
//   #7  awaiting_non_promise — needs type information; a value's
//       promise-ness is invisible to a static line scan.
//   #9  abortcontroller_not_propagated — needs call-graph flow; the
//       observable slice (fetch in an effect without abort) is owned by
//       React Hygiene's cancellation check.
//   #10 promise_race_no_timeout — whether a race arm IS the timeout is
//       unknowable without types; every realistic fixture read both ways.
//   #15 event_handler_no_error_trap — requires inferring which handlers can
//       reject meaningfully; FP-dominated in adversarial modeling.

import { isTestFile, isScannerSelfSource } from '../../file-filter.js';
import { maskCommentsForPath } from '../_internal/masking.js';
import { lineIndex } from './line-index.js';
import { parseModule, walk } from './context.js';

export const ASYNC_LOOP_SPAN_BUDGET = 4000;
export const ASYNC_FILE_RE = /\.(?:[jt]sx?|mjs|cjs)$/i;
const AST_FILE_RE = /\.(?:jsx?|mjs|cjs)$/i;

const IO_CALLEE_RE =
  /\bfetch\s*\(|\baxios\b|\bprisma\.\w+\.(?:find|create|update|delete|upsert|count)|\bsupabase\s*\.\s*from\s*\(|\bdb\.(?:query|execute|collection)|\bfs\.(?:promises\.)?\w+\s*\(|\.query\s*\(|\.exec(?:ute)?\s*\(/;

const finding = (o) => ({
  probe: 'Async Correctness',
  category: 'Code Correctness',
  severity: 'medium',
  cwe: 'CWE-1088',
  ...o,
});

function readBraceSpan(content, openBrace, budget = ASYNC_LOOP_SPAN_BUDGET) {
  let depth = 0;
  const end = Math.min(content.length, openBrace + budget);
  for (let i = openBrace; i < end; i++) {
    const ch = content[i];
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return content.slice(openBrace + 1, i);
    }
  }
  return null;
}

export function probeAsyncCorrectness(files) {
  const findings = [];
  const pkgs = files.filter(
    (f) => /(^|\/)package\.json$/.test(f.path) && !/node_modules/.test(f.path)
  );
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!ASYNC_FILE_RE.test(file.path)) return;
    const content = file.content || '';
    if (!content.trim()) return;
    // The gate must cover every check's trigger vocabulary, not just the
    // async keywords: the floating-call and JSON.parse checks fire on files
    // that never say async at all.
    if (
      !/\basync\b|\bawait\b|\.then\s*\(|Promise\b|\bfetch\s*\(|JSON\.parse\s*\(|\.(?:save|send|write|commit|flush|sync|deleteOne|insertOne|updateOne)\s*\(/.test(
        content
      )
    )
      return;
    const code = maskCommentsForPath(file.path, content);
    const lineAt = lineIndex(content);
    const codeLines = code.split('\n');
    const rawLines = content.split('\n');
    const push = (line, o) =>
      findings.push(
        finding({
          file: file.path,
          line,
          evidence: (rawLines[line - 1] ?? '').trim().slice(0, 160),
          ...o,
        })
      );

    // 3. await on an IO call inside a loop: N round trips, one at a time.
    //    Opt-out: a `/* serial */` marker on the loop line (read from the RAW
    //    line, since comments are blanked in the match view).
    // The header admits two levels of nested parens: `for (const id of
    // Object.keys(map))` and `for (const x of items.filter((i) => i.ok))`
    // were invisible to a `[^)]*` header (Gate-3 G7, G38). The alternatives
    // are disjoint, so the scan stays linear.
    const loopRe =
      /\b(?:for|while)\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)\s*(\{)|\bfor\s+await\s*\(/g;
    let lm;
    while ((lm = loopRe.exec(code)) !== null) {
      if (!lm[1]) continue; // `for await` is already streaming; not this shape
      const openBrace = lm.index + lm[0].length - 1;
      const span = readBraceSpan(code, openBrace);
      if (span === null) continue;
      const ln = lineAt(lm.index);
      if (/\/\*\s*serial\s*\*\//.test(rawLines[ln - 1] ?? '')) continue;
      // Only the pure fan-out shape fires: the awaited call must use the
      // loop variable, and the body must not feed one iteration into the
      // next. Corpus round 2026-09-03: 73 highs on the FP canary, most of
      // them deliberate sequential processing — serial-by-design is a
      // choice, not a defect, so this teaches at medium and only where the
      // parallel rewrite is mechanical.
      const header = code.slice(lm.index, openBrace);
      // Gate-2: for...of/in, C-style for (let i = 0; …) and while all
      // count — two of the three loop forms the Learn page names were
      // structurally unreachable.
      const loopVar = (header.match(/\b(?:const|let|var)?\s*(\w+)\s*(?:of|in)\b/) ||
        header.match(/for\s*\(\s*(?:let|var)\s+(\w+)\s*=/) ||
        [])[1];
      const isWhileLoop = /^\s*while\b/.test(header);
      const awaitUsesLoopVar =
        (loopVar && new RegExp(`await[^;\\n]*\\b${loopVar}\\b`).test(span)) ||
        (!loopVar && isWhileLoop);
      // Dependent when any variable REASSIGNED in the loop body is also read
      // by an await expression — that covers cursor threading
      // (`cursor = page.rows.at(-1).id` feeding the next query) and every
      // accumulator spelling, not just a name list (Gate-1: cursor
      // pagination and ordered migrations drew the parallelize advice,
      // which would corrupt both). Migration paths are serial by contract.
      // Gate-2: string-blanked, line-split — awaited reads come from await
      // lines, reassignments from the OTHER lines, so `page = await next()`
      // does not vouch for itself and text inside literals never counts.
      const shapeLines = span.replace(/(['"`])(?:(?!\1)[^\\\n]|\\.)*\1/g, "''").split('\n');
      const awaitExprs = shapeLines.filter((l) => /\bawait\b/.test(l)).join(' ');
      // REassignments only: a fresh `const r = await …` declares the fan-out
      // result, it does not thread state between iterations.
      const spanNoDecl = shapeLines
        .filter((l) => !/\bawait\b/.test(l))
        .join('\n')
        .replace(/\b(?:const|let|var)\s+[\w{[\], ]+\s*=/g, '§');
      const reassigned = [...spanNoDecl.matchAll(/(?:^|[^=!<>+\-*/§])\b(\w+)\s*=(?![=>])/g)].map(
        (x) => x[1]
      );
      const feedsForward =
        reassigned.some((n) => new RegExp(`\\b${n}\\b`).test(awaitExprs)) ||
        /migrat/i.test(file.path);
      if (/\bawait\b/.test(span) && IO_CALLEE_RE.test(span) && awaitUsesLoopVar && !feedsForward) {
        push(ln, {
          id: `async-await-in-loop-${file.path}-${ln}`,
          title: 'Awaited I/O inside a loop runs serially',
          severity: 'medium',
          remediation:
            'Ten items means ten round trips, one at a time; the total is the sum of every latency. Map the items to promises and await Promise.all(items.map(async (item) => ...)) so they run together. If the iterations genuinely depend on each other, mark the loop with /* serial */ and this finding stands down.',
        });
      }
    }

    codeLines.forEach((line, i) => {
      const ln = i + 1;
      // 16. .forEach(async ...) — the promises are dropped on the floor.
      if (/\.forEach\s*\(\s*async\b/.test(line)) {
        push(ln, {
          id: `async-foreach-${file.path}-${ln}`,
          title: 'async callback passed to forEach',
          severity: 'medium',
          remediation:
            'forEach ignores the returned promises: nothing waits for them, and a rejection in any of them is unhandled. Use for...of with await for serial work, or await Promise.all(items.map(async ...)) for parallel.',
        });
      }
      // 11. useEffect(async () => ...) — React reads the returned promise as
      //     the cleanup function.
      if (/\buse(?:Layout)?Effect\s*\(\s*async\b/.test(line)) {
        push(ln, {
          id: `async-effect-${file.path}-${ln}`,
          title: 'useEffect callback declared async',
          severity: 'medium',
          remediation:
            'An async function returns a promise, and React treats an effect’s return value as the cleanup function, so the cleanup is silently a promise and never runs. Keep the effect synchronous and define an inner async function to call, or use an IIFE.',
        });
      }
      // 5. new Promise(async ...) — rejections inside vanish.
      if (/\bnew\s+Promise\s*\(\s*async\b/.test(line)) {
        push(ln, {
          id: `async-promise-ctor-${file.path}-${ln}`,
          title: 'async executor passed to new Promise',
          severity: 'medium',
          remediation:
            'A throw inside an async executor rejects the executor’s own promise, which nothing holds, not the one being constructed, so errors vanish. The function is already async: drop the wrapper and use await directly.',
        });
      }
      // 6. Mixing then-chains and await on one statement.
      // Bounded: open-ended `[^;]*` rescanned to end-of-line from every
      // await on a semicolon-free minified line (Gate-3 G17).
      if (/\bawait\b[^;]{0,300}\.then\s*\(/.test(line)) {
        push(ln, {
          id: `async-mixed-${file.path}-${ln}`,
          title: 'await and .then mixed in one expression',
          severity: 'low',
          remediation:
            'Both spellings work; using them together hides which value is awaited and where a rejection lands. Pick await, move the .then body after it, and let one try/catch own the errors.',
        });
      }
      // 2. Promise.all over a request-derived collection with no bound.
      // Gate-1: multer's upload.array('x', N) / limits: { files: N } bounds
      // the array before the handler runs — a bounded fan-out is fine.
      if (
        /Promise\.all\s*\(/.test(line) &&
        /\b(?:req|request|ctx|body|params|input|payload)\b[^)]*\.map\s*\(/.test(line) &&
        !/limits\s*:|\.array\s*\(\s*['"][^'"]+['"]\s*,\s*\d|\.max\s*\(\s*\d|slice\s*\(\s*0\s*,/.test(
          code
        )
      ) {
        push(ln, {
          id: `async-unbounded-all-${file.path}-${ln}`,
          title: 'Promise.all fans out over request-sized input',
          severity: 'medium',
          remediation:
            'The caller controls the array length, so the caller controls your concurrency: a 10,000-item body is 10,000 simultaneous requests from your server. Chunk the work or run it through a small worker pool with a fixed limit.',
        });
      }
      // 12. fetch response used without an ok/status check nearby.
      const fm = line.match(/(\w+)\s*=\s*await\s+fetch\s*\(/);
      if (fm) {
        const windowText = codeLines.slice(i, Math.min(codeLines.length, i + 6)).join('\n');
        const name = fm[1];
        // A response handed to any helper before parsing counts as a
        // delegated check — `ensureOk(res)` / `checkStatus(res)` is the
        // factored-out shape every multi-fetch codebase writes (Gate-1).
        // Gate-2: console.log(res) is not a status check — logging callees
        // do not count as delegation.
        const delegatedCheck = [
          ...windowText.matchAll(new RegExp(`([\\w.$]+)\\s*\\(\\s*${name}\\s*[),]`, 'g')),
        ].some((m) => !/(?:^|\.)(?:log|warn|error|info|debug|trace|dir)$/.test(m[1]));
        if (
          new RegExp(`\\b${name}\\s*\\.\\s*json\\s*\\(`).test(windowText) &&
          !new RegExp(`\\b${name}\\s*\\.\\s*(?:ok|status)\\b`).test(windowText) &&
          !delegatedCheck
        ) {
          push(ln, {
            id: `async-no-ok-check-${file.path}-${ln}`,
            title: 'fetch response parsed without checking res.ok',
            severity: 'medium',
            remediation:
              'fetch only rejects on network failure; a 500 resolves normally and .json() then throws on the HTML error page, or hands your code an error body as if it were data. Check res.ok (or res.status) before parsing, and throw with the status when it is false.',
          });
        }
      }
      // 14. JSON.parse over storage/request input with no try nearby.
      if (
        /JSON\.parse\s*\(\s*(?:localStorage|sessionStorage|req\.|request\.|params|atob\()/.test(
          line
        ) &&
        // 20-line lookback: a storage-restore function routinely has a few
        // validation lines between its try and the parse (Gate-1: a fully
        // guarded restoreSession drew the finding at the 6-line window).
        !/\btry\b/.test(codeLines.slice(Math.max(0, i - 20), i + 1).join('\n'))
      ) {
        push(ln, {
          id: `async-json-parse-${file.path}-${ln}`,
          title: 'JSON.parse on external input without try/catch',
          severity: 'medium',
          remediation:
            'Storage can hold anything an old version wrote and a request can carry anything at all; one malformed value throws and takes the whole handler with it. Wrap the parse in try/catch and fall back to a default.',
        });
      }
    });

    // 8. Top-level async entry called without a rejection handler.
    if (
      /\basync\s+function\s+main\b/.test(code) &&
      /^\s*(?:void\s+)?main\s*\(\s*\)\s*;?\s*$/m.test(code) &&
      !/main\s*\(\s*\)\s*\.\s*catch/.test(code)
    ) {
      const idx = code.search(/^\s*(?:void\s+)?main\s*\(\s*\)\s*;?\s*$/m);
      push(lineAt(idx), {
        id: `async-main-unhandled-${file.path}`,
        title: 'async main() called without .catch',
        severity: 'medium',
        remediation:
          'If main rejects, the process gets an unhandled rejection: a warning today, a crash under --unhandled-rejections=strict and in newer runtimes. Call main().catch((err) => { console.error(err); process.exit(1); }).',
      });
    }

    // 4. Route handler awaits with no try boundary. AST-free heuristic: the
    //    handler callback opened on app/router.<verb>( with an async
    //    callback whose span contains await and no try.
    // Gate-1 framework awareness: a wrapper like asyncHandler() IS the
    // recommended fix, and Fastify / Express 5 forward async rejections to
    // their error handling by design — flagging them tells users their
    // correct code is broken.
    // Gate-2: fastify counts only as an IMPORT (a string mention in a
    // response body stood the check down file-wide), and wrapper vocabulary
    // credits only the route it wraps — a half-adopted asyncHandler file is
    // MORE likely to hold the unwrapped defect.
    const autoHandledFramework =
      /require\s*\(\s*['"]fastify['"]|from\s+['"]fastify['"]/.test(code) ||
      pkgs.some((f) => /"express"\s*:\s*"[\^~]?5/.test(f.content || ''));
    const routeRe =
      /\b(?:app|router|server)\s*\.\s*(?:get|post|put|patch|delete)\s*\([^)]*?async\s*(?:\([^)]*\)|\w+)\s*=>\s*(\{)/g;
    let rm;
    while ((rm = routeRe.exec(code)) !== null) {
      if (autoHandledFramework) break;
      if (/\b(?:asyncHandler|wrapAsync|catchAsync|asyncWrap)\s*\(/.test(rm[0])) continue;
      const span = readBraceSpan(code, rm.index + rm[0].length - 1);
      if (span === null) continue;
      if (/\bawait\b/.test(span) && !/\btry\b/.test(span)) {
        const ln = lineAt(rm.index);
        push(ln, {
          id: `async-route-boundary-${file.path}-${ln}`,
          title: 'Route handler awaits without a try boundary',
          severity: 'medium',
          remediation:
            'Any awaited failure inside the handler becomes an unhandled rejection; Express 4 never sends a response and the client hangs until timeout. Wrap the body in try/catch and answer with a status, or use an async error wrapper middleware.',
        });
      }
    }

    // 1. Floating promise: a known-async call in statement position, result
    //    dropped. AST-only (statement position is a tree fact).
    if (!AST_FILE_RE.test(file.path)) return;
    const ast = parseModule(content);
    if (!ast) return;
    walk(ast, (node) => {
      if (node.type !== 'ExpressionStatement') return;
      const e = node.expression;
      if (e?.type !== 'CallExpression') return;
      const calleeText = content.slice(e.callee.start, e.callee.end);
      // send/write removed from the suffix set — Gate-1: Express res.send()
      // returns the Response synchronously and WebSocket#send returns void;
      // "await it" was impossible advice on the most common server lines.
      if (
        !/^(?:fetch|Promise\.(?:all|allSettled|race|any)|\w+\.(?:save|commit|flush|deleteOne|insertOne|updateOne))$/.test(
          calleeText
        ) ||
        /^(?:res|response|reply|ctx)\./.test(calleeText)
      )
        return;
      push(lineAt(node.start), {
        id: `async-floating-${file.path}-${node.start}`,
        title: `Result of ${calleeText}() is not awaited or handled`,
        severity: 'medium',
        remediation:
          'The call starts, nothing waits for it, and its rejection is unhandled: work races the response and failures vanish. await it, return it, or if fire-and-forget is truly intended, mark it with void and attach a .catch.',
      });
    });
  });
  return findings;
}

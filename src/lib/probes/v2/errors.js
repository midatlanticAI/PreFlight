// src/lib/probes/v2/errors.js
//
// F3: Error handling (docs/preflight-v2-spec.md §F3, 22-probe roster; the
// largest family per arXiv:2603.28592 — broad exception handling sits in the
// top five smell rules across 484,606 issues in 304k AI-authored commits).
// Errors are signals; AI-generated code treats them like garbage to hide.
//
// Severity ceiling: MEDIUM — deliberately matching F7. The risk TIER takes
// the worst severity present, and a correctness finding must not brand a
// repo HIGH RISK (pinned by calibration-acceptance-v1). Whether health-axis
// findings should ever reach high is the parked class-ceiling decision;
// until it is made, these families teach at medium and below.
//
// Roster entries deliberately not built, with reasons:
//   #4  console_log_as_handling — merged into #1: a catch whose only use of
//       the error is console.* IS the broad-catch-swallow shape.
//   #6  generic_message / #7 try_around_safe_code / #12 no_error_class_
//       hierarchy — style judgments with no defect boundary a deterministic
//       probe can defend; every adversarial fixture was arguable.
//   #11 log_but_continue — merged into #1's alternation (console/logger/log).
//   #15 fetch_error_returns_empty_data — merged into #9: returning a default
//       from catch is one shape whatever the default's type.
//   #17 db_error_wrong_message / #18 network_treated_as_app /
//   #19 validation_as_system — classification of the error's KIND needs
//       semantics a line scan does not have (spec confidence: low).
//   #21 multiple_catches_overlap — a JS try has one catch; the TS/instanceof
//       chain variant needs type narrowing analysis.
//   #13 async_try_no_catch (try/finally around await) — REMOVED after the
//       first corpus round: 44 hits on the FP canary, and nearly all were
//       the correct acquire/clean-up/propagate idiom where a caller owns
//       the failure. Whether anything upstream catches is not knowable from
//       one file, and a probe should not call a correct idiom a defect.

import { isTestFile, isScannerSelfSource } from '../../file-filter.js';
import { maskCommentsForPath, maskCodeShapeForPath } from '../_internal/masking.js';
import { lineIndex } from './line-index.js';

export const ERRORS_FILE_RE = /\.(?:[jt]sx?|mjs|cjs)$/i;
export const ERRORS_CATCH_SPAN_BUDGET = 2500;

const finding = (o) => ({
  probe: 'Error Handling',
  category: 'Code Correctness',
  severity: 'medium',
  cwe: 'CWE-755',
  ...o,
});

// Catch parameters go into dynamic patterns escaped ($err is legal).
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function readBraceSpan(content, openBrace, budget = ERRORS_CATCH_SPAN_BUDGET) {
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

export function probeErrorHandling(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    const isPy = /\.py$/i.test(file.path);
    if (!ERRORS_FILE_RE.test(file.path) && !isPy) return;
    const content = file.content || '';
    if (!content.trim()) return;
    const code = maskCommentsForPath(file.path, content);
    // String-blind view for the catch scanner: a `}` inside a log string
    // closed the block before its throw, so a catch that rethrew with cause
    // was reported as a swallow, and the catch parameter spelled inside a
    // string ('e-mail failed') counted as a use (Gate-3 G9, G39). Masks
    // preserve length, so offsets read the same source on every view.
    const shape = maskCodeShapeForPath(file.path, content);
    const lineAt = lineIndex(content);
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

    // ---- Python: resources opened outside `with` (#16) ----
    if (isPy) {
      const pyLines = code.split('\n');
      pyLines.forEach((line, i) => {
        // Gate-1: try/finally f.close() is semantically `with` — the handle
        // closes on every path; only an unguarded open is the lesson.
        const followed = pyLines.slice(i + 1, i + 12).join('\n');
        const finallyCloses = /finally\s*:[\s\S]{0,160}\.close\s*\(/.test(followed);
        if (/^\s*\w+\s*=\s*open\s*\(/.test(line) && !/\bwith\b/.test(line) && !finallyCloses) {
          push(i + 1, {
            id: `errors-py-open-${file.path}-${i}`,
            title: 'File opened without a with block',
            severity: 'medium',
            cwe: 'CWE-772',
            remediation:
              'If anything between open() and close() raises, the handle leaks; enough of those and the process hits the descriptor limit. Use `with open(...) as f:` and the file closes on every path, including the failing ones.',
          });
        }
      });
      return; // the JS catch checks below do not apply to Python
    }

    // ---- catch-block checks (1, 2, 3, 9, 10, 20, 22, 13) ----
    // The parameter may be typed (`catch (e: unknown)`, the TypeScript
    // spelling in every .ts file this family claims) or destructured
    // (`catch ({ message })`); the first draft accepted a bare identifier
    // only, so every catch check was dead in typed code (Gate-3 G8, G40).
    // A destructured parameter has no single name to count uses of and is
    // treated like a bare `catch {`.
    const catchRe =
      /\bcatch\s*(?:\(\s*(?:([A-Za-z_$][\w$]*)(?:\s*:\s*[\w$.<>[\]| ]+)?|\{[^}]{0,200}\})\s*\))?\s*(\{)/g;
    let cm;
    while ((cm = catchRe.exec(shape)) !== null) {
      const param = cm[1] || null;
      const openBrace = cm.index + cm[0].length - 1;
      const span = readBraceSpan(shape, openBrace);
      if (span === null) continue;
      const body = span.trim();
      const ln = lineAt(cm.index);

      // 2. Entirely empty catch.
      if (body === '') {
        push(ln, {
          id: `errors-empty-catch-${file.path}-${ln}`,
          title: 'Empty catch block',
          severity: 'medium',
          cwe: 'CWE-1069',
          remediation:
            'Every failure in the try block now vanishes without a trace: network down, auth expired, parse failed, all identical, all silent. Read the signal and decide: show the user a message, retry, or rethrow so something upstream can.',
        });
        continue;
      }
      // 1 (+4, +11 merged). The error is used only to log it, or never used.
      // Counted on the string-blind body. Template interpolations survive
      // the mask as code, so `errors.push(`failed: ${err.message}`)` is a
      // use and `showBanner('e-mail failed')` is not.
      const rawSpan = content.slice(openBrace + 1, openBrace + 1 + span.length);
      const paramUses = param
        ? [...body.matchAll(new RegExp(`(?<![\\w$])${esc(param)}(?![\\w$])`, 'g'))].length
        : 0;
      // Handling signals: anything that answers, surfaces, retries, or
      // propagates. Sending a response IS handling — the first draft called
      // `catch (e) { res.status(500).json(…) }` a swallow (caught by an
      // overlap fixture before it ever reached a corpus).
      const HANDLED_RE =
        /\bthrow\b|\breturn\b|\bset[A-Z]|\bres\s*\.|\bresponse\s*\.|\breply\s*[.(]|\bctx\s*\.|\bnext\s*\(|process\.exit|\bdispatch\b|\btoast\b|\balert\s*\(|\bnotify|\bretry|\brollback|\bcapture(?:Exception|Message)\b|Sentry\.|metrics?\b|statsd|prometheus|\bincrement\s*\(|\.inc\s*\(|telemetry/;
      // Gate-2: the mask keeps comment DELIMITERS, so `console.log(e); //`
      // broke the anchored log-only test and every commented swallow walked;
      // and "retrying" inside a log STRING is prose, not a retry. Strip
      // comment remnants and blank string literals before either test.
      const bodyShape = body
        .replace(/\/\/.*$/gm, '')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/(['"`])(?:(?!\1)[^\\\n]|\\.)*\1/g, "''")
        .trim();
      const logOnly =
        (/^(?:(?:console|logger|log)\s*\.\s*\w+\s*\([^;]*\)\s*;?\s*)+$/.test(bodyShape) &&
          !HANDLED_RE.test(bodyShape)) ||
        (param !== null && paramUses === 0 && !HANDLED_RE.test(bodyShape));
      if (logOnly) {
        // A swallow the author explained is still a swallow, but a
        // documented best-effort ignore (`catch (removeErr) { // best
        // effort }`) is a decision, not an accident — corpus round
        // 2026-09-03. The mask is length-preserving, so the raw span sits
        // at the same indices.
        const explained = /\/\/|\/\*/.test(rawSpan);
        push(ln, {
          id: `errors-catch-swallow-${file.path}-${ln}`,
          title: 'Catch swallows the error',
          severity: explained ? 'low' : 'medium',
          cwe: 'CWE-1069',
          remediation:
            'Logging and moving on is taping over the warning light: the stack trace you need at 2am is in the console of a user you will never meet, and the app continues in an undefined state. Set error state the UI can show, retry, or rethrow for an upstream boundary. Catching is not handling.',
        });
        continue;
      }
      // 3. Bare rethrow with no transformation.
      if (param && new RegExp(`^throw\\s+${esc(param)}\\s*;?$`).test(body)) {
        push(ln, {
          id: `errors-bare-rethrow-${file.path}-${ln}`,
          title: 'Catch only rethrows the same error',
          severity: 'info',
          remediation:
            'catch (e) { throw e; } is a no-op with extra stack noise. Delete the try/catch, or make the catch earn its place: add context with `throw new Error("loading profile failed", { cause: e })`.',
        });
      }
      // 10. Rethrow that drops the stack.
      // Gate-1: `new Error(e.message, { cause: e })` KEEPS the original,
      // stack included — it is this probe's own recommended fix.
      if (
        param &&
        new RegExp(`throw\\s+new\\s+Error\\s*\\(\\s*${esc(param)}\\s*\\.\\s*message`).test(body) &&
        !/\bcause\s*:/.test(body)
      ) {
        push(ln, {
          id: `errors-lost-stack-${file.path}-${ln}`,
          title: 'Rethrow keeps the message and drops the stack',
          severity: 'low',
          remediation:
            'new Error(e.message) starts a fresh stack at this line; where it actually failed is gone. Pass the original along: throw new Error("context", { cause: e }).',
        });
      }
      // 9 (+15 merged). Catch quietly returns a default.
      if (
        /^return\s+(?:\[\s*\]|\{\s*\}|null|undefined|false|''|""|\{\s*data\s*:\s*\[\s*\]\s*\})\s*;?$/.test(
          body
        ) ||
        (param &&
          paramUses === 0 &&
          /^return\s+(?:\[\s*\]|\{\s*\}|null|undefined|false)/.test(body))
      ) {
        // `catch { return null; }` with NO parameter is the author
        // explicitly discarding the error — a deliberate optional-probe
        // idiom on the corpus (68 hits, mostly bare) — so it teaches at
        // info; taking the parameter and then ignoring it stays medium.
        push(ln, {
          id: `errors-default-return-${file.path}-${ln}`,
          title: 'Catch returns a default and hides the failure',
          severity: param === null ? 'info' : 'medium',
          remediation:
            'The caller receives an empty list and renders an empty screen; nobody, including you, learns the request failed. Return the default if that is truly the design, but record the error first and give the UI a way to say "could not load" instead of "nothing here".',
        });
      }
      // 20. Catch parameter shadowed by a nested catch with the same name.
      if (param && new RegExp(`catch\\s*\\(\\s*${esc(param)}\\s*[:)]`).test(span)) {
        push(ln, {
          id: `errors-shadowed-catch-${file.path}-${ln}`,
          title: `Nested catch shadows outer parameter ${param}`,
          severity: 'low',
          remediation:
            'Inside the nested catch, the outer error is unreachable behind the same name, and it is easy to log or rethrow the wrong one. Name them for what they are: outerErr, retryErr.',
        });
      }
      // 22. Cleanup in catch instead of finally.
      // Gate-1: res.status(500).end() terminates the HTTP error response,
      // not a resource — response receivers are exempt, and bare `.end(`
      // left the verb list (it is overwhelmingly the response API).
      const cleanupCall = body.match(/(\w+)\s*\.\s*(?:close|release|disconnect|destroy)\s*\(/);
      if (
        cleanupCall !== null &&
        !/^(?:res|response|reply|ctx)$/.test(cleanupCall[1]) &&
        !/\bfinally\b/.test(code.slice(openBrace, openBrace + span.length + 40))
      ) {
        push(ln, {
          id: `errors-cleanup-in-catch-${file.path}-${ln}`,
          title: 'Cleanup runs in catch, not finally',
          severity: 'medium',
          cwe: 'CWE-772',
          remediation:
            'Cleanup in the catch runs only on failure; the success path leaks the same resource. Move close/release/disconnect into finally so both paths pay the same bill.',
        });
      }
    }

    // 5. Throwing a non-Error value.
    code.split('\n').forEach((line, i) => {
      if (/\bthrow\s+(?:['"`]|\{|\[|\d)/.test(line)) {
        push(i + 1, {
          id: `errors-throw-nonerror-${file.path}-${i}`,
          title: 'Non-Error value thrown',
          severity: 'medium',
          remediation:
            'A thrown string or object literal has no stack trace, fails instanceof Error checks, and prints as [object Object] in half the log pipelines. Throw new Error("message") — subclass it if callers need to distinguish kinds.',
        });
      }
      // 14. Rejection logged, never propagated.
      // Gate-1/Gate-2: `void job().catch(console.error)` is verbatim what
      // the Async Correctness floating-promise remediation instructs for
      // intended fire-and-forget — one family must not fine the other's
      // fix — so the void form teaches at info instead of standing down.
      if (
        /\.catch\s*\(\s*(?:console\.\w+|(?:\(\s*\w+\s*\)|\w+)\s*=>\s*console\.\w+\s*\([^)]*\)\s*)\)/.test(
          line
        )
      ) {
        const isVoided = /\bvoid\s/.test(line);
        push(i + 1, {
          id: `errors-catch-console-${file.path}-${i}`,
          title: 'Rejection logged and dropped in .catch',
          severity: isVoided ? 'info' : 'medium',
          remediation:
            '.catch(console.error) converts a failure into a log line and a success, and everything after proceeds as if the data arrived. Handle it where the promise is consumed: set error state, retry, or rethrow. With void in front the drop is declared intent, so this only asks you to confirm the failure truly needs no follow-up.',
        });
      }
      // 27 (Gate-2). Rejection swallowed by an EMPTY .catch handler — worse
      // than logging: the failure leaves no trace at all.
      if (
        /\.catch\s*\(\s*(?:\(\s*\w*\s*\)|\w+)?\s*=>\s*(?:\{\s*\}|null|undefined)\s*\)|\.catch\s*\(\s*function\s*\([^)]*\)\s*\{\s*\}\s*\)/.test(
          line
        )
      ) {
        push(i + 1, {
          id: `errors-catch-empty-${file.path}-${i}`,
          title: 'Rejection silenced by an empty .catch',
          severity: /\bvoid\s/.test(line) ? 'info' : 'medium',
          cwe: 'CWE-1069',
          remediation:
            '.catch(() => {}) deletes the failure: no log line, no error state, no retry, and the await above resolves to undefined as if that were data. At minimum log it; better, set error state or rethrow so something upstream decides.',
        });
      }
    });
  });

  // 8. React project with no error boundary anywhere: one render throw
  //    blanks the page. Fires once, on the first JSX file.
  const jsxFiles = files.filter(
    (f) => /\.(?:jsx|tsx)$/i.test(f.path) && !isTestFile(f.path) && !isScannerSelfSource(f.path)
  );
  if (jsxFiles.length >= 3) {
    const hasBoundary = files.some(
      (f) =>
        (/componentDidCatch|getDerivedStateFromError|react-error-boundary|ErrorBoundary/.test(
          f.content || ''
        ) ||
          // Next.js App Router: app/**/error.tsx and global-error.tsx ARE
          // generated error boundaries by file convention (Gate-1).
          /(^|\/)app\/(?:.*\/)?(?:global-)?error\.(?:jsx|tsx|js|ts)$/.test(f.path)) &&
        !isTestFile(f.path)
    );
    if (!hasBoundary) {
      findings.push(
        finding({
          id: `errors-no-boundary-${jsxFiles[0].path}`,
          title: 'No error boundary anywhere in a React app',
          severity: 'medium',
          file: jsxFiles[0].path,
          line: 1,
          evidence: `${jsxFiles.length} component files, no componentDidCatch / react-error-boundary anywhere`,
          remediation:
            'One throw during render unmounts the entire tree: white screen, no message, nothing to click. Add one boundary near the root and smaller ones around risky islands (feeds, editors, third-party widgets) so a failure blanks a card instead of the app.',
        })
      );
    }
  }
  return findings;
}

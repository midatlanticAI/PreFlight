// src/lib/probes/v2/api-patterns.js
//
// F11: Backend and API patterns (docs/preflight-v2-spec.md §F11, 11-probe
// roster). Tenzai's 15-app AI-codegen study: 0 of 15 shipped rate limiting
// that held, and validation was the exception, not the rule.
//
// Severity ceiling: MEDIUM — deliberately matching F7. The risk TIER takes
// the worst severity present, and a correctness finding must not brand a
// repo HIGH RISK (pinned by calibration-acceptance-v1). Whether health-axis
// findings should ever reach high is the parked class-ceiling decision;
// until it is made, these families teach at medium and below. The
// clearly-security members of the roster are owned by existing security
// probes and declined below.
//
// Roster entries deliberately not built, with reasons:
//   cors_wildcard_with_credentials — owned by the existing CORS probe.
//   n_plus_1_in_handler — owned by Async Correctness (await-in-loop).
//   background_task_fire_and_forget — owned by Async Correctness (floating
//       calls) and the Code Quality fire-and-forget checks.
//   endpoint_returns_more_than_client_needs — needs the client; a handler
//       alone cannot show overfetch.
//   middleware_order_incorrect — "correct" depends on intent; modeling
//       produced arguable fixtures only.
//   websocket_no_ping_pong — narrow, framework-dependent, low yield.

import { isTestFile, isScannerSelfSource } from '../../file-filter.js';
import { maskCommentsForPath } from '../_internal/masking.js';
import { lineIndex } from './line-index.js';

export const API_FILE_RE = /\.(?:[jt]sx?|mjs|cjs|py)$/i;

const finding = (o) => ({
  probe: 'API Patterns',
  category: 'Auth & Access',
  severity: 'medium',
  cwe: 'CWE-20',
  ...o,
});

function readBraceSpan(content, openBrace, budget = 4000) {
  let depth = 0;
  const end = Math.min(content.length, openBrace + budget);
  for (let i = openBrace; i < end; i++) {
    if (content[i] === '{') depth++;
    else if (content[i] === '}') {
      depth--;
      if (depth === 0) return content.slice(openBrace + 1, i);
    }
  }
  return null;
}

export function probeApiPatterns(files) {
  const findings = [];
  const projectHasRateLimit = files.some((f) =>
    /express-rate-limit|rate-limiter-flexible|@upstash\/ratelimit|hono\/rate-limit|slowapi|django-ratelimit|flask-limiter|\bratelimit\b|limit_req|rate_limit/i.test(
      f.content || ''
    )
  );

  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!API_FILE_RE.test(file.path)) return;
    const content = file.content || '';
    if (!content.trim()) return;
    const isPy = /\.py$/i.test(file.path);
    if (!/\.(?:post|put|patch|get|delete)\s*\(|@(?:app|router)\.|async\s+def/.test(content)) return;
    const code = maskCommentsForPath(file.path, content);
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

    if (isPy) {
      // Blocking call inside an async handler: one slow request stalls the
      // event loop for everyone.
      const lines = code.split('\n');
      let inAsyncDef = false;
      let asyncIndent = 0;
      lines.forEach((line, i) => {
        const dm = line.match(/^(\s*)async\s+def\s+\w+/);
        if (dm) {
          inAsyncDef = true;
          asyncIndent = dm[1].length;
          return;
        }
        if (inAsyncDef) {
          const ind = (line.match(/^(\s*)\S/) || [null, null])[1];
          if (ind !== null && ind.length <= asyncIndent && line.trim() !== '') inAsyncDef = false;
        }
        if (
          inAsyncDef &&
          // Gate-1: a bare psycopg2 mention in an except clause is an
          // exception-class reference, and asyncio.to_thread IS the fix —
          // only actual blocking CALLS outside to_thread count.
          !/to_thread|run_in_executor/.test(line) &&
          !/^\s*except\b/.test(line) &&
          /\btime\.sleep\s*\(|\brequests\.(?:get|post|put|delete)\s*\(|\bpsycopg2\.\w+\s*\(|\bsqlite3\.connect\s*\(/.test(
            line
          )
        ) {
          push(i + 1, {
            id: `api-blocking-async-${file.path}-${i}`,
            title: 'Blocking call inside an async handler',
            severity: 'medium',
            remediation:
              'time.sleep and the synchronous requests/DB clients block the event loop itself, so while this handler waits, EVERY request waits. Use the async versions (asyncio.sleep, httpx.AsyncClient, an async driver) or run the sync work in a thread with asyncio.to_thread.',
          });
        }
      });
      return;
    }

    // JS route handlers.
    const routeRe =
      /\b(?:app|router|server)\s*\.\s*(post|put|patch)\s*\(\s*['"`]([^'"`\n]{1,80})['"`][\s\S]{0,120}?(?:=>|function[^{]*)\s*(\{)/g;
    let rm;
    while ((rm = routeRe.exec(code)) !== null) {
      const routePath = rm[2];
      const span = readBraceSpan(code, rm.index + rm[0].length - 1);
      if (span === null) continue;
      const ln = lineAt(rm.index);

      // Request body fed to persistence with no validation signal in scope.
      const writesFromBody =
        /\breq\.body\b/.test(span) &&
        /\.(?:create|insert|insertOne|save|update|updateOne|query|execute|run)\s*\(/.test(span);
      const validates =
        /\b(?:zod|joi|yup|ajv|valibot|typia|arktype|superstruct|io-ts|runtypes|celebrate)\b|class-validator|validateOrReject|plainToInstance|\.parse\s*\(|\.safeParse\s*\(|\.validate(?:Async|Sync)?\s*\(|validationResult\s*\(|express-validator|assert\w*\(|schema\s*:/i.test(
          span + code.slice(0, 800)
        );
      if (writesFromBody && !validates) {
        push(ln, {
          id: `api-no-validation-${file.path}-${ln}`,
          title: `${routePath} writes request body without validation`,
          severity: 'medium',
          remediation:
            "Whatever arrives is whatever gets stored: missing fields, wrong types, 10 MB strings, extra keys your later code trusts. Parse the body through a schema at the top of the handler (zod's schema.parse(req.body) is one line) and everything after it works with known-shaped data.",
        });
      }
      // Login/auth route with no rate limiting anywhere in the project.
      // Gate-1: 'auth' matched inside '/authors' — segments, not
      // substrings, and bare 'token' is out (design-tokens, push-tokens).
      const routeSegs = routePath.toLowerCase().split(/[/\-_.]+/);
      const credentialRoute = routeSegs.some((seg) =>
        ['login', 'signin', 'auth', 'password', 'session', 'register', 'reset'].includes(seg)
      );
      if (credentialRoute && !projectHasRateLimit) {
        push(ln, {
          id: `api-no-ratelimit-${file.path}-${ln}`,
          title: `${routePath} has no rate limiting in the project`,
          severity: 'medium',
          cwe: 'CWE-307',
          remediation:
            'An unthrottled credential endpoint hands attackers unlimited guesses at machine speed. Add a limiter in front of the auth routes (express-rate-limit is a few lines; hosted platforms have an edge switch) with a tight per-IP budget on failures.',
        });
      }
      // Response sent, execution continues into another response.
      const sends = [...span.matchAll(/res\s*\.\s*(?:json|send|end|redirect|sendStatus)\s*\(/g)];
      if (sends.length >= 2) {
        const between = span.slice(sends[0].index, sends[1].index);
        // Gate-1: `out.on('error', …send(500)); out.on('finish', …send(201))`
        // is mutually exclusive event branching, not sequential flow.
        if (
          !/\breturn\b|\belse\b|\bcatch\b|\?\s*:|\bswitch\b|\.on\s*\(|addEventListener/.test(
            between
          )
        ) {
          push(ln, {
            id: `api-double-send-${file.path}-${ln}`,
            title: `${routePath} can send two responses`,
            severity: 'medium',
            remediation:
              'Execution runs past the first res.json into the second: ERR_HTTP_HEADERS_SENT at runtime, and the code after the first send ran when you thought the request was over. return the response calls (return res.json(...)) so each path ends where it answers.',
          });
        }
      }
    }

    // Gate-2 (C15+C16): the rate-limit lesson only needs the ROUTE — the
    // span-based regex above requires an inline arrow/function body, so
    // router.route('/login').post(handler) and app.post('/login',
    // loginHandler) both escaped it. This pass reads just the path.
    if (!projectHasRateLimit) {
      const flaggedIds = new Set(findings.map((f) => f.id));
      const refRouteRe =
        /\b(?:app|router|server)\s*\.\s*(?:route\s*\(\s*['"`]([^'"`\n]{1,80})['"`]\s*\)[\s\S]{0,60}?\.\s*(?:post|put|patch)\s*\(|(?:post|put|patch)\s*\(\s*['"`]([^'"`\n]{1,80})['"`]\s*,\s*[A-Za-z_$][\w$.]*\s*[),])/g;
      let rr;
      while ((rr = refRouteRe.exec(code)) !== null) {
        const routePath = rr[1] || rr[2];
        const ln = lineAt(rr.index);
        const id = `api-no-ratelimit-${file.path}-${ln}`;
        if (flaggedIds.has(id)) continue;
        const routeSegs = routePath.toLowerCase().split(/[/\-_.]+/);
        const credentialRoute = routeSegs.some((seg) =>
          ['login', 'signin', 'auth', 'password', 'session', 'register', 'reset'].includes(seg)
        );
        if (credentialRoute) {
          flaggedIds.add(id);
          push(ln, {
            id,
            title: `${routePath} has no rate limiting in the project`,
            severity: 'medium',
            cwe: 'CWE-307',
            remediation:
              'An unthrottled credential endpoint hands attackers unlimited guesses at machine speed. Add a limiter in front of the auth routes (express-rate-limit is a few lines; hosted platforms have an edge switch) with a tight per-IP budget on failures.',
          });
        }
      }
    }

    // Unpaginated list endpoints: GET handler returning findMany/find({})
    // with no limit vocabulary.
    const listRe =
      /\b(?:app|router)\s*\.\s*get\s*\(\s*['"`]([^'"`\n]{1,80})['"`][\s\S]{0,120}?(?:=>|function[^{]*)\s*(\{)/g;
    let lm;
    while ((lm = listRe.exec(code)) !== null) {
      const span = readBraceSpan(code, lm.index + lm[0].length - 1);
      if (span === null) continue;
      // Gate-1: bounded reference tables (countries, roles, plans …) are
      // whole-table by design; pagination there is over-engineering.
      const referenceish =
        /countr|currenc|language|locale|timezone|role|plan|categor|status|setting|enum|type/i.test(
          lm[1] + span.slice(0, 200)
        );
      if (
        /\.findMany\s*\(\s*\)|\.findMany\s*\(\s*\{\s*\}\s*\)|\.find\s*\(\s*\{?\s*\}?\s*\)\s*(?:\.toArray)?|SELECT\s+\*\s+FROM\s+\w+\s*(?:['"`;]|$)/i.test(
          span
        ) &&
        !/\b(?:take|limit|LIMIT|first|pageSize|per_page|top)\b/.test(span) &&
        !referenceish
      ) {
        const ln = lineAt(lm.index);
        push(ln, {
          id: `api-no-pagination-${file.path}-${ln}`,
          title: `${lm[1]} returns the whole table`,
          severity: 'medium',
          remediation:
            'It works at 50 rows and times out at 50,000 — the failure arrives with success, when real users show up. Take a limit and a cursor/offset from the query string, cap the limit server-side, and return the next cursor with the page.',
        });
      }
    }
  });
  return findings;
}

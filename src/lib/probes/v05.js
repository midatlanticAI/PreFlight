// src/lib/probes/v05.js
//
// v0.5 OWASP-framed probe additions. Five probes covering high-prevalence
// classes the v0.4 surface did not catch:
//
//   probeSQLInjectionTemplateLiterals  — CWE-89  (OWASP A03)
//   probePathTraversal                 — CWE-22  (OWASP A01)
//   probeWeakRandomness                — CWE-338 (OWASP A02)
//   probeStackTraceLeaks               — CWE-209 / CWE-497 (OWASP A04)
//   probeSubresourceIntegrity          — CWE-353 (OWASP A08)
//
// Same contract as the existing probes: pure function over `files: { path, content }[]`,
// returns an array of finding objects, never mutates inputs, calls isTestFile /
// isScannerSelfSource at the top of each per-file loop.

import { isTestFile, isScannerSelfSource } from '../file-filter.js';

// ---------- 1. SQL injection via template literals ----------
//
// Catches the pattern where untrusted input is concatenated into a SQL string
// via a template literal passed to a query API. Real ORMs (Prisma, Drizzle,
// Knex) use parameterized queries; raw `db.query(\`SELECT ... ${user}\`)` is
// a SQL injection waiting for an attacker.
//
// Heuristic: function calls like `query(`, `execute(`, `raw(`, `unsafe(`,
// `db.query(`, `client.query(`, `connection.query(`, `sql\`` whose argument
// is a template literal containing `${...}` interpolations.
//
// Excludes:
//   - tagged template literals from known-safe libraries (sql.js placeholder
//     tags like `sql\`SELECT ... ${id}\`` from `postgres`, `slonik`, and
//     `@vercel/postgres` are parameterized; we whitelist by tag name).
//   - String literals without interpolation.

const SQL_PARAMETERIZED_TAGS = new Set(['sql', 'pg', 'postgres', 'slonik', 'drizzle']);
const SQL_RISK_CALLEES =
  /\b(?:db|client|connection|conn|pool|knex|sequelize)\.(?:query|raw|execute|unsafe)\s*\(\s*`/g;
const SQL_BARE_CALLEES = /\b(?:query|execute|raw|unsafe|prepare)\s*\(\s*`/g;
const SQL_HAS_INTERPOLATION = /\$\{[^}]+\}/;

export function probeSQLInjectionTemplateLiterals(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.[jt]sx?$|\.py$|\.go$/.test(file.path)) return;

    const lines = file.content.split('\n');
    lines.forEach((line, i) => {
      // First check: tagged template `sql\`...\`` with interpolation. We allow
      // these because the well-known SQL tag libraries handle parameterization.
      const tagMatch = line.match(/(\w+)`[^`]*\$\{/);
      if (tagMatch && SQL_PARAMETERIZED_TAGS.has(tagMatch[1].toLowerCase())) {
        return; // safe-by-convention parameterized tagged template
      }

      // Risky callees: `db.query(\`...${...}...\`)` or `client.execute(\`...\`)`.
      const m1 = SQL_RISK_CALLEES.exec(line);
      SQL_RISK_CALLEES.lastIndex = 0;
      // Look ahead a few lines for the interpolation in case the call spans
      // multiple lines (`.query(\n\`SELECT...\n${x}\n\`)`).
      const span = lines.slice(i, Math.min(lines.length, i + 4)).join('\n');
      if (m1 && SQL_HAS_INTERPOLATION.test(span)) {
        findings.push({
          id: `sqli-tl-${file.path}-${i}`,
          probe: 'SQL Injection',
          title: 'SQL query built with template-literal interpolation',
          severity: 'critical',
          category: 'Injection',
          cwe: 'CWE-89',
          file: file.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation:
            'Use parameterized queries. The canonical pattern depends on the driver: with `pg` use `db.query("SELECT * FROM users WHERE id = $1", [id])`; with Prisma use `prisma.user.findUnique({ where: { id } })`; with Knex use `knex("users").where({ id })`. The pattern flagged here interpolates user input into the SQL string at parse time, which is the textbook SQL injection.',
        });
        return;
      }

      // Bare callees inside a likely-DB context (heuristic: file path contains
      // 'db', 'query', 'sql', or the line itself contains 'SELECT' / 'INSERT'
      // / 'UPDATE' / 'DELETE' inside the template).
      const m2 = SQL_BARE_CALLEES.exec(line);
      SQL_BARE_CALLEES.lastIndex = 0;
      if (m2 && SQL_HAS_INTERPOLATION.test(span)) {
        const looksLikeSQL = /SELECT |INSERT INTO|UPDATE |DELETE FROM/i.test(span);
        if (looksLikeSQL) {
          findings.push({
            id: `sqli-tl-${file.path}-${i}`,
            probe: 'SQL Injection',
            title: 'Likely SQL query built with template-literal interpolation',
            severity: 'high',
            category: 'Injection',
            cwe: 'CWE-89',
            file: file.path,
            line: i + 1,
            evidence: line.trim().slice(0, 200),
            remediation:
              "This call interpolates user input into a SQL string. Switch to parameterized queries using the driver's built-in placeholder syntax. See the related Learn pattern for driver-specific examples.",
          });
        }
      }
    });
  });
  return findings;
}

// ---------- 2. Path traversal ----------
//
// Catches `fs.readFile(req.body.path)`, `path.join(__dirname, userInput)`,
// `fs.createReadStream(userInput)` and variants where user-supplied input
// flows into a filesystem operation without obvious normalization.
//
// Heuristic: filesystem call sites where one of the arguments is a request-
// derived variable (body / query / params / headers / cookies) or is built
// from a `path.join` with such a variable.

const FS_CALL_RE =
  /\b(?:fs|fsPromises|fsp|node:fs)\.(?:read|write|append|create(?:Read|Write)Stream|stat|lstat|access|unlink|rmdir|readdir|opendir|cp|copy)(?:File|Sync)?\s*\(/g;
const PATH_JOIN_RE = /\bpath\.(?:join|resolve)\s*\(/g;
// Includes `url`, `originalUrl`, `path`, `baseUrl`. The first is the single
// most fundamental request-derived value on a raw Node http.createServer
// handler (`http.createServer((req, res) => { path.join(__dirname, req.url) })`)
// and missing it produced a silent FN on the May 2026 emailassist field-tech
// PWA gap report: arbitrary file read landed unflagged because req.url was
// not in the alternation. The other three cover Express's URL accessors.
const USER_INPUT_TOKEN_RE =
  /\b(?:req|request|ctx|context|event)\.(?:body|query|params|headers|cookies|searchParams|url|originalUrl|path|baseUrl)(?:\.\w+)?/;
const SAFE_NORMALIZE_RE =
  /\bpath\.(?:normalize|relative|isAbsolute)|escape|sanitize|allow(?:list)?|whitelist/i;

export function probePathTraversal(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.[jt]sx?$|\.py$/.test(file.path)) return;

    const lines = file.content.split('\n');
    lines.forEach((line, i) => {
      const fsHit = FS_CALL_RE.exec(line);
      FS_CALL_RE.lastIndex = 0;
      const joinHit = PATH_JOIN_RE.exec(line);
      PATH_JOIN_RE.lastIndex = 0;
      if (!fsHit && !joinHit) return;

      // Look at ±3 lines of context for the user-input token and for any
      // normalization that would mitigate the risk.
      const ctx = lines.slice(Math.max(0, i - 1), Math.min(lines.length, i + 4)).join(' ');
      if (!USER_INPUT_TOKEN_RE.test(ctx)) return;
      if (SAFE_NORMALIZE_RE.test(ctx)) return;

      findings.push({
        id: `path-traversal-${file.path}-${i}`,
        probe: 'Path Traversal',
        title: 'Filesystem operation built from user-controlled path',
        severity: 'high',
        category: 'Injection',
        cwe: 'CWE-22',
        file: file.path,
        line: i + 1,
        evidence: line.trim().slice(0, 200),
        remediation:
          'A user-controlled path reaches a filesystem call without visible normalization. Validate the path: resolve it against a fixed base directory with `path.resolve(BASE, userInput)`, then assert the result still starts with BASE via `resolved.startsWith(BASE + path.sep)`. Reject otherwise. Prefer an allowlist of filenames where the use case permits.',
      });
    });
  });
  return findings;
}

// ---------- 3. Weak randomness ----------
//
// Catches `Math.random()` used in security-sensitive contexts: token
// generation, session IDs, password reset codes, OTP codes, CSRF tokens,
// API keys. Math.random is not cryptographically secure; an attacker can
// predict subsequent values from a few observed ones.
//
// Heuristic: `Math.random()` calls within a few lines of a name like
// `token`, `secret`, `password`, `key`, `nonce`, `csrf`, `session`, `otp`,
// `verification`, `reset`. Excludes UI / animation contexts (jitter, delay,
// shuffle) where Math.random is appropriate.

const WEAK_RANDOM_CALL_RE = /Math\.random\s*\(\s*\)/g;
// Match security-related words anywhere in the surrounding context, including
// inside camelCase identifiers (`generateResetToken`, `csrfToken`, `magicLink`).
// We deliberately drop \b word boundaries because camelCase identifiers like
// `ResetToken` would not match `\btoken\b`. Accepting some "secretly" / "keyboard"
// false positives is the right trade given the severity.
const SECURITY_CONTEXT_RE =
  /token|secret|password|nonce|csrf|otp|verification|verifyemail|reset|signature|recovery|magiclink|invitetoken|magic[A-Z]|invite[A-Z]/i;
const UI_CONTEXT_RE =
  /\b(?:jitter|delay|shuffle|animation|fade|color|hsl|rgb|pixel|particle|preview|placeholder|mock|fake)\b/i;

export function probeWeakRandomness(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.[jt]sx?$/.test(file.path)) return;

    const lines = file.content.split('\n');
    lines.forEach((line, i) => {
      const hit = WEAK_RANDOM_CALL_RE.exec(line);
      WEAK_RANDOM_CALL_RE.lastIndex = 0;
      if (!hit) return;

      const ctx = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 4)).join(' ');
      if (UI_CONTEXT_RE.test(ctx)) return; // animation / preview use; fine
      if (!SECURITY_CONTEXT_RE.test(ctx)) return;

      findings.push({
        id: `weak-random-${file.path}-${i}`,
        probe: 'Weak Randomness',
        title: 'Math.random() used in a security-sensitive context',
        severity: 'high',
        category: 'Cryptographic Failure',
        cwe: 'CWE-338',
        file: file.path,
        line: i + 1,
        evidence: line.trim().slice(0, 200),
        remediation:
          'Replace `Math.random()` with a CSPRNG. In the browser: `crypto.getRandomValues(new Uint8Array(n))`. In Node: `crypto.randomBytes(n)` or `crypto.randomInt(min, max)`. For UUIDs, `crypto.randomUUID()` is the standard pattern. The visible context here (token / secret / nonce / etc.) means the random value will be used as an authenticator, and Math.random produces predictable sequences.',
      });
    });
  });
  return findings;
}

// ---------- 4. Stack trace leaks ----------
//
// Catches Express / Next / Hono error handlers that ship the full Error
// stack trace (with file paths, line numbers, and library versions) back
// to the client. Production stack traces leak server internals and aid
// reconnaissance.
//
// Heuristic: response writes (`res.send`, `res.json`, `return Response.json`,
// `ctx.json`, etc.) where the body contains `err.stack`, `error.stack`,
// `e.stack`, or `JSON.stringify(err)` (which serializes the stack along
// with the message).

// Match response-emitting calls and a stack reference on the same line. Simpler
// than trying to express the full "stack appears inside the response args" with
// one regex that handles nested parens (which JS regex cannot easily do).
const RESPONSE_CALL_RE =
  /\b(?:res|reply|ctx|response)\.(?:send|json|status\s*\(\s*\d+\s*\)\.(?:send|json))|\breturn\s+Response\.(?:json|redirect)|\breturn\s+new\s+Response\b|\b(?:res|reply|ctx)\.body\s*=/i;
const STACK_REF_RE = /\b(?:err|error|e|exception)\.stack\b/;
const JSON_STRINGIFY_ERR_RE = /JSON\.stringify\s*\(\s*(?:err|error|e|exception)\b/;

// "Catches" but inside known-dev guards: if `if (process.env.NODE_ENV !== 'production')`
// is on the same statement or directly precedes, skip the finding (intentional dev surface).
const DEV_GUARD_RE = /process\.env\.NODE_ENV\s*(?:!==|===)\s*['"]?production['"]?|isDev|__DEV__/;

export function probeStackTraceLeaks(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.[jt]sx?$/.test(file.path)) return;

    const lines = file.content.split('\n');
    lines.forEach((line, i) => {
      const hasResponse = RESPONSE_CALL_RE.test(line);
      const hasStack = STACK_REF_RE.test(line);
      const hasStringifyErr = JSON_STRINGIFY_ERR_RE.test(line);
      // A real leak: response call on a line that mentions err.stack, OR a
      // response call that JSON.stringify's the raw error (which serializes
      // its stack property).
      if (!(hasResponse && (hasStack || hasStringifyErr))) return;

      const ctx = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 2)).join(' ');
      if (DEV_GUARD_RE.test(ctx)) return;

      findings.push({
        id: `stack-leak-${file.path}-${i}`,
        probe: 'Stack Trace Leaks',
        title: 'Server error response includes the stack trace',
        severity: 'medium',
        category: 'Information Disclosure',
        cwe: 'CWE-209',
        file: file.path,
        line: i + 1,
        evidence: line.trim().slice(0, 200),
        remediation:
          'Strip the stack from production error responses. Return a generic error shape (`{ error: "Internal Server Error" }`) with the actual stack logged server-side via your logger. Stack traces leak file paths, dependency versions, and call chains, all of which simplify follow-up attacks.',
      });
    });
  });
  return findings;
}

// ---------- 5. Subresource Integrity (SRI) ----------
//
// Catches `<script src="https://cdn..."` and `<link rel="stylesheet" href="..."`
// pointing at third-party origins without an `integrity` attribute. SRI is the
// browser-level guarantee that a third-party asset has not been tampered with
// at the CDN.
//
// Heuristic: external <script src> or <link rel="stylesheet" href> on an
// origin other than the current site, without `integrity="..."`.

const SCRIPT_TAG_RE = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
const LINK_STYLE_RE =
  /<link\b[^>]*\brel\s*=\s*["']stylesheet["'][^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>/gi;
const HAS_INTEGRITY_RE = /\bintegrity\s*=\s*["'][^"']+["']/;

function isCrossOrigin(url) {
  if (!url) return false;
  // Treat protocol-relative + absolute URLs to non-same-origin as cross-origin.
  // We can't know the deploy origin at scan time, so any absolute URL that
  // isn't obviously a relative path is treated as cross-origin for SRI purposes.
  return /^(https?:)?\/\//i.test(url);
}

export function probeSubresourceIntegrity(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.(?:html?|jsx?|tsx?|astro|vue|svelte)$/.test(file.path)) return;

    const lines = file.content.split('\n');
    lines.forEach((line, i) => {
      // Script tags
      let m;
      SCRIPT_TAG_RE.lastIndex = 0;
      while ((m = SCRIPT_TAG_RE.exec(line)) !== null) {
        const url = m[1];
        if (!isCrossOrigin(url)) continue;
        if (HAS_INTEGRITY_RE.test(m[0])) continue;
        findings.push({
          id: `sri-script-${file.path}-${i}-${m.index}`,
          probe: 'Subresource Integrity',
          title: 'Cross-origin <script> tag missing integrity attribute',
          severity: 'medium',
          category: 'Supply Chain',
          cwe: 'CWE-353',
          file: file.path,
          line: i + 1,
          evidence: m[0].trim().slice(0, 200),
          remediation:
            'Add an `integrity="sha384-..."` attribute (and `crossorigin="anonymous"`) to every cross-origin <script> tag. The browser will refuse to execute the asset if its hash does not match. Generate the hash with `cat file.js | openssl dgst -sha384 -binary | openssl base64 -A`, or use the integrity value the CDN publishes.',
        });
      }

      // Stylesheet links
      LINK_STYLE_RE.lastIndex = 0;
      while ((m = LINK_STYLE_RE.exec(line)) !== null) {
        const url = m[1];
        if (!isCrossOrigin(url)) continue;
        if (HAS_INTEGRITY_RE.test(m[0])) continue;
        findings.push({
          id: `sri-link-${file.path}-${i}-${m.index}`,
          probe: 'Subresource Integrity',
          title: 'Cross-origin stylesheet missing integrity attribute',
          severity: 'medium',
          category: 'Supply Chain',
          cwe: 'CWE-353',
          file: file.path,
          line: i + 1,
          evidence: m[0].trim().slice(0, 200),
          remediation:
            'Add an `integrity="sha384-..."` attribute to the <link rel="stylesheet"> tag. A CDN compromise that swaps the file content for a hostile version is blocked at the browser level when integrity is set.',
        });
      }
    });
  });
  return findings;
}

// src/lib/probes/builtin.js
//
// The v0.4 built-in probe implementations: 26 pure functions from
// probeSecrets through probeNpmrcHygiene, plus the internal
// stripLineComments helper. Extracted verbatim from probes.js, which is
// now a thin registry hub. The public import surface is unchanged:
// probes.js re-exports every function below, so App.jsx, the tests, and
// history snapshots keep importing them from '../probes.js'.
//
// Why the split: probes.js crossed the 1500-line review threshold the
// scanner itself enforces. The fix the tool teaches (see the
// monolithic-spa Shape page) is to extract along a real seam and keep
// the surface stable, not to suppress the finding.
//
// Pure: every export is a plain function. No React, no DOM, no
// localStorage.

import {
  SECRET_PATTERNS,
  COMPROMISED_PACKAGES,
  TYPOSQUATS,
  SLOPSQUAT_GENERIC_RE,
  BIDI_CONTROL_RE,
  NEXT_PUBLIC_DANGER_NAMES,
  NEXT_PUBLIC_DANGER_VALUES,
} from '../threat-intel.js';
import {
  isTestFile,
  isScannerSelfSource,
  isMetaDocFile,
  isEnvTemplateFile,
  isDocumentationMarkdownFile,
} from '../file-filter.js';

// Substrings inside a regex-matched value that obviously mark the value as a
// placeholder rather than a real secret. The list is intentionally broad
// because the cost of a single FP placeholder match is high (every "your-key"
// firing trains users to ignore the panel). False negatives from a real
// secret that happens to embed one of these substrings are improbable and
// would still be caught at runtime by the issuing service's own scanner.
//
// Matches: `AKIAXXXXXXXXXXXXXXXX`, `sk_live_xxxxxxxxxxxxxxxxxxxx`,
// `xoxb-REPLACE-ME-WITH-A-REAL-BOT-TOKEN`, `xoxp-DEMO-DEMO-DEMO-DEMO`,
// `sk-proj-REPLACE_THIS_BEFORE_RUNNING_LOCALLY`,
// `AKIAIOSFODNN7EXAMPLE` (the AWS-published documentation value),
// `<your-key-here>`.
const SECRET_VALUE_PLACEHOLDER_RE =
  /x{4,}|REPLACE[_\-]?(?:ME|THIS|HERE|WITH|YOUR)?|YOUR[_\-]?(?:KEY|API|TOKEN|SECRET|PRIVATE|SLACK|AWS|STRIPE|OPENAI|ANTHROPIC|GITHUB|GOOGLE|[A-Z]+)[_\-A-Z]*HERE|YOUR[_\-]?(?:KEY|API|TOKEN|SECRET|PRIVATE)|PLACEHOLDER|DEMO[_\-]?(?:DEMO|TOKEN|KEY)?|EXAMPLE|<[^<>]+>|\{\{[^}]+\}\}|CHANGE[_\-]?ME|\bTODO(?:[_\-]\w+)*\b|FILL[_\-]?(?:IN|ME|HERE)|^stub[._-]/i;

// True when the match's enclosing statement assigns to a variable whose
// name explicitly marks it as a sample/example/test/fake fixture, e.g.
// `const SAMPLE_OPENAI_KEY = 'sk-proj-...'` or `const FAKE_STRIPE = 'sk_live_...'`.
// Both signals — explicit naming AND value shape — are required for suppression;
// generic names like `API_KEY` or `AWS_SECRET` continue to fire, since those
// are exactly what real leaked code looks like.
const PLACEHOLDER_VAR_NAME_RE =
  /\b(?:SAMPLE|EXAMPLE|FAKE|DUMMY|MOCK|FIXTURE|PLACEHOLDER|STUB|NOT_?A_?REAL|TEST_(?:KEY|TOKEN|SECRET|API))[_A-Z0-9]*\s*[:=]/;
function isMatchInPlaceholderNamedAssignment(content, matchIndex) {
  // Check the entire line containing the match. Looking only at content BEFORE
  // the match misses cases where a sibling secret pattern matches mid-identifier
  // (e.g. Generic-Hardcoded-Secret matching `API_KEY = "..."` from inside
  // TEST_API_KEY — the LHS identifier sits partly after the match index).
  const lineStart = content.lastIndexOf('\n', matchIndex - 1) + 1;
  const lineEnd = content.indexOf('\n', matchIndex);
  const line = content.slice(lineStart, lineEnd === -1 ? content.length : lineEnd);
  return PLACEHOLDER_VAR_NAME_RE.test(line);
}

// True when the match site lies inside a single-line // comment or an
// unterminated /* */ block comment. A documentation comment naming a secret
// shape ("// AKIAIOSFODNN7EXAMPLE is the AWS-documented sample value") is
// teaching, not leaking; suppress.
function isMatchInsideComment(content, matchIndex) {
  const lineStart = content.lastIndexOf('\n', matchIndex - 1) + 1;
  const beforeOnLine = content.slice(lineStart, matchIndex);
  // // comment opened earlier on this line, before the match
  if (/\/\//.test(beforeOnLine)) return true;
  // Inside a /* ... */ block that opens before the match and hasn't closed
  const lastOpen = content.lastIndexOf('/*', matchIndex);
  if (lastOpen === -1) return false;
  const closeAfterOpen = content.indexOf('*/', lastOpen);
  if (closeAfterOpen === -1 || closeAfterOpen > matchIndex) return true;
  return false;
}

// Whole-file content masker. Walks the content
// once, replacing the *interior* of multi-line `/* ... */` blocks, `//` line
// comments, and `'`/`"`/backtick string literals with spaces while preserving
// every newline and the opening/closing delimiters themselves. The output has
// the same line count and same indices as the input, so probes that emit
// line numbers and slice positions stay correct. This is the version
// structural probes should use when the FP set includes patterns hidden
// inside multi-line comments or template-literal docstrings.
// Narrower mask for probes that scan per-line for real code patterns inside
// string literals (e.g. `localStorage.setItem('jwt', token)` — the literal
// 'jwt' MUST stay visible). This mask blanks only block comments, line
// comments, and BACKTICK template literals. Single/double-quoted string
// content is preserved. Indices and newlines preserved.
function maskBlockCommentsAndTemplateLiterals(content) {
  if (typeof content !== 'string' || content.length === 0) return content || '';
  const out = [];
  const len = content.length;
  let i = 0;
  const blankExceptNewline = (ch) => (ch === '\n' ? '\n' : ' ');
  while (i < len) {
    const c = content[i];
    const c2 = i + 1 < len ? content[i + 1] : '';
    if (c === '/' && c2 === '*') {
      out.push('/', '*');
      const end = content.indexOf('*/', i + 2);
      if (end === -1) {
        for (let j = i + 2; j < len; j++) out.push(blankExceptNewline(content[j]));
        return out.join('');
      }
      for (let j = i + 2; j < end; j++) out.push(blankExceptNewline(content[j]));
      out.push('*', '/');
      i = end + 2;
      continue;
    }
    if (c === '/' && c2 === '/') {
      out.push('/', '/');
      let j = i + 2;
      while (j < len && content[j] !== '\n') {
        out.push(' ');
        j++;
      }
      i = j;
      continue;
    }
    if (c === '`') {
      out.push('`');
      let j = i + 1;
      while (j < len) {
        if (content[j] === '\\' && j + 1 < len) {
          out.push(blankExceptNewline(content[j]));
          out.push(blankExceptNewline(content[j + 1]));
          j += 2;
          continue;
        }
        if (content[j] === '`') break;
        out.push(blankExceptNewline(content[j]));
        j++;
      }
      if (j >= len) return out.join('');
      out.push('`');
      i = j + 1;
      continue;
    }
    out.push(c);
    i++;
  }
  return out.join('');
}

function maskCommentsAndStringsFromContent(content) {
  if (typeof content !== 'string' || content.length === 0) return content || '';
  const out = [];
  const len = content.length;
  let i = 0;
  const blankExceptNewline = (ch) => (ch === '\n' ? '\n' : ' ');
  while (i < len) {
    const c = content[i];
    const c2 = i + 1 < len ? content[i + 1] : '';
    // /* block comment (may span lines)
    if (c === '/' && c2 === '*') {
      out.push('/', '*');
      const end = content.indexOf('*/', i + 2);
      if (end === -1) {
        for (let j = i + 2; j < len; j++) out.push(blankExceptNewline(content[j]));
        return out.join('');
      }
      for (let j = i + 2; j < end; j++) out.push(blankExceptNewline(content[j]));
      out.push('*', '/');
      i = end + 2;
      continue;
    }
    // // line comment
    if (c === '/' && c2 === '/') {
      out.push('/', '/');
      let j = i + 2;
      while (j < len && content[j] !== '\n') {
        out.push(' ');
        j++;
      }
      i = j;
      continue;
    }
    // String literal: ' " or backtick. Template literals can span lines.
    if (c === "'" || c === '"' || c === '`') {
      const quote = c;
      out.push(quote);
      let j = i + 1;
      while (j < len) {
        if (content[j] === '\\' && j + 1 < len) {
          // Skip escape and the character it escapes; blank both, preserve newlines.
          out.push(blankExceptNewline(content[j]));
          out.push(blankExceptNewline(content[j + 1]));
          j += 2;
          continue;
        }
        if (content[j] === quote) break;
        out.push(blankExceptNewline(content[j]));
        j++;
      }
      if (j >= len) return out.join(''); // unterminated string; trail consumed
      out.push(quote);
      i = j + 1;
      continue;
    }
    out.push(c);
    i++;
  }
  return out.join('');
}

// True when a Private Key Block match should be SUPPRESSED. Two cases:
//   1. A matching END marker exists nearby and the body contains placeholder
//      markers (the canonical "documentation PEM" shape).
//   2. No END marker exists within a reasonable window — this is a framing
//      reference, not a key. Real PEM blocks always pair BEGIN and END within
//      ~50 lines because the body is dense base64; an unaccompanied BEGIN is
//      either a constant naming the framing (`export const BEGIN = '-----...'`)
//      or a documentation snippet truncated to the header.
function isPEMBodyPlaceholderOrHeaderOnly(content, beginIndex) {
  const afterBegin = content.slice(beginIndex);
  const endIdx = afterBegin.search(/-----END /);
  // No END within the search window: framing-only reference, suppress.
  if (endIdx === -1) return true;
  if (endIdx > 4000) return true; // body too far to be a real PEM body
  const body = afterBegin.slice(0, endIdx);
  // Placeholder markers in the body (REPLACE_WITH_YOUR_KEY, EXAMPLE, ...).
  if (SECRET_VALUE_PLACEHOLDER_RE.test(body)) return true;
  // Framing-as-constants shape: `const BEGIN = '-----BEGIN ...'; const END = '-----END ...'`.
  // Real PEM bodies are dense base64 lines with no JS quotes, semicolons, or
  // language keywords. The presence of any of those between BEGIN and END
  // means we're looking at code that declares the framing as constants, not
  // a key body. Suppress.
  if (/['";]|\bexport\b|\bconst\b|\blet\b|\bvar\b|\bfunction\b/.test(body)) return true;
  return false;
}

// True when the match site lies inside a backtick-delimited template literal
// that is NOT itself the value being assigned to a variable (i.e., the
// template literal contains text that LOOKS like code — a documentation
// snippet, JSX child string, or similar). The simplest reliable signal is
// the parity of unescaped backticks before the match: an odd count means
// the match is between opening and closing backticks of a template literal.
//
// This produces a small recall sacrifice on the rare case of a secret stored
// in a template literal that wraps the value (e.g. `const k = `sk-live-...`;`)
// but eliminates the much more common precision failure: documentation
// strings that quote a secret-shaped example via backticks. The recall risk
// is acceptable because secrets pinned via backticks are unusual in real
// code; production keys are almost always pinned via single or double quotes.
function isMatchInsideTemplateLiteral(content, matchIndex) {
  let count = 0;
  for (let i = 0; i < matchIndex; i++) {
    if (content[i] === '\\' && i + 1 < content.length) {
      i++;
      continue;
    }
    if (content[i] === '`') count++;
  }
  return count % 2 === 1;
}

export function probeSecrets(files) {
  const findings = [];
  files.forEach((file) => {
    // Filename-based suppressions (cheap, catch obvious non-source surfaces).
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    // .env.example, .env.template, .env.sample, etc. The spec's `isEnvTemplateFile`
    // helper already enumerates the conventions; honor it here. Placeholder-shaped
    // values in template files are not credentials, they are documentation of where
    // a credential goes at deploy time.
    if (isEnvTemplateFile(file.path)) return;
    // Markdown documentation. The Pattern page promises this exclusion:
    //   "PreFlight skips ... markdown documentation files where the key is
    //    part of an example."
    // Real secret material pasted into a markdown file is vanishingly rare
    // relative to documentation references to the shape; the FP cost of
    // scanning README/docs is far higher than the FN cost of skipping them.
    if (isDocumentationMarkdownFile(file.path)) return;
    SECRET_PATTERNS.forEach((pat) => {
      const matches = [...file.content.matchAll(pat.regex)];
      matches.forEach((m) => {
        const idx = m.index ?? 0;
        // Suppress matches whose value is an obvious placeholder. The check
        // looks at the matched text only so a real key embedded next to a
        // placeholder marker still fires.
        if (SECRET_VALUE_PLACEHOLDER_RE.test(m[0])) return;
        // Suppress matches whose enclosing assignment names the variable as
        // a sample/example/test/fake fixture (e.g. SAMPLE_OPENAI_KEY).
        // Generic identifiers like API_KEY or AWS_SECRET still fire — those
        // are exactly what leaked code looks like.
        if (isMatchInPlaceholderNamedAssignment(file.content, idx)) return;
        // Suppress matches whose surrounding context is a comment naming
        // the shape rather than committing the value.
        if (isMatchInsideComment(file.content, idx)) return;
        // Suppress matches inside backtick-delimited template literals.
        // These are usually code-as-string documentation snippets; real
        // production secrets are almost always pinned via single/double
        // quotes. EXCEPTION: PEM blocks are routinely stored in template
        // literals (`const KEY = \`-----BEGIN ... -----\``) in real source;
        // suppressing them by template-literal context would break legitimate
        // PEM detection. PEM cases fall through to the body-placeholder /
        // header-only check below.
        if (pat.name !== 'Private Key Block' && isMatchInsideTemplateLiteral(file.content, idx)) {
          return;
        }
        // For PEM blocks specifically, two suppressions: (a) the placeholder
        // lives in the body, e.g. `-----BEGIN ... -----\n  REPLACE_WITH ... \n-----END`;
        // (b) no END marker is found nearby, meaning the match is a framing
        // reference, not a key. Both cases handled by the same helper.
        if (pat.name === 'Private Key Block' && isPEMBodyPlaceholderOrHeaderOnly(file.content, idx))
          return;
        const lineNum = file.content.slice(0, idx).split('\n').length;
        const line = file.content.split('\n')[lineNum - 1] || '';
        const masked = m[0].length > 12 ? m[0].slice(0, 6) + '...' + m[0].slice(-4) : m[0];
        findings.push({
          id: `secret-${file.path}-${pat.name}-${idx}`,
          probe: 'Secret Scanner',
          title: `${pat.name} found in source`,
          severity: pat.severity,
          category: pat.category,
          cwe: pat.cwe,
          file: file.path,
          line: lineNum,
          evidence: line.replace(m[0], masked).trim().slice(0, 200),
          remediation: `Remove this credential from source immediately. Rotate it in the issuing service. Move to a server-only environment variable (no NEXT_PUBLIC_ prefix). If this file is committed to git, the secret is permanently in history — rotation is the only fix.`,
        });
      });
    });
  });
  return findings;
}

export function probeNextPublic(files) {
  const findings = [];
  files.forEach((file) => {
    if (!/\.env|\.config\.|next\.config/.test(file.path)) return;
    const lines = file.content.split('\n');
    lines.forEach((line, i) => {
      const m = line.match(/NEXT_PUBLIC_([A-Z0-9_]+)\s*[=:]\s*["']?([^"'\n\r]+)["']?/);
      if (!m) return;
      const [, varName, value] = m;
      const dangerName = NEXT_PUBLIC_DANGER_NAMES.test(varName);
      const dangerValue = NEXT_PUBLIC_DANGER_VALUES.test(value.trim());
      if (dangerName || dangerValue) {
        findings.push({
          id: `nextpublic-${file.path}-${i}`,
          probe: 'NEXT_PUBLIC_ Misuse',
          title: `Server secret exposed via NEXT_PUBLIC_${varName}`,
          severity: 'critical',
          category: 'Data Breach',
          cwe: 'CWE-200',
          file: file.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation: `NEXT_PUBLIC_ variables are bundled into the browser. This secret is visible to every visitor. Rename to remove the NEXT_PUBLIC_ prefix and access only from server-side code (Server Components, API routes, route handlers). Rotate the credential since it has been public.`,
        });
      }
    });
  });
  return findings;
}

export function probeSupabaseRLS(files) {
  const findings = [];
  files.forEach((file) => {
    if (!/\.sql$/.test(file.path)) return;
    const content = file.content;
    // Allow case-insensitive identifier capture (Supabase + Postgres allow "Users" etc).
    const tableMatches = [
      ...content.matchAll(
        /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:[a-z_][\w]*\.)?["`]?([A-Za-z_][\w]*)["`]?/gi
      ),
    ];
    tableMatches.forEach((tm) => {
      const tableName = tm[1];
      // Match the same table regardless of schema qualifier (public.users, app.users, plain users).
      const enableRegex = new RegExp(
        `alter\\s+table\\s+(?:[a-z_][\\w]*\\.)?["\`]?${tableName}["\`]?\\s+enable\\s+row\\s+level\\s+security`,
        'i'
      );
      if (!enableRegex.test(content)) {
        findings.push({
          id: `rls-${file.path}-${tableName}`,
          probe: 'Supabase RLS Check',
          title: `Table "${tableName}" missing ENABLE ROW LEVEL SECURITY`,
          severity: 'critical',
          category: 'Data Breach',
          cwe: 'CWE-284',
          file: file.path,
          line: tm.index ? content.slice(0, tm.index).split('\n').length : 1,
          evidence: tm[0],
          remediation: `Add the following to your migration:\n\nALTER TABLE public.${tableName} ENABLE ROW LEVEL SECURITY;\n\nThen create explicit policies for SELECT, INSERT, UPDATE, DELETE. Without RLS, any client with the anon key can read and modify all rows. This is the single most common Supabase production breach.`,
        });
      }
    });
    const permissivePolicies = [
      ...content.matchAll(/create\s+policy[\s\S]*?using\s*\(\s*true\s*\)/gi),
    ];
    permissivePolicies.forEach((pm) => {
      findings.push({
        id: `rls-permissive-${file.path}-${pm.index}`,
        probe: 'Supabase RLS Check',
        title: 'Permissive RLS policy "USING (true)"',
        severity: 'high',
        category: 'Data Breach',
        cwe: 'CWE-284',
        file: file.path,
        line: content.slice(0, pm.index).split('\n').length,
        evidence: pm[0].slice(0, 200).replace(/\s+/g, ' '),
        remediation: `A USING (true) policy allows the policy role to access every row. Replace with an explicit predicate, e.g. USING (auth.uid() = user_id) for owner-only access, or scope to specific roles.`,
      });
    });
  });
  return findings;
}

export function probeFirebaseRules(files) {
  const findings = [];
  files.forEach((file) => {
    if (!/firestore\.rules$|storage\.rules$/.test(file.path)) return;
    const content = file.content;
    const lines = content.split('\n');
    lines.forEach((line, i) => {
      if (/allow\s+(read|write|create|update|delete|get|list)[^;]*:\s*if\s+true\s*;/.test(line)) {
        findings.push({
          id: `firebase-true-${file.path}-${i}`,
          probe: 'Firebase Rules Check',
          title: 'Firebase rule grants unrestricted access',
          severity: 'critical',
          category: 'Data Breach',
          cwe: 'CWE-284',
          file: file.path,
          line: i + 1,
          evidence: line.trim(),
          remediation: `"if true" allows anyone on the internet to read or write. Replace with an authentication check at minimum (request.auth != null) and an ownership check ideally (request.auth.uid == resource.data.userId). Test rules in the Firebase emulator before deploying.`,
        });
      }
      if (
        /allow\s+(?:read|write)[^;]*:\s*if\s+request\.auth\s*!=\s*null\s*;/.test(line) &&
        /storage\.rules$/.test(file.path)
      ) {
        findings.push({
          id: `firebase-auth-only-${file.path}-${i}`,
          probe: 'Firebase Rules Check',
          title: 'Storage rule allows any authenticated user',
          severity: 'high',
          category: 'Data Breach',
          cwe: 'CWE-284',
          file: file.path,
          line: i + 1,
          evidence: line.trim(),
          remediation: `Any authenticated user can read or write this path, including users accessing each other's files. Add an ownership check, e.g. allow read: if request.auth.uid == resource.metadata.ownerId;`,
        });
      }
    });
  });
  return findings;
}

export function probePackageJson(files) {
  const findings = [];
  files.forEach((file) => {
    if (!/package\.json$/.test(file.path)) return;
    let pkg;
    try {
      pkg = JSON.parse(file.content);
    } catch {
      return;
    }
    // Scan-coverage gap. The May 2026 emailassist field-tech PWA gap was
    // exactly this: package.json had "scripts.start": "node server.js" but
    // server.js was not in the scan set. The probe team-fixed the req.url
    // taint detector (commit 92b0c13), and this surfaces the OTHER half
    // of the gap: tell the user when their entry-point file is missing.
    const entryRefs = new Set();
    if (typeof pkg.main === 'string') entryRefs.add(pkg.main);
    const scriptCmds = pkg.scripts || {};
    for (const key of ['start', 'dev', 'serve', 'server']) {
      const cmd = scriptCmds[key];
      if (typeof cmd !== 'string') continue;
      // Extract a referenced file path from the command (e.g. "node server.js",
      // "ts-node src/server.ts", "nodemon --watch src api/index.js").
      const m =
        cmd.match(/\b(?:node|ts-node|nodemon|tsx|deno|bun)\s+[^&|;]*?(\S+\.[mc]?[jt]s)\b/) ||
        cmd.match(/(\S+\.[mc]?[jt]s)\b/);
      if (m && m[1] && !m[1].startsWith('-')) entryRefs.add(m[1]);
    }
    const baseDir = file.path.replace(/[^/]+$/, ''); // dir of this package.json
    const filePaths = new Set(files.map((x) => x.path));
    for (const ref of entryRefs) {
      const stripped = ref.replace(/^\.\//, '');
      const candidates = [
        stripped,
        baseDir + stripped,
        baseDir + stripped.replace(/^\.\//, ''),
        stripped.replace(/^\.?\.\//, ''),
      ];
      const found = candidates.some((c) => filePaths.has(c));
      if (!found && /\.[mc]?[jt]s$/.test(stripped)) {
        findings.push({
          id: `pkg-entry-not-scanned-${file.path}-${ref.replace(/\W/g, '_')}`,
          probe: 'Architecture',
          title: `Entry point referenced in package.json is not in the scan set: ${ref}`,
          severity: 'high',
          category: 'Misconfiguration',
          cwe: 'CWE-1059',
          file: file.path,
          line: 1,
          evidence: `package.json references "${ref}" via main / scripts.start / dev / serve / server, but this file was not loaded for scanning.`,
          remediation: `The backend entry point is the most security-sensitive file in a Node project (auth, routing, file serving, request parsing all live here). Re-run the scan with this file included: in GitHub mode the entry-point file is auto-prioritized; in Files / Folder mode, drag the file in or upload the parent directory. The May 2026 emailassist gap shipped because PreFlight scanned 5 frontend files and missed server.js, which had a public arbitrary-file-read. Do not ship without seeing the result for this file.`,
        });
      }
    }
    const scripts = pkg.scripts || {};
    if (scripts.postinstall || scripts.preinstall || scripts.install) {
      const script = scripts.postinstall || scripts.preinstall || scripts.install;
      if (/curl|wget|eval|http:\/\//.test(script)) {
        findings.push({
          id: `pkg-postinstall-${file.path}`,
          probe: 'Supply Chain',
          title: 'Suspicious install hook detected',
          severity: 'high',
          category: 'Supply Chain',
          cwe: 'CWE-506',
          file: file.path,
          line: 1,
          evidence: `"postinstall": ${JSON.stringify(script)}`,
          remediation: `Install hooks that download and execute remote code are a common supply-chain attack vector. Audit this script and any package that introduced it. Consider using --ignore-scripts during install in CI.`,
        });
      }
    }
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    Object.entries(deps).forEach(([name, version]) => {
      if (typeof version === 'string' && /^(?:git\+|http:|https:|file:)/.test(version)) {
        findings.push({
          id: `pkg-nonregistry-${file.path}-${name}`,
          probe: 'Supply Chain',
          title: `Non-registry dependency "${name}"`,
          severity: 'medium',
          category: 'Supply Chain',
          cwe: 'CWE-1357',
          file: file.path,
          line: 1,
          evidence: `"${name}": "${version}"`,
          remediation: `Dependencies installed from arbitrary git or HTTP sources bypass registry integrity checks. If this is intentional and trusted, pin to a specific commit hash rather than a branch. Otherwise migrate to a registry version.`,
        });
      }
      if (typeof version === 'string' && /^(\*|latest|>)/.test(version)) {
        findings.push({
          id: `pkg-floating-${file.path}-${name}`,
          probe: 'Supply Chain',
          title: `Unpinned dependency version "${name}": "${version}"`,
          severity: 'low',
          category: 'Supply Chain',
          cwe: 'CWE-1357',
          file: file.path,
          line: 1,
          evidence: `"${name}": "${version}"`,
          remediation: `Floating versions like "*" or "latest" allow any future version, including malicious updates, to install. Pin to a caret range (^1.2.3) or exact version.`,
        });
      }
    });
  });
  return findings;
}

// Preventive check: does the project's .gitignore actually have a pattern that
// would catch .env files BEFORE they get committed? Most leaked-secret incidents
// from vibe-coded repos are committed `.env` because the `.gitignore` rule was
// never added — by the time PreFlight's per-file probe catches it, the file is
// already in git history and the secrets are already compromised. Auditing the
// ignore rules is the *preventive* upgrade.
//
// FP avoidance: only fires when .gitignore EXISTS in the corpus (no false alarm
// on projects that never started one) AND has no recognizable .env pattern.
// Accepts any of: `.env`, `.env.*`, `*.env`, `.env*`, `*.local`, `.env.local`
// (and other forms with trailing slashes, leading whitespace).
function gitignoreHasEnvPattern(content) {
  const lines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  return lines.some(
    (l) =>
      /^\.env(\..+|\*|$)/.test(l) || // .env, .env.local, .env.* , .env*
      /^\*\.local$/.test(l) || // *.local catches .env.local
      /^\*\.env$/.test(l) // *.env (rare but valid)
  );
}

export function probeEnvFiles(files) {
  const findings = [];
  files.forEach((file) => {
    if (!/(^|\/)\.env(\..+)?$/i.test(file.path)) return;
    // Template / documentation env files (.env.example, .env-example,
    // .env.dist, ...) are SUPPOSED to be committed and hold placeholders.
    // Flagging their mere presence as high-risk "Data Breach" was a real
    // false positive reported by an early user. A real secret pasted into
    // one is still caught by the secret scanner (it inspects content).
    if (isEnvTemplateFile(file.path)) return;
    findings.push({
      id: `env-tracked-${file.path}`,
      probe: 'Env Hygiene',
      title: '.env file present in repository',
      severity: 'high',
      category: 'Data Breach',
      cwe: 'CWE-538',
      file: file.path,
      line: 1,
      evidence: file.path,
      remediation: `Real .env files should never be committed to git. Add .env, .env.local, .env.production to .gitignore. Use .env.example with placeholder values for documentation. If this file has been committed to a public repo, treat every value in it as compromised and rotate.`,
    });
  });

  // Preventive: audit the project's .gitignore for .env coverage.
  const gitignore = files.find((f) => /(^|\/)\.gitignore$/.test(f.path));
  if (gitignore && !gitignoreHasEnvPattern(gitignore.content)) {
    findings.push({
      id: `env-gitignore-missing-${gitignore.path}`,
      probe: 'Env Hygiene',
      title: '.gitignore missing .env ignore rule',
      severity: 'low',
      category: 'Misconfiguration',
      cwe: 'CWE-538',
      file: gitignore.path,
      line: 1,
      evidence: 'No `.env`, `.env.*`, or `*.local` pattern in .gitignore',
      remediation: `Add to .gitignore so .env files cannot be committed by accident:

.env
.env.*
!.env.example

The !.env.example exception keeps the placeholder template committable. This matches the Next.js, Vite, SvelteKit, Astro, and Nuxt conventions (all use the same .env / .env.local / .env.*.local hierarchy). Without these patterns a future .env that an AI agent generates will silently land in the repo.`,
    });
  }
  return findings;
}

// Strip a single line of `// ...` comments and `/* ... */` (within-line) before testing for code patterns.
// Heuristic — won't fool template literals or strings containing //, but kills the common false-positive
// of matching `eval()` or `algorithm: none` inside a TODO comment.
function stripLineComments(line) {
  // Remove block comments first.
  let s = line.replace(/\/\*[\s\S]*?\*\//g, '');
  // Find an unquoted // and chop.
  let inSingle = false,
    inDouble = false,
    inBack = false;
  for (let j = 0; j < s.length; j++) {
    const c = s[j];
    const prev = j > 0 ? s[j - 1] : '';
    if (c === "'" && prev !== '\\' && !inDouble && !inBack) inSingle = !inSingle;
    else if (c === '"' && prev !== '\\' && !inSingle && !inBack) inDouble = !inDouble;
    else if (c === '`' && prev !== '\\' && !inSingle && !inDouble) inBack = !inBack;
    else if (c === '/' && s[j + 1] === '/' && !inSingle && !inDouble && !inBack) {
      return s.slice(0, j);
    }
  }
  return s;
}

export function probeAuthWeakness(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    // Hardcoded password in YAML / JSON / .env / config. Separate handler
    // because these file types don't have the JS comment/template semantics
    // the rest of this probe assumes. Match `password: 'literal'` (YAML),
    // `"password": "literal"` (JSON), `DB_PASSWORD=value` (.env), all with
    // placeholder filtering.
    const isConfigFile =
      /\.(?:ya?ml|json|properties|toml|conf|cfg|ini)$/i.test(file.path) ||
      /(?:^|\/)\.env(?:\.\w+)?$/i.test(file.path);
    if (isConfigFile) {
      const lines = file.content.split('\n');
      lines.forEach((rawLine, i) => {
        // JSON/YAML/TOML: `"password": "value"` or `password: 'value'`. Allow
        // an optional close-quote on the key.
        // .env: `DB_PASSWORD=value` (no quotes around the value typically).
        const m = rawLine.match(
          /\b(\w*(?:password|passwd|pwd|secret|api[_-]?password))\b["']?\s*[:=]\s*["']?([^"'\s\n,}]{3,})["']?/i
        );
        if (!m) return;
        const value = m[2];
        if (SECRET_VALUE_PLACEHOLDER_RE.test(value)) return;
        if (/^[$!#]/.test(value)) return;
        if (/^(?:\$\{|process\.env\.)/.test(value)) return;
        // skip comment-only lines in YAML/TOML/.env
        if (/^\s*[#;]/.test(rawLine)) return;
        findings.push({
          id: `auth-hardcodedpwd-config-${file.path}-${i}`,
          probe: 'Auth Weakness',
          title: 'Hardcoded password in config file',
          severity: 'critical',
          category: 'Auth & Access',
          cwe: 'CWE-798',
          file: file.path,
          line: i + 1,
          evidence: rawLine.trim().slice(0, 200),
          remediation:
            'Configs checked into git ship with the password. Use env interpolation (${DB_PASSWORD}), a secret manager reference, or move the secret out of the config entirely. Rotate the leaked value.',
        });
      });
      return;
    }
    if (!/\.[jt]sx?$/.test(file.path)) return;
    // Mask the whole content so block comments AND template-literal documentation
    // snippets (e.g. Demi persona spec strings) no longer trip the regexes.
    // The mask preserves indices and newlines, so per-line iteration and the
    // emitted line numbers stay correct.
    // Narrow mask: blanks block comments, line comments, and backtick template
    // literals. Single/double-quoted string content stays visible so the
    // regexes can still see real auth-token-name string literals.
    const maskedContent = maskBlockCommentsAndTemplateLiterals(file.content);
    const maskedLines = maskedContent.split('\n');
    const originalLines = file.content.split('\n');
    maskedLines.forEach((rawLine, i) => {
      const line = stripLineComments(rawLine);
      const realLine = originalLines[i] || '';
      // Match quoted OR unquoted "none" — agent FN: `algorithm: none` (no quotes) used to evade.
      if (/(?:algorithm|alg)\s*:\s*['"]?none['"]?(?:\s|,|$)/i.test(line)) {
        findings.push({
          id: `auth-algnone-${file.path}-${i}`,
          probe: 'Auth Weakness',
          title: 'JWT signed with algorithm "none"',
          severity: 'critical',
          category: 'Auth & Access',
          cwe: 'CWE-327',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim(),
          remediation: `alg: none means tokens are unsigned. Anyone can forge a token claiming to be any user. Use HS256 with a strong secret or RS256 with a key pair.`,
        });
      }
      if (/jwt\.verify\([^,)]+\)/.test(line) && !/secret|publicKey|key/.test(line)) {
        findings.push({
          id: `auth-noverify-${file.path}-${i}`,
          probe: 'Auth Weakness',
          title: 'jwt.verify called without secret argument',
          severity: 'high',
          category: 'Auth & Access',
          cwe: 'CWE-347',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim(),
          remediation: `Verify with an explicit secret or public key. Without one, signature validation may be skipped depending on the library, allowing forged tokens.`,
        });
      }
      if (/eval\s*\(/.test(line) && !/eslint-disable/.test(line)) {
        findings.push({
          id: `code-eval-${file.path}-${i}`,
          probe: 'Code Injection',
          title: 'eval() usage detected',
          severity: 'high',
          category: 'Code Injection',
          cwe: 'CWE-95',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation: `eval() executes arbitrary code. If the input is ever user-controlled, this is RCE. Replace with safe alternatives: JSON.parse for data, a real expression parser, or a switch statement for known operations.`,
        });
      }
      if (/dangerouslySetInnerHTML/.test(line)) {
        findings.push({
          id: `code-dsih-${file.path}-${i}`,
          probe: 'Code Injection',
          title: 'dangerouslySetInnerHTML used',
          severity: 'medium',
          category: 'Code Injection',
          cwe: 'CWE-79',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation: `dangerouslySetInnerHTML bypasses React's XSS protection. Confirm the input is sanitized with DOMPurify or similar. If the content is from user input or a third party, you have an XSS risk.`,
        });
      }
      // EXPANSION (Thread 6, 2026-06-05): the documented 4 shapes above are
      // far from the full A07 surface. The shapes below are the most common
      // shapes AI-generated code produces and that cause real auth breaks.
      //
      // Plaintext password comparison: `req.body.password === user.password`
      // or against a `.password`/`storedPassword` field. The defining shape is
      // equality (=== or ==) against an identifier whose name ends in
      // `password` (case-insensitive). Real auth uses bcrypt.compare or
      // argon2.verify, which look completely different.
      if (
        /(?:\b\w*(?:password|passwd|pwd)\b)\s*(?:===|==)\s*\w+(?:\.\w+)*\b/i.test(line) ||
        /\w+(?:\.\w+)*\s*(?:===|==)\s*\b\w*(?:password|passwd|pwd)\b/i.test(line)
      ) {
        findings.push({
          id: `auth-plainpasswordcompare-${file.path}-${i}`,
          probe: 'Auth Weakness',
          title: 'Plaintext password comparison',
          severity: 'critical',
          category: 'Auth & Access',
          cwe: 'CWE-261',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'Never compare passwords with === / ==. That implies the password is stored in plaintext or compared as raw input. Use bcrypt.compare(input, hash) or argon2.verify(hash, input) — both are constant-time and force you to store a real hash.',
        });
      }
      // Weak password hashing: md5 / sha1 / sha256 (no KDF) applied to a value
      // named password/passwd/pwd. Cryptographic hashes are designed to be fast;
      // password hashes (bcrypt/argon2/scrypt) are designed to be slow with a
      // tunable work factor. Using a plain hash for passwords is an OWASP A02
      // classic.
      if (
        /\b(?:md5|sha1)\s*\([^)]*\b\w*(?:password|passwd|pwd|pw)\b/i.test(line) ||
        /createHash\(\s*['"](?:md5|sha1)['"]\s*\)\s*\.\s*update\s*\(\s*[^)]*?\b(?:password|passwd|pwd|pw)\b/i.test(
          line
        )
      ) {
        findings.push({
          id: `auth-weakhash-${file.path}-${i}`,
          probe: 'Auth Weakness',
          title: 'Weak password hash (MD5/SHA1)',
          severity: 'critical',
          category: 'Auth & Access',
          cwe: 'CWE-916',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'MD5 and SHA1 are designed to be fast — that is exactly wrong for password hashing. Modern attackers crack them at billions of attempts per second on commodity GPUs. Use bcrypt (cost factor 12+), argon2id (memory cost 19 MiB+), or scrypt.',
        });
      }
      // sha256 used for password hashing (without a KDF wrapper like
      // PBKDF2/HKDF): still cryptographic, still wrong for passwords. Same
      // reason as MD5/SHA1 — too fast, no work factor.
      if (
        /createHash\(\s*['"]sha256['"]\s*\)\s*\.\s*update\s*\(\s*\b\w*(?:password|passwd|pwd)\b/i.test(
          line
        ) ||
        /\bsha256\s*\(\s*\b\w*(?:password|passwd|pwd)\b/i.test(line)
      ) {
        // Only fire if PBKDF2/HKDF/scrypt/bcrypt/argon2 is NOT in the same file.
        // If the developer is wrapping sha256 in a real KDF, it's defensible.
        const fileHasKdf = /pbkdf2|hkdf|scrypt|bcrypt|argon2/i.test(file.content);
        if (!fileHasKdf) {
          findings.push({
            id: `auth-sha256pwd-${file.path}-${i}`,
            probe: 'Auth Weakness',
            title: 'SHA-256 used for password hashing without a KDF',
            severity: 'high',
            category: 'Auth & Access',
            cwe: 'CWE-916',
            file: file.path,
            line: i + 1,
            evidence: realLine.trim().slice(0, 200),
            remediation:
              'SHA-256 alone is still a fast hash. Wrap it in PBKDF2 (Node crypto.pbkdf2 with at least 600,000 iterations) or switch to bcrypt/argon2id/scrypt. Adding a salt does not fix the speed problem.',
          });
        }
      }
      // Default credentials: admin/admin, root/root, test/test123,
      // user/password patterns in source. Strong "this was never updated"
      // signal in AI-generated code. Match the pattern as a kv-pair where the
      // key is admin/root/test/user/etc. and the value is the same word, a
      // single digit, or a known weak default.
      if (
        /(['"])(admin|root|test|user|guest)\1\s*[,:]\s*(['"])(\2|admin|root|password|123456|test123|password1|guest)\3/i.test(
          line
        ) ||
        /(?:user(?:name)?|login)\s*[:=]\s*['"](?:admin|root|test)['"][\s\S]{0,40}?(?:password|pass|pwd)\s*[:=]\s*['"](?:admin|root|password|123456|test123|password1)['"]/i.test(
          line
        )
      ) {
        findings.push({
          id: `auth-defaultcreds-${file.path}-${i}`,
          probe: 'Auth Weakness',
          title: 'Default credentials in source',
          severity: 'critical',
          category: 'Auth & Access',
          cwe: 'CWE-798',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'admin/admin, root/root, test/test123 — these are the first guesses an attacker tries. Defaults baked into source mean every clone of this repo ships with the same backdoor. Generate per-deploy credentials with a real secret manager; require rotation on first login.',
        });
      }
      // Session token in URL. Putting an auth token in the query string puts
      // it in browser history, in the Referer header sent to third parties,
      // in server access logs, and in any analytics SDK the page loads. The
      // shape: a literal or template-string URL containing ?token= /
      // ?sessionId= / ?accessToken= / ?jwt= with a real-looking value.
      // Use realLine because the URL contains `//` that stripLineComments
      // would chop. Template literals in realLine still trigger here (the
      // FP risk on documentation strings is acceptable for this check).
      if (
        /[?&](?:token|sessionId|session_id|accessToken|access_token|jwt|auth(?:Token)?)=/i.test(
          realLine
        ) &&
        /(?:fetch|axios|http|location\.href|window\.location|new\s+URL|navigate|router\.push|redirect)/i.test(
          realLine
        )
      ) {
        findings.push({
          id: `auth-tokeninurl-${file.path}-${i}`,
          probe: 'Auth Weakness',
          title: 'Auth token passed in URL query string',
          severity: 'high',
          category: 'Auth & Access',
          cwe: 'CWE-598',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'Query strings leak: browser history, server access logs, the Referer header sent to every third-party resource the page loads, analytics SDKs. Send tokens in an Authorization: Bearer header or an httpOnly cookie. Never as ?token=.',
        });
      }
      // Hardcoded password literal in a const/let/var. probeSecrets handles
      // known provider patterns (sk_live_, AKIA, etc.); a bare
      // `const PASSWORD = 'admin123'` is a different shape. The placeholder-
      // name filter (SAMPLE_/EXAMPLE_/FAKE_/TEST_KEY etc., reused from
      // probeSecrets via isMatchInPlaceholderNamedAssignment) suppresses
      // sample/test fixtures; the secret-value placeholder filter suppresses
      // CHANGEME/REPLACE/etc. values.
      // Object-literal credential fields: `password: 'literal'`,
      // `pass: 'literal'`, `username: 'admin', password: 'admin'` in a JS
      // config object. Match the key-value pair on a single line. (Multi-line
      // is handled by the whole-content pass below.)
      {
        const objLiteralCred = /\b(?:password|passwd|pwd|pass|secret)\s*:\s*(['"])([^'"\n]{3,})\1/i;
        const m = line.match(objLiteralCred);
        if (m) {
          const value = m[2];
          const matchIdx = file.content.indexOf(realLine);
          const inPlaceholderCtx =
            matchIdx >= 0 && isMatchInPlaceholderNamedAssignment(file.content, matchIdx);
          const valueIsPlaceholder = SECRET_VALUE_PLACEHOLDER_RE.test(value);
          if (!inPlaceholderCtx && !valueIsPlaceholder) {
            findings.push({
              id: `auth-objpwd-${file.path}-${i}`,
              probe: 'Auth Weakness',
              title: 'Hardcoded password in object literal',
              severity: 'critical',
              category: 'Auth & Access',
              cwe: 'CWE-798',
              file: file.path,
              line: i + 1,
              evidence: realLine.trim().slice(0, 200),
              remediation:
                'Object-literal passwords (auth: { user, pass: "literal" }) ship with the repo. Use env vars (process.env.SMTP_PASSWORD), a secret manager reference, or runtime injection. Rotate the leaked value.',
            });
          }
        }
      }
      // Basic auth header: `Authorization: 'Basic ' + Buffer.from('user:pass')`,
      // `const AUTH = 'Basic <base64>'`. Both are hardcoded creds in HTTP headers.
      if (
        /Buffer\.from\s*\(\s*['"][^'"\n]+:[^'"\n]+['"]\s*\)\s*\.\s*toString\s*\(\s*['"]base64/i.test(
          realLine
        ) ||
        /['"]Basic\s+[A-Za-z0-9+/=]{8,}['"]/.test(realLine)
      ) {
        findings.push({
          id: `auth-basicheader-${file.path}-${i}`,
          probe: 'Auth Weakness',
          title: 'Hardcoded Basic auth credentials in HTTP header',
          severity: 'critical',
          category: 'Auth & Access',
          cwe: 'CWE-798',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'Basic auth strings encoded inline ship the credentials with the repo. Load user:pass from env / secret manager and encode at runtime, or use a Bearer token from a real auth flow.',
        });
      }
      // Plaintext password persisted to DB. Two shapes:
      //  - `INSERT INTO users (..., password) VALUES (..., 'literal')`
      //  - ORM: `db.user.create({ data: { ..., password: req.body.password } })`
      // The second is plaintext-from-request — taint flow.
      if (
        /INSERT\s+INTO\s+[\w.]+\s*\([^)]*\bpassword\b[^)]*\)\s*VALUES\s*\([^)]*['"][^'"]{3,}['"]/i.test(
          realLine
        ) ||
        /(?:\.create|\.update|\.insert|\.save)\s*\([^)]*\bpassword\s*:\s*(?:req\.body\.\w*|input\.\w*|userInput|user\.password)/i.test(
          realLine
        )
      ) {
        findings.push({
          id: `auth-plainpwdstore-${file.path}-${i}`,
          probe: 'Auth Weakness',
          title: 'Plaintext password persisted to database',
          severity: 'critical',
          category: 'Auth & Access',
          cwe: 'CWE-256',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'Storing raw passwords means any DB read compromises every account. Hash with bcrypt.hash(password, 12) / argon2.hash / scrypt before insert, store the hash, never the plaintext. Constant-time compare at login time.',
        });
      }
      {
        // Match the assignment RHS specifically. Only fire if the value
        // IMMEDIATELY after `=` is a string literal (not a function call,
        // not a process.env access, not a logical-or default chain). The
        // canonical leak is `const PASSWORD = 'literal'` — exactly that.
        // Identifier must end in PASSWORD/PASSWD/PWD/SECRET, possibly with
        // a prefix like API_, DB_, JWT_ (all-caps + underscore + suffix).
        const credLiteral =
          /(?:const|let|var)\s+((?:[A-Z][A-Z0-9_]*_)?(?:PASSWORD|PASSWD|PWD|SECRET))\b\s*[:=]\s*(['"])([^'"\n]{3,})\2\s*[;,)\]}\s]*$/;
        const m = line.match(credLiteral);
        if (m) {
          const varName = m[1];
          const value = m[3];
          const matchIdx = file.content.indexOf(realLine);
          const inPlaceholderCtx =
            matchIdx >= 0 && isMatchInPlaceholderNamedAssignment(file.content, matchIdx);
          const valueIsPlaceholder = SECRET_VALUE_PLACEHOLDER_RE.test(value);
          if (!inPlaceholderCtx && !valueIsPlaceholder) {
            findings.push({
              id: `auth-hardcodedpwd-${file.path}-${i}`,
              probe: 'Auth Weakness',
              title: `Hardcoded password literal (${varName})`,
              severity: 'critical',
              category: 'Auth & Access',
              cwe: 'CWE-798',
              file: file.path,
              line: i + 1,
              evidence: realLine.trim().slice(0, 200),
              remediation:
                'Passwords pasted into source are committed to git history forever and shipped to every developer who clones the repo. Load from a secret manager (Doppler, 1Password, Vault, AWS Secrets Manager) or environment variable, NEVER a literal.',
            });
          }
        }
      }
      // JWT signing with a literal short secret. jwt.sign(payload, 'literal').
      // Short literal secrets (typically <32 chars) are brute-forceable in
      // hours on a laptop. Use `[^)]*?` so the regex backtracks past commas
      // INSIDE the payload object (e.g. `jwt.sign({sub, role}, 'secret')`).
      if (/jwt\.sign\s*\([^)]*?,\s*['"][^'"]{1,31}['"]\s*[\),]/.test(line)) {
        findings.push({
          id: `auth-weakjwtsecret-${file.path}-${i}`,
          probe: 'Auth Weakness',
          title: 'JWT signed with a short literal secret',
          severity: 'critical',
          category: 'Auth & Access',
          cwe: 'CWE-321',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'A 6-character literal secret is brute-forceable in seconds. Use crypto.randomBytes(64).toString("hex") at minimum, loaded from env / secret manager. The secret must be unguessable.',
        });
      }
      // JWT verify with empty-string secret: `jwt.verify(token, '')`. Some
      // legacy library versions accept this and skip verification entirely.
      if (/jwt\.verify\s*\(\s*[^,)]+,\s*(['"])\1\s*[\),]/.test(line)) {
        findings.push({
          id: `auth-emptyjwtsecret-${file.path}-${i}`,
          probe: 'Auth Weakness',
          title: 'jwt.verify called with empty-string secret',
          severity: 'critical',
          category: 'Auth & Access',
          cwe: 'CWE-347',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'An empty string is not a secret. Some library versions treat empty-string secrets as "skip verification" — every forged token verifies as authentic. Load the real secret from env / secret manager and assert it is non-empty before passing.',
        });
      }
      // Default credentials inside a connection-string URL:
      // `mysql://root:root@host`, `postgres://admin:admin@host`. Same identifier
      // for user AND password is the strongest "this was never changed" signal.
      // Use realLine — stripLineComments mangles the `//` in the URL scheme.
      if (
        /(?:mysql|postgres(?:ql)?|mongodb|mongo|redis|amqp|http|https|ftp|smtp|imap):\/\/(\w+):(\w+)@/i.test(
          realLine
        )
      ) {
        const urlMatch = realLine.match(
          /(?:mysql|postgres(?:ql)?|mongodb|mongo|redis|amqp|http|https|ftp|smtp|imap):\/\/(\w+):(\w+)@/i
        );
        if (urlMatch && urlMatch[1].toLowerCase() === urlMatch[2].toLowerCase()) {
          findings.push({
            id: `auth-defaultcredsurl-${file.path}-${i}`,
            probe: 'Auth Weakness',
            title: 'Default credentials in connection string (user == password)',
            severity: 'critical',
            category: 'Auth & Access',
            cwe: 'CWE-798',
            file: file.path,
            line: i + 1,
            evidence: realLine.trim().slice(0, 200),
            remediation:
              'Same identifier for both user AND password (root:root, admin:admin) is the strongest "this is the install default" signal. Set per-deploy credentials at provisioning time.',
          });
        }
      }
      // Express handler writes to DB with no req.user / auth check on the
      // same line — match the destructive db call and confirm the file has
      // NO auth signals anywhere.
      if (
        /\b(?:db|prisma|knex|sequelize)\s*\.\s*\w+\s*\.\s*(?:delete|update|create|destroy|findAll|findMany|getAll)\s*\(/.test(
          line
        )
      ) {
        const fileNoAuth =
          !/(?:req\.user|req\.session|req\.auth|getServerSession|getUser|currentUser|withAuth|requireAuth|authenticate|jwt\.verify\s*\([^,)]+,)/i.test(
            file.content
          );
        const inExpressOrNext =
          /\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete)\s*\(/.test(file.content) ||
          /export\s+(?:async\s+)?(?:function|const)\s+(?:GET|POST|PUT|PATCH|DELETE)\b/.test(
            file.content
          ) ||
          // Next.js Pages Router uses `export default async function handler(req, res)`.
          /export\s+default\s+(?:async\s+)?function\s+\w+\s*\(\s*req\b/.test(file.content) ||
          /pages\/api\//.test(file.path);
        if (fileNoAuth && inExpressOrNext) {
          findings.push({
            id: `auth-noauthcheck-${file.path}-${i}`,
            probe: 'Auth Weakness',
            title: 'DB mutation in handler with no auth check anywhere in the file',
            severity: 'high',
            category: 'Auth & Access',
            cwe: 'CWE-306',
            file: file.path,
            line: i + 1,
            evidence: realLine.trim().slice(0, 200),
            remediation:
              'A handler that mutates the database with no auth gate is open to anyone. Add req.user / getServerSession() / passport.authenticate at the top of the handler, return 401 if absent, then check ownership of the target row before the mutation.',
          });
        }
      }
      // JWT no-expiresIn (CWE-613): the token is valid forever. Both this
      // production probe AND the JS-AUTH-001 shadow probe emit identical
      // findings (same id, title, severity) so the v05-phase2 parity test
      // stays green. Sync the emission shape if one is changed.
      if (/jwt\.sign\s*\(/.test(line)) {
        const startIdx = file.content.indexOf(realLine);
        const around = startIdx >= 0 ? file.content.slice(startIdx, startIdx + 400) : line;
        if (!/expiresIn\s*:|\bexp\s*:/.test(around)) {
          findings.push({
            id: `auth-noexpiry-${file.path}-${i}`,
            probe: 'Auth Weakness',
            title: 'JWT minted without expiresIn',
            severity: 'medium',
            category: 'Auth & Access',
            cwe: 'CWE-613',
            file: file.path,
            line: i + 1,
            evidence: realLine.trim(),
            remediation:
              'A JWT without expiresIn is valid forever. Stolen tokens remain valid until the secret is rotated. Pass { expiresIn: "15m" } (access) or short windows appropriate to the use case, and issue refresh tokens separately.',
          });
        }
      }
      // JWT verify accepting algorithms allowlist containing 'none'. Even if
      // the developer remembered to allowlist, including 'none' defeats the
      // entire point — an attacker just sends an unsigned token.
      if (
        /jwt\.verify\s*\([^)]*algorithms\s*:\s*\[[^\]]*['"]none['"]/i.test(line) ||
        /jwt\.verify\s*\([^)]*algorithms\s*:\s*\[[^\]]*['"]None['"]/.test(line)
      ) {
        findings.push({
          id: `auth-noneinallowlist-${file.path}-${i}`,
          probe: 'Auth Weakness',
          title: 'JWT verify algorithms allowlist includes "none"',
          severity: 'critical',
          category: 'Auth & Access',
          cwe: 'CWE-327',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'Allowlisting "none" defeats the allowlist. Remove "none" from the algorithms array. Pin to one strong algorithm like HS256 with a strong secret or RS256 with a key pair.',
        });
      }
    });
  });
  return findings;
}

export function probeAdminRoutes(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.[jt]sx?$/.test(file.path)) return;
    if (!/(admin|dashboard|internal)/i.test(file.path)) return;
    // Exclude obvious marketing/preview routes that happen to contain "dashboard" in the path.
    if (/(marketing|landing|public|preview|sample|demo|docs?|example)/i.test(file.path)) return;
    // Next.js route groups in parens are layout-only, not user-routable: app/(marketing)/... .
    if (/\(([a-z_-]+)\)/i.test(file.path) && /(marketing|public|landing)/i.test(file.path)) return;
    const hasServerCheck =
      /(getServerSession|auth\(\)|requireAuth|withAuth|middleware|verifyToken)/.test(file.content);
    const hasClientOnlyCheck = /(useUser|useSession|useAuth)/.test(file.content);
    if (!hasServerCheck && hasClientOnlyCheck) {
      findings.push({
        id: `admin-clientonly-${file.path}`,
        probe: 'Admin Route Exposure',
        title: 'Admin route appears to rely on client-side auth check only',
        severity: 'high',
        category: 'Auth & Access',
        cwe: 'CWE-602',
        file: file.path,
        line: 1,
        evidence: `Path matches admin pattern, contains client hooks (useUser/useSession), no server-side check detected`,
        remediation: `Client-side auth checks (useUser, useSession) only hide the UI. The route is still accessible by direct fetch. Add a server-side check via middleware.ts, getServerSession, or a route handler that verifies auth and role before returning data. This is a manual review finding; verify by hitting the route directly without authentication.`,
      });
    }
  });
  return findings;
}

// Parse a Cloudflare Pages / Netlify `_headers` file for the set of header names
// it configures. Format: indented `Header-Name: value` lines under a path
// pattern (`/*`, `/admin/*`, etc.). Returns a lowercased Set.
function parseHeadersFileNames(content) {
  const headers = new Set();
  for (const line of content.split(/\r?\n/)) {
    const m = line.match(/^[ \t]+([A-Za-z][A-Za-z0-9-]*)\s*:/);
    if (m) headers.add(m[1].toLowerCase());
  }
  return headers;
}

// Parse vercel.json `headers` array for header names across all path blocks.
function parseVercelHeaderNames(content) {
  const headers = new Set();
  try {
    const cfg = JSON.parse(content);
    const blocks = Array.isArray(cfg.headers) ? cfg.headers : [];
    for (const block of blocks) {
      const list = Array.isArray(block.headers) ? block.headers : [];
      for (const h of list) {
        if (h && typeof h.key === 'string') headers.add(h.key.toLowerCase());
      }
    }
  } catch {
    /* malformed JSON: caller treats as no headers configured */
  }
  return headers;
}

// Parse firebase.json hosting.headers for header names.
function parseFirebaseHeaderNames(content) {
  const headers = new Set();
  try {
    const cfg = JSON.parse(content);
    const blocks = Array.isArray(cfg?.hosting?.headers) ? cfg.hosting.headers : [];
    for (const block of blocks) {
      const list = Array.isArray(block.headers) ? block.headers : [];
      for (const h of list) {
        if (h && typeof h.key === 'string') headers.add(h.key.toLowerCase());
      }
    }
  } catch {
    /* malformed JSON: caller treats as no headers configured */
  }
  return headers;
}

// Minimal TOML parse for [[headers]] blocks: pulls header key names out of
// `[headers.values]` tables. Full TOML parser is overkill for this scope.
function parseNetlifyTomlHeaderNames(content) {
  const headers = new Set();
  // Match each [[headers]] block and the [headers.values] sub-table inside it.
  const re = /\[headers\.values\]([\s\S]*?)(?=\n\s*\[|$)/g;
  let m;
  while ((m = re.exec(content))) {
    for (const line of m[1].split(/\r?\n/)) {
      const km = line.match(/^\s*([A-Za-z][A-Za-z0-9-]*)\s*=/);
      if (km) headers.add(km[1].toLowerCase());
    }
  }
  return headers;
}

// FP-3 disambiguation: presence of any IaC template suggests headers may be
// configured at the host edge layer (CloudFront Response Headers Policy, etc.)
// where PreFlight can't statically see them. Downgrade severity rather than
// suppress entirely so the user still sees a reminder.
function hasInfraAsCode(files) {
  return files.some((f) =>
    /(\.tf|(^|\/)cdk\.json|(^|\/)template\.ya?ml|(^|\/)serverless\.ya?ml)$/.test(f.path)
  );
}

// FP-10 disambiguation: a reverse proxy in front of the app may inject headers
// outside PreFlight's static view.
function hasReverseProxy(files) {
  return files.some((f) =>
    /((^|\/)Caddyfile|(^|\/)nginx\.conf|(^|\/)traefik\.ya?ml)$/.test(f.path)
  );
}

// FP-8 disambiguation: a GitHub Pages target has no first-class header config
// mechanism; flagging "missing _headers" is misleading because the user can't
// fix it at the framework layer.
function isGitHubPagesOnly(files, hostsDetected) {
  if (hostsDetected.size > 1) return false;
  return files.some(
    (f) =>
      /\.github\/workflows\/.+\.ya?ml$/.test(f.path) &&
      /(actions\/deploy-pages|actions\/upload-pages-artifact|gh-pages)/.test(f.content)
  );
}

// FP-9 disambiguation: Next.js `output: 'export'` silently disables
// next.config.js `headers()`. The probe's positive signal becomes meaningless.
function isNextStaticExport(nextFile) {
  return /output\s*:\s*['"`]export['"`]/.test(nextFile.content);
}

// Cheap host classifier. Used only for the GitHub-Pages-only suppression today
// (FP-8); host-config-file detection drives the rest of the probe directly.
function classifyHosts(files) {
  const hosts = new Set();
  if (files.some((f) => /(^|\/)wrangler\.(toml|jsonc?)$/.test(f.path))) hosts.add('cloudflare');
  if (files.some((f) => /(^|\/)netlify\.toml$/.test(f.path))) hosts.add('netlify');
  if (files.some((f) => /(^|\/)vercel\.(json|ts)$/.test(f.path))) hosts.add('vercel');
  if (files.some((f) => /(^|\/)fly\.toml$/.test(f.path))) hosts.add('fly');
  if (files.some((f) => /(^|\/)render\.yaml$/.test(f.path))) hosts.add('render');
  if (files.some((f) => /(^|\/)railway\.(json|toml)$/.test(f.path))) hosts.add('railway');
  if (files.some((f) => /(^|\/)firebase\.json$/.test(f.path))) hosts.add('firebase');
  if (files.some((f) => /(^|\/)_headers$/.test(f.path))) hosts.add('static-headers');
  return hosts;
}

// Canonical security-header set for SAST-visible checking. Sourced from MDN's
// HTTP security headers reference. Per-header severity is calibrated to the
// real-world impact of each individual header missing in 2026:
//   CSP / HSTS    medium  (foundational defenses)
//   X-CTO         low     (older defense, still recommended)
//   Referrer      low     (privacy + small auth-token-in-URL leak risk)
//   Permissions   low     (least urgent on apps that don't use camera/mic/etc)
// Frame-ancestors is checked separately because either X-Frame-Options or a
// CSP with frame-ancestors directive satisfies it.
const CANONICAL_SECURITY_HEADERS = [
  { key: 'content-security-policy', label: 'Content-Security-Policy', baseSev: 'medium' },
  { key: 'strict-transport-security', label: 'Strict-Transport-Security', baseSev: 'medium' },
  { key: 'x-content-type-options', label: 'X-Content-Type-Options', baseSev: 'low' },
  { key: 'referrer-policy', label: 'Referrer-Policy', baseSev: 'low' },
  { key: 'permissions-policy', label: 'Permissions-Policy', baseSev: 'low' },
];

export function probeMissingHeaders(files) {
  const findings = [];

  // Stage 0: FP-8 — GitHub Pages target with no other host signal: suppress.
  const hostsDetected = classifyHosts(files);
  if (isGitHubPagesOnly(files, hostsDetected)) return findings;

  // Stage 1: collect statically-parseable host config sources and the union of
  // header names they configure. next.config.js is excluded from this set
  // because its `headers()` function is opaque to static analysis (returns at
  // runtime), so we treat it as an ambiguous-positive in Stage 3.
  const configured = new Set();
  const staticSources = [];
  const collect = (file, names) => {
    staticSources.push(file.path);
    for (const n of names) configured.add(n);
  };

  const headersFile = files.find((f) => /(^|\/)_headers$/.test(f.path));
  if (headersFile) collect(headersFile, parseHeadersFileNames(headersFile.content));

  const netlifyToml = files.find((f) => /(^|\/)netlify\.toml$/.test(f.path));
  if (netlifyToml) collect(netlifyToml, parseNetlifyTomlHeaderNames(netlifyToml.content));

  const vercelJson = files.find((f) => /(^|\/)vercel\.json$/.test(f.path));
  if (vercelJson) collect(vercelJson, parseVercelHeaderNames(vercelJson.content));

  const firebaseJson = files.find((f) => /(^|\/)firebase\.json$/.test(f.path));
  if (firebaseJson) collect(firebaseJson, parseFirebaseHeaderNames(firebaseJson.content));

  const next = files.find((f) => /(^|\/)next\.config\.(js|mjs|ts)$/.test(f.path));
  const nextConfigured =
    next && (/headers\s*\(/.test(next.content) || /securityHeaders/.test(next.content));
  const nextStaticExport = next ? isNextStaticExport(next) : false;

  // Stage 2: FP-9 — Next static-export with only next.config.js headers() is
  // effectively missing because Next silently drops headers() on static export.
  if (nextConfigured && nextStaticExport && staticSources.length === 0) {
    findings.push({
      id: `headers-next-static-export-${next.path}`,
      probe: 'Security Headers',
      title: 'next.config.js headers() ignored on static export',
      severity: 'medium',
      category: 'Misconfiguration',
      cwe: 'CWE-693',
      file: next.path,
      line: 1,
      evidence:
        'next.config has output: "export" and headers(), but Next.js does not apply headers() on static exports.',
      remediation: `Static-exported Next.js apps must configure headers at the host layer. Add the headers to public/_headers (Cloudflare Pages / Netlify), vercel.json's headers array, or firebase.json's hosting.headers. The headers() function in next.config will not run on a static export. Reference: https://nextjs.org/docs/app/api-reference/config/next-config-js/headers`,
    });
    return findings;
  }

  // Stage 3: Per-header coverage on statically-parseable host config.
  if (staticSources.length > 0) {
    const downgrade = hasInfraAsCode(files) || hasReverseProxy(files);
    const primarySource = staticSources[0];
    const allSources = staticSources.join(', ');

    for (const c of CANONICAL_SECURITY_HEADERS) {
      if (!configured.has(c.key)) {
        findings.push({
          id: `headers-missing-${c.key}-${primarySource}`,
          probe: 'Security Headers',
          title: `Missing ${c.label} header`,
          severity: downgrade ? 'info' : c.baseSev,
          category: 'Misconfiguration',
          cwe: 'CWE-693',
          file: primarySource,
          line: 1,
          evidence: `${c.label} is not set in ${allSources}.${downgrade ? ' Severity downgraded to info because IaC or a reverse proxy was detected, which may set headers outside this repo.' : ''}`,
          remediation: `Add ${c.label} to ${primarySource}. See MDN's reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/${c.label}. The security-headers Learn page has recommended values for each.`,
        });
      }
    }

    // Frame-ancestors: satisfied by X-Frame-Options OR a CSP that includes
    // `frame-ancestors`. Check the raw config contents for the directive.
    const hasXFO = configured.has('x-frame-options');
    const hasCspFrameAncestors =
      configured.has('content-security-policy') &&
      [headersFile, netlifyToml, vercelJson, firebaseJson]
        .filter(Boolean)
        .some((f) => /frame-ancestors/i.test(f.content));
    if (!hasXFO && !hasCspFrameAncestors) {
      findings.push({
        id: `headers-missing-frame-ancestors-${primarySource}`,
        probe: 'Security Headers',
        title: 'No clickjacking protection (X-Frame-Options or CSP frame-ancestors)',
        severity: downgrade ? 'info' : 'medium',
        category: 'Misconfiguration',
        cwe: 'CWE-1021',
        file: primarySource,
        line: 1,
        evidence: `Neither X-Frame-Options nor a Content-Security-Policy with a frame-ancestors directive is set in ${allSources}.`,
        remediation: `Add either X-Frame-Options: DENY (or SAMEORIGIN) to ${primarySource}, or include frame-ancestors 'none' (or 'self') in your Content-Security-Policy. CSP frame-ancestors supersedes X-Frame-Options in modern browsers; either is acceptable.`,
      });
    }
    return findings;
  }

  // Stage 4: No statically-parseable host config. If next.config.js declared a
  // headers() function, treat as opaque-positive and suppress (we cannot
  // inspect what it returns; legacy behavior preserved for compatibility).
  if (next && nextConfigured) return findings;

  // Stage 5: next.config.js exists but has no headers() — legacy single
  // finding preserved. Any other framework with no host config is silent here
  // to avoid false positives on architectures the probe doesn't yet model.
  if (next && !nextConfigured) {
    findings.push({
      id: `headers-${next.path}`,
      probe: 'Security Headers',
      title: 'No custom security headers configured in next.config',
      severity: 'medium',
      category: 'Misconfiguration',
      cwe: 'CWE-693',
      file: next.path,
      line: 1,
      evidence: 'No headers() function or securityHeaders array found',
      remediation: `Add a headers() function returning Content-Security-Policy, Strict-Transport-Security, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and Referrer-Policy: strict-origin-when-cross-origin. These prevent XSS, clickjacking, and MIME sniffing attacks. If this is a static export (output: 'export'), configure headers at the host layer (public/_headers or vercel.json) instead.`,
    });
  }
  return findings;
}

export function probeCORS(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.[jt]sx?$/.test(file.path)) return;
    const lines = file.content.split('\n');
    lines.forEach((line, i) => {
      if (/Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']/.test(line)) {
        findings.push({
          id: `cors-wildcard-${file.path}-${i}`,
          probe: 'CORS Check',
          title: 'CORS wildcard "*" on Access-Control-Allow-Origin',
          severity: 'medium',
          category: 'Misconfiguration',
          cwe: 'CWE-942',
          file: file.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation: `If this endpoint returns user-specific data or accepts authenticated requests, "*" allows any origin to read responses. Restrict to known origins or echo the request Origin against an allowlist.`,
        });
      }
    });
  });
  return findings;
}

// ==========================================================================
// MODERN ATTACK SURFACE PROBES (May 2026)
// ==========================================================================

// --- LLM / AI Application Security (OWASP LLM Top 10 2025) ---
export function probeLLMSecurity(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.[jt]sx?$|\.py$/.test(file.path)) return;
    const content = file.content;
    const lines = content.split('\n');
    const isClientFile =
      /^['"]use client['"]/m.test(content) ||
      (/\.tsx?$/.test(file.path) &&
        /(components|app)\//.test(file.path) &&
        !/\/api\/|\/server\/|route\.[jt]sx?$|middleware\./.test(file.path));

    // LLM01: Prompt Injection — user input concatenated into prompts
    lines.forEach((line, i) => {
      if (
        /(?:content|prompt|messages|system)\s*:\s*[`'"][^`'"]*\$\{[^}]*(?:req\.|request\.|userInput|userMessage|body\.|query\.|params\.|searchParams)/.test(
          line
        )
      ) {
        findings.push({
          id: `llm-injection-${file.path}-${i}`,
          probe: 'LLM Security',
          title: 'User input interpolated into LLM prompt (prompt injection)',
          severity: 'high',
          category: 'AI/LLM Security',
          cwe: 'CWE-1336 (LLM01)',
          file: file.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation:
            'Direct string interpolation enables prompt injection. The user can override your system prompt with payloads like "Ignore previous instructions." Pass user input as a separate user-role message, never interpolated into the system prompt or tool descriptions. Validate the LLM output schema before acting on it. OWASP LLM01:2025.',
        });
      }
    });

    // LLM02: Sensitive Information Disclosure — LLM call from client
    lines.forEach((line, i) => {
      if (
        isClientFile &&
        /(openai|anthropic|cohere|together|replicate|groq|mistral)\.(?:chat|completions|messages|generate|complete)/i.test(
          line
        )
      ) {
        findings.push({
          id: `llm-client-${file.path}-${i}`,
          probe: 'LLM Security',
          title: 'LLM API call from client component (key exposure)',
          severity: 'critical',
          category: 'AI/LLM Security',
          cwe: 'CWE-200 (LLM02)',
          file: file.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation:
            'LLM API calls from client code expose your provider key to every visitor. Move the call to a server route handler, API route, or Edge Function. Pass only the prompt content from client to server, never the key. OWASP LLM02:2025.',
        });
      }
    });

    // LLM05: Improper Output Handling — LLM output rendered as HTML
    lines.forEach((line, i) => {
      if (/dangerouslySetInnerHTML/.test(line)) {
        const ctx = lines.slice(Math.max(0, i - 5), i + 1).join(' ');
        if (
          /(completion|response|message|content|reply|llmOutput|aiResponse)/i.test(ctx) &&
          /(openai|anthropic|chat|llm|generate)/i.test(content)
        ) {
          findings.push({
            id: `llm-html-${file.path}-${i}`,
            probe: 'LLM Security',
            title: 'LLM response possibly rendered as raw HTML',
            severity: 'high',
            category: 'AI/LLM Security',
            cwe: 'CWE-79 (LLM05)',
            file: file.path,
            line: i + 1,
            evidence: line.trim().slice(0, 200),
            remediation:
              'LLMs can be coerced into emitting HTML/JS via prompt injection; rendering through dangerouslySetInnerHTML becomes XSS. Use react-markdown with rehype-sanitize, or DOMPurify the HTML before injection. OWASP LLM05:2025.',
          });
        }
      }
    });

    // LLM06: Excessive Agency — dangerous LangChain/agent tools
    const dangerousAgent = content.match(
      /\b(PythonREPL|PythonREPLTool|ShellTool|RequestsTool|RequestsGetTool|RequestsPostTool|BashProcess|TerminalTool|FileManagementToolkit|ExperimentalCodeInterpreter)\b/
    );
    if (dangerousAgent) {
      const ln = content.slice(0, dangerousAgent.index).split('\n').length;
      findings.push({
        id: `llm-agency-${file.path}-${dangerousAgent.index}`,
        probe: 'LLM Security',
        title: `${dangerousAgent[0]} grants arbitrary code execution to the LLM`,
        severity: 'critical',
        category: 'AI/LLM Security',
        cwe: 'CWE-94 (LLM06)',
        file: file.path,
        line: ln,
        evidence: dangerousAgent[0],
        remediation:
          'PythonREPL, ShellTool, RequestsTool and similar let the LLM execute arbitrary code or make arbitrary network requests on your server. A successful prompt injection becomes RCE. Replace with narrowly-scoped tools that take typed arguments and validate them. If sandboxed execution is genuinely needed, isolate it in Pyodide, Modal, e2b, or Daytona. OWASP LLM06:2025.',
      });
    }

    // LLM06: Tool definitions with destructive names
    const destructiveTool = [
      ...content.matchAll(
        /name\s*:\s*['"`]((?:exec|run_?shell|run_?command|execute_?code|execute_?python|delete_?file|delete_?user|run_?sql|grant_?admin|sudo)[a-z_]*)['"`]/gi
      ),
    ];
    destructiveTool.forEach((m) => {
      const ln = content.slice(0, m.index).split('\n').length;
      findings.push({
        id: `llm-tool-${file.path}-${m.index}`,
        probe: 'LLM Security',
        title: `LLM tool with destructive name: "${m[1]}"`,
        severity: 'high',
        category: 'AI/LLM Security',
        cwe: 'CWE-77 (LLM06)',
        file: file.path,
        line: ln,
        evidence: m[0],
        remediation:
          'Tools with destructive capabilities exposed to an LLM agent must perform authorization checks INSIDE the tool implementation, not just at the route level. The LLM can be tricked into calling them by indirect prompt injection (poisoned issues, README, RAG content). Validate caller identity, scope, and arguments inside every tool. OWASP LLM06:2025.',
      });
    });

    // LLM07: System Prompt Leakage — hardcoded system prompt in client bundle
    if (isClientFile) {
      const sysPrompt = content.match(
        /(?:system\s*[:=]\s*|role\s*:\s*['"`]system['"`][\s\S]{0,80}content\s*:\s*)['"`]([^'"`]{40,})['"`]/
      );
      if (sysPrompt) {
        const ln = content.slice(0, sysPrompt.index).split('\n').length;
        findings.push({
          id: `llm-prompt-${file.path}-${sysPrompt.index}`,
          probe: 'LLM Security',
          title: 'System prompt embedded in client-side bundle',
          severity: 'medium',
          category: 'AI/LLM Security',
          cwe: 'CWE-200 (LLM07)',
          file: file.path,
          line: ln,
          evidence: sysPrompt[1].slice(0, 100) + (sysPrompt[1].length > 100 ? '...' : ''),
          remediation:
            'System prompts shipped to the client are inspectable by every user (DevTools, View Source) and reveal product logic, guardrails, and competitive IP. Move prompt construction server-side. OWASP LLM07:2025.',
        });
      }
    }

    // LLM10: Unbounded Consumption — no max_tokens and no rate limit
    const hasLLMCall =
      /(openai|anthropic|cohere|together|replicate|groq)\.(?:chat|completions|messages|generate|complete)/i.test(
        content
      );
    if (hasLLMCall && !/max_tokens|maxTokens|max_output_tokens/i.test(content)) {
      findings.push({
        id: `llm-unbounded-${file.path}`,
        probe: 'LLM Security',
        title: 'LLM call without max_tokens limit',
        severity: 'low',
        category: 'AI/LLM Security',
        cwe: 'CWE-770 (LLM10)',
        file: file.path,
        line: 1,
        evidence: 'LLM API call detected with no max_tokens / max_output_tokens parameter',
        remediation:
          'Without an output cap, an attacker can craft inputs that force long generations, multiplying your bill (Denial of Wallet) and degrading service. Always set a reasonable max_tokens. Pair with per-user rate limits. OWASP LLM10:2025.',
      });
    }
  });
  return findings;
}

// --- Webhook Signature Verification ---
export function probeWebhookValidation(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.[jt]sx?$|\.py$/.test(file.path)) return;
    if (!/webhook/i.test(file.path) && !/webhook/i.test(file.content)) return;
    const c = file.content;
    if (/stripe/i.test(c) && /webhook/i.test(file.path)) {
      const verified = /(constructEvent|stripe-signature)/i.test(c);
      const readsBody = /(req\.body|request\.body|await\s+req\.text|await\s+req\.json)/i.test(c);
      if (readsBody && !verified) {
        findings.push({
          id: `webhook-stripe-${file.path}`,
          probe: 'Webhook Validation',
          title: 'Stripe webhook handler missing signature verification',
          severity: 'high',
          category: 'Auth & Access',
          cwe: 'CWE-345',
          file: file.path,
          line: 1,
          evidence: 'Reads request body, no constructEvent or stripe-signature check found',
          remediation:
            'Without signature verification anyone can POST a forged webhook to upgrade users, mark orders complete, or trigger refunds. Use stripe.webhooks.constructEvent(rawBody, sig, secret). Read the raw body, not JSON-parsed.',
        });
      }
    }
    if (/github|x-hub-signature/i.test(c) && /webhook/i.test(file.path)) {
      if (!/(x-hub-signature|verifyHmac|crypto\.timingSafeEqual)/i.test(c)) {
        findings.push({
          id: `webhook-github-${file.path}`,
          probe: 'Webhook Validation',
          title: 'GitHub webhook handler missing HMAC verification',
          severity: 'high',
          category: 'Auth & Access',
          cwe: 'CWE-345',
          file: file.path,
          line: 1,
          evidence: 'No X-Hub-Signature-256 verification detected',
          remediation:
            'Verify the X-Hub-Signature-256 header against your webhook secret using crypto.timingSafeEqual. Otherwise any attacker can forge events.',
        });
      }
    }
  });
  return findings;
}

// --- GitHub Actions Workflow Security ---
export function probeGitHubActions(files) {
  const findings = [];
  files.forEach((file) => {
    if (!/\.github\/workflows\/.+\.ya?ml$/.test(file.path)) return;
    const c = file.content;
    if (/pull_request_target/.test(c)) {
      const checkoutHead =
        /actions\/checkout@[\s\S]*?ref:\s*\$\{\{\s*github\.(?:event\.pull_request\.head\.ref|head_ref)/.test(
          c
        );
      if (checkoutHead) {
        findings.push({
          id: `gha-prtarget-${file.path}`,
          probe: 'GitHub Actions',
          title: 'pull_request_target workflow checks out untrusted PR code',
          severity: 'critical',
          category: 'Supply Chain',
          cwe: 'CWE-829',
          file: file.path,
          line: 1,
          evidence: 'pull_request_target trigger combined with checkout of PR head ref',
          remediation:
            'pull_request_target runs with secrets and write permissions. Checking out the PR head and running scripts from it is privilege escalation: anyone who opens a PR can exfiltrate your secrets. Use pull_request instead, or split into untrusted-build (pull_request) plus trusted-deploy (workflow_run).',
        });
      }
    }
    [...c.matchAll(/uses:\s*([^@\s]+)@(\S+)/g)].forEach((m) => {
      const [, action, ref] = m;
      if (action.startsWith('./') || action.includes('docker://')) return;
      const isSha = /^[a-f0-9]{40}$/.test(ref);
      const isVer = /^v?\d+(\.\d+)*$/.test(ref);
      if (!isSha && !isVer) {
        const ln = c.slice(0, m.index).split('\n').length;
        findings.push({
          id: `gha-unpinned-${file.path}-${m.index}`,
          probe: 'GitHub Actions',
          title: `Action "${action}" pinned to mutable ref "${ref}"`,
          severity: 'medium',
          category: 'Supply Chain',
          cwe: 'CWE-1357',
          file: file.path,
          line: ln,
          evidence: m[0],
          remediation: `If the action's owner is compromised your CI runs malicious code with whatever secrets you've granted. Pin to a full commit SHA: uses: ${action}@<40-char-sha>. Use Dependabot or Renovate to keep SHAs current.`,
        });
      }
    });
  });
  return findings;
}

// --- Client-side auth token storage ---
export function probeClientAuthStorage(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.[jt]sx?$/.test(file.path)) return;
    // Mask comments + string literals so the anti-pattern shape inside
    // documentation comments, JSDoc warnings, and code-as-string snippets
    // (teaching examples) no longer trips the regex. Indices preserved so the
    // emitted line numbers stay correct against the real source.
    // Narrow mask: blanks block comments, line comments, and backtick template
    // literals. Single/double-quoted string content stays visible so the
    // regexes can still see real auth-token-name string literals.
    const maskedContent = maskBlockCommentsAndTemplateLiterals(file.content);
    const maskedLines = maskedContent.split('\n');
    const originalLines = file.content.split('\n');
    // Common auth-name regex for storage keys. The keyword family must
    // appear as a substring inside a quoted key. Underscored forms
    // (auth_token, access_token) and camelCase forms (authToken) both
    // match without imposing word-boundary constraints.
    const AUTH_KEY_RE =
      /['"`][^'"`]*(?:token|jwt|auth|session|bearer|access_?token|refresh_?token|api[_-]?key)[^'"`]*['"`]/i;
    // Exclude OAuth/PKCE flow values that are PUBLIC by RFC 7636 design —
    // state, nonce, code_verifier, pkce. Storing these in sessionStorage is
    // intentional CSRF protection, not a credential leak.
    const OAUTH_PUBLIC_RE = /\b(?:oauth_?state|state|nonce|code_?verifier|pkce_?verifier)\b/i;
    maskedLines.forEach((maskedLine, i) => {
      const realLine = originalLines[i] || '';
      // localStorage.setItem('jwt', ...)
      if (/localStorage\.setItem\s*\(\s*[^,)]*\)/i.test(maskedLine) === false) {
        // skip
      }
      if (/localStorage\.setItem\s*\(/i.test(maskedLine) && AUTH_KEY_RE.test(maskedLine)) {
        findings.push({
          id: `auth-localstorage-${file.path}-${i}`,
          probe: 'Client Auth Storage',
          title: 'Auth token stored in localStorage',
          severity: 'medium',
          category: 'Auth & Access',
          cwe: 'CWE-922',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'localStorage is readable by any JS on the page, including third-party scripts and successful XSS. Use httpOnly secure SameSite cookies set server-side. If JS-readable storage is necessary, accept the risk explicitly and harden CSP.',
        });
      }
      // sessionStorage.setItem — slightly better than localStorage (cleared on
      // tab close) but still XSS-readable. Same XSS-readable threat model.
      // Excludes OAuth state/nonce/PKCE — RFC 7636 SPEC requires the client
      // to remember these across the redirect, and they are not credentials.
      if (
        /sessionStorage\.setItem\s*\(/i.test(maskedLine) &&
        AUTH_KEY_RE.test(maskedLine) &&
        !OAUTH_PUBLIC_RE.test(maskedLine)
      ) {
        findings.push({
          id: `auth-sessionstorage-${file.path}-${i}`,
          probe: 'Client Auth Storage',
          title: 'Auth token stored in sessionStorage',
          severity: 'medium',
          category: 'Auth & Access',
          cwe: 'CWE-922',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'sessionStorage is XSS-readable just like localStorage. The only difference is it clears on tab close. Same fix: httpOnly secure SameSite cookies set server-side.',
        });
      }
      // IndexedDB writes carrying auth: db.put('auth', ...), objectStore.put(
      // { token: ... }), idb-keyval set('jwt', ...), tx.objectStore('x').
      // put({ jwt: value }). The bare-key object form (`{ jwt: ... }`) is
      // not quoted, so AUTH_KEY_RE misses it — detect explicit-key shapes.
      const idbAuthMethodOnLine =
        /\.(?:put|add)\s*\(/.test(maskedLine) ||
        /\bidb(?:Keyval)?\.set\s*\(/.test(maskedLine) ||
        /\bset\s*\(\s*['"`][^'"`]*(?:token|jwt|auth|session|bearer)/i.test(maskedLine);
      const idbAuthKeyInObject =
        /\{\s*[^}]*\b(?:jwt|authToken|accessToken|refreshToken|bearer|sessionId)\s*:/i.test(
          maskedLine
        );
      // File-level IDB signal: any of the canonical IDB API names, OR a
      // `store.add/put({...})` shape (idb-keyval wrappers and raw IDB code
      // typically introduce a `store` variable from objectStore() or openDB()).
      const idbFileSignal =
        /indexedDB|objectStore|idb|openDB|IDBObjectStore|IDBDatabase/i.test(file.content) ||
        /\bstore\s*\.\s*(?:add|put)\s*\(/.test(file.content);
      if (
        idbAuthMethodOnLine &&
        idbFileSignal &&
        (AUTH_KEY_RE.test(maskedLine) || idbAuthKeyInObject)
      ) {
        findings.push({
          id: `auth-indexeddb-${file.path}-${i}`,
          probe: 'Client Auth Storage',
          title: 'Auth token stored in IndexedDB',
          severity: 'medium',
          category: 'Auth & Access',
          cwe: 'CWE-922',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'IndexedDB is JavaScript-readable, same XSS exposure as localStorage. Use httpOnly cookies set by the server.',
        });
      }
      // document.cookie = 'token=...' WITHOUT HttpOnly. Setting a cookie from
      // JS cannot set HttpOnly (browsers refuse). Any token cookie set from
      // client JS is XSS-readable by construction. Same risk as localStorage.
      // Use realLine — the cookie name and value may span template literal
      // interpolations that the narrow mask DOES blank (it masks template
      // bodies). Suppress if the line OR the file content explicitly says
      // HttpOnly somewhere near (server-side cookies set by middleware should
      // be using res.cookie, not document.cookie — but Koa ctx.cookies.set
      // with httpOnly=true is server-side, so check the ctx.cookies form).
      const cookieAuthShape =
        /document\.cookie\s*=\s*['"`][^=]*?(?:token|jwt|auth|session|bearer|access[_-]?token|refresh[_-]?token)/i.test(
          realLine
        ) ||
        /\bCookies\.set\s*\(\s*['"`][^'"`]*(?:token|jwt|auth|session|bearer|access[_-]?token|refresh[_-]?token)/i.test(
          realLine
        );
      // Koa / Express ctx.cookies.set + httpOnly is SERVER-SIDE and correct;
      // do not flag this shape under the client-side rule.
      const isServerSideCtxCookies = /\bctx\.cookies\.set\b|\bres\.cookie\b/i.test(realLine);
      if (cookieAuthShape && !isServerSideCtxCookies) {
        findings.push({
          id: `auth-clientcookie-${file.path}-${i}`,
          probe: 'Client Auth Storage',
          title: 'Auth cookie set from client JS (HttpOnly impossible)',
          severity: 'high',
          category: 'Auth & Access',
          cwe: 'CWE-1004',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'Cookies set via document.cookie from client JS CANNOT be HttpOnly — browsers reject the flag. The cookie is XSS-readable by definition. Set the cookie server-side with Set-Cookie: ...; HttpOnly; Secure; SameSite=Strict.',
        });
      }
      // window.* / globalThis.* token globals: window.authToken = ...,
      // window.__JWT__ = ... (underscore-wrapped). Persisted in JS scope,
      // XSS-readable.
      if (
        /(?:window|globalThis|self)\s*\.\s*_*(?:token|jwt|auth(?:Token)?|session(?:Id)?|access_?token|refresh_?token|bearer)_*\s*=/i.test(
          maskedLine
        )
      ) {
        findings.push({
          id: `auth-windowglobal-${file.path}-${i}`,
          probe: 'Client Auth Storage',
          title: 'Auth token stored on window / globalThis',
          severity: 'high',
          category: 'Auth & Access',
          cwe: 'CWE-922',
          file: file.path,
          line: i + 1,
          evidence: realLine.trim().slice(0, 200),
          remediation:
            'Window-scoped globals are reachable by any script on the page — including third-party tags, browser extensions in some contexts, and any XSS payload. Hold tokens in closure-scoped variables; for persistence use httpOnly cookies.',
        });
      }
    });
    // Cache Storage API auth caching. The Cache Storage API is available in
    // BOTH service worker scope AND window/document scope. Either way, the
    // cache is JS-readable persistent storage on the origin. Fire when:
    //   1. The file uses caches.open(...) / cache.put(...) / caches.match
    //   2. The file body mentions an auth signal (Authorization, Set-Cookie,
    //      bearer, token, jwt, authHeader)
    // The SW-specific path/event check is broadened to include any sw-prefixed
    // filename and any `self.addEventListener` regardless of event type. Plus
    // a generic any-file Cache API check for window-scoped code.
    const cacheApiInUse = /\bcaches\.(?:open|match|put)\s*\(|\bcache\.put\s*\(/i.test(file.content);
    const fileHasAuthSignal =
      /\bAuthorization\b|\bSet-Cookie\b|\bbearer\b|\btoken\b|\bjwt\b|\bauthHeader\b/i.test(
        file.content
      );
    if (cacheApiInUse && fileHasAuthSignal) {
      const swLines = maskedContent.split('\n');
      swLines.forEach((swLine, i) => {
        if (/\bcaches?\.put\s*\(|\bcache\.put\s*\(|\bcaches\.open\s*\(/.test(swLine)) {
          findings.push({
            id: `auth-swcachewrite-${file.path}-${i}`,
            probe: 'Client Auth Storage',
            title: 'Service worker may cache a response containing auth headers',
            severity: 'high',
            category: 'Auth & Access',
            cwe: 'CWE-922',
            file: file.path,
            line: i + 1,
            evidence: (originalLines[i] || '').trim().slice(0, 200),
            remediation:
              'Cached responses live in JS-readable Cache Storage. If the response carries Authorization or Set-Cookie headers, the token is now persistent and XSS-readable. Strip auth-related headers from the Response before caches.put, or exclude authed requests from the cache entirely.',
          });
        }
      });
    }

    // Multi-line / library patterns where the regex needs to see ACROSS lines.
    // Redux/Zustand/Jotai persist middleware: persist({ name: 'auth-store', ... })
    // commonly defaults to localStorage. Match the construct on the masked
    // whole content to allow newlines between persist( and the name field.
    {
      const masked = maskedContent;
      // persist({ name: 'auth' }) or persist(<state>, { name: 'auth' }). Also
      // catches redux-persist's `key:` form, and the common
      // `const persistConfig = { key: 'auth', storage }` pattern where the
      // config is a separate variable.
      const persistRe =
        /(?:persist|persistReducer|persistConfig)\s*[(=]\s*\(?\{?([\s\S]{0,400}?)\b(?:name|key)\s*:\s*['"][^'"]*(?:auth|jwt|token|session|user)/i;
      const pm = masked.match(persistRe);
      if (pm) {
        // Locate the line in the original
        const idx = masked.indexOf(pm[0]);
        const ln = idx >= 0 ? masked.slice(0, idx).split('\n').length : 1;
        findings.push({
          id: `auth-reduxpersist-${file.path}-${ln}`,
          probe: 'Client Auth Storage',
          title: 'State store persisted with auth-named slice (likely localStorage)',
          severity: 'medium',
          category: 'Auth & Access',
          cwe: 'CWE-922',
          file: file.path,
          line: ln,
          evidence: (originalLines[ln - 1] || '').trim().slice(0, 200),
          remediation:
            'Redux/Zustand/Jotai `persist` middleware defaults to localStorage. Auth-named slices written there are XSS-readable. Exclude the auth slice from persistence (zustand `partialize`, redux-persist `whitelist`/`blacklist`) and hold tokens in httpOnly cookies.',
        });
      }
      // jotai atomWithStorage('jwt', ...) — same persistence default.
      const atomRe = /atomWithStorage\s*\(\s*['"][^'"]*\b(?:token|jwt|auth|session)\b/i;
      const am = masked.match(atomRe);
      if (am) {
        const idx = masked.indexOf(am[0]);
        const ln = idx >= 0 ? masked.slice(0, idx).split('\n').length : 1;
        findings.push({
          id: `auth-atomstorage-${file.path}-${ln}`,
          probe: 'Client Auth Storage',
          title: 'jotai atomWithStorage holds an auth-named value',
          severity: 'medium',
          category: 'Auth & Access',
          cwe: 'CWE-922',
          file: file.path,
          line: ln,
          evidence: (originalLines[ln - 1] || '').trim().slice(0, 200),
          remediation:
            'atomWithStorage defaults to localStorage. Auth-named atoms are XSS-readable. Use a server-side session for tokens.',
        });
      }
    }
  });
  return findings;
}

// --- SSRF / Open Redirect ---
export function probeSSRFOpenRedirect(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.[jt]sx?$|\.py$/.test(file.path)) return;
    file.content.split('\n').forEach((line, i) => {
      if (
        /(?:res\.redirect|NextResponse\.redirect|redirect)\s*\(\s*(?:req\.|request\.|searchParams\.get|params\.)/i.test(
          line
        )
      ) {
        findings.push({
          id: `redirect-${file.path}-${i}`,
          probe: 'Open Redirect',
          title: 'Redirect target taken from user input',
          severity: 'medium',
          category: 'Code Injection',
          cwe: 'CWE-601',
          file: file.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation:
            'Open redirects feed phishing campaigns: your-domain.com/?next=evil.com looks legitimate. Validate the target against an allowlist of known-safe paths or domains before redirecting.',
        });
      }
      if (
        /(?:fetch|axios\.(?:get|post|put|delete|request)|http\.(?:get|request))\s*\(\s*(?:req\.|request\.)(?:body|query|params)\./i.test(
          line
        )
      ) {
        findings.push({
          id: `ssrf-${file.path}-${i}`,
          probe: 'SSRF',
          title: 'Server-side fetch with user-controlled URL',
          severity: 'high',
          category: 'Code Injection',
          cwe: 'CWE-918',
          file: file.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation:
            'Server-side request forgery lets attackers reach your internal network: cloud metadata endpoints (169.254.169.254 = AWS credentials), localhost-bound admin services, internal DBs. Validate URLs against an allowlist before fetching, or proxy through a service that blocks internal IPs. Now part of OWASP A01:2025 Broken Access Control.',
        });
      }
    });
  });
  return findings;
}

// --- Auth cookie flag hygiene ---
export function probeCookieFlags(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.[jt]sx?$|\.py$/.test(file.path)) return;
    const lines = file.content.split('\n');
    lines.forEach((line, i) => {
      if (!/(?:setCookie|cookies\.set|res\.cookie|Set-Cookie)/i.test(line)) return;
      if (!/(?:session|auth|token|jwt|csrf)/i.test(line)) return;
      const ctx = lines.slice(i, Math.min(lines.length, i + 4)).join(' ');
      const missing = [];
      if (!/httpOnly\s*:\s*true|HttpOnly/i.test(ctx)) missing.push('httpOnly');
      if (!/secure\s*:\s*true|;\s*Secure/i.test(ctx)) missing.push('secure');
      if (!/sameSite/i.test(ctx)) missing.push('sameSite');
      if (missing.length >= 2) {
        findings.push({
          id: `cookie-${file.path}-${i}`,
          probe: 'Cookie Security',
          title: `Auth cookie missing ${missing.join(', ')}`,
          severity: 'medium',
          category: 'Auth & Access',
          cwe: 'CWE-1004',
          file: file.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation:
            'Auth cookies should set httpOnly (blocks JS access, mitigates XSS token theft), secure (HTTPS only), and sameSite: "lax" or "strict" (mitigates CSRF). Without these, one XSS becomes account takeover.',
        });
      }
    });
  });
  return findings;
}

// --- API Route Auth ---
export function probeAPIRouteAuth(files) {
  const findings = [];
  // Corpus-level signal: a Next.js middleware.ts/.js at the project root (or
  // src/) that matches /api/* paths is the canonical place to enforce auth
  // across many routes. When present, per-route findings would be
  // false positives — the route IS gated, just from a sibling file. We can't
  // verify the matcher actually covers each route without parsing config, so
  // this is a corpus-aware downgrade: if a middleware file exists and contains
  // an auth-shaped call, every route is treated as having auth at the corpus
  // level.
  const hasCorpusMiddleware = files.some((mf) => {
    if (!/(^|\/)(src\/)?middleware\.[jt]sx?$/.test(mf.path)) return false;
    if (typeof mf.content !== 'string') return false;
    // In a middleware file the call site is intentional auth, so accept
    // `auth(` with arguments (e.g. `export default auth((req) => ...)` is the
    // canonical NextAuth v5 / Auth.js v5 wrapper shape).
    return /(clerkMiddleware|withAuth|getServerSession|getUser|currentUser|requireAuth|\bauth\s*\(|verifyToken|jwt\.verify\s*\([^,)]+,)/i.test(
      mf.content
    );
  });
  // Corpus-level Express / Hono / Koa app-wide auth middleware. The shapes:
  //   app.use(authMiddleware)
  //   app.use('/api', authMiddleware)
  //   app.use(passport.authenticate('jwt', { session: false }))
  //   honoApp.use('*', jwt({ secret }))
  // If any file in the corpus registers an auth-shaped middleware app-wide,
  // routes in the same project are considered gated for THIS probe.
  const hasAppWideAuthMiddleware = files.some((mf) => {
    if (typeof mf.content !== 'string') return false;
    if (isTestFile(mf.path)) return false;
    return (
      /\b(?:app|router)\.use\s*\(\s*(?:['"`][^'"`]*['"`]\s*,\s*)?(?:authenticate|authMiddleware|requireAuth|isAuthenticated|verifyJWT|verifyToken|protect|guard|passport\.authenticate|clerkMiddleware|withAuth)/i.test(
        mf.content
      ) ||
      /\bapp\.use\s*\(\s*['"`]\*['"`]\s*,\s*(?:jwt|bearerAuth|basicAuth|auth)\s*\(/i.test(
        mf.content
      )
    );
  });
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.[jt]sx?$/.test(file.path)) return;
    if (hasCorpusMiddleware) return; // gated at the middleware layer
    if (hasAppWideAuthMiddleware) return; // gated by Express/Hono/Koa app.use
    const c = file.content;
    // jwt.verify alone is NOT proof of valid auth — it must be called with a secret/key as a 2nd arg.
    const hasJwtVerifyWithSecret = /jwt\.verify\s*\(\s*[^,)]+,\s*[^)]+\)/.test(c);
    // Generic auth signals applicable across frameworks. Add SvelteKit/Hono/
    // CF Worker / Astro / Fastify / Express hook shapes.
    const hasAuth =
      // Require `(` after the keyword so substring matches inside identifiers
      // (e.g. `targetUserId` contained `getUser` and tripped this) no longer
      // produce a false negative on missing-auth.
      /(?:getServerSession|requireAuth|getUser|currentUser|withAuth|createServerClient)\s*\(/i.test(
        c
      ) ||
      /(?<!\w)auth\s*\(\s*\)/.test(c) ||
      /verifyToken\s*\(/.test(c) ||
      hasJwtVerifyWithSecret ||
      // Common framework auth signals:
      /\blocals\.(?:user|session|auth)\b/.test(c) || // SvelteKit / Astro locals
      /c\.get\s*\(\s*['"](?:user|session|auth|jwt)['"]/i.test(c) || // Hono context
      /\bclerkClient\b|\bauthenticatedFetch\b/i.test(c) ||
      /\brequireUser\s*\(|\brequireRole\s*\(/.test(c) ||
      /\bensureAuthenticated\b|\bisAuthenticated\b/.test(c) ||
      /passport\.authenticate\s*\(/.test(c) ||
      /supabase\.auth\.getUser\s*\(/.test(c) ||
      // Express middleware ordering: route declared with auth middleware arg
      /\.(?:get|post|put|patch|delete|all)\s*\(\s*['"`][^'"`]+['"`]\s*,\s*(?:authenticate|authMiddleware|requireAuth|isAuthenticated|verifyJWT|verifyToken|protect|guard|cors\s*\([^)]*\),\s*auth)/i.test(
        c
      ) ||
      // Fastify route options: { preHandler: authHook } or onRequest: authHook
      /(?:preHandler|onRequest)\s*:\s*(?:\[?\s*)?(?:authenticate|authMiddleware|requireAuth|verifyJWT|verifyToken|protect|isAuthenticated|authHook)/i.test(
        c
      ) ||
      /\b(?:fastify|app)\.register\s*\(\s*(?:fastifyAuth|fastifyJwt|fastifyJWT|fastifyBearerAuth)/i.test(
        c
      ) ||
      // Webhook signature verification IS the auth (Stripe, GitHub, Slack)
      /(?:stripe\.webhooks\.constructEvent|x-hub-signature|x-slack-signature|wh\.verify|webhookCallback)/i.test(
        c
      ) ||
      // GraphQL: resolver context.user check
      /\bcontext(?:\.\w+)?\.(?:user|userId|currentUser|session)\b/.test(c) ||
      // The route is itself an OAuth callback or public auth endpoint
      /\/(?:auth\/callback|auth\/signin|auth\/login|sign-in|sign-up|register|forgot-password)\//.test(
        file.path
      );

    // Route-shape detection across frameworks. We classify by the file
    // content shape, not the path alone, so backend-only Express apps with
    // no `pages/api` are covered.
    const isNextRoute = /(?:\/api\/.*route\.[jt]sx?$|pages\/api\/)/.test(file.path);
    const isSvelteKitEndpoint = /(?:\/routes\/.*\/\+server\.[jt]sx?$)/.test(file.path);
    const isAstroEndpoint =
      /(?:\/pages\/api\/.*\.[jt]sx?$|\/src\/pages\/.*\.[jt]sx?$)/.test(file.path) &&
      /\bexport\s+(?:async\s+)?(?:const|function)\s+(?:GET|POST|PUT|PATCH|DELETE|ALL)\b/.test(c);
    // Express-style: app.METHOD(path, handler) or router.METHOD(...). Drop
    // the framework-keyword guard — real Express files often skip the
    // `import express` if it's imported elsewhere (server.js entry), and
    // the app.METHOD pattern alone is a strong route-shape signal that we
    // gate on auth separately.
    const isExpressLike =
      /\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|use|all)\s*\(\s*['"`]/.test(c);
    const isFastify =
      /\bfastify\s*\.\s*(?:get|post|put|patch|delete|register|route)\s*\(/i.test(c) ||
      /\brequire\s*\(\s*['"]fastify['"]/.test(c) ||
      /\bimport\s+[^;]*\bfastify\b/i.test(c);
    const isHono =
      /\bnew\s+Hono\s*\(/.test(c) ||
      /import\s+[^;]*\bHono\b\s+from\s+['"]hono/.test(c) ||
      /\bapp\.(?:get|post|put|patch|delete)\s*\(\s*['"`][^'"`]+['"`]\s*,\s*\(?\s*c\s*[:,)]/i.test(
        c
      );
    const isCFWorker =
      /\baddEventListener\s*\(\s*['"]fetch['"]/.test(c) ||
      /export\s+default\s*\{[\s\S]{0,60}?\bfetch\s*\(/i.test(c);
    // GraphQL: any Mutation field is a mutating endpoint; the resolver name
    // (e.g. promoteToAdmin / refundOrder) is arbitrary. Detect a Mutation
    // block containing ANY resolver field with an async/handler function.
    const isGraphQLResolver =
      /\bMutation\s*:\s*\{[\s\S]{0,2000}?\b\w+\s*:\s*(?:async\s*)?\(/i.test(c) &&
      /\b(?:resolvers|makeExecutableSchema|gql|graphql|typeDefs|apollo)\b/i.test(c);

    const isAnyRoute =
      isNextRoute ||
      isSvelteKitEndpoint ||
      isAstroEndpoint ||
      isExpressLike ||
      isFastify ||
      isHono ||
      isCFWorker ||
      isGraphQLResolver;
    if (!isAnyRoute) return;

    // Sensitivity heuristics. Path patterns first. For Express-style routes
    // the path lives in the route string (`app.post('/api/admin/...')`), not
    // the file path — check BOTH.
    const sensitiveKw =
      /(admin|internal|delete|update|create|user|payment|checkout|billing|dashboard|invoice|impersonate|promote|refund|settings|moderate)/i;
    const isSensitivePath =
      sensitiveKw.test(file.path) ||
      (isExpressLike &&
        /\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|use|all)\s*\(\s*['"`][^'"`]*(?:admin|internal|delete|update|user|payment|checkout|billing|dashboard|invoice|impersonate|promote|refund|settings|moderate)/i.test(
          c
        ));
    const hasDestructiveVerb =
      /export\s+(?:async\s+)?(?:function|const)\s+(?:DELETE|PUT|PATCH)/.test(c) ||
      /\b(?:app|router|fastify|hono?)\s*\.\s*(?:delete|put|patch)\s*\(/i.test(c) ||
      /\.(?:delete|update|create|remove)\w*\s*\(/.test(c) || // ORM/DB call signal
      // CF Worker: request.method === 'POST'|'PUT'|'DELETE'|'PATCH' is a
      // state-changing handler.
      (isCFWorker && /\brequest\.method\s*===?\s*['"](?:POST|PUT|DELETE|PATCH)['"]/i.test(c)) ||
      // CF Worker: env.DB.prepare('INSERT...|UPDATE...|DELETE...') is a
      // direct destructive SQL call (no taint-flow needed; the SQL is literal).
      (isCFWorker && /\benv\.[A-Z_]+\.prepare\s*\(\s*['"`](?:INSERT|UPDATE|DELETE)/i.test(c));

    if (isSensitivePath && !hasAuth) {
      findings.push({
        id: `api-noauth-${file.path}`,
        probe: 'API Route Auth',
        title: 'Sensitive API route without auth check',
        severity: 'critical',
        category: 'Auth & Access',
        cwe: 'CWE-306',
        file: file.path,
        line: 1,
        evidence: `Path matches sensitive pattern, no auth function call detected`,
        remediation:
          'API routes are reachable by direct fetch from anywhere. Verify auth at the top of the handler: getServerSession (Next), locals.user (SvelteKit), c.get("user") (Hono), passport.authenticate (Express). Then check role and resource ownership. Manual review recommended if auth lives in middleware not visible here.',
      });
    }
    if (hasDestructiveVerb && !hasAuth) {
      findings.push({
        id: `api-destructive-${file.path}`,
        probe: 'API Route Auth',
        title: 'Destructive HTTP handler (DELETE/PUT/PATCH) without auth check',
        severity: 'high',
        category: 'Auth & Access',
        cwe: 'CWE-306',
        file: file.path,
        line: 1,
        evidence: 'Destructive handler / mutation export found, no auth call in same file',
        remediation:
          'Mutation endpoints must verify the caller is authenticated AND authorized for the specific resource. Otherwise an unauthenticated curl can delete or modify any record. The May 2025 Lovable BOLA incident (CVE-2025-48757) is an instance of this class.',
      });
    }
  });
  return findings;
}

// --- 2026: Known compromised package versions ---
export function probeCompromisedPackages(files) {
  const findings = [];
  files.forEach((file) => {
    if (!/package\.json$/.test(file.path)) return;
    let pkg;
    try {
      pkg = JSON.parse(file.content);
    } catch {
      return;
    }
    const deps = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
      ...(pkg.peerDependencies || {}),
    };
    Object.entries(deps).forEach(([name, version]) => {
      const known = COMPROMISED_PACKAGES[name];
      if (!known) return;
      const versionStr = String(version).replace(/^[\^~>=<]+/, '');
      const matches =
        known.versions.includes('*') ||
        known.versions.some((v) => versionStr === v || versionStr.startsWith(v));
      if (matches) {
        findings.push({
          id: `compromised-${file.path}-${name}`,
          probe: 'Compromised Packages',
          title: `Known-compromised package: ${name}@${versionStr}`,
          severity: 'critical',
          category: 'Supply Chain',
          cwe: 'CWE-506',
          file: file.path,
          line: 1,
          evidence: `"${name}": "${version}"  — ${known.note}`,
          remediation: `Confirmed malicious version per public threat intel (May 2026). Remove or downgrade immediately, then rotate every secret accessible to your build environment (CI tokens, npm tokens, cloud creds). Audit lockfile for the dependency chain. Review CISA / Socket / Wiz advisories for the specific incident.`,
        });
      }
    });
  });
  return findings;
}

// --- 2026: Slopsquatting / Typosquat detection ---
export function probeSlopsquatting(files) {
  const findings = [];
  files.forEach((file) => {
    if (!/package\.json$/.test(file.path)) return;
    let pkg;
    try {
      pkg = JSON.parse(file.content);
    } catch {
      return;
    }
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    Object.keys(deps).forEach((name) => {
      if (TYPOSQUATS[name]) {
        findings.push({
          id: `typosquat-${file.path}-${name}`,
          probe: 'Slopsquat / Typosquat',
          title: `Likely typosquat: "${name}" (real package: "${TYPOSQUATS[name]}")`,
          severity: 'high',
          category: 'Supply Chain',
          cwe: 'CWE-1357',
          file: file.path,
          line: 1,
          evidence: `"${name}": "${deps[name]}"`,
          remediation: `Typosquatted packages are a common malware delivery vector and a known artifact of LLM "package hallucination" (slopsquatting — ~20% of AI-generated code references nonexistent packages). Verify this name was intentional. If you meant ${TYPOSQUATS[name]}, fix it.`,
        });
      } else if (!name.startsWith('@') && SLOPSQUAT_GENERIC_RE.test(name)) {
        findings.push({
          id: `slopsquat-${file.path}-${name}`,
          probe: 'Slopsquat / Typosquat',
          title: `Generic-shaped package name (possible LLM hallucination): "${name}"`,
          severity: 'low',
          category: 'Supply Chain',
          cwe: 'CWE-1357',
          file: file.path,
          line: 1,
          evidence: `"${name}": "${deps[name]}"`,
          remediation: `AI assistants frequently hallucinate plausible-sounding package names like ${name}. Attackers register the hallucinated names with malicious payloads. Verify this package exists, has reasonable download counts, and a credible maintainer before installing.`,
        });
      }
    });
  });
  return findings;
}

// --- 2026: MCP Server / AI Tooling Configuration ---
export function probeMCPSecurity(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    const isMCPConfig = /(claude_desktop_config\.json|\.mcp\.json|mcp\.json)$/.test(file.path);
    if (isMCPConfig) {
      let cfg;
      try {
        cfg = JSON.parse(file.content);
      } catch {
        return;
      }
      // Walk multiple known locations: top-level mcpServers/servers (Anthropic, Cursor),
      // nested mcp.servers (VS Code), and tools (LibreChat-style). Merge so all are checked.
      const candidateBuckets = [
        cfg.mcpServers,
        cfg.servers,
        cfg.tools,
        cfg.mcp?.servers,
        cfg.mcp?.mcpServers,
      ];
      const servers = candidateBuckets.filter(Boolean).reduce((a, b) => Object.assign(a, b), {});
      Object.entries(servers).forEach(([name, srv]) => {
        if (!srv) return;
        // Shell-spawning MCP servers
        if (
          srv.command &&
          /^(bash|sh|zsh|cmd|powershell|pwsh|node)$/.test(String(srv.command).toLowerCase())
        ) {
          const args = (srv.args || []).join(' ');
          if (/-c\b|-e\b|-Command/i.test(args)) {
            findings.push({
              id: `mcp-shell-${file.path}-${name}`,
              probe: 'MCP Security',
              title: `MCP server "${name}" spawns shell interpreter`,
              severity: 'critical',
              category: 'AI/LLM Security',
              cwe: 'CWE-77',
              file: file.path,
              line: 1,
              evidence: `${name}: ${srv.command} ${args}`.slice(0, 200),
              remediation:
                'MCP STDIO has known architectural command-injection issues (CVE-2025-49596 MCP Inspector, CVE-2026-22252 LibreChat, CVE-2026-22688 WeKnora). Configurations that spawn shell interpreters with -c / -e are exploitable via prompt injection. Replace with a fixed binary path and validated arguments.',
            });
          }
        }
        // Vulnerable mcp-server-git versions
        const cmdLine = `${srv.command || ''} ${(srv.args || []).join(' ')}`;
        if (/mcp-server-git/.test(cmdLine)) {
          findings.push({
            id: `mcp-git-${file.path}-${name}`,
            probe: 'MCP Security',
            title: `mcp-server-git in MCP config — verify version is post-Dec 2025`,
            severity: 'high',
            category: 'AI/LLM Security',
            cwe: 'CWE-1336',
            file: file.path,
            line: 1,
            evidence: cmdLine.slice(0, 200),
            remediation:
              'Versions of mcp-server-git released before December 8, 2025 are vulnerable to indirect prompt injection via malicious README files, issue descriptions, and webpages (Cyata research). Upgrade to a post-Dec-2025 release and pin by SHA / lockfile.',
          });
        }
        // Public bind
        const argStr = JSON.stringify(srv);
        if (/0\.0\.0\.0|"::"/i.test(argStr) || (srv.host && /^(0\.0\.0\.0|::)$/.test(srv.host))) {
          findings.push({
            id: `mcp-bind-${file.path}-${name}`,
            probe: 'MCP Security',
            title: `MCP server "${name}" binds to all network interfaces`,
            severity: 'high',
            category: 'AI/LLM Security',
            cwe: 'CWE-668',
            file: file.path,
            line: 1,
            evidence: argStr.slice(0, 200),
            remediation:
              'Researchers identified ~200K MCP servers internet-exposed on 0.0.0.0 with command-execution flaws. Bind to 127.0.0.1 unless deliberately publishing the server with authentication. (April 2026 OX Security advisory)',
          });
        }
      });
      return;
    }
    // Inline MCP usage in source
    if (!/\.(ts|tsx|js|jsx|py)$/.test(file.path)) return;
    if (/StdioServerTransport|stdio_server|StdioClientTransport/.test(file.content)) {
      if (/shell\s*:\s*true|spawn\(\s*["'`](bash|sh|cmd|powershell)/i.test(file.content)) {
        findings.push({
          id: `mcp-stdio-${file.path}`,
          probe: 'MCP Security',
          title: 'MCP STDIO server with shell:true / shell-spawn pattern',
          severity: 'high',
          category: 'AI/LLM Security',
          cwe: 'CWE-77',
          file: file.path,
          line: 1,
          evidence: 'StdioServerTransport with shell execution',
          remediation:
            'shell:true and dynamic shell command construction inside an MCP server is the exact pattern that produced multiple 2026 CVEs. Use exec with a fixed binary and explicit args; never pass through prompt content.',
        });
      }
    }
  });
  return findings;
}

// --- 2026: Trojan Source / hidden bidi Unicode ---
export function probeTrojanSource(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!BIDI_CONTROL_RE.test(file.content)) return;
    const lines = file.content.split('\n');
    lines.forEach((line, i) => {
      if (BIDI_CONTROL_RE.test(line)) {
        findings.push({
          id: `trojan-${file.path}-${i}`,
          probe: 'Trojan Source',
          title: 'Bidirectional Unicode control character in source',
          severity: 'high',
          category: 'Code Injection',
          cwe: 'CWE-1007',
          file: file.path,
          line: i + 1,
          evidence: 'Hidden Unicode (U+202A-U+202E or U+2066-U+2069) on this line',
          remediation:
            'Bidirectional override characters reorder how source displays without changing what the compiler executes (CVE-2021-42574). The same primitive drives the 2026 "rules file backdoor" attacks against Cursor and GitHub Copilot. Strip these characters in CI; configure your editor to render them as visible markers.',
        });
      }
    });
  });
  return findings;
}

// --- 2026: AI tooling rule-file and prompt-injection-via-config ---
export function probeAIRulesFiles(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.cursorrules$|\.cursor\/rules\/|\.windsurfrules$|CLAUDE\.md$/.test(file.path)) return;
    if (BIDI_CONTROL_RE.test(file.content)) {
      findings.push({
        id: `rules-bidi-${file.path}`,
        probe: 'AI Rules Files',
        title: `Hidden Unicode in AI rules file ${file.path}`,
        severity: 'critical',
        category: 'AI/LLM Security',
        cwe: 'CWE-1007',
        file: file.path,
        line: 1,
        evidence: 'Bidirectional Unicode detected',
        remediation:
          'Pillar Security demonstrated the "rules file backdoor": hidden instructions in rules files used by Cursor and Copilot get followed by the AI assistant invisibly. Inspect this file character-by-character. Strip non-printing Unicode.',
      });
    }
    if (
      /ignore\s+(?:previous|all|the)\s+(?:instructions|rules)|disregard\s+system|override\s+system/i.test(
        file.content
      )
    ) {
      findings.push({
        id: `rules-override-${file.path}`,
        probe: 'AI Rules Files',
        title: `Rules file contains instruction-override language`,
        severity: 'high',
        category: 'AI/LLM Security',
        cwe: 'CWE-1336',
        file: file.path,
        line: 1,
        evidence: 'Phrases like "ignore previous instructions" found',
        remediation:
          'Rules files that include override-style language are either jailbreak attempts or compromised. Verify every instruction was placed by your team. Treat these files as code that ships with the product.',
      });
    }
  });
  return findings;
}

// --- 2026: Malicious post-infection artifacts (Mini Shai-Hulud TanStack campaign) ---
//
// The May 11, 2026 npm worm by TeamPCP infects @tanstack/* / @mistralai/* / @uipath/* /
// @opensearch-project/* / @squawk/* etc. via the `prepare` lifecycle script of a
// poisoned `optionalDependencies` entry. After install it survives `npm uninstall` by
// writing itself into developer-tooling config files and dropping helper scripts at
// well-known paths. If a scanned project contains those files / strings, the host that
// installed the package is already compromised — credentials it could read have been
// exfiltrated, and the dead-man's-switch handler will `rm -rf ~/` if its stolen GitHub
// token gets revoked.
//
// Confirmed IOCs (verified against the TanStack postmortem, the GHSA advisory,
// and independent IOC tracking — see the Mini Shai-Hulud field report in Learn):
//   • Files dropped on disk:
//       .claude/router_runtime.js   .claude/setup.mjs   .vscode/setup.mjs
//       tanstack_runner.js          router_init.js  (committed at package root)
//   • Config-file payload paths the worm hijacks:
//       .claude/settings.json   .vscode/tasks.json
//   • Persistence script that polls api.github.com/user:
//       ~/.local/bin/gh-token-monitor.sh   (Linux systemd user service)
//       com.user.gh-token-monitor          (macOS LaunchAgent label)
//   • Distinctive in-payload strings:
//       __DAEMONIZED   tanstack_runner   filev2.getsession.org
//   • Spoofed commit author:
//       claude@users.noreply.github.com
//   • optionalDependencies pin:
//       "@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
export function probeMaliciousArtifacts(files) {
  const findings = [];

  // Drop-file paths whose mere presence is a high-confidence indicator of infection.
  const ARTIFACT_PATHS = [
    {
      re: /(^|\/)\.claude\/router_runtime\.js$/,
      label: '.claude/router_runtime.js',
    },
    { re: /(^|\/)\.claude\/setup\.mjs$/, label: '.claude/setup.mjs' },
    { re: /(^|\/)\.vscode\/setup\.mjs$/, label: '.vscode/setup.mjs' },
    { re: /(^|\/)tanstack_runner\.js$/, label: 'tanstack_runner.js' },
    { re: /(^|\/)router_init\.js$/, label: 'router_init.js' },
  ];

  // Distinctive strings inside the payload. Any one is suggestive; multiple together
  // make false positives extremely unlikely in a static scan of normal source.
  const IOC_STRINGS = [
    { re: /\b__DAEMONIZED\b/, label: '__DAEMONIZED guard variable' },
    { re: /\btanstack_runner\b/i, label: 'tanstack_runner reference' },
    { re: /filev2\.getsession\.org/i, label: 'Session messenger exfil endpoint' },
    { re: /seed[123]\.getsession\.org/i, label: 'Session seed-node exfil endpoint' },
    { re: /gh-token-monitor/i, label: 'gh-token-monitor persistence handler' },
    { re: /com\.user\.gh-token-monitor/i, label: 'gh-token-monitor LaunchAgent label' },
    { re: /claude@users\.noreply\.github\.com/i, label: 'spoofed Claude commit author' },
    {
      re: /tanstack\/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c/i,
      label: 'malicious @tanstack/setup commit pin',
    },
  ];

  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (isMetaDocFile(file.path)) return;

    // 1. File-path indicators — presence alone is critical.
    for (const a of ARTIFACT_PATHS) {
      if (a.re.test(file.path)) {
        findings.push({
          id: `mal-artifact-path-${file.path}`,
          probe: 'Malicious Artifacts',
          title: `Post-infection artifact: ${a.label}`,
          severity: 'critical',
          category: 'Supply Chain',
          cwe: 'CWE-506',
          file: file.path,
          line: 1,
          evidence: `File path matches known Mini Shai-Hulud (TanStack, May 11, 2026) drop-file`,
          remediation: `This file is dropped by the Mini Shai-Hulud npm worm to survive \`npm uninstall\`. If it exists, the host that ran \`npm install\` is compromised — assume every credential the build process touched has been exfiltrated (npm tokens, GitHub tokens, OIDC tokens, cloud creds, crypto wallets, browser session cookies). Steps: 1) DO NOT revoke your GitHub token yet — the worm runs \`rm -rf ~/\` when its stolen token returns 40x. First disconnect the machine from the network. 2) Pull a known-good system. 3) Rotate every credential offline. 4) Audit CI for the malicious GitHub Actions workflows the worm tries to inject. See the Mini Shai-Hulud field report in Learn for the full IOC list and operational sequence.`,
        });
        return; // one path-based finding per file is enough; don't also string-scan it
      }
    }

    // 2. String indicators inside content — applicable to ANY scanned file, not just JS.
    const content = file.content || '';
    if (!content || content.length > 5_000_000) return; // skip very large blobs (memory)
    const hits = [];
    for (const ioc of IOC_STRINGS) {
      if (ioc.re.test(content)) hits.push(ioc.label);
    }
    if (hits.length > 0) {
      findings.push({
        id: `mal-ioc-${file.path}`,
        probe: 'Malicious Artifacts',
        title: `Mini Shai-Hulud IOC string in ${file.path}`,
        severity: 'critical',
        category: 'Supply Chain',
        cwe: 'CWE-506',
        file: file.path,
        line: 1,
        evidence: `Matched ${hits.length} IOC(s): ${hits.slice(0, 4).join(' · ')}`,
        remediation: `One or more strings from the Mini Shai-Hulud (TanStack, May 11, 2026) payload appear in this file. If you didn't put them there, your repo or your dev machine is compromised. See remediation in the per-file-path finding for incident response steps. Do NOT revoke the GitHub token before disconnecting the machine — the worm wipes \`~\` on 40x responses.`,
      });
    }
  });

  return findings;
}

// --- 2026: AI-generated code smells (insecure patterns common in LLM output) ---
export function probeAICodeSmells(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.[jt]sx?$/.test(file.path)) return;
    // Mask multi-line block comments, line comments, and string-literal
    // contents (including multi-line template literals and JSDoc blocks)
    // from the file content before pattern matching, so the probe fires
    // on actual code shape and not on a documentation block that quotes
    // the shape. Line numbers stay correct because the masker preserves
    // every `\n`.
    const masked = maskCommentsAndStringsFromContent(file.content);
    // Empty catch can span lines:  `catch (e) {\n}`. The character class
    // `\s` matches newlines by default in JS regex, so a content-wide
    // match handles both same-line and multi-line forms.
    const emptyCatchMatches = masked.match(/catch\s*(?:\([^)]*\))?\s*\{\s*\}/g) || [];
    const emptyCatch = emptyCatchMatches.length;
    // The any-type checks are line-scoped — they don't legitimately span
    // lines, so per-line keeps false-positives lower.
    let anyType = 0;
    masked.split('\n').forEach((line) => {
      if (/:\s*any\b|as\s+any\b/.test(line)) anyType++;
    });
    if (emptyCatch >= 1) {
      findings.push({
        id: `smell-emptycatch-${file.path}`,
        probe: 'AI Code Smells',
        title: `${emptyCatch} empty catch block${emptyCatch > 1 ? 's' : ''} silently swallow errors`,
        // The Pattern page (ai-code-smells.md) calls this probe "informational":
        // "The expected response is 'go look at this code path more carefully'
        // rather than 'patch immediately'." Severity follows the Pattern page.
        severity: 'info',
        category: 'Misconfiguration',
        cwe: 'CWE-390',
        file: file.path,
        line: 1,
        evidence: `${emptyCatch} occurrence(s) of catch {} or catch (e) {} pattern`,
        remediation:
          'Empty catch blocks are a documented signature of AI-generated code — industry studies show ~45% of AI code samples introduce OWASP Top 10 issues, and silent catches are one of the most common patterns. They mask security errors and operational issues. At minimum log; ideally only catch what you can recover from and let the rest propagate.',
      });
    }
    if (anyType >= 5) {
      findings.push({
        id: `smell-anytype-${file.path}`,
        probe: 'AI Code Smells',
        title: `Heavy use of "any" type (${anyType} occurrences)`,
        severity: 'info',
        category: 'Misconfiguration',
        cwe: 'CWE-754',
        file: file.path,
        line: 1,
        evidence: `${anyType} uses of ": any" or "as any"`,
        remediation:
          '"any" disables type checking and is over-represented in AI-generated code. While not a vulnerability per se, dense "any" usage correlates with missing input validation downstream. Replace with concrete types or unknown + narrowing.',
      });
    }
  });
  return findings;
}

// --- 2026: .npmrc hygiene / package manager hardening ---
export function probeNpmrcHygiene(files) {
  const findings = [];
  const npmrc = files.find((f) => /(^|\/)\.npmrc$/.test(f.path));
  const hasPackageJson = files.some((f) => /package\.json$/.test(f.path));
  if (!hasPackageJson) return findings;
  if (!npmrc) {
    findings.push({
      id: `npmrc-missing`,
      probe: 'Package Manager Hardening',
      title: '.npmrc with security defaults not found',
      severity: 'low',
      category: 'Supply Chain',
      cwe: 'CWE-1357',
      file: 'package.json (project root)',
      line: 1,
      evidence: 'No .npmrc in scanned files',
      remediation:
        'After the Shai-Hulud, Axios, and Mini Shai-Hulud incidents (2025-2026), recommended hardening: add .npmrc with min-release-age=10080 (7 days, blocks installing brand-new versions during the active worm window) and audit-level=high. Better yet, switch from npm CLI to pnpm v11+ which ships consumer-side defenses by default.',
    });
    return findings;
  }
  if (!/min-release-age/.test(npmrc.content)) {
    findings.push({
      id: `npmrc-cooldown-${npmrc.path}`,
      probe: 'Package Manager Hardening',
      title: '.npmrc missing min-release-age (release cooldown)',
      severity: 'low',
      category: 'Supply Chain',
      cwe: 'CWE-1357',
      file: npmrc.path,
      line: 1,
      evidence: 'No min-release-age directive',
      remediation:
        'Set min-release-age=10080 (7 days) so brand-new package versions are not installed during the typical worm propagation window. Most npm supply-chain incidents in 2025-2026 (Shai-Hulud, Axios, Mini Shai-Hulud) were detected and pulled within hours to days; a 7-day cooldown would have blocked them.',
    });
  }
  return findings;
}

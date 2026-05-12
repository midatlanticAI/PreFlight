// src/lib/probes.js
// Hub file: imports every threat-intel constant, file-filter helper, stable-id utility,
// and suppression API from their now-dedicated modules and re-exports them so existing
// callers (App.jsx, tests, history snapshots) keep working unchanged. Hosts the probe
// FUNCTIONS themselves plus the PROBES registry that drives the scan loop.
//
// Pure: every export is a plain function or data structure. No React, no DOM, no
// localStorage. The audit-app App component imports from here.

import {
  SECRET_PATTERNS,
  COMPROMISED_PACKAGES,
  TYPOSQUATS,
  SLOPSQUAT_GENERIC_RE,
  BIDI_CONTROL_RE,
  NEXT_PUBLIC_DANGER_NAMES,
  NEXT_PUBLIC_DANGER_VALUES,
  URL_PLACEHOLDER_HOSTS,
  URL_PLACEHOLDER_IP_RE,
  URL_SAFE_HOSTS,
  URL_SUSPICIOUS_TLD_RE,
  URL_RAW_IP_RE,
  URL_SHORTENERS,
  isHostInSafeList,
  AI_CRAWLER_BOTS,
  FILE_SIZE_WARN_LINES,
  FILE_SIZE_FAIL_LINES,
} from './threat-intel.js';
import {
  isTestFile,
  isScannerSelfSource,
  isMetaDocFile,
  FILE_INCLUDE,
  FILE_EXCLUDE,
  shouldScanFile,
} from './file-filter.js';
import { stableId, attachStableIds, PROBE_META, attachProbeMeta } from './stable-id.js';
import {
  SUPPRESSION_KEY,
  SUPPRESSION_DISPOSITIONS,
  loadSuppressions,
  saveSuppressions,
  suppressFinding,
  unsuppressFinding,
  partitionFindings,
} from './suppression.js';
export {
  SECRET_PATTERNS,
  COMPROMISED_PACKAGES,
  TYPOSQUATS,
  SLOPSQUAT_GENERIC_RE,
  BIDI_CONTROL_RE,
  NEXT_PUBLIC_DANGER_NAMES,
  NEXT_PUBLIC_DANGER_VALUES,
  URL_PLACEHOLDER_HOSTS,
  URL_PLACEHOLDER_IP_RE,
  URL_SAFE_HOSTS,
  URL_SUSPICIOUS_TLD_RE,
  URL_RAW_IP_RE,
  URL_SHORTENERS,
  isHostInSafeList,
  AI_CRAWLER_BOTS,
  FILE_SIZE_WARN_LINES,
  FILE_SIZE_FAIL_LINES,
  isTestFile,
  isScannerSelfSource,
  isMetaDocFile,
  FILE_INCLUDE,
  FILE_EXCLUDE,
  shouldScanFile,
  stableId,
  attachStableIds,
  PROBE_META,
  attachProbeMeta,
  SUPPRESSION_KEY,
  SUPPRESSION_DISPOSITIONS,
  loadSuppressions,
  saveSuppressions,
  suppressFinding,
  unsuppressFinding,
  partitionFindings,
};

export function probeSecrets(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    SECRET_PATTERNS.forEach((pat) => {
      const matches = [...file.content.matchAll(pat.regex)];
      matches.forEach((m) => {
        const idx = m.index ?? 0;
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

export function probeEnvFiles(files) {
  const findings = [];
  files.forEach((file) => {
    if (!/(^|\/)\.env(\..+)?$/i.test(file.path)) return;
    const isExample = /\.example$|\.sample$|\.template$/i.test(file.path);
    if (!isExample) {
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
    }
  });
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
    if (!/\.[jt]sx?$/.test(file.path)) return;
    const lines = file.content.split('\n');
    lines.forEach((rawLine, i) => {
      const line = stripLineComments(rawLine);
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
          evidence: line.trim(),
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
          evidence: line.trim(),
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
          evidence: line.trim().slice(0, 200),
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
          evidence: line.trim().slice(0, 200),
          remediation: `dangerouslySetInnerHTML bypasses React's XSS protection. Confirm the input is sanitized with DOMPurify or similar. If the content is from user input or a third party, you have an XSS risk.`,
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

export function probeMissingHeaders(files) {
  const findings = [];
  const next = files.find((f) => /next\.config\.(js|mjs|ts)$/.test(f.path));
  if (next) {
    if (!/headers\s*\(/.test(next.content) && !/securityHeaders/.test(next.content)) {
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
        remediation: `Add a headers() function returning Content-Security-Policy, Strict-Transport-Security, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and Referrer-Policy: strict-origin-when-cross-origin. These prevent XSS, clickjacking, and MIME sniffing attacks.`,
      });
    }
  }
  const vercel = files.find((f) => /vercel\.json$/.test(f.path));
  if (vercel) {
    try {
      const cfg = JSON.parse(vercel.content);
      if (!cfg.headers) {
        findings.push({
          id: `headers-vercel-${vercel.path}`,
          probe: 'Security Headers',
          title: 'No security headers in vercel.json',
          severity: 'low',
          category: 'Misconfiguration',
          cwe: 'CWE-693',
          file: vercel.path,
          line: 1,
          evidence: 'No "headers" array in vercel.json',
          remediation: `If you are not setting headers in next.config, add them in vercel.json. See vercel.com/docs/headers for the schema.`,
        });
      }
    } catch {}
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
    file.content.split('\n').forEach((line, i) => {
      if (
        /localStorage\.setItem\s*\(\s*['"`][^'"`]*(?:token|jwt|auth|session|access_token|refresh_token)[^'"`]*['"`]/i.test(
          line
        )
      ) {
        findings.push({
          id: `auth-localstorage-${file.path}-${i}`,
          probe: 'Client Auth Storage',
          title: 'Auth token stored in localStorage',
          severity: 'medium',
          category: 'Auth & Access',
          cwe: 'CWE-922',
          file: file.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation:
            'localStorage is readable by any JS on the page, including third-party scripts and successful XSS. Use httpOnly secure SameSite cookies set server-side. If JS-readable storage is necessary, accept the risk explicitly and harden CSP.',
        });
      }
    });
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
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/(?:\/api\/.*route\.[jt]sx?$|pages\/api\/)/.test(file.path)) return;
    const c = file.content;
    // jwt.verify alone is NOT proof of valid auth — it must be called with a secret/key as a 2nd arg.
    // Match jwt.verify(token, secret...) explicitly. Lone jwt.verify(token) doesn't count.
    const hasJwtVerifyWithSecret = /jwt\.verify\s*\(\s*[^,)]+,\s*[^)]+\)/.test(c);
    const hasAuth =
      /(getServerSession|requireAuth|getUser|currentUser|withAuth|createServerClient)/i.test(c) ||
      /(?<!\w)auth\s*\(\s*\)/.test(c) || // bare auth() call (Clerk, NextAuth)
      /verifyToken\s*\(/.test(c) ||
      hasJwtVerifyWithSecret;
    const isSensitive = /(admin|internal|delete|update|create|user)/i.test(file.path);
    if (isSensitive && !hasAuth) {
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
          'API routes are reachable by direct fetch from anywhere. Verify auth at the top of the handler: const session = await getServerSession(authOptions); if (!session) return Response.json({error}, {status: 401}); Then check role and resource ownership. Manual review recommended (auth may be in middleware).',
      });
    }
    if (/export\s+async\s+function\s+(DELETE|PUT|PATCH)/.test(c) && !hasAuth) {
      findings.push({
        id: `api-destructive-${file.path}`,
        probe: 'API Route Auth',
        title: 'Destructive HTTP handler (DELETE/PUT/PATCH) without auth check',
        severity: 'high',
        category: 'Auth & Access',
        cwe: 'CWE-306',
        file: file.path,
        line: 1,
        evidence: 'DELETE/PUT/PATCH export found, no auth call in same file',
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
// Confirmed IOCs (Aikido, Snyk, Socket, Wiz, StepSecurity, TanStack postmortem):
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
          remediation: `This file is dropped by the Mini Shai-Hulud npm worm to survive \`npm uninstall\`. If it exists, the host that ran \`npm install\` is compromised — assume every credential the build process touched has been exfiltrated (npm tokens, GitHub tokens, OIDC tokens, cloud creds, crypto wallets, browser session cookies). Steps: 1) DO NOT revoke your GitHub token yet — the worm runs \`rm -rf ~/\` when its stolen token returns 40x. First disconnect the machine from the network. 2) Pull a known-good system. 3) Rotate every credential offline. 4) Audit CI for the malicious GitHub Actions workflows the worm tries to inject. Public IOC tracking: Aikido, Snyk, Socket, Wiz, StepSecurity (May 2026).`,
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
    const lines = file.content.split('\n');
    let emptyCatch = 0,
      anyType = 0;
    lines.forEach((line) => {
      if (/catch\s*(?:\([^)]*\))?\s*\{\s*\}/.test(line)) emptyCatch++;
      if (/:\s*any\b|as\s+any\b/.test(line)) anyType++;
    });
    if (emptyCatch >= 1) {
      findings.push({
        id: `smell-emptycatch-${file.path}`,
        probe: 'AI Code Smells',
        title: `${emptyCatch} empty catch block${emptyCatch > 1 ? 's' : ''} silently swallow errors`,
        severity: 'low',
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

// --- 2026: External URL reputation surface (extract + heuristic + lookup links) ---
// Placeholder / documentation-example hosts that appear in copy and aren't real references.

// Probes extracted to focused modules (see src/lib/probes/*). Re-imported and re-exported
// here so the registry at the bottom of this file plus historical callers (App.jsx, tests)
// keep working without import-path changes.
import {
  probeExternalURLs,
  probeHTML,
  probeSEOHygiene,
  probeGEOHygiene,
  probeA11yLandmarks,
} from './probes/web.js';
import { probeCodeQuality, classifyProject, probeArchitecture } from './probes/quality.js';
import { probeCodeCorrectness } from './probes/code-correctness.js';
export {
  probeExternalURLs,
  probeHTML,
  probeSEOHygiene,
  probeGEOHygiene,
  probeA11yLandmarks,
  probeCodeQuality,
  classifyProject,
  probeArchitecture,
  probeCodeCorrectness,
};
export const PROBES = [
  { name: 'Architecture', fn: probeArchitecture },
  { name: 'Secret Scanner', fn: probeSecrets },
  { name: 'NEXT_PUBLIC_ Misuse', fn: probeNextPublic },
  { name: 'Supabase RLS', fn: probeSupabaseRLS },
  { name: 'Firebase Rules', fn: probeFirebaseRules },
  { name: 'Package.json', fn: probePackageJson },
  { name: 'Env File Hygiene', fn: probeEnvFiles },
  { name: 'Auth Weakness', fn: probeAuthWeakness },
  { name: 'Admin Route Exposure', fn: probeAdminRoutes },
  { name: 'Security Headers', fn: probeMissingHeaders },
  { name: 'CORS', fn: probeCORS },
  { name: 'LLM Security', fn: probeLLMSecurity },
  { name: 'Webhook Validation', fn: probeWebhookValidation },
  { name: 'GitHub Actions', fn: probeGitHubActions },
  { name: 'Client Auth Storage', fn: probeClientAuthStorage },
  { name: 'SSRF / Open Redirect', fn: probeSSRFOpenRedirect },
  { name: 'Cookie Security', fn: probeCookieFlags },
  { name: 'API Route Auth', fn: probeAPIRouteAuth },
  { name: 'Compromised Packages', fn: probeCompromisedPackages },
  { name: 'Slopsquat / Typosquat', fn: probeSlopsquatting },
  { name: 'MCP Security', fn: probeMCPSecurity },
  { name: 'Trojan Source', fn: probeTrojanSource },
  { name: 'AI Rules Files', fn: probeAIRulesFiles },
  { name: 'Malicious Artifacts', fn: probeMaliciousArtifacts },
  { name: 'AI Code Smells', fn: probeAICodeSmells },
  { name: 'URL Reputation', fn: probeExternalURLs },
  { name: 'HTML Hygiene', fn: probeHTML },
  { name: 'SEO Hygiene', fn: probeSEOHygiene },
  { name: 'GEO Hygiene', fn: probeGEOHygiene },
  { name: 'A11y Landmarks', fn: probeA11yLandmarks },
  { name: 'Code Quality', fn: probeCodeQuality },
  { name: 'Code Correctness', fn: probeCodeCorrectness },
  { name: 'Package Manager Hardening', fn: probeNpmrcHygiene },
];

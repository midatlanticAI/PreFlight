// src/lib/probes.js
// All scanner probes, threat-intel constants, file-include rules, project classifier,
// and the PROBES registry. Extracted from src/App.jsx to keep the monolith honest.
//
// This module is pure: every export is a plain function or data structure. No React,
// no DOM, no localStorage. The audit-app App component imports from here.

// ==========================================================================
// DETECTION PATTERNS
// ==========================================================================
export const SECRET_PATTERNS = [
  {
    name: 'AWS Access Key ID',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'AWS Secret Access Key',
    regex: /aws[_\-]?secret[_\-]?(?:access[_\-]?)?key["'\s:=]+["']?([A-Za-z0-9/+=]{40})["']?/gi,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Stripe Live Secret Key',
    regex: /\bsk_live_[A-Za-z0-9]{20,}\b/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Stripe Test Secret Key',
    regex: /\bsk_test_[A-Za-z0-9]{20,}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'OpenAI API Key',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_\-]{40,}\b/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Anthropic API Key',
    regex: /\bsk-ant-[A-Za-z0-9_\-]{40,}\b/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Google API Key',
    regex: /\bAIza[0-9A-Za-z_\-]{35}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Slack Bot Token',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'SendGrid API Key',
    regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Hugging Face Token',
    regex: /\bhf_[A-Za-z0-9]{30,}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Replicate API Token',
    regex: /\br8_[A-Za-z0-9]{30,}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Groq API Key',
    regex: /\bgsk_[A-Za-z0-9]{40,}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Perplexity API Key',
    regex: /\bpplx-[A-Za-z0-9]{40,}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  // ReDoS-safe: each segment forbids ':' and '@' so the user / pass / host parts can't ambiguously overlap.
  {
    name: 'Database Connection URL with Credentials',
    regex:
      /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s"'<>:@/]+:[^\s"'<>:@/]+@[^\s"'<>/]+/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Private Key Block',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Generic Hardcoded Secret',
    regex: /(?:secret|password|passwd|api[_-]?key)\s*[:=]\s*["'][A-Za-z0-9_\-!@#$%^&*]{16,}["']/gi,
    severity: 'medium',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
];

const NEXT_PUBLIC_DANGER_NAMES =
  /SECRET|PRIVATE|SERVICE_ROLE|TOKEN|PASSWORD|STRIPE_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY/i;
const NEXT_PUBLIC_DANGER_VALUES = /^sk_live_|^sk_test_|^sk-ant-|^sk-proj-|service_role/;

// ==========================================================================
// 2026 THREAT INTEL: known-compromised package versions
// Sources: CISA, GTIG/Mandiant, Socket, Wiz, Unit 42, OX Security, OWASP
// ==========================================================================
export const COMPROMISED_PACKAGES = {
  // Sapphire Sleet (DPRK) Axios compromise — March 31, 2026
  axios: {
    versions: ['1.14.1', '0.30.4'],
    note: 'Sapphire Sleet RAT injection via plain-crypto-js dep (CISA, GTIG)',
  },
  'plain-crypto-js': {
    versions: ['*'],
    note: 'Malicious dep injected into axios; do not install any version',
  },
  // Bitwarden CLI compromise — April 22, 2026
  '@bitwarden/cli': { versions: ['2026.4.0'], note: 'Hunted Claude/Cursor/Codex credentials' },
  // Mini Shai-Hulud SAP campaign — April 29, 2026
  'intercom-client': { versions: ['7.0.4', '7.0.5'], note: 'Mini Shai-Hulud credential stealer' },
  '@cap-js/sqlite': {
    versions: ['*'],
    note: 'SAP CAP toolchain; Mini Shai-Hulud — review version against Socket advisory',
  },
  '@cap-js/db-service': {
    versions: ['*'],
    note: 'SAP CAP toolchain; Mini Shai-Hulud — review version against Socket advisory',
  },
  // PyPI Mini Shai-Hulud
  lightning: { versions: ['2.6.2', '2.6.3'], note: 'PyPI Mini Shai-Hulud variant' },
};

// Common typosquats targeting popular packages
export const TYPOSQUATS = {
  reactt: 'react',
  reactjs: 'react',
  lodahs: 'lodash',
  lodaash: 'lodash',
  lodashy: 'lodash',
  expreess: 'express',
  expres: 'express',
  crossenv: 'cross-env',
  'discord-js': 'discord.js',
  momnet: 'moment',
  momentjs: 'moment',
  noodejs: 'node',
  jsonwebtokenn: 'jsonwebtoken',
  colorss: 'colors',
};

// Generic-looking package name patterns common in LLM hallucinations (slopsquat)
export const SLOPSQUAT_GENERIC_RE =
  /^(auth|api|db|user|admin|util|helper|core|server|client|app|web|http|json|crypto|fast|smart|easy|simple|secure|pro|advanced)-(auth|api|util|utils|helper|helpers|core|client|server|tool|tools|kit|lib|js|ts|node|sdk|wrapper|manager)$/i;

// Bidirectional Unicode control characters (CVE-2021-42574 / Trojan Source).
// Built from \u escape codes (NOT literal characters) so this file itself doesn't trip our own
// Trojan Source probe when scanning the scanner. The codepoint ranges are:
//   U+202A-U+202E  LRE / RLE / PDF / LRO / RLO
//   U+2066-U+2069  LRI / RLI / FSI / PDI
export const BIDI_CONTROL_RE = new RegExp('[' + '\\u202A-\\u202E\\u2066-\\u2069' + ']');

// --- Test-file exclusion: pattern-matching probes should skip test files ---
// Test files legitimately demonstrate vulnerable patterns to verify detection. Running content-
// pattern probes against `*.test.{js,jsx,ts,tsx}`, `*.spec.*`, or anything under `test/`/`tests/`
// /`__tests__/` produces self-reference findings instead of real ones (the regression test for
// "we should detect eval()" is itself a string containing `eval(`).
// Structural probes (file size, missing .npmrc, architecture) should still see test files.
export function isTestFile(path) {
  if (!path) return false;
  if (/\.(test|spec)\.[jt]sx?$/i.test(path)) return true;
  if (/(^|\/)(test|tests|__tests__)\//i.test(path)) return true;
  return false;
}

// --- Self-source exclusion: pattern-matching probes should skip scanner internals ---
// The scanner's own regex literals and remediation copy contain the exact patterns it looks
// for (eval, PythonREPL, dangerouslySetInnerHTML, algorithm: 'none'). Without an exclusion,
// every pattern-matching probe finds itself in src/lib/probes.js and in the production
// bundle (dist/) which inlines probes.js. These aren't real vulnerabilities; they're the
// scanner's definitions of what real vulnerabilities look like.
export function isScannerSelfSource(path) {
  if (!path) return false;
  if (/(^|\/)src\/lib\/probes\.[jt]sx?$/i.test(path)) return true;
  // The Vite-bundled JS in dist/ contains the inlined probes.js source.
  if (/(^|\/)dist\/.*\.js$/i.test(path)) return true;
  return false;
}

export const FILE_INCLUDE = [
  /(^|\/)\.env(\..+)?$/i,
  /package\.json$/,
  /package-lock\.json$/,
  /yarn\.lock$/,
  /pnpm-lock\.yaml$/,
  /(^|\/)\.npmrc$/,
  /\.tsx?$/,
  /\.jsx?$/,
  /\.mjs$/,
  /\.cjs$/,
  /\.py$/,
  /\.go$/,
  /\.rb$/,
  /\.php$/,
  /\.java$/,
  /\.html?$/i,
  /\.vue$/,
  /\.svelte$/,
  /\.astro$/,
  /firestore\.rules$/,
  /storage\.rules$/,
  /firebase\.json$/,
  /(^|\/)supabase\/.*\.sql$/,
  /migrations\/.*\.sql$/,
  /next\.config\.(js|mjs|ts)$/,
  /vercel\.json$/,
  /netlify\.toml$/,
  /\.config\.[jt]s$/,
  /Dockerfile$/,
  /docker-compose\.ya?ml$/,
  // SEO / GEO / discoverability files
  /(^|\/)llms\.txt$/i,
  /(^|\/)robots\.txt$/i,
  /(^|\/)sitemap\.xml$/i,
  // Repo-local Pre-Flight config so the suppression workflow loads on GitHub URL scans
  /(^|\/)\.preflight\.(ya?ml|json)$/i,
  // 2026 additions: AI tooling configs, MCP servers, CI workflows
  /\.github\/workflows\/.+\.ya?ml$/,
  /(^|\/)\.cursorrules$/,
  /\.cursor\/rules\/.+\.(mdc?|md|txt)$/,
  /(^|\/)\.windsurfrules$/,
  /(^|\/)CLAUDE\.md$/,
  /claude_desktop_config\.json$/,
  /(^|\/)\.mcp\.json$/,
  /(^|\/)mcp\.json$/,
];

export const FILE_EXCLUDE = [
  /node_modules/,
  /(^|\/)\.git\//,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /(^|\/)\.next\//,
  /(^|\/)coverage\//,
  /(^|\/)\.cache\//,
  /(^|\/)\.turbo\//,
];

export function shouldScanFile(path) {
  if (FILE_EXCLUDE.some((p) => p.test(path))) return false;
  return FILE_INCLUDE.some((p) => p.test(path));
}

// ==========================================================================
// PROBE MODULES
// ==========================================================================

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
// Includes the IANA-reserved example domains, common documentation strings, and RFC 5737
// reserved IP ranges (TEST-NET-1/2/3 — used in code samples and test fixtures).
export const URL_PLACEHOLDER_HOSTS = new Set([
  'example.com',
  'example.org',
  'example.net',
  'example.io',
  'yourdomain.com',
  'yoursite.com',
  'mydomain.com',
  'somedomain.com',
  'foo.bar',
  'foo.baz',
  'host',
  '[::1]',
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
]);
// RFC 5737 ranges: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — reserved for documentation.
export const URL_PLACEHOLDER_IP_RE = /^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/;

export const URL_SAFE_HOSTS = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  'example.com',
  'example.org',
  'test.com',
  'github.com',
  'githubusercontent.com',
  'gitlab.com',
  'bitbucket.org',
  'npmjs.com',
  'pypi.org',
  'rubygems.org',
  'go.dev',
  'google.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'gstatic.com',
  'microsoft.com',
  'azure.com',
  'aws.amazon.com',
  'amazonaws.com',
  'cloudflare.com',
  'jsdelivr.net',
  'unpkg.com',
  'cdnjs.cloudflare.com',
  'mozilla.org',
  'developer.mozilla.org',
  'w3.org',
  'schema.org',
  'openai.com',
  'anthropic.com',
  'huggingface.co',
  'cohere.com',
  'replicate.com',
  'stripe.com',
  'twilio.com',
  'sendgrid.com',
  'vercel.com',
  'netlify.com',
  'render.com',
  'fly.io',
  'supabase.co',
  'supabase.com',
  'firebase.google.com',
  'firebaseio.com',
  'googleapis.com',
  'apple.com',
  'icloud.com',
  'tailwindcss.com',
  'reactjs.org',
  'react.dev',
  'nextjs.org',
  'vuejs.org',
]);
export const URL_SUSPICIOUS_TLD_RE =
  /\.(tk|ml|ga|cf|gq|top|xyz|click|loan|work|men|surf|cyou|rest|zip|mov|wang|country|kim|science|date|stream)$/i;
export const URL_RAW_IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
export const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  'goo.gl',
  't.co',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'rebrand.ly',
  'shorte.st',
  'cutt.ly',
]);

function isHostInSafeList(host) {
  if (URL_SAFE_HOSTS.has(host)) return true;
  for (const safe of URL_SAFE_HOSTS) {
    if (host.endsWith('.' + safe)) return true;
  }
  return false;
}

export function probeExternalURLs(files) {
  const findings = [];
  // Char class includes `:` `[` `]` `@` so we capture IPv6 (`https://[::1]/`) and
  // credentials-in-URL (`https://user:pass@host/`) instead of breaking at those chars.
  const URL_RE = /https?:\/\/[A-Za-z0-9.\-_~%:@\[\]]+(?::\d+)?(?:\/[^\s"'<>`)\]]*)?/g;
  // host -> { occurrences: [{file,line,url}], allHttp: bool }
  const seen = new Map();

  // Self-domain allowlist from package.json#homepage (if present).
  const selfDomains = new Set();
  const pkgFile = files.find(
    (f) => /(^|\/)package\.json$/.test(f.path) && !/node_modules/.test(f.path)
  );
  if (pkgFile) {
    try {
      const pkg = JSON.parse(pkgFile.content);
      if (pkg.homepage) {
        try {
          selfDomains.add(new URL(pkg.homepage).hostname.toLowerCase());
        } catch {}
      }
    } catch {}
  }

  // Returns true if the URL match sits inside a remediation/description/help string literal
  // context — i.e. it's documentation, not a real reference. Heuristic: walk back up to 80
  // chars from the match index looking for one of those property names.
  const isInHelpContext = (content, idx) => {
    const back = content.slice(Math.max(0, idx - 120), idx);
    return /\b(remediation|description|help|docs?Url|message|note|hint)\s*[:=]\s*[`'"][^`'"]*$/i.test(
      back
    );
  };

  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    // Skip lockfiles (massive volume of registry URLs that drown the signal).
    if (/(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/i.test(file.path)) return;
    const content = file.content || '';
    let m;
    URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(content)) !== null) {
      const raw = m[0].replace(/[.,;:!?)\]\}]+$/, ''); // strip trailing punctuation
      let host;
      try {
        host = new URL(raw).hostname.toLowerCase();
      } catch {
        continue;
      }
      if (!host || isHostInSafeList(host)) continue;
      if (URL_PLACEHOLDER_HOSTS.has(host)) continue;
      if (URL_PLACEHOLDER_IP_RE.test(host)) continue;
      if (selfDomains.has(host)) continue;
      if (isInHelpContext(content, m.index)) continue;

      const lineNum = content.slice(0, m.index).split('\n').length;
      const isHttp = raw.startsWith('http:');
      const entry = seen.get(host) || { occurrences: [], allHttp: true };
      entry.occurrences.push({ file: file.path, line: lineNum, url: raw });
      entry.allHttp = entry.allHttp && isHttp;
      seen.set(host, entry);
    }
  });

  for (const [host, info] of seen) {
    const isIP = URL_RAW_IP_RE.test(host);
    const sketchyTLD = URL_SUSPICIOUS_TLD_RE.test(host);
    const isShortener = URL_SHORTENERS.has(host);
    const httpOnly = info.allHttp;

    let severity = 'info';
    let reason = 'External URL referenced in source';
    if (isIP) {
      severity = 'medium';
      reason = 'Raw IP address used as endpoint';
    } else if (sketchyTLD) {
      severity = 'medium';
      reason = 'Suspicious TLD';
    } else if (isShortener) {
      severity = 'medium';
      reason = 'URL shortener (hides destination)';
    } else if (httpOnly) {
      severity = 'low';
      reason = 'HTTP only — no TLS';
    }

    const first = info.occurrences[0];
    const evidence = info.occurrences
      .slice(0, 3)
      .map((o) => `${o.file}:${o.line} → ${o.url.length > 90 ? o.url.slice(0, 90) + '…' : o.url}`)
      .join(' | ');
    findings.push({
      id: `url-${host}-${first.file}-${first.line}`,
      probe: 'URL Reputation',
      title: `${reason}: ${host}${info.occurrences.length > 1 ? ` (×${info.occurrences.length} occurrences)` : ''}`,
      severity,
      category: 'Misconfiguration',
      cwe: 'CWE-829',
      file: first.file,
      line: first.line,
      evidence,
      remediation:
        `Verify this domain hasn't been compromised, repurposed, or sold. The audit tool can't query reputation feeds from the browser due to CORS, so confirm with these one-click checks:\n\n` +
        `• VirusTotal: https://www.virustotal.com/gui/domain/${encodeURIComponent(host)}\n` +
        `• urlhaus (abuse.ch): https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(host)}\n` +
        `• whois: https://who.is/whois/${encodeURIComponent(host)}\n\n` +
        `Why this matters: a domain you trusted at write-time can change hands or get compromised. dasgas.com is a real example — Seclookup flagged it Malicious in the past. If you don't actively monitor your dependency URLs, a once-clean domain can become a quiet exfiltration target without anyone noticing.`,
    });
  }
  return findings;
}

// --- HTML / static-site probe (catches the "I wrote it in plain HTML" cohort) ---
export function probeHTML(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.html?$/i.test(file.path)) return;
    const content = file.content || '';
    const lines = content.split('\n');

    // Inline event handlers — XSS sinks if any attribute value comes from user data.
    // Expanded vocabulary covers the common DOMPurify-bypass favorites that the original
    // 8-event regex missed (adversarial finding): dblclick, key events, paste, toggle, pointer, aux.
    lines.forEach((line, i) => {
      const inlineHandler = line.match(
        /\son(?:click|dblclick|auxclick|load|error|mouseover|mousedown|mouseup|focus|blur|input|change|submit|keydown|keyup|keypress|paste|copy|cut|drop|drag|toggle|pointerdown|pointerup|pointermove|wheel|scroll|resize|select)\s*=/i
      );
      if (inlineHandler) {
        findings.push({
          id: `html-inline-${file.path}-${i}`,
          probe: 'HTML Hygiene',
          title: 'Inline event handler in HTML',
          severity: 'low',
          category: 'Code Injection',
          cwe: 'CWE-79',
          file: file.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation:
            'Inline handlers like onclick="..." are common XSS sinks when any attribute value is templated from user data. Move to addEventListener in a script block, and apply a Content-Security-Policy that disallows inline scripts and inline handlers.',
        });
      }
    });

    // <a target="_blank"> without rel="noopener" — tabnabbing on older browsers.
    [...content.matchAll(/<a\s[^>]*target\s*=\s*["']_blank["'][^>]*>/gi)].forEach((m) => {
      if (!/rel\s*=\s*["'][^"']*noopener/i.test(m[0])) {
        const ln = content.slice(0, m.index).split('\n').length;
        findings.push({
          id: `html-tabnab-${file.path}-${m.index}`,
          probe: 'HTML Hygiene',
          title: 'target="_blank" without rel="noopener"',
          severity: 'low',
          category: 'Code Injection',
          cwe: 'CWE-1022',
          file: file.path,
          line: ln,
          evidence: m[0].slice(0, 200),
          remediation:
            'Pages opened via target="_blank" can manipulate window.opener and redirect the original tab. Add rel="noopener noreferrer" to every external link with target="_blank".',
        });
      }
    });

    // Mixed-content fetches: HTTPS page loading http:// scripts/images.
    [
      ...content.matchAll(
        /<(?:script|img|iframe|link)[^>]*\b(?:src|href)\s*=\s*["']http:\/\/[^"']+["']/gi
      ),
    ].forEach((m) => {
      const ln = content.slice(0, m.index).split('\n').length;
      findings.push({
        id: `html-mixed-${file.path}-${m.index}`,
        probe: 'HTML Hygiene',
        title: 'HTTP resource referenced in HTML (mixed-content risk)',
        severity: 'medium',
        category: 'Misconfiguration',
        cwe: 'CWE-319',
        file: file.path,
        line: ln,
        evidence: m[0].slice(0, 200),
        remediation:
          'When served over HTTPS, browsers block or downgrade-warn on http:// scripts/images. Switch to https://, or use protocol-relative //example.com/x.js if the asset host supports both.',
      });
    });

    // <script> blocks containing eval() / new Function() — classic RCE class in static sites.
    [...content.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)].forEach((m) => {
      const body = m[1];
      if (/\beval\s*\(/.test(body) || /\bnew\s+Function\s*\(/.test(body)) {
        const ln = content.slice(0, m.index).split('\n').length;
        findings.push({
          id: `html-eval-${file.path}-${m.index}`,
          probe: 'HTML Hygiene',
          title: 'eval() or new Function() inside <script>',
          severity: 'high',
          category: 'Code Injection',
          cwe: 'CWE-95',
          file: file.path,
          line: ln,
          evidence: (body.match(/.{0,80}(?:eval|new Function)\s*\([^)]{0,80}/) || [''])[0],
          remediation:
            'Inline eval/new Function in a <script> is a direct RCE path if any input ever flows into the evaluated string. Use JSON.parse for data, switch statements for known operations, or a real expression parser.',
        });
      }
    });

    // Forms posting over HTTP, even on HTTPS pages.
    [...content.matchAll(/<form[^>]*\baction\s*=\s*["']http:\/\/[^"']+["']/gi)].forEach((m) => {
      const ln = content.slice(0, m.index).split('\n').length;
      findings.push({
        id: `html-form-http-${file.path}-${m.index}`,
        probe: 'HTML Hygiene',
        title: 'Form posts to http:// endpoint',
        severity: 'high',
        category: 'Data Breach',
        cwe: 'CWE-319',
        file: file.path,
        line: ln,
        evidence: m[0].slice(0, 200),
        remediation:
          'A form that POSTs over HTTP exposes submitted data (passwords, tokens, PII) to anyone on the network path. Switch the action URL to https://.',
      });
    });

    // Missing or weak CSP meta tag in <head> of an otherwise scriptful page.
    const hasInlineScript = /<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/i.test(content);
    const hasCsp = /<meta[^>]*http-equiv\s*=\s*["']content-security-policy["']/i.test(content);
    if (hasInlineScript && !hasCsp) {
      findings.push({
        id: `html-nocsp-${file.path}`,
        probe: 'HTML Hygiene',
        title: 'Inline <script> with no Content-Security-Policy meta tag',
        severity: 'low',
        category: 'Misconfiguration',
        cwe: 'CWE-693',
        file: file.path,
        line: 1,
        evidence: '<script> block detected; no CSP meta tag found',
        remediation:
          'A CSP header is the single most effective XSS mitigation. If you cannot set it via server headers, add <meta http-equiv="Content-Security-Policy" content="default-src \'self\'; ..."> in <head>. Then iterate to add only the origins you need.',
      });
    }
  });
  return findings;
}

// --- SEO Hygiene: index.html meta tags, robots.txt, sitemap.xml ---
export function probeSEOHygiene(files) {
  const findings = [];
  files.forEach((file) => {
    // index.html (or any *.html that looks like a SPA entry — has <head>)
    if (/\.html?$/i.test(file.path)) {
      const c = file.content || '';
      const head = (c.match(/<head[^>]*>([\s\S]*?)<\/head>/i) || ['', ''])[1];
      const isEntry =
        /<div\s+id=["']root["']|<div\s+id=["']app["']/i.test(c) ||
        /\/?index\.html?$/i.test(file.path);
      if (!isEntry) return;

      const issues = [];
      if (!/<html[^>]*\blang\s*=/i.test(c))
        issues.push({
          k: 'no-lang',
          t: '<html> missing lang attribute',
          s: 'medium',
          cwe: 'WCAG 3.1.1',
        });
      if (!/<title[^>]*>[^<]{4,}<\/title>/i.test(head))
        issues.push({
          k: 'no-title',
          t: 'Missing or empty <title> in <head>',
          s: 'high',
          cwe: 'SEO-fundamentals',
        });
      if (!/<meta[^>]*name=["']description["'][^>]*content=["'][^"']{20,}["']/i.test(head))
        issues.push({
          k: 'no-description',
          t: 'Missing or thin <meta name="description">',
          s: 'medium',
          cwe: 'SEO-fundamentals',
        });
      if (!/<meta[^>]*name=["']viewport["']/i.test(head))
        issues.push({
          k: 'no-viewport',
          t: 'Missing <meta name="viewport">',
          s: 'medium',
          cwe: 'WCAG 1.4.10',
        });
      if (!/<link[^>]*rel=["']canonical["']/i.test(head))
        issues.push({
          k: 'no-canonical',
          t: 'Missing <link rel="canonical">',
          s: 'low',
          cwe: 'SEO-fundamentals',
        });
      if (!/<meta[^>]*property=["']og:title["']/i.test(head))
        issues.push({
          k: 'no-og-title',
          t: 'Missing Open Graph og:title',
          s: 'low',
          cwe: 'SEO-social-share',
        });
      if (!/<meta[^>]*property=["']og:description["']/i.test(head))
        issues.push({
          k: 'no-og-desc',
          t: 'Missing Open Graph og:description',
          s: 'low',
          cwe: 'SEO-social-share',
        });
      if (!/<meta[^>]*property=["']og:image["']/i.test(head))
        issues.push({
          k: 'no-og-image',
          t: 'Missing Open Graph og:image (poor share previews)',
          s: 'low',
          cwe: 'SEO-social-share',
        });
      if (!/<meta[^>]*name=["']twitter:card["']/i.test(head))
        issues.push({
          k: 'no-twitter',
          t: 'Missing twitter:card meta',
          s: 'info',
          cwe: 'SEO-social-share',
        });
      if (!/<link[^>]*rel=["']icon["']/i.test(head))
        issues.push({
          k: 'no-favicon',
          t: 'Missing favicon <link rel="icon">',
          s: 'info',
          cwe: 'SEO-fundamentals',
        });
      // Schema drift / missing JSON-LD
      const hasJsonLd = /<script[^>]*type=["']application\/ld\+json["'][^>]*>/i.test(head);
      if (!hasJsonLd)
        issues.push({
          k: 'no-jsonld',
          t: 'No JSON-LD structured data in <head>',
          s: 'medium',
          cwe: 'SEO-structured-data',
        });

      issues.forEach((issue) => {
        findings.push({
          id: `seo-${issue.k}-${file.path}`,
          probe: 'SEO Hygiene',
          title: issue.t,
          severity: issue.s,
          category: 'Misconfiguration',
          cwe: issue.cwe,
          file: file.path,
          line: 1,
          evidence: `entry HTML: ${file.path}`,
          remediation: `Search engines and AI-search crawlers rely on these head tags. ${
            issue.k === 'no-title'
              ? 'Add <title>Your descriptive title</title>.'
              : issue.k === 'no-description'
                ? 'Add <meta name="description" content="..." /> with 70–160 chars describing the page.'
                : issue.k === 'no-canonical'
                  ? 'Add <link rel="canonical" href="https://yourdomain.com/" /> to prevent duplicate-content penalties.'
                  : issue.k === 'no-og-title'
                    ? 'Add <meta property="og:title" content="..." /> so links shared on social show a title card.'
                    : issue.k === 'no-og-image'
                      ? 'Add <meta property="og:image" content="https://yourdomain.com/og.png" /> with a 1200×630 image.'
                      : issue.k === 'no-lang'
                        ? 'Add lang="en" (or the appropriate BCP47 code) to <html>. Required for screen-reader pronunciation (WCAG 3.1.1).'
                        : issue.k === 'no-viewport'
                          ? 'Add <meta name="viewport" content="width=device-width, initial-scale=1" /> so mobile zoom and text scaling work (WCAG 1.4.10).'
                          : issue.k === 'no-jsonld'
                            ? 'Add a <script type="application/ld+json"> block with at minimum a WebSite or SoftwareApplication entity. Google and Perplexity use it directly.'
                            : 'Add the missing tag — most are 1 line of HTML.'
          }`,
        });
      });
    }

    if (/(^|\/)robots\.txt$/i.test(file.path)) {
      const c = file.content || '';
      if (!/^\s*Sitemap:\s*\S+/im.test(c)) {
        findings.push({
          id: `seo-robots-no-sitemap-${file.path}`,
          probe: 'SEO Hygiene',
          title: 'robots.txt has no Sitemap: line',
          severity: 'low',
          category: 'Misconfiguration',
          cwe: 'SEO-fundamentals',
          file: file.path,
          line: 1,
          evidence: 'No "Sitemap:" directive found',
          remediation:
            'Add a line: Sitemap: https://yourdomain.com/sitemap.xml — helps crawlers discover URLs they would otherwise miss.',
        });
      }
      // Only flag a site-blocking Disallow when it appears under a wildcard `User-agent: *` block.
      // A `Disallow: /` under a specific bot (e.g. BadBot) is a deliberate per-bot block, not a
      // catastrophic site-wide misconfig (adversarial-agent finding).
      {
        const cleanedRobots = c
          .split('\n')
          .map((l) => l.replace(/#.*$/, '').trimEnd())
          .join('\n');
        for (const block of cleanedRobots.split(/\n\s*\n/)) {
          const uas = [...block.matchAll(/^User-agent:\s*(\S+)/gim)].map((m) => m[1]);
          if (!uas.includes('*')) continue;
          if (!/^Disallow:\s*\/\s*$/im.test(block)) continue;
          if (/^Allow:\s*\//im.test(block)) continue;
          findings.push({
            id: `seo-robots-disallow-all-${file.path}`,
            probe: 'SEO Hygiene',
            title: 'robots.txt blocks the entire site (Disallow: / under User-agent: *)',
            severity: 'critical',
            category: 'Misconfiguration',
            cwe: 'SEO-fundamentals',
            file: file.path,
            line: 1,
            evidence: 'Wildcard User-agent block contains "Disallow: /" with no compensating Allow',
            remediation:
              'A "Disallow: /" under "User-agent: *" blocks every search engine from indexing the site. If this is intentional (staging, deprecated), ignore; otherwise change to "Disallow:" (empty) or add a permissive "Allow: /" line.',
          });
          break; // one finding per file
        }
      }
    }
  });
  return findings;
}

// --- GEO Hygiene: AI-search visibility ---
export const AI_CRAWLER_BOTS = [
  'GPTBot',
  'ChatGPT-User',
  'OAI-SearchBot',
  'anthropic-ai',
  'ClaudeBot',
  'Claude-Web',
  'PerplexityBot',
  'Google-Extended',
  'CCBot',
];

export function probeGEOHygiene(files) {
  const findings = [];
  const hasLlms = files.some((f) => /(^|\/)llms\.txt$/i.test(f.path));
  const robotsFile = files.find((f) => /(^|\/)robots\.txt$/i.test(f.path));
  const htmlFile = files.find(
    (f) => /\.html?$/i.test(f.path) && /<div\s+id=["'](root|app)["']/i.test(f.content || '')
  );
  const hasAnyHtml = files.some((f) => /\.html?$/i.test(f.path));

  if (hasAnyHtml && !hasLlms) {
    findings.push({
      id: 'geo-no-llmstxt',
      probe: 'GEO Hygiene',
      title: 'No llms.txt for AI-search crawlers',
      severity: 'low',
      category: 'Misconfiguration',
      cwe: 'GEO-fundamentals',
      file: 'public/llms.txt (missing)',
      line: 1,
      evidence: 'Project has HTML but no llms.txt at the site root',
      remediation:
        'Create public/llms.txt per https://llmstxt.org — a Markdown summary of your site for AI crawlers (Perplexity, ChatGPT search, Gemini). Headline tagline first, then sectioned facts. AI search engines preferentially quote llms.txt content.',
    });
  }

  if (robotsFile) {
    const c = robotsFile.content || '';
    // Walk robots.txt block by block. A "block" is a contiguous set of non-blank lines
    // (after stripping # comments) that share their User-agent context. This is the only
    // way to correctly scope `Disallow: /` to the user-agent that owns it — a free-floating
    // regex falsely attributes one bot's Disallow to a different bot mentioned earlier in a
    // comment or empty-Disallow block (adversarial-agent finding).
    const cleaned = c
      .split('\n')
      .map((l) => l.replace(/#.*$/, '').trimEnd())
      .join('\n');
    const blocks = cleaned.split(/\n\s*\n/);
    for (const block of blocks) {
      const uaLines = [...block.matchAll(/^User-agent:\s*(\S+)/gim)].map((m) => m[1]);
      if (uaLines.length === 0) continue;
      const fullDisallow = /^Disallow:\s*\/\s*$/im.test(block);
      if (!fullDisallow) continue;
      AI_CRAWLER_BOTS.forEach((bot) => {
        if (uaLines.some((ua) => ua.toLowerCase() === bot.toLowerCase())) {
          findings.push({
            id: `geo-block-${bot}`,
            probe: 'GEO Hygiene',
            title: `robots.txt blocks ${bot}`,
            severity: 'low',
            category: 'Misconfiguration',
            cwe: 'GEO-fundamentals',
            file: robotsFile.path,
            line: 1,
            evidence: `User-agent: ${bot} block contains "Disallow: /"`,
            remediation: `${bot} is the crawler for an AI search engine. Blocking it means your content cannot appear in AI-generated answers. If that is intentional, ignore. If you want to be cited, remove the Disallow.`,
          });
        }
      });
    }
  }

  if (htmlFile) {
    const head = (htmlFile.content.match(/<head[^>]*>([\s\S]*?)<\/head>/i) || ['', ''])[1];
    // Freshness signal — JSON-LD with dateModified, OR a visible <time> element somewhere in the body.
    const hasDateModified = /"dateModified"\s*:\s*"\d{4}-\d{2}-\d{2}/.test(htmlFile.content);
    const hasTimeTag = /<time[^>]*\bdatetime\s*=/i.test(htmlFile.content);
    if (!hasDateModified && !hasTimeTag) {
      findings.push({
        id: 'geo-no-freshness',
        probe: 'GEO Hygiene',
        title: 'No freshness signal (dateModified in JSON-LD or <time datetime>) on the page',
        severity: 'low',
        category: 'Misconfiguration',
        cwe: 'GEO-fundamentals',
        file: htmlFile.path,
        line: 1,
        evidence:
          'Page has no dateModified in structured data and no <time datetime="..."> in markup',
        remediation:
          'AI search engines prioritize recently-updated content. Add either "dateModified": "YYYY-MM-DD" to your JSON-LD or a visible <time dateTime="YYYY-MM-DD">Updated YYYY-MM-DD</time> element. Both is better.',
      });
    }
    // FAQPage schema present but no visible FAQs anywhere in the project — schema drift risk.
    // For SPAs, the visible FAQ may live in a JSX file rendered at runtime; we accept that.
    const faqInSchema = /"@type"\s*:\s*"FAQPage"/.test(head);
    const visibleFaqHere = /<(?:dl|details|h2|h3)[^>]*>[\s\S]*?(?:question|faq|frequently)/i.test(
      htmlFile.content
    );
    const visibleFaqInJsx = files.some(
      (f) =>
        /\.[jt]sx$/i.test(f.path) &&
        (/aria-labelledby=["']faq-heading["']/i.test(f.content || '') ||
          /id=["']faq-heading["']/i.test(f.content || '') ||
          /<dl[^>]*>[\s\S]{0,300}<dt/i.test(f.content || ''))
    );
    if (faqInSchema && !visibleFaqHere && !visibleFaqInJsx) {
      findings.push({
        id: 'geo-schema-drift-faq',
        probe: 'GEO Hygiene',
        title: 'FAQPage JSON-LD with no visible FAQ section on the page',
        severity: 'medium',
        category: 'Misconfiguration',
        cwe: 'GEO-schema-drift',
        file: htmlFile.path,
        line: 1,
        evidence:
          '@type: FAQPage in JSON-LD; no <dl> / <details> / FAQ-headed section in DOM or JSX',
        remediation:
          'Google March 2026 update penalizes schema markup that contradicts visible content. Either remove the FAQPage schema or render the Q&As as visible HTML (a <dl> with <dt>/<dd> pairs works well).',
      });
    }
  }

  return findings;
}

// --- A11y Landmarks: img alt, button labels, input labels, html lang, target size ---
export function probeA11yLandmarks(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    const isHtml = /\.html?$/i.test(file.path);
    const isJsx = /\.[jt]sx$/i.test(file.path);
    const isVue = /\.vue$/i.test(file.path);
    const isSvelte = /\.svelte$/i.test(file.path);
    const isAstro = /\.astro$/i.test(file.path);
    if (!isHtml && !isJsx && !isVue && !isSvelte && !isAstro) return;
    const content = file.content || '';

    // <img> tags without an alt attribute (any image with no alt fails 1.1.1).
    // Vue / Svelte use :src / bind:src; check those file types via the same regex
    // since alt is universal (Vue/Svelte don't rename it).
    [...content.matchAll(/<img\s[^>]*\/?>/gi)].forEach((m) => {
      if (!/\balt\s*=/.test(m[0])) {
        const ln = content.slice(0, m.index).split('\n').length;
        findings.push({
          id: `a11y-img-no-alt-${file.path}-${m.index}`,
          probe: 'A11y Landmarks',
          title: '<img> without alt attribute',
          severity: 'medium',
          category: 'Misconfiguration',
          cwe: 'WCAG 1.1.1',
          file: file.path,
          line: ln,
          evidence: m[0].slice(0, 200),
          remediation:
            'Every <img> needs alt. For decorative images use alt="" (empty string) so screen readers skip them. For meaningful images, describe what the user would lose if the image failed to load.',
        });
      }
    });

    if (isHtml) {
      // <html lang="...">
      if (!/<html[^>]*\blang\s*=/i.test(content)) {
        findings.push({
          id: `a11y-html-no-lang-${file.path}`,
          probe: 'A11y Landmarks',
          title: '<html> missing lang attribute',
          severity: 'high',
          category: 'Misconfiguration',
          cwe: 'WCAG 3.1.1',
          file: file.path,
          line: 1,
          evidence: '<html> tag has no lang=',
          remediation:
            'Add lang="en" (or correct BCP47 code) so screen readers pronounce content with the right pronunciation engine. WCAG 3.1.1 Level A — failure here is a hard fail.',
        });
      }
      // <input type="text|email|search|password|number|tel|url"> without label / aria-label / aria-labelledby
      // Skip type=hidden / aria-hidden inputs — they're never user-facing (adversarial finding).
      [
        ...content.matchAll(
          /<input\s[^>]*\btype\s*=\s*["'](?:text|email|search|password|number|tel|url)["'][^>]*>/gi
        ),
      ].forEach((m) => {
        const tag = m[0];
        if (/\baria-hidden\s*=\s*["']true["']/i.test(tag)) return;
        if (
          /\bhidden\b(?!\s*=\s*["']false)/i.test(tag) &&
          !/\btype\s*=\s*["'](?:text|email)/i.test(
            tag.match(/type\s*=\s*["'][^"']+["']/i)?.[0] || ''
          )
        ) {
          // boolean hidden attribute on a non-text type: skip
          return;
        }
        const hasAriaLabel = /\baria-label\s*=\s*["']/i.test(tag);
        const hasAriaLabelledby = /\baria-labelledby\s*=\s*["']/i.test(tag);
        const idMatch = tag.match(/\bid\s*=\s*["']([^"']+)["']/i);
        const hasLabelFor = idMatch
          ? new RegExp(`<label[^>]*\\bfor\\s*=\\s*["']${idMatch[1]}["']`, 'i').test(content)
          : false;
        // Wrapping <label>…<input/>…</label> association
        const wrapping = new RegExp(
          `<label\\b[^>]*>(?:[^<]|<(?!input)[^>]*>)*${tag.replace(/[.*+?^${}()|[\]\\]/g, '\\\\$&')}`,
          's'
        );
        const hasWrappingLabel = wrapping.test(content);
        if (!hasAriaLabel && !hasAriaLabelledby && !hasLabelFor && !hasWrappingLabel) {
          const ln = content.slice(0, m.index).split('\n').length;
          findings.push({
            id: `a11y-input-no-label-${file.path}-${m.index}`,
            probe: 'A11y Landmarks',
            title: 'Form input without an associated label',
            severity: 'high',
            category: 'Misconfiguration',
            cwe: 'WCAG 1.3.1, 3.3.2',
            file: file.path,
            line: ln,
            evidence: tag.slice(0, 200),
            remediation:
              'Add one of: <label for="myid">…</label> + <input id="myid">, aria-label="…" on the input, or aria-labelledby="other-id". Without a label, screen readers announce the field as "edit" with no meaning.',
          });
        }
      });
      // Skip-link presence (a11y best practice — visible-on-focus link at top of <body>)
      const hasSkipLink = /<a\s[^>]*href=["']#(main|content)[^>]*>(skip|jump)/i.test(content);
      if (!hasSkipLink && /<body[^>]*>/i.test(content)) {
        findings.push({
          id: `a11y-no-skip-link-${file.path}`,
          probe: 'A11y Landmarks',
          title: 'No skip-to-content link at top of <body>',
          severity: 'low',
          category: 'Misconfiguration',
          cwe: 'WCAG 2.4.1',
          file: file.path,
          line: 1,
          evidence: 'No <a href="#main">Skip…</a> pattern found before main content',
          remediation:
            'Add <a href="#main" class="skip-link">Skip to main content</a> as the first element after <body>, styled to be visible only on keyboard focus. Lets keyboard users bypass repetitive nav.',
        });
      }
    }

    if (isJsx) {
      // <button> tags with only an icon child (no visible text, no aria-label).
      // This is a heuristic — looks for <button ...>\n? <Icon ... /> \n? </button> with no plain text.
      [...content.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)].forEach((m) => {
        const attrs = m[1];
        const body = m[2];
        const hasAriaLabel = /\baria-label\s*=/.test(attrs);
        // Strip just the TAG TOKENS (open / close / self-closing) but preserve text and JSX
        // expressions between them. A button with a Chevron icon AND visible {finding.title}
        // text in a sibling div still has visible content — it must NOT be flagged. Marking
        // each JSX expression with a sentinel so we know "this likely resolves to text".
        const stripped = body
          .replace(/<\/?[A-Za-z][^<>]*\/?>/g, ' ') // tag tokens → space (keeps inner text)
          .replace(/\{[^}]+\}/g, ' __EXPR__ ') // JSX expressions → sentinel
          .replace(/\s+/g, ' ')
          .trim();
        const hasExpr = /\b__EXPR__\b/.test(stripped);
        const hasText = stripped.replace(/__EXPR__/g, '').trim().length > 0;
        const hasCapitalTag = /<[A-Z][A-Za-z0-9]*\b/.test(body);
        const hasOnlyIcon = hasCapitalTag && !hasText && !hasExpr;
        if (hasOnlyIcon && !hasAriaLabel) {
          const ln = content.slice(0, m.index).split('\n').length;
          findings.push({
            id: `a11y-button-icon-only-${file.path}-${m.index}`,
            probe: 'A11y Landmarks',
            title: 'Icon-only <button> without aria-label',
            severity: 'medium',
            category: 'Misconfiguration',
            cwe: 'WCAG 4.1.2',
            file: file.path,
            line: ln,
            evidence: m[0].slice(0, 200).replace(/\s+/g, ' '),
            remediation:
              'Add aria-label="…" so screen readers announce the button\'s purpose. Example: <button aria-label="Delete entry"><Trash /></button>. The visible icon alone has no accessible name.',
          });
        }
      });
    }
  });
  return findings;
}

// --- Code Quality: console statements, file size, unhandled promises, async/try ---
export const FILE_SIZE_WARN_LINES = 1500;
export const FILE_SIZE_FAIL_LINES = 5000;

export function probeCodeQuality(files) {
  const findings = [];
  files.forEach((file) => {
    // Skip test files, lib/logger.js (a logger IS the right place for console mirroring),
    // generated bundles, and config files. We're judging *production source*.
    if (/(^|\/)(test|tests|__tests__|spec)\//i.test(file.path)) return;
    if (/(^|\/)dist\//i.test(file.path)) return;
    if (/(^|\/)\.test\.|\.spec\./i.test(file.path)) return;
    if (/(^|\/)logger\.[jt]sx?$/i.test(file.path)) return;
    if (/(^|\/)vite\.config\./i.test(file.path)) return;
    if (/(^|\/)vitest\.config\./i.test(file.path)) return;
    if (/(^|\/)setup\.[jt]sx?$/i.test(file.path)) return;
    if (!/\.[jt]sx?$/i.test(file.path)) return;

    const content = file.content || '';
    const lines = content.split('\n');

    // --- console.* in production source. Each occurrence becomes ONE finding (deduped per file).
    let consoleCount = 0;
    lines.forEach((line) => {
      const stripped = line.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/, '');
      if (/\bconsole\.(log|debug|info|warn|error|trace)\s*\(/.test(stripped)) {
        consoleCount++;
      }
    });
    if (consoleCount > 0) {
      findings.push({
        id: `cq-console-${file.path}`,
        probe: 'Code Quality',
        title: `${consoleCount} console.* call${consoleCount === 1 ? '' : 's'} in production source`,
        severity: consoleCount > 5 ? 'medium' : 'low',
        category: 'Misconfiguration',
        cwe: 'CWE-489',
        file: file.path,
        line: 1,
        evidence: `${consoleCount} occurrence(s) of console.log/debug/info/warn/error/trace`,
        remediation:
          'Console statements left in production source bloat the bundle, leak diagnostic data to user devtools, and confuse end-users debugging on their own. Route through a logger module that respects an env-driven log level, or strip with a build-time transform (Vite: define.replace).',
      });
    }

    // --- file size warnings
    if (lines.length >= FILE_SIZE_FAIL_LINES) {
      findings.push({
        id: `cq-file-huge-${file.path}`,
        probe: 'Code Quality',
        title: `File is ${lines.length} lines (extremely large)`,
        severity: 'medium',
        category: 'Misconfiguration',
        cwe: 'CWE-1041',
        file: file.path,
        line: 1,
        evidence: `${lines.length} lines exceeds ${FILE_SIZE_FAIL_LINES} threshold`,
        remediation:
          'Files this large hurt onboarding, code review, and test isolation. Split into modules organized by responsibility (probes, formatters, history, UI components).',
      });
    } else if (lines.length >= FILE_SIZE_WARN_LINES) {
      findings.push({
        id: `cq-file-large-${file.path}`,
        probe: 'Code Quality',
        title: `File is ${lines.length} lines (consider splitting)`,
        severity: 'info',
        category: 'Misconfiguration',
        cwe: 'CWE-1041',
        file: file.path,
        line: 1,
        evidence: `${lines.length} lines exceeds ${FILE_SIZE_WARN_LINES} warning threshold`,
        remediation:
          'Not a bug, but consider splitting on the next major refactor. Files over 1500 lines tend to accrete unrelated responsibilities and become harder to test in isolation.',
      });
    }

    // --- .then(...) without a subsequent .catch(...)
    // Walk the statement to its END (terminating semicolon, end of file, or back-to-column-1 at
    // the start of a new statement) before deciding it's unhandled. Previous fixed 200-char
    // window false-positived on .then() handlers with long bodies (adversarial-agent finding).
    [...content.matchAll(/\.then\s*\(/g)].forEach((m) => {
      // Walk forward through balanced parens / braces until we hit a semicolon at depth 0
      // or two consecutive newlines (paragraph break).
      let i = m.index;
      let pDepth = 0,
        bDepth = 0;
      let inSingle = false,
        inDouble = false,
        inBack = false;
      let lastChar = '';
      let chainEnd = content.length;
      for (; i < content.length; i++) {
        const ch = content[i];
        if (inSingle) {
          if (ch === "'" && lastChar !== '\\') inSingle = false;
          lastChar = ch;
          continue;
        }
        if (inDouble) {
          if (ch === '"' && lastChar !== '\\') inDouble = false;
          lastChar = ch;
          continue;
        }
        if (inBack) {
          if (ch === '`' && lastChar !== '\\') inBack = false;
          lastChar = ch;
          continue;
        }
        if (ch === "'") inSingle = true;
        else if (ch === '"') inDouble = true;
        else if (ch === '`') inBack = true;
        else if (ch === '(') pDepth++;
        else if (ch === ')') pDepth--;
        else if (ch === '{') bDepth++;
        else if (ch === '}') bDepth--;
        else if (ch === ';' && pDepth === 0 && bDepth === 0) {
          chainEnd = i;
          break;
        } else if (ch === '\n' && content[i + 1] === '\n' && pDepth === 0 && bDepth === 0) {
          chainEnd = i;
          break;
        }
        lastChar = ch;
      }
      const window = content.slice(m.index, chainEnd);
      if (/\.catch\s*\(|\.finally\s*\(/.test(window)) return;
      const ln = content.slice(0, m.index).split('\n').length;
      findings.push({
        id: `cq-then-no-catch-${file.path}-${m.index}`,
        probe: 'Code Quality',
        title: 'Promise .then() with no .catch() — unhandled rejection on error',
        severity: 'low',
        category: 'Misconfiguration',
        cwe: 'CWE-755',
        file: file.path,
        line: ln,
        evidence: window.slice(0, 80),
        remediation:
          'Add a .catch() handler, or prefer async/await with a try/catch wrapper. Unhandled promise rejections terminate Node processes in newer versions and leave a confusing console error in browsers.',
      });
    });

    // --- async function with await but no try/catch wrapping (heuristic — top-level await only)
    // Find each `async (...) =>` or `async function ...` body; check whether it contains `await`
    // but no `try {` before the await. Balanced brace scan SKIPS string and regex literals so a
    // `const x = "}"` or `/\}/` inside the body doesn't terminate parsing early (adversarial finding).
    const asyncBodies = [
      ...content.matchAll(/async\s+(?:function\s+\w+\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{/g),
    ];
    asyncBodies.forEach((m) => {
      let depth = 1;
      let i = m.index + m[0].length;
      let inSingle = false,
        inDouble = false,
        inBack = false,
        inLineComment = false,
        inBlockComment = false;
      let prev = '';
      while (i < content.length && depth > 0) {
        const ch = content[i];
        const next = content[i + 1];
        if (inLineComment) {
          if (ch === '\n') inLineComment = false;
          i++;
          prev = ch;
          continue;
        }
        if (inBlockComment) {
          if (ch === '*' && next === '/') {
            inBlockComment = false;
            i++;
          }
          i++;
          prev = ch;
          continue;
        }
        if (inSingle) {
          if (ch === "'" && prev !== '\\') inSingle = false;
          i++;
          prev = ch;
          continue;
        }
        if (inDouble) {
          if (ch === '"' && prev !== '\\') inDouble = false;
          i++;
          prev = ch;
          continue;
        }
        if (inBack) {
          if (ch === '`' && prev !== '\\') inBack = false;
          i++;
          prev = ch;
          continue;
        }
        if (ch === '/' && next === '/') {
          inLineComment = true;
          i += 2;
          prev = next;
          continue;
        }
        if (ch === '/' && next === '*') {
          inBlockComment = true;
          i += 2;
          prev = next;
          continue;
        }
        if (ch === "'") inSingle = true;
        else if (ch === '"') inDouble = true;
        else if (ch === '`') inBack = true;
        else if (ch === '{') depth++;
        else if (ch === '}') depth--;
        i++;
        prev = ch;
      }
      const body = content.slice(m.index + m[0].length, i - 1);
      if (/\bawait\b/.test(body) && !/\btry\s*\{/.test(body)) {
        const ln = content.slice(0, m.index).split('\n').length;
        findings.push({
          id: `cq-async-no-try-${file.path}-${m.index}`,
          probe: 'Code Quality',
          title: 'async function uses await with no try/catch in body',
          severity: 'low',
          category: 'Misconfiguration',
          cwe: 'CWE-755',
          file: file.path,
          line: ln,
          evidence: m[0].slice(0, 120),
          remediation:
            'Wrap your awaits in try/catch and decide whether to surface errors to the UI, log them, or rethrow with context. A naked await that rejects becomes an unhandled rejection in the browser console and the calling code gets a Promise<rejected> instead of a value.',
        });
      }
    });
  });
  return findings;
}

// --- Architecture classifier + per-type best-practice teaching ---
// Heuristic classifier; emits one info finding with the detected type + signals so the user can
// verify the classification was reasonable, then emits low/medium findings for type-specific
// anti-patterns. Each finding includes extended teaching ("why this matters") so the audit doubles
// as a learning tool, not just a checklist.
export function classifyProject(files) {
  const has = (re) => files.some((f) => re.test(f.path));
  const fileCount = files.length;
  const signals = [];

  let pkg = null;
  const pkgFile = files.find(
    (f) => /(^|\/)package\.json$/.test(f.path) && !/node_modules/.test(f.path)
  );
  if (pkgFile) {
    try {
      pkg = JSON.parse(pkgFile.content);
    } catch {}
  }
  const deps = pkg ? { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) } : {};

  const subPackages = files.filter((f) =>
    /(^|\/)(packages|services|apps)\/[^/]+\/package\.json$/.test(f.path)
  );
  // Require ≥2 sub-packages to qualify as a monorepo. A single package under packages/
  // is just a folder convention (adversarial finding).
  const monorepoDirs = subPackages.length >= 2;
  if (monorepoDirs)
    signals.push(`${subPackages.length} package.json files under packages/ services/ or apps/`);
  // Library detection: Vite build.lib config, package.json#main + exports without an index.html.
  const viteConfig = files.find((f) => /(^|\/)vite\.config\.[jt]s$/.test(f.path));
  const hasViteLibMode =
    viteConfig && /build\s*:\s*\{[\s\S]*?lib\s*:/.test(viteConfig.content || '');
  const hasStorybook = files.some((f) => /(^|\/)\.storybook\//.test(f.path));
  const hasPkgExports =
    pkg && (pkg.exports || pkg.main) && !files.some((f) => /(^|\/)index\.html$/.test(f.path));
  if (hasViteLibMode) signals.push('vite.config has build.lib');
  if (hasStorybook) signals.push('.storybook directory present');
  if (hasPkgExports) signals.push('package.json#exports/main set, no index.html');

  const hasReactNative = !!deps['react-native'] || !!deps.expo;
  if (hasReactNative) signals.push('react-native or expo dependency');
  // Tauri and Electron get separate labels — different stacks, different security teaching.
  const hasTauri = files.some((f) => /(^|\/)src-tauri\//.test(f.path)) || !!deps['@tauri-apps/api'];
  const hasElectron = !!deps.electron;
  if (hasTauri) signals.push('Tauri shell (src-tauri/)');
  if (hasElectron) signals.push('Electron main process dependency');
  const hasAstro = !!deps.astro || has(/\.astro$/);
  // Inspect astro.config for output mode — defaults to 'static' but server/hybrid modes are SSR.
  const astroConfig = files.find((f) => /(^|\/)astro\.config\.(js|mjs|ts)$/.test(f.path));
  const astroOutput = astroConfig
    ? (astroConfig.content.match(/output\s*:\s*['"](\w+)['"]/) || [])[1]
    : null;
  if (astroOutput) signals.push(`astro output: ${astroOutput}`);
  const hasNextExport = pkg && /['"]output['"]\s*:\s*['"]export['"]/.test(pkgFile?.content || '');
  const hasNext = !!deps.next;
  const hasExpress = !!deps.express || !!deps.fastify || !!deps.koa;
  if (hasExpress) signals.push('express/fastify/koa server dependency');
  const hasReact = !!deps.react;
  const hasVue = !!deps.vue;
  const hasSvelte = !!deps.svelte;
  const hasInk = !!deps.ink; // React for terminals → CLI, not SPA (adversarial finding)
  if (hasInk) signals.push('ink dependency (React for terminals)');
  const hasNotebook = has(/\.ipynb$/);
  const hasBin = !!(pkg && pkg.bin);
  const hasHtml = has(/\.html?$/);
  // Python project detection (adversarial finding: ipynb-with-py-files was falling through to unknown)
  const hasPyproject = files.some((f) => /(^|\/)pyproject\.toml$/.test(f.path));
  const hasRequirements = files.some((f) => /(^|\/)requirements(\-\w+)?\.txt$/.test(f.path));
  const hasSetupPy = files.some((f) => /(^|\/)setup\.(py|cfg)$/.test(f.path));
  const isPython = (hasPyproject || hasRequirements || hasSetupPy) && !pkg;
  if (isPython) signals.push('pyproject.toml / requirements.txt / setup.py detected');
  const sourceFiles = files.filter(
    (f) => /\.[jt]sx?$/.test(f.path) && !/node_modules|dist|\.test\.|\.spec\.|\/test\//.test(f.path)
  );
  const largestSourceLines = Math.max(
    0,
    ...sourceFiles.map((f) => (f.content || '').split('\n').length)
  );
  const totalSrcLines = sourceFiles.reduce((a, f) => a + (f.content || '').split('\n').length, 0);

  let type, label, summary;
  if (isPython) {
    type = 'python';
    label = 'Python Project';
    summary = `Python project detected (${hasPyproject ? 'pyproject.toml' : hasSetupPy ? 'setup.py' : 'requirements.txt'}). Probes targeting Python source patterns will run; JS-specific probes are skipped.`;
  } else if (hasNotebook && files.filter((f) => /\.ipynb$/.test(f.path)).length >= 2) {
    type = 'notebook';
    label = 'Notebook / Data Science';
    summary = '.ipynb files dominate. Treat as a notebook codebase.';
  } else if (monorepoDirs) {
    // Distinguish a plain monorepo from monorepo+SSR.
    if (hasNext) {
      type = 'monorepo-ssr';
      label = 'Monorepo with Next.js (SSR + multiple packages)';
      summary = `${subPackages.length} sub-packages + Next.js dependency — monorepo serving an SSR app.`;
    } else {
      type = 'monorepo';
      label = 'Microservices monorepo';
      summary = `${subPackages.length} package.json files under packages/ services/ apps/.`;
    }
  } else if (hasReactNative) {
    type = 'mobile';
    label = 'Mobile (React Native / Expo)';
    summary = 'react-native or expo manifest detected.';
  } else if (hasTauri) {
    type = 'desktop-tauri';
    label = 'Desktop (Tauri)';
    summary =
      'src-tauri/ present — Rust-backed desktop shell with a webview UI. Note: security model differs from Electron (no Node integration).';
  } else if (hasElectron) {
    type = 'desktop-electron';
    label = 'Desktop (Electron)';
    summary =
      'electron dependency — Node-backed desktop shell. Watch for nodeIntegration and contextIsolation footguns.';
  } else if (hasAstro) {
    if (astroOutput === 'server' || astroOutput === 'hybrid') {
      type = 'ssr-astro';
      label = `SSR (Astro, output: ${astroOutput})`;
      summary = `Astro framework with output: "${astroOutput}" — renders some routes on the server at request time.`;
    } else {
      type = 'ssg';
      label = 'Static Site Generator (Astro)';
      summary = 'Astro framework, static output (default or explicit). Pre-rendered HTML.';
    }
  } else if (hasNextExport) {
    type = 'ssg';
    label = 'Static Site Generator (Next export)';
    summary = 'Next.js with output: "export" — pre-rendered static output.';
  } else if (hasNext) {
    type = 'ssr';
    label = 'Server-Side Rendered (Next.js)';
    summary = 'Next.js without static export — render at request time on the server.';
  } else if (hasInk && hasBin) {
    type = 'cli-ink';
    label = 'CLI Tool (React-rendered terminal UI via Ink)';
    summary =
      'package.json has a bin entry AND react+ink — a CLI using React-for-terminals, not an SPA.';
  } else if (hasBin && !hasReact && !hasVue && !hasSvelte) {
    type = 'cli';
    label = 'CLI Tool';
    summary = 'package.json has a bin entry and no UI framework dependency.';
  } else if (hasExpress && !hasReact && !hasVue && !hasSvelte) {
    type = 'backend-api';
    label = 'Backend API';
    summary = 'Express/Fastify/Koa with no frontend framework.';
  } else if (hasViteLibMode || hasStorybook || hasPkgExports) {
    type = 'library';
    label = 'Component / Utility Library';
    summary = hasViteLibMode
      ? 'Vite library mode build.'
      : hasStorybook
        ? 'Storybook config present — library shipped with isolated component previews.'
        : 'package.json declares exports/main and no index.html — meant to be consumed, not deployed.';
  } else if (hasReact || hasVue || hasSvelte) {
    // SPA — distinguish monolith from modular
    if (largestSourceLines >= 1500 && largestSourceLines / Math.max(totalSrcLines, 1) > 0.4) {
      type = 'monolithic-spa';
      label = 'Monolithic SPA';
      summary = `${hasReact ? 'React' : hasVue ? 'Vue' : 'Svelte'} SPA with one file (${largestSourceLines} lines) holding ${Math.round((100 * largestSourceLines) / Math.max(totalSrcLines, 1))}% of the source.`;
    } else if (sourceFiles.length >= 6) {
      type = 'modular-spa';
      label = 'Modular SPA';
      summary = `${hasReact ? 'React' : hasVue ? 'Vue' : 'Svelte'} SPA, ${sourceFiles.length} source files, largest is ${largestSourceLines} lines.`;
    } else {
      type = 'small-spa';
      label = 'Small SPA';
      summary = `${hasReact ? 'React' : hasVue ? 'Vue' : 'Svelte'} SPA, ${sourceFiles.length} source file${sourceFiles.length === 1 ? '' : 's'}.`;
    }
  } else if (hasHtml && !pkg) {
    type = 'static-html';
    label = 'Static HTML / CSS';
    summary = '.html files, no package.json or build tool — plain static site.';
  } else if (hasHtml && pkg) {
    type = 'static-html-build';
    label = 'Static HTML with build tool';
    summary = '.html plus a build tool but no framework — landing-page / static-site-with-bundler.';
  } else {
    type = 'unknown';
    label = 'Unknown';
    summary = `Could not classify (${fileCount} files, ${sourceFiles.length} JS/TS source).`;
  }
  signals.unshift(`largest source file: ${largestSourceLines} lines`);
  signals.unshift(`source files: ${sourceFiles.length}`);
  return { type, label, summary, signals, largestSourceLines, sourceFileCount: sourceFiles.length };
}

export function probeArchitecture(files) {
  const findings = [];
  const klass = classifyProject(files);

  // Always emit a classification finding (info) so users see what the tool thinks they have.
  findings.push({
    id: `arch-classify-${klass.type}`,
    probe: 'Architecture',
    title: `Detected: ${klass.label}`,
    severity: 'info',
    category: 'Misconfiguration',
    cwe: 'INFO-architecture',
    file: 'project root',
    line: 1,
    evidence: `${klass.summary}\nSignals: ${klass.signals.join(' · ')}`,
    remediation: `This is informational — it tells you what architecture the audit thinks you have so the type-specific rules below make sense.

Why architecture matters:
• A bug in a 200-line module is a bad afternoon. A bug in a 4000-line module that does six things is a bad week.
• Code organization isn't a style preference; it's a leverage choice. Smaller, single-purpose modules are easier to test, easier to reason about, easier to delete, and easier for AI tools (and humans) to refactor without breaking unrelated functionality.
• "Microservices vs monolith" is a deployment-and-team question, not a code-organization question. A well-modularized monolith and a well-designed microservice mesh share the same principle: clear boundaries between unrelated concerns. Most teams should NOT adopt microservices for code-organization reasons — that's a tooling tax for something module structure already solves.

If the classification looks wrong (e.g., you got "Unknown" or a category that doesn't match), the signal list above shows what the heuristic saw. Architecture is judgment-driven; this is a starting point.`,
  });

  // Type-specific best-practice findings.
  if (klass.type === 'monolithic-spa') {
    findings.push({
      id: 'arch-monolith-split',
      probe: 'Architecture',
      title: `Single source file is ${klass.largestSourceLines} lines (consider splitting)`,
      severity: 'low',
      category: 'Misconfiguration',
      cwe: 'CWE-1041',
      file: 'src/ (root)',
      line: 1,
      evidence: `largest source file: ${klass.largestSourceLines} lines; ${klass.sourceFileCount} total source files`,
      remediation: `Why monolith-in-one-file fails:
• Diffs become huge: a 5-line behavior change reads as part of a 4000-line file in code review.
• Test isolation is impossible: a bug in module A re-runs every test in the file.
• Mental model overload: every reader has to load all responsibilities to understand any one.
• AI-assisted refactors get worse: Claude / Cursor / Copilot quality degrades on long files because more unrelated context competes for attention.

How to split:
• Identify natural seams — usually: one file per probe, one for formatters, one for history, one for theme, components in their own directory.
• Move bottom-up: leaves first (small helpers), then groups, last the main component.
• Keep the public import surface stable: re-export from the old file path during transition so callers don't need updates.

When NOT to split:
• Files under ~500 lines are usually fine in one file. Splitting prematurely costs more than it saves.
• Components that are genuinely tightly coupled (e.g., a wizard with 5 steps that all share state) may belong together.`,
    });
  }

  if (klass.type === 'static-html' || klass.type === 'static-html-build') {
    findings.push({
      id: 'arch-static-html-teach',
      probe: 'Architecture',
      title: 'Static HTML — minimum-viable hardening checklist',
      severity: 'info',
      category: 'Misconfiguration',
      cwe: 'INFO-architecture',
      file: 'index.html',
      line: 1,
      evidence: 'static HTML detected',
      remediation: `Best practices for a static HTML site:
• Every page has <meta name="viewport"> for mobile (WCAG 1.4.10).
• Every page has lang="en" on <html> (WCAG 3.1.1).
• Every page has a <title>, a <meta name="description">, and Open Graph + Twitter Card tags for social shares.
• Add a Content-Security-Policy via <meta http-equiv> or server header — disables inline scripts/handlers that XSS depends on.
• Minify CSS and HTML for production (Vite / esbuild handle this automatically).
• Add cache-busting filename hashes for CSS/JS so users get fresh assets on deploy.
• Defer-load non-critical JS with <script defer> or <script type="module">.

The HTML Hygiene, SEO Hygiene, and A11y Landmarks probes above check each of these.`,
    });
  }

  if (klass.type === 'monorepo') {
    findings.push({
      id: 'arch-monorepo-teach',
      probe: 'Architecture',
      title: 'Microservices monorepo — boundary discipline matters more than any other check',
      severity: 'info',
      category: 'Misconfiguration',
      cwe: 'INFO-architecture',
      file: 'project root',
      line: 1,
      evidence: 'multiple package.json found',
      remediation: `Best practices for monorepos:
• Each service has its own package.json with explicit "name" and "version". No "private: true" workspace inherits versioning from parent.
• Cross-service imports MUST go through the published package name, never relative paths into a sibling package. Enforce with eslint-plugin-import or workspace constraints.
• Each service has its own README.md, its own test suite, its own CI matrix entry.
• Shared types live in a dedicated package (e.g. packages/types) — not duplicated across services.
• Lockfile is at the root, not per-package; let your package manager (pnpm / yarn workspaces / npm workspaces) handle hoisting.
• Atomic refactors across services are the killer feature of a monorepo — use them, don't avoid them.

Anti-pattern: a monorepo where every service still ships independently with no shared code. That's just a folder with multiple repos jammed in it — you have the tooling overhead with none of the benefit.`,
    });
  }

  if (klass.type === 'modular-spa' || klass.type === 'small-spa') {
    findings.push({
      id: 'arch-modular-teach',
      probe: 'Architecture',
      title: 'Modular SPA — keep the discipline',
      severity: 'info',
      category: 'Misconfiguration',
      cwe: 'INFO-architecture',
      file: 'src/',
      line: 1,
      evidence: `${klass.sourceFileCount} source files, largest ${klass.largestSourceLines} lines`,
      remediation: `What a senior engineer watches for in a modular SPA:
• File size cap: aim for < 400 lines per file. Past 800 it's almost always doing two unrelated things.
• Import depth: ../../../foo is a smell. Use path aliases (vite.config: resolve.alias) or move the file closer.
• Barrel files (index.ts re-exporting a directory) are good for public surfaces, bad for internal ones — they tank tree-shaking.
• Components should be presentational by default. Business logic lives in plain functions in lib/ or hooks.
• Shared state goes in one place (Zustand / Redux / context) — not duplicated across components.

When in doubt, ask: if I deleted this file, how many other files would I need to touch? Less than 2 = clean. More than 5 = consider splitting.`,
    });
  }

  if (klass.type === 'ssr') {
    findings.push({
      id: 'arch-ssr-teach',
      probe: 'Architecture',
      title: 'SSR — server-only code separation is the failure mode',
      severity: 'info',
      category: 'Misconfiguration',
      cwe: 'INFO-architecture',
      file: 'project root',
      line: 1,
      evidence: 'Next.js without static export',
      remediation: `Best practices for SSR (Next.js / Remix / SvelteKit):
• Server-only modules MUST not leak into the client bundle. Use "server-only" import (Next.js) or the explicit /server/ directory convention.
• Database credentials, API keys, and PII helpers belong in server-only paths. The NEXT_PUBLIC_ probe above catches the easiest leak.
• Hydration boundaries are expensive — minimize them. Use Server Components by default; Client Components for islands.
• Streaming responses (React 18+) cut TTFB but require all data fetches to be promise-aware up front.
• Edge runtime has different APIs from Node — code that uses fs / crypto.randomBytes / etc. won't run there.`,
    });
  }

  return findings;
}

// --- Stable cross-scan finding ID ---
// The existing `id` field on each finding uses byte offsets, so adding a line above the
// vulnerability creates a new `id`. That makes suppression / "you've seen this before" impossible.
//
// stableId() returns a deterministic hash from {probe, file, title, ±3-line normalized context}.
// The context is whitespace-normalized so trivial reformats don't perturb the ID. The hash itself
// is a 32-bit FNV-1a → base36 (8 chars), fast in JS, collision rate is fine at this scale.

function fnv1a(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(36);
}

export function stableId(finding, fileContent) {
  const file = (finding.file || '').replace(/\\/g, '/');
  const lines = (fileContent || '').split('\n');
  const ln = finding.line || 0;
  const ctxStart = Math.max(0, ln - 4);
  const ctxEnd = Math.min(lines.length, ln + 3);
  const ctx = lines
    .slice(ctxStart, ctxEnd)
    .map((s) => s.replace(/\s+/g, ' ').trim())
    .filter(Boolean)
    .join('|');
  const key = `${finding.probe}|${file}|${finding.title}|${ctx}`;
  return fnv1a(key);
}

// Apply stableId to every finding. Pure helper — call from handleScan after probes run.
export function attachStableIds(findings, files) {
  const fileMap = new Map(files.map((f) => [f.path, f.content]));
  findings.forEach((f) => {
    f.stableId = stableId(f, fileMap.get(f.file));
  });
  return findings;
}

// --- Probe metadata: confidence + fixability ---
// Each probe declares two attributes the UI surfaces alongside severity:
//
//   confidence:
//     'high'      — deterministic pattern match. Almost no false positives in practice.
//     'medium'    — regex matches that need a glance of context to validate.
//     'heuristic' — path / structural inference; real but warrants manual review.
//
//   autofix:
//     'mechanical'    — a one-or-two-line drop-in patch fixes it cleanly.
//     'review-needed' — clear remediation path but requires reading the surrounding code.
//     'manual'        — architectural / scope-dependent; no canned fix.
//
// These aren't severity. A 'critical' + 'heuristic' finding still demands attention; the
// tag just tells the user "look at this twice before acting." A 'low' + 'mechanical' finding
// is the 30-second win that's worth doing before merge.
export const PROBE_META = {
  // Deterministic + mechanical: drop-in patches
  'Env File Hygiene': { confidence: 'high', autofix: 'mechanical' },
  'AI Rules Files': { confidence: 'high', autofix: 'mechanical' },
  'Trojan Source': { confidence: 'high', autofix: 'mechanical' },
  'Package Manager Hardening': { confidence: 'high', autofix: 'mechanical' },
  'Slopsquat / Typosquat': { confidence: 'high', autofix: 'mechanical' },

  // Deterministic + needs-review: clear fix but requires looking around
  'Secret Scanner': { confidence: 'high', autofix: 'review-needed' },
  'NEXT_PUBLIC_ Misuse': { confidence: 'high', autofix: 'review-needed' },
  'Compromised Packages': { confidence: 'high', autofix: 'review-needed' },

  // Pattern matches: regex + light context
  CORS: { confidence: 'medium', autofix: 'mechanical' },
  'Cookie Security': { confidence: 'medium', autofix: 'mechanical' },
  'HTML Hygiene': { confidence: 'medium', autofix: 'mechanical' },
  'A11y Landmarks': { confidence: 'medium', autofix: 'mechanical' },
  'SEO Hygiene': { confidence: 'medium', autofix: 'mechanical' },
  'GEO Hygiene': { confidence: 'medium', autofix: 'mechanical' },

  // Pattern matches that need real fix work
  'Supabase RLS': { confidence: 'medium', autofix: 'review-needed' },
  'Firebase Rules': { confidence: 'medium', autofix: 'review-needed' },
  'Auth Weakness': { confidence: 'medium', autofix: 'review-needed' },
  'Webhook Validation': { confidence: 'medium', autofix: 'review-needed' },
  'GitHub Actions': { confidence: 'medium', autofix: 'review-needed' },
  'Client Auth Storage': { confidence: 'medium', autofix: 'review-needed' },
  'SSRF / Open Redirect': { confidence: 'medium', autofix: 'review-needed' },
  'MCP Security': { confidence: 'medium', autofix: 'review-needed' },
  'URL Reputation': { confidence: 'medium', autofix: 'manual' },
  'AI Code Smells': { confidence: 'medium', autofix: 'review-needed' },

  // Heuristics that benefit from manual scrutiny
  'Admin Route Exposure': { confidence: 'heuristic', autofix: 'manual' },
  'API Route Auth': { confidence: 'heuristic', autofix: 'manual' },
  'Security Headers': { confidence: 'medium', autofix: 'review-needed' },
  'LLM Security': { confidence: 'heuristic', autofix: 'review-needed' },
  'Code Quality': { confidence: 'medium', autofix: 'manual' },

  // Architectural classification — informational, no autofix
  Architecture: { confidence: 'heuristic', autofix: 'manual' },

  // Package.json supply-chain hooks (catch-all)
  'Package.json': { confidence: 'medium', autofix: 'mechanical' },
  'Supply Chain': { confidence: 'medium', autofix: 'mechanical' },
  'Code Injection': { confidence: 'medium', autofix: 'review-needed' },
};

// Attach probe-level confidence and autofix metadata to each finding.
export function attachProbeMeta(findings) {
  findings.forEach((f) => {
    const meta = PROBE_META[f.probe];
    if (meta) {
      f.confidence = meta.confidence;
      f.autofix = meta.autofix;
    } else {
      // Default: treat as medium / manual when we haven't classified a probe yet.
      f.confidence = 'medium';
      f.autofix = 'manual';
    }
  });
  return findings;
}

// --- Suppression store (false-positive / won't-fix / accepted-risk) ---
// Stored in localStorage keyed by stableId so a re-scan after a fix or a reformat keeps
// the suppression attached. Three dispositions; "false-positive" is the strongest signal
// (the user is telling us the probe is wrong).

export const SUPPRESSION_KEY = 'audit-app:suppressions:v1';
export const SUPPRESSION_DISPOSITIONS = ['false-positive', 'wont-fix', 'accepted-risk'];

export function loadSuppressions() {
  try {
    if (typeof localStorage === 'undefined') return {};
    const raw = localStorage.getItem(SUPPRESSION_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return {};
    return parsed;
  } catch {
    return {};
  }
}

export function saveSuppressions(map) {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(SUPPRESSION_KEY, JSON.stringify(map));
      return true;
    }
  } catch {}
  return false;
}

export function suppressFinding(map, stableIdKey, disposition, note = '') {
  if (!stableIdKey) return map;
  if (!SUPPRESSION_DISPOSITIONS.includes(disposition)) return map;
  return { ...map, [stableIdKey]: { disposition, note, at: new Date().toISOString() } };
}

export function unsuppressFinding(map, stableIdKey) {
  if (!stableIdKey || !map[stableIdKey]) return map;
  const { [stableIdKey]: _gone, ...rest } = map;
  return rest;
}

// Returns { visible, suppressed } partition. visible[].suppression is undefined,
// suppressed[].suppression carries the disposition + note + timestamp.
export function partitionFindings(findings, suppressions) {
  const visible = [];
  const suppressed = [];
  findings.forEach((f) => {
    const s = f.stableId ? suppressions[f.stableId] : undefined;
    if (s) {
      suppressed.push({ ...f, suppression: s });
    } else {
      visible.push(f);
    }
  });
  return { visible, suppressed };
}

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
  { name: 'AI Code Smells', fn: probeAICodeSmells },
  { name: 'URL Reputation', fn: probeExternalURLs },
  { name: 'HTML Hygiene', fn: probeHTML },
  { name: 'SEO Hygiene', fn: probeSEOHygiene },
  { name: 'GEO Hygiene', fn: probeGEOHygiene },
  { name: 'A11y Landmarks', fn: probeA11yLandmarks },
  { name: 'Code Quality', fn: probeCodeQuality },
  { name: 'Package Manager Hardening', fn: probeNpmrcHygiene },
];

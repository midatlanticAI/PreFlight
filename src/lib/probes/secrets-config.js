// src/lib/probes/secrets-config.js
//
// Secrets, hardcoded credentials, and public-bundle env-var leaks.
//
// Extracted from the prior builtin.js monolith when it crossed the
// file-size HIGH threshold. Probe bodies are byte-identical to the
// originals; only the location moved. Public import surface is
// preserved by builtin.js, which is now a back-compat shim re-exporting
// every probe function from its new family file.

import {
  SECRET_PATTERNS,
  NEXT_PUBLIC_DANGER_NAMES,
  NEXT_PUBLIC_DANGER_VALUES,
} from '../threat-intel.js';
import {
  isTestFile,
  isScannerSelfSource,
  isEnvTemplateFile,
  isDocumentationMarkdownFile,
} from '../file-filter.js';
import {
  SECRET_VALUE_PLACEHOLDER_RE,
  isMatchInPlaceholderNamedAssignment,
  isMatchInsideComment,
  isPEMBodyPlaceholderOrHeaderOnly,
  isMatchInsideTemplateLiteral,
  maskCommentsForPath,
  redactValueInEvidence,
} from './_internal/masking.js';

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
    // Match against the language-aware comment-blind view, not raw content.
    // isMatchInsideComment below understands only JS `//` and `/* */`, so a
    // documented example in a Python/YAML/#-commented .env line fired as a
    // real credential — verified live, FP triage 2026-09-03. The mask is
    // length-preserving, so every index below still maps to real source.
    const matchView = maskCommentsForPath(file.path, file.content);
    // Firebase CLIENT config: Google's own docs state Firebase web/app API
    // keys are identifiers delivered to every client, not access-control
    // secrets — flutterfire emits firebase_options.dart to be committed.
    // Gate-1 2026-09-03: every Flutter+Firebase app fired critical on its
    // generated config. Teach key-restriction at low instead.
    const isFirebaseClientConfig =
      /firebase_options\.dart$/i.test(file.path) ||
      /firebaseapp\.com|FlutterFire/i.test(file.content);
    SECRET_PATTERNS.forEach((pat) => {
      const matches = [...matchView.matchAll(pat.regex)];
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
          // Gate-2 2026-09-03, calibrated against the earlier template
          // pins: a documentation template is multi-line, interpolates, or
          // nests the key in inner quotes (code-as-string:
          // `apiKey: 'sk-…'`). A PASTED key is the opposite on all three —
          // Authorization: `Bearer sk-proj-…` is single-line, bare, and
          // uninterpolated, and it was invisible stack-wide.
          const prevTick = file.content.lastIndexOf('`', idx);
          const nextTick = file.content.indexOf('`', idx + m[0].length);
          const span =
            prevTick >= 0 && nextTick > prevTick ? file.content.slice(prevTick, nextTick + 1) : '';
          const wrappedInInnerQuotes = /['"]/.test(file.content[idx - 1] || '');
          const docLike =
            span === '' || span.includes('${') || span.includes('\n') || wrappedInInnerQuotes;
          if (docLike) return;
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
        // postgres://postgres:postgres@localhost is the documented local-dev
        // idiom, not a breach — verified firing critical on a stock dev
        // .env, FP triage 2026-09-03. A loopback/compose-network host with a
        // stock default password teaches at low; the same URL with a
        // real-shaped password, or any remote host, stays critical.
        let devDefaultDbUrl = false;
        if (pat.name === 'Database Connection URL with Credentials') {
          const urlParts = m[0].match(/^[a-z+]+:\/\/([^:]+):([^@]+)@([^\s"'<>/:]+)/i);
          if (urlParts) {
            const [, dbUser, dbPass, dbHost] = urlParts;
            const localHost =
              /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal|db|database|postgres|mysql|mariadb|mongo|mongodb|redis)$/i.test(
                dbHost
              );
            const stockPass =
              dbPass === dbUser ||
              /^(?:postgres|mysql|mariadb|root|admin|password|example|secret|changeme|dev|devpassword|local|test)$/i.test(
                dbPass
              );
            devDefaultDbUrl = localHost && stockPass;
          }
        }
        // Scoped to the config-object member `apiKey:` on the MATCHED LINE —
        // a file-level sniff downgraded a Gemini key (GEMINI_API_KEY, a
        // billing-bearing server secret) to low just for sharing a file with
        // firebaseConfig (Gate-2 confirmed, 2026-09-03).
        const firebaseClientKey =
          isFirebaseClientConfig &&
          (pat.name === 'Google API Key' || pat.name === 'Generic Hardcoded Secret') &&
          /\bapiKey\s*[:=]/.test(line);
        // One key, one card: the Google pattern carries the Firebase
        // teaching; the Generic pattern rebadged to an identical twin card
        // on the same line (Gate-3 duplicate audit).
        if (firebaseClientKey && pat.name === 'Generic Hardcoded Secret') return;
        findings.push({
          id: `secret-${file.path}-${pat.name}-${idx}`,
          probe: 'Secret Scanner',
          title: devDefaultDbUrl
            ? 'Local development database URL with stock credentials'
            : firebaseClientKey
              ? 'Firebase client API key without stated restrictions'
              : `${pat.name} found in source`,
          severity: devDefaultDbUrl || firebaseClientKey ? 'low' : pat.severity,
          category: pat.category,
          cwe: pat.cwe,
          file: file.path,
          line: lineNum,
          evidence: line.replace(m[0], masked).trim().slice(0, 200),
          remediation: devDefaultDbUrl
            ? 'A stock local database URL is fine while the database only listens on your machine. Keep it out of the file anyway — reference it as ${DATABASE_URL} from an uncommitted .env — so the day this config reaches a real server, the real credentials do not ride along.'
            : firebaseClientKey
              ? 'A Firebase client API key is an identifier, not an access-control secret — it ships to every client by design, so committing it is normal. What protects you is restriction, not secrecy: in the Google Cloud console, restrict this key to your app identifiers and the Firebase APIs it needs, and enforce access with Security Rules, not the key.'
              : `Remove this credential from source immediately. Rotate it in the issuing service. Move to a server-only environment variable (no NEXT_PUBLIC_ prefix). If this file is committed to git, the secret is permanently in history — rotation is the only fix.`,
        });
      });
    });
  });
  return findings;
}

export function probeNextPublic(files) {
  const findings = [];
  files.forEach((file) => {
    // Depth round 3: widened file gate to all public-bundle frameworks.
    if (
      !/\.env|\.config\.|next\.config|vite\.config|svelte\.config|astro\.config|nuxt\.config|remix\.config|expo\.config|app\.config|gatsby-config/.test(
        file.path
      )
    )
      return;
    const lines = file.content.split('\n');
    lines.forEach((line, i) => {
      // Match any of the public-bundle prefixes (NEXT_PUBLIC_, VITE_, PUBLIC_,
      // REACT_APP_, EXPO_PUBLIC_, GATSBY_, NUXT_PUBLIC_, PARCEL_PUBLIC_).
      const m = line.match(
        /\b(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_|EXPO_PUBLIC_|GATSBY_|NUXT_PUBLIC_|PARCEL_PUBLIC_)([A-Z0-9_]+)\s*[=:]\s*["']?([^"'\n\r]+)["']?/
      );
      if (!m) return;
      const [, prefix, varName, value] = m;
      // Anon / publishable / public-key cookies are PUBLIC BY DESIGN. Don't
      // fire on Supabase ANON keys (eyJ-shaped) just because the value pattern
      // matches a JWT shape.
      if (/ANON|PUBLISHABLE|PUBLIC_KEY|CLIENT_ID/i.test(varName)) return;
      // Two more public-by-design conventions, verified firing critical on
      // an intentionally-public Mapbox token, FP triage 2026-09-03: site
      // keys (Turnstile/reCAPTCHA SITE_KEY — the secret half is named
      // SECRET_KEY), and values with the pk. / pk_ publishable prefix
      // (Mapbox pk., Stripe pk_ — their secret halves are sk./sk_).
      // SITE must be its own segment: the unanchored form treated
      // NEXT_PUBLIC_WEBSITE_KEY / WEBSITE_TOKEN as captcha site keys and
      // suppressed a real bundle-inlined secret (Gate-1 confirmed).
      if (/(?:^|_)SITE_?(?:KEY|TOKEN)$/i.test(varName)) return;
      if (/^pk[._]/.test(value.trim())) return;
      const dangerName = NEXT_PUBLIC_DANGER_NAMES.test(varName);
      const dangerValue = NEXT_PUBLIC_DANGER_VALUES.test(value.trim());
      if (dangerName || dangerValue) {
        findings.push({
          id: `publicenv-${file.path}-${i}`,
          probe: 'NEXT_PUBLIC_ Misuse',
          title: `Server secret exposed via ${prefix}${varName}`,
          severity: 'critical',
          category: 'Data Breach',
          cwe: 'CWE-200',
          file: file.path,
          line: i + 1,
          evidence: redactValueInEvidence(line.trim(), value.trim()).slice(0, 200),
          remediation: `${prefix} variables are inlined into the client bundle. This secret is visible to every visitor. Remove the public prefix and access only from server-side code (Server Components, API routes, route handlers, server actions). Rotate the credential since it has been public.`,
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

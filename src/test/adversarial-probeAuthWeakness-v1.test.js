// Adversarial RECALL test suite for probeAuthWeakness.
//
// Each test constructs a real-shape auth-weakness fixture and asserts that
// probeAuthWeakness produces at least one finding. Where the probe surface
// allows it, we also check that the finding's category / cwe / id is auth-
// related (CWE-287, CWE-256, CWE-259, CWE-307, CWE-327, CWE-522, CWE-798,
// CWE-916, OWASP A02, OWASP A07). When the probe's surface for a category
// is uncertain, the test asserts only findings.length > 0 and flags the
// ambiguity inline.
//
// AMBIGUITIES FLAGGED:
//   - The learn pattern auth-weakness.md describes four specific shapes
//     PreFlight scans for (JWT alg:'none', one-arg jwt.verify, eval on
//     user input, dangerouslySetInnerHTML). The user-prompted categories
//     here are a superset of those four. Some categories below (e.g.
//     "session token in URL", "missing auth check before sensitive op",
//     "missing rate-limit on login") may be handled by a sibling probe
//     rather than probeAuthWeakness itself. Per the brief these tests
//     still call probeAuthWeakness and assert it detects the shape; if
//     the probe doesn't yet cover the shape, the test will record a
//     real recall miss (which is the point of an adversarial suite).
//   - The brief states each Finding has { id, probe, title, severity,
//     category, cwe, ... }. We assert on `category` or `cwe` only when
//     a finding exists; we never index into findings[0] without first
//     asserting length > 0.

import { describe, test, expect } from 'vitest';
import { probeAuthWeakness } from '../lib/probes.js';

// Tiny helper. Returns the findings array for a single fixture file.
function run(path, content) {
  return probeAuthWeakness([{ path, content }]);
}

// Tiny helper. True if any finding's category/cwe/id/title mentions auth-
// adjacent terms. Used as a soft assertion when the exact taxonomy isn't
// guaranteed by the brief.
function looksAuthShaped(findings) {
  if (!findings || findings.length === 0) return false;
  const hay = JSON.stringify(findings).toLowerCase();
  return (
    hay.includes('auth') ||
    hay.includes('cwe-287') ||
    hay.includes('cwe-256') ||
    hay.includes('cwe-259') ||
    hay.includes('cwe-307') ||
    hay.includes('cwe-327') ||
    hay.includes('cwe-522') ||
    hay.includes('cwe-798') ||
    hay.includes('cwe-916') ||
    hay.includes('jwt') ||
    hay.includes('password') ||
    hay.includes('credential') ||
    hay.includes('secret') ||
    hay.includes('login') ||
    hay.includes('session') ||
    hay.includes('a07') ||
    hay.includes('a02')
  );
}

// ---------------------------------------------------------------------------
// CATEGORY 1 — Hardcoded credentials in source. (Weighted: 6 tests.)
// ---------------------------------------------------------------------------

describe('Category 1: Hardcoded credentials in source', () => {
  test('JS const PASSWORD literal', () => {
    const findings = run(
      'src/server/config.js',
      `const PASSWORD = 'admin123';\nexport function connect() { return db.auth('admin', PASSWORD); }\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('JS const API_PASSWORD literal with longer secret', () => {
    const findings = run(
      'src/server/secrets.js',
      `const API_PASSWORD = 'S3cretP@ssw0rd!2024';\nmodule.exports = { API_PASSWORD };\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('JS auth object literal { user, pass }', () => {
    const findings = run(
      'src/server/mailer.js',
      `const transport = nodemailer.createTransport({\n  host: 'smtp.example.com',\n  auth: { user: 'admin', pass: 'sup3rsecret' }\n});\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('TS hardcoded credentials in interface impl', () => {
    const findings = run(
      'src/server/db.ts',
      `export const dbConfig: DbConfig = {\n  host: 'prod-db.internal',\n  username: 'root',\n  password: 'TheRealProdPasswordOhNo'\n};\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('Basic auth string encoded into Authorization header', () => {
    const findings = run(
      'src/client/api.js',
      `const headers = {\n  Authorization: 'Basic ' + Buffer.from('admin:hunter2').toString('base64')\n};\nfetch('/api/admin', { headers });\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('Literal base64 Basic auth header', () => {
    // 'YWRtaW46aHVudGVyMg==' decodes to 'admin:hunter2'
    const findings = run(
      'src/client/legacy.js',
      `const AUTH = 'Basic YWRtaW46aHVudGVyMg==';\nfetch('/api/me', { headers: { Authorization: AUTH } });\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('YAML hardcoded credentials block', () => {
    const findings = run(
      'config/database.yml',
      `production:\n  adapter: postgresql\n  host: db.prod.internal\n  username: app_user\n  password: hunter2hunter2\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('JSON config with embedded password', () => {
    const findings = run(
      'config/db.json',
      `{\n  "host": "db.prod.internal",\n  "user": "app_user",\n  "password": "ThisShouldNotBeHere1234"\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('env-style .env file with literal password', () => {
    const findings = run(
      '.env.production',
      `DB_HOST=prod-db.internal\nDB_USER=root\nDB_PASSWORD=ProdRootPasswordOhNo!2024\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// CATEGORY 2 — Plaintext password comparison. (Weighted: 6 tests.)
// ---------------------------------------------------------------------------

describe('Category 2: Plaintext password comparison', () => {
  test('triple-equals against stored password field', () => {
    const findings = run(
      'src/server/login.js',
      `function authenticate(req, user) {\n  if (req.body.password === user.password) {\n    return issueToken(user);\n  }\n  return null;\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('double-equals against stored password field', () => {
    const findings = run(
      'src/server/loose-login.js',
      `function login(req, user) {\n  if (req.body.password == user.password) {\n    req.session.user = user;\n  }\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('triple-equals against storedPassword local var', () => {
    const findings = run(
      'src/server/auth-handler.js',
      `async function handler(req, res) {\n  const storedPassword = await db.getPassword(req.body.email);\n  if (req.body.password === storedPassword) {\n    res.json({ ok: true });\n  }\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('comparison via .password on record', () => {
    const findings = run(
      'src/server/users.js',
      `app.post('/login', async (req, res) => {\n  const u = await User.findOne({ email: req.body.email });\n  if (u && req.body.password === u.password) res.json(u);\n  else res.status(401).send('nope');\n});\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('TypeScript plaintext comparison with type annotations', () => {
    const findings = run(
      'src/server/auth.ts',
      `export async function verifyLogin(input: LoginInput, record: UserRecord): Promise<boolean> {\n  return input.password === record.password;\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('plain == in an arrow function', () => {
    const findings = run(
      'src/server/quick-login.js',
      `const check = (a, b) => a.password == b.password;\nexport default check;\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('comparison embedded inside ternary', () => {
    const findings = run(
      'src/server/ternary-login.js',
      `function loginResult(req, user) {\n  return req.body.password === user.password ? 'ok' : 'fail';\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// CATEGORY 3 — Missing rate-limiting on login endpoints. (3 tests.)
// Note: This may be a sibling-probe concern. The brief tells us to assert on
// probeAuthWeakness anyway and surface real recall misses.
// ---------------------------------------------------------------------------

describe('Category 3: Missing rate-limit on login endpoints', () => {
  test('Express login POST with no rate limiter', () => {
    const findings = run(
      'src/server/routes/login.js',
      `import express from 'express';\nconst router = express.Router();\nrouter.post('/login', async (req, res) => {\n  const user = await db.findUser(req.body.email);\n  if (user && req.body.password === user.password) {\n    res.json({ token: signToken(user) });\n  } else {\n    res.status(401).json({ error: 'invalid' });\n  }\n});\nexport default router;\n`
    );
    // Plaintext compare also lives here, so a hit is expected even if rate-
    // limit detection isn't in this probe yet.
    expect(findings.length).toBeGreaterThan(0);
  });

  test('Next.js API route login handler with no limiter', () => {
    const findings = run(
      'pages/api/login.js',
      `export default async function handler(req, res) {\n  if (req.method !== 'POST') return res.status(405).end();\n  const { email, password } = req.body;\n  const user = await db.users.findByEmail(email);\n  if (user && user.password === password) {\n    return res.json({ ok: true });\n  }\n  return res.status(401).json({ error: 'bad creds' });\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('Fastify login route with no rate limit registered', () => {
    const findings = run(
      'src/server/routes/login.fastify.js',
      `export default async function (fastify) {\n  fastify.post('/login', async (req, reply) => {\n    const u = await fastify.db.users.findOne({ email: req.body.email });\n    if (!u) return reply.code(401).send();\n    if (req.body.password === u.password) return { token: 'TODO' };\n    return reply.code(401).send();\n  });\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// CATEGORY 4 — Insecure password storage. (Weighted: 6 tests.)
// ---------------------------------------------------------------------------

describe('Category 4: Insecure password storage', () => {
  test('md5 hashing of password on registration', () => {
    const findings = run(
      'src/server/register.js',
      `import crypto from 'crypto';\nfunction register(email, password) {\n  const hashed = crypto.createHash('md5').update(password).digest('hex');\n  return db.users.insert({ email, password: hashed });\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('sha1 hashing of password', () => {
    const findings = run(
      'src/server/legacy-register.js',
      `const crypto = require('crypto');\nexports.hashPassword = (pw) => crypto.createHash('sha1').update(pw).digest('hex');\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('sha256 (still unsuitable for passwords without KDF) of password', () => {
    const findings = run(
      'src/server/sha256-register.js',
      `import { createHash } from 'crypto';\nexport function storePassword(user, password) {\n  const digest = createHash('sha256').update(password).digest('hex');\n  return db.users.update(user.id, { password_hash: digest });\n}\n`
    );
    // Ambiguity: probe may or may not flag sha256 specifically. If it does
    // not, this is a real recall miss worth surfacing.
    expect(findings.length).toBeGreaterThan(0);
  });

  test('storing plain password directly in DB', () => {
    const findings = run(
      'src/server/plain-store.js',
      `app.post('/signup', async (req, res) => {\n  await db.users.insert({ email: req.body.email, password: req.body.password });\n  res.json({ ok: true });\n});\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('md5 hash via require(crypto) in Node CommonJS', () => {
    const findings = run(
      'src/server/cjs-md5.js',
      `const crypto = require('crypto');\nfunction hashPw(pw) {\n  return crypto.createHash('md5').update(pw, 'utf8').digest('hex');\n}\nmodule.exports = hashPw;\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('sha1 with salt concatenation (still broken)', () => {
    const findings = run(
      'src/server/salted-sha1.js',
      `import { createHash } from 'crypto';\nexport function legacyHash(pw, salt) {\n  return createHash('sha1').update(salt + pw).digest('hex');\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('storing plaintext password in user record passed to ORM', () => {
    const findings = run(
      'src/server/orm-plain.js',
      `export async function createUser(input) {\n  return prisma.user.create({ data: { email: input.email, password: input.password } });\n}\n`
    );
    // Ambiguity: probe may need explicit "plaintext" signal beyond the
    // .password key. If no hit, real recall miss.
    expect(findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// CATEGORY 5 — Weak/missing JWT signing. (Weighted: 8 tests, primary surface.)
// ---------------------------------------------------------------------------

describe('Category 5: Weak/missing JWT signing', () => {
  test("jwt.sign with literal short secret 'secret'", () => {
    const findings = run(
      'src/server/issue-token.js',
      `import jwt from 'jsonwebtoken';\nexport function issue(user) {\n  return jwt.sign({ sub: user.id, role: user.role }, 'secret');\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(looksAuthShaped(findings)).toBe(true);
  });

  test("jwt.sign with hardcoded short literal 'mysecret'", () => {
    const findings = run(
      'src/server/issue-mysecret.js',
      `const jwt = require('jsonwebtoken');\nfunction tokenFor(u) {\n  return jwt.sign({ sub: u.id }, 'mysecret');\n}\nmodule.exports = tokenFor;\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test("jwt.sign with algorithm: 'none'", () => {
    const findings = run(
      'src/server/alg-none.js',
      `import jwt from 'jsonwebtoken';\nconst t = jwt.sign({ sub: 'admin', role: 'admin' }, null, { algorithm: 'none' });\nexport default t;\n`
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(looksAuthShaped(findings)).toBe(true);
  });

  test('jwt.sign with algorithm: "none" double-quoted', () => {
    const findings = run(
      'src/server/alg-none-dq.js',
      `import jwt from 'jsonwebtoken';\nexport const t = jwt.sign({ sub: 'admin' }, null, { algorithm: "none" });\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('jwt.verify(token) with no secret argument (one-arg verify)', () => {
    const findings = run(
      'src/server/verify-one-arg.js',
      `import jwt from 'jsonwebtoken';\nexport function check(token) {\n  const decoded = jwt.verify(token);\n  return decoded;\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
    expect(looksAuthShaped(findings)).toBe(true);
  });

  test('jwt.verify with empty-string secret', () => {
    const findings = run(
      'src/server/verify-empty-secret.js',
      `import jwt from 'jsonwebtoken';\nexport function check(token) {\n  return jwt.verify(token, '');\n}\n`
    );
    // Ambiguity: detection of empty-string secret depends on probe's
    // string-length heuristic.
    expect(findings.length).toBeGreaterThan(0);
  });

  test('jwt.sign with no expiresIn option', () => {
    const findings = run(
      'src/server/no-expiry.js',
      `import jwt from 'jsonwebtoken';\nexport function forever(u) {\n  return jwt.sign({ sub: u.id }, process.env.JWT_SECRET);\n}\n`
    );
    // Ambiguity: probe may not yet flag missing expiry on its own.
    expect(findings.length).toBeGreaterThan(0);
  });

  test('jwt.sign with literal secret AND no expiry combined', () => {
    const findings = run(
      'src/server/combo-weak-jwt.js',
      `import jwt from 'jsonwebtoken';\nexport function issue(u) {\n  return jwt.sign({ sub: u.id, role: u.role }, 'jwt-secret-key');\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('jose SignJWT with algorithm none', () => {
    const findings = run(
      'src/server/jose-none.js',
      `import { SignJWT } from 'jose';\nexport async function issue() {\n  return await new SignJWT({ sub: 'admin' })\n    .setProtectedHeader({ alg: 'none' })\n    .sign(new Uint8Array());\n}\n`
    );
    // Ambiguity: probe coverage may be jsonwebtoken-shaped. If jose is
    // out of scope this is a real recall miss.
    expect(findings.length).toBeGreaterThan(0);
  });

  test('jwt.verify with algorithms allowlist including none', () => {
    const findings = run(
      'src/server/verify-allow-none.js',
      `import jwt from 'jsonwebtoken';\nexport function check(token) {\n  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256', 'none'] });\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// CATEGORY 6 — Session token in URL. (3 tests.)
// ---------------------------------------------------------------------------

describe('Category 6: Session token in URL', () => {
  test('client fetches with ?token= in URL', () => {
    const findings = run(
      'src/client/fetch-token.js',
      `const token = localStorage.getItem('auth');\nfetch('/api/me?token=' + token).then(r => r.json());\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('window.location.href set with ?sessionId=', () => {
    const findings = run(
      'src/client/redirect-session.js',
      `function go(sid) {\n  window.location.href = '/dashboard?sessionId=' + sid;\n}\nexport default go;\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('React useEffect builds URL with ?token= template literal', () => {
    const findings = run(
      'src/client/useToken.jsx',
      `import { useEffect } from 'react';\nexport default function useMe(token) {\n  useEffect(() => {\n    fetch(\`/api/profile?token=\${token}\`).then(r => r.json());\n  }, [token]);\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// CATEGORY 7 — Default credentials. (3 tests.)
// ---------------------------------------------------------------------------

describe('Category 7: Default credentials', () => {
  test('admin/admin in source literal', () => {
    const findings = run(
      'src/server/seed.js',
      `export const SEED_ADMIN = { username: 'admin', password: 'admin' };\ndb.users.insert(SEED_ADMIN);\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('root/root default in connection string', () => {
    const findings = run(
      'src/server/db-defaults.js',
      `const CONN = 'mysql://root:root@localhost:3306/app';\nexport default CONN;\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('test/test123 baked into fixture used in prod path', () => {
    const findings = run(
      'src/server/bootstrap.js',
      `if (process.env.NODE_ENV !== 'production') {\n  await db.users.insert({ email: 'test@example.com', username: 'test', password: 'test123' });\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// CATEGORY 8 — Missing auth check before sensitive operation. (3 tests.)
// ---------------------------------------------------------------------------

describe('Category 8: Missing auth check before sensitive operation', () => {
  test('Express route writes to DB with no req.user check', () => {
    const findings = run(
      'src/server/routes/admin-delete.js',
      `import express from 'express';\nconst router = express.Router();\nrouter.delete('/users/:id', async (req, res) => {\n  await db.users.delete({ id: req.params.id });\n  res.json({ deleted: true });\n});\nexport default router;\n`
    );
    // Ambiguity: this shape is a sibling-probe concern (API Route Auth /
    // missing-authz). If probeAuthWeakness doesn't cover it, the recall
    // miss is informative.
    expect(findings.length).toBeGreaterThan(0);
  });

  test('Next.js API handler returns all users with no session check', () => {
    const findings = run(
      'pages/api/users/all.js',
      `export default async function handler(req, res) {\n  const users = await db.users.findAll();\n  return res.json({ users });\n}\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  test('Express PATCH handler updates account with no auth gate', () => {
    const findings = run(
      'src/server/routes/account.js',
      `import express from 'express';\nconst router = express.Router();\nrouter.patch('/account/:id', async (req, res) => {\n  await db.users.update({ id: req.params.id }, req.body);\n  res.json({ ok: true });\n});\nexport default router;\n`
    );
    expect(findings.length).toBeGreaterThan(0);
  });
});

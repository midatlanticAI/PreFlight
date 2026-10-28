// src/test/field-scan-precision-2026-10.test.js
//
// Pins from the 2026-10-28 field scan of a Cloudflare Workers + D1 service
// business app (PWA shell, Twilio voice Worker, admin API). Every negative
// below is a finding the scanner reported on working code, reproduced
// through the real PROBES registry before its fix; every positive pins the
// recall the fix must not cost.

import { describe, it, expect } from 'vitest';
import { PROBES } from '../lib/probes.js';
import { isTestFile, isServiceWorkerFile } from '../lib/file-filter.js';

const PROBE_BY_NAME = Object.fromEntries(PROBES.map((p) => [p.name, p.fn]));
const file = (path, content) => ({ path, content });
const run = (name, ...files) => PROBE_BY_NAME[name](files);
const titles = (res) => res.map((x) => `${x.severity}:${x.title}`).join(' | ');
const none = (res, re) =>
  expect(
    res.filter((x) => re.test(x.title)),
    titles(res)
  ).toHaveLength(0);
const some = (res, re) =>
  expect(
    res.some((x) => re.test(x.title)),
    titles(res)
  ).toBe(true);

const SW = `const CACHE = 'shell-v3';
self.addEventListener('install', (event) => { event.waitUntil(caches.open(CACHE).then((c) => c.addAll(['/']))); self.skipWaiting(); });
self.addEventListener('activate', (event) => { event.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  event.respondWith(fetch(req).then((res) => { caches.open(CACHE).then((c) => c.put(req, res.clone())); return res; }).catch(() => caches.match(req)));
});
`;

describe('test-file detection covers the ESM and CommonJS test extensions', () => {
  it('treats *.test.mjs / *.spec.cjs / *.test.mts as test files', () => {
    for (const p of [
      'admin/api/jobs.test.mjs',
      'lib/x.spec.cjs',
      'src/y.test.mts',
      'src/z.test.ts',
    ])
      expect(isTestFile(p), p).toBe(true);
    expect(isTestFile('admin/api/jobs.mjs')).toBe(false);
  });
  it('Database Patterns and Secret Scanner skip an .mjs test fixture', () => {
    const fixture = file(
      'admin/api/admin.test.mjs',
      `const env = () => ({ SESSION_SECRET: 'test-session-secret-value', ADMIN_PASSWORD: 'bootstrap-pw' });\nawait e.DB.prepare("UPDATE jobs SET status = 'paid'").run();\n`
    );
    none(run('Database Patterns', fixture), /no WHERE/);
    none(run('Secret Scanner', fixture), /Secret/);
  });
});

describe('Supabase RLS: the migration phase needs Postgres evidence', () => {
  const d1 = `CREATE TABLE tenants (\n  id TEXT PRIMARY KEY,\n  name TEXT NOT NULL,\n  created_at TEXT NOT NULL\n);\nCREATE TABLE users (\n  id TEXT PRIMARY KEY,\n  tenant_id TEXT NOT NULL REFERENCES tenants(id),\n  email TEXT NOT NULL\n);\n`;
  it('does NOT report a D1 / SQLite schema as missing RLS', () => {
    const res = run(
      'Supabase RLS',
      file('db/migrations/0001_init.sql', d1),
      file('wrangler.jsonc', `{ "d1_databases": [{ "binding": "DB", "database_name": "app" }] }`),
      file('package.json', `{ "dependencies": { "hono": "^4.0.0" } }`)
    );
    none(res, /ROW LEVEL SECURITY/);
  });
  it('does NOT report a schema that spells SQLite or MySQL', () => {
    none(
      run(
        'Supabase RLS',
        file('db/schema.sql', `CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);\n`)
      ),
      /ROW LEVEL SECURITY/
    );
    none(
      run(
        'Supabase RLS',
        file('db/schema.sql', `CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY) ENGINE=InnoDB;\n`)
      ),
      /ROW LEVEL SECURITY/
    );
  });
  it('still reports a Supabase migration, a Postgres-spelled schema, and a Supabase project', () => {
    some(
      run(
        'Supabase RLS',
        file('supabase/migrations/0001_init.sql', `create table orders (id int primary key);\n`)
      ),
      /orders.*ROW LEVEL SECURITY/
    );
    some(
      run(
        'Supabase RLS',
        file(
          'db/schema.sql',
          `create table profiles (id uuid default gen_random_uuid() primary key);\n`
        )
      ),
      /profiles.*ROW LEVEL SECURITY/
    );
    some(
      run(
        'Supabase RLS',
        file('db/schema.sql', `create table posts (id int primary key);\n`),
        file('package.json', `{ "dependencies": { "@supabase/supabase-js": "^2.0.0" } }`)
      ),
      /posts.*ROW LEVEL SECURITY/
    );
  });
});

describe('Auth Weakness: an env var NAME in the value position is a reference', () => {
  it('does NOT flag a provider table that names the setting holding the key', () => {
    const res = run(
      'Auth Weakness',
      file(
        'admin/api/routes/assistant.js',
        `export const PROVIDERS = {\n  anthropic: { label: 'Claude', secret: 'ANTHROPIC_API_KEY', defaultModel: 'claude-sonnet-5' },\n  openai: { label: 'OpenAI', secret: 'OPENAI_API_KEY', defaultModel: 'gpt-6' },\n};\nconst key = (env, p) => env[PROVIDERS[p].secret];\n`
      )
    );
    none(res, /Hardcoded password/);
  });
  it('still flags a literal credential under the same key', () => {
    some(
      run(
        'Auth Weakness',
        file('src/config.js', `export const smtp = { user: 'ops', password: 'Sup3r$ecret99' };\n`)
      ),
      /Hardcoded password in object literal/
    );
  });
  it('does NOT read a role list as default credentials', () => {
    none(
      run(
        'Auth Weakness',
        file(
          'scripts/qa/auth-http.mjs',
          `for (const role of ['tech', 'office', 'admin', 'owner']) {\n  await login(role);\n}\n`
        )
      ),
      /Default credentials/
    );
  });
});

describe('service workers are browser code, not routes or SSRF sinks', () => {
  it('isServiceWorkerFile reads the lifecycle, not the filename', () => {
    expect(isServiceWorkerFile('admin/public/sw.js', SW)).toBe(true);
    expect(isServiceWorkerFile('site/sw.js', `console.log('bundle')`)).toBe(false);
    expect(
      isServiceWorkerFile(
        'worker/index.js',
        `export default { async fetch(request, env) { return new Response('ok'); } };\n`
      )
    ).toBe(false);
    expect(isServiceWorkerFile('x.js', undefined)).toBe(false);
  });
  it('API Route Auth does NOT flag a PWA service worker under an admin path', () => {
    none(run('API Route Auth', file('admin/public/sw.js', SW)), /without auth/);
  });
  it('Taint Flow does NOT read event.request as a user-controlled URL', () => {
    none(run('Taint Flow', file('site/sw.js', SW)), /user-controlled URL/);
  });
  it('still flags an unauthenticated destructive Cloudflare Worker and a real SSRF', () => {
    some(
      run(
        'API Route Auth',
        file(
          'worker/index.js',
          `export default {\n  async fetch(request, env) {\n    if (request.method === 'DELETE') {\n      await env.DB.prepare('DELETE FROM jobs WHERE id = ?1').bind(1).run();\n    }\n    return new Response('ok');\n  },\n};\n`
        )
      ),
      /Destructive HTTP handler/
    );
    some(
      run(
        'Taint Flow',
        file(
          'server/proxy.js',
          `app.get('/proxy', async (req, res) => {\n  const target = req.query.url;\n  const r = await fetch(target);\n  res.send(await r.text());\n});\n`
        )
      ),
      /user-controlled URL/
    );
  });
});

describe('API Route Auth: a Twilio signature check is the auth', () => {
  it('does NOT flag a voice Worker that validates X-Twilio-Signature', () => {
    const res = run(
      'API Route Auth',
      file(
        'voice/index.js',
        `import { validateTwilioSignature } from './lib/twilio.js';\nexport default {\n  async fetch(request, env, ctx) {\n    const params = await readParams(request);\n    const valid = await validateTwilioSignature(request, params, env.TWILIO_AUTH_TOKEN, env.PUBLIC_URL);\n    if (!valid) return new Response('invalid signature', { status: 403 });\n    await env.DB.prepare('INSERT INTO calls (sid) VALUES (?1)').bind(params.CallSid).run();\n    return new Response('ok');\n  },\n};\n`
      )
    );
    none(res, /without auth/);
  });
});

describe('Weak Randomness: bare key is a list key', () => {
  it('does NOT flag a React row-key generator', () => {
    none(
      run(
        'Weak Randomness',
        file(
          'admin/public/views/invoices.js',
          `const key = () => Math.random().toString(36).slice(2);\nconst fromServer = (l) => ({ key: l.id || key(), kind: l.kind });\n`
        )
      ),
      /Math\.random/
    );
    none(
      run(
        'Weak Randomness',
        file(
          'src/List.jsx',
          `const rowKey = () => Math.random().toString(36).slice(2);\nreturn items.map((it) => <li key={rowKey()}>{it}</li>);\n`
        )
      ),
      /Math\.random/
    );
  });
  it('still flags apiKey / sessionKey / token generators', () => {
    for (const name of ['apiKey', 'sessionKey', 'signingKey', 'token'])
      some(
        run(
          'Weak Randomness',
          file('src/auth.js', `const ${name} = Math.random().toString(36).slice(2);\n`)
        ),
        /Math\.random/
      );
  });
});

describe('Trojan Source: a strip list is the defence', () => {
  it('does NOT flag a regex character class that lists the bidi controls beside escaped ranges', () => {
    none(
      run(
        'Trojan Source',
        file(
          'admin/api/lib/insights.js',
          `export const INVISIBLE = /[\\u0000-\\u001F\\u007F-\\u009F\u200B\u200E\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g;\n`
        )
      ),
      /Bidirectional/
    );
  });
  it('still flags a bidi control hidden in a string or a comment', () => {
    some(
      run(
        'Trojan Source',
        file('src/a.js', `const access = 'user\u202E // check if admin\u2066';\n`)
      ),
      /Bidirectional/
    );
    some(
      run('Trojan Source', file('src/b.js', `const re = /[a-z\u202E]/; // \u2066 reorder\n`)),
      /Bidirectional/
    );
  });
});

describe('Database Patterns: quoted values and sequenced migrations', () => {
  it('does NOT read a scoped UPDATE with a quoted value as all-rows', () => {
    none(
      run(
        'Database Patterns',
        file(
          'admin/api/routes/jobs.js',
          `export async function complete(env, id) {\n  await env.DB.prepare("UPDATE jobs SET status = 'completed' WHERE id = ?1").bind(id).run();\n  await env.DB.prepare('DELETE FROM job_notes WHERE job_id = ?1 AND kind = "draft"').bind(id).run();\n}\n`
        )
      ),
      /no WHERE/
    );
  });
  it('still flags a real all-rows write', () => {
    some(
      run(
        'Database Patterns',
        file(
          'server/admin.js',
          `export async function resetAll(db) {\n  await db.query("UPDATE users SET credits = 0, note = 'reset'");\n}\n`
        )
      ),
      /UPDATE with no WHERE/
    );
  });
  it('does NOT flag CREATE TABLE in a sequence-numbered migration', () => {
    for (const p of [
      'db/migrations/0001_init.sql',
      'migrations/20240901120000_users.sql',
      'db/migration/V3__orders.sql',
    ])
      none(
        run('Database Patterns', file(p, `CREATE TABLE t (id TEXT PRIMARY KEY);\n`)),
        /re-runnable/
      );
  });
  it('still flags a hand-applied migration file', () => {
    some(
      run(
        'Database Patterns',
        file('migrations/schema.sql', `CREATE TABLE t (id TEXT PRIMARY KEY);\n`)
      ),
      /re-runnable/
    );
  });
});

describe('Secret Scanner: the generic rule shares the credential-shape judgement', () => {
  it('does NOT flag an env var name in the value position', () => {
    none(
      run(
        'Secret Scanner',
        file(
          'admin/api/routes/assistant.js',
          `export const PROVIDERS = {\n  anthropic: { label: 'Claude', secret: 'ANTHROPIC_API_KEY', defaultModel: 'claude-sonnet-5' },\n};\n`
        )
      ),
      /Generic Hardcoded Secret/
    );
  });
  it('does NOT flag a fixture-marked word chain or a QA harness script', () => {
    none(
      run(
        'Secret Scanner',
        file(
          'docker/dev.env.js',
          `export const env = { SESSION_SECRET: 'qa-auth-isolated-secret' };\n`
        )
      ),
      /Generic Hardcoded Secret/
    );
    none(
      run(
        'Secret Scanner',
        file(
          'scripts/qa/auth-http.mjs',
          `const body = { email, role: 'owner', temp_password: 'TempPass12345!' };\n`
        )
      ),
      /Generic Hardcoded Secret/
    );
    expect(isTestFile('qa/operations.mjs')).toBe(true);
    expect(isTestFile('src/qa/retriever.js')).toBe(false);
  });
  it('still flags a committed signing secret', () => {
    some(
      run(
        'Secret Scanner',
        file('src/config.js', `export const SESSION_SECRET = 'kjh3k4jh5k3jh45kjh3k45';\n`)
      ),
      /Generic Hardcoded Secret/
    );
    some(
      run(
        'Secret Scanner',
        file('src/config.js', `const cfg = { secret: 'correct-horse-battery-staple' };\n`)
      ),
      /Generic Hardcoded Secret/
    );
  });
});

describe('Database Patterns: a column list built in an interpolation', () => {
  it('does NOT read the inner backtick as the end of the statement', () => {
    none(
      run(
        'Database Patterns',
        file(
          'admin/api/routes/customers.js',
          "const queueCustomer = (id, patch) => stmts.push(env.DB.prepare(`UPDATE customers SET ${Object.keys(patch).map((k, i) => `${k} = ?${i + 3}`).join(', ')} WHERE id = ?1 AND tenant_id = ?2`).bind(id, tenant, ...Object.values(patch)));\n"
        )
      ),
      /no WHERE/
    );
  });
  it('still flags the same shape with no WHERE', () => {
    some(
      run(
        'Database Patterns',
        file(
          'admin/api/routes/customers.js',
          "const resetAll = (patch) => stmts.push(env.DB.prepare(`UPDATE customers SET ${Object.keys(patch).map((k, i) => `${k} = ?${i + 1}`).join(', ')}`).bind(...Object.values(patch)));\n"
        )
      ),
      /UPDATE with no WHERE/
    );
  });
});

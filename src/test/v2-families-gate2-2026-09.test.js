// src/test/v2-families-gate2-2026-09.test.js
//
// Gate-2 pins for the v2 family build (2026-09-03): 32 confirmed findings
// from the promise-vs-delivery + over-correction attack, each independently
// reproduced by a second contextless checker before its fix. C1-C12 pin
// recall that Gate-1's precision fixes had silently cost; C13-C32 pin
// delivery of what each family's Learn page promises.

import { describe, it, expect } from 'vitest';
import { PROBES } from '../lib/probes.js';

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
const sev = (res, re) => res.find((x) => re.test(x.title))?.severity;

describe('Gate-2 C1/C6/C7: opaque-cleanup deference reads only real cleanups', () => {
  it('C1: a return inside a nested helper does not vouch for an effect with no cleanup', () => {
    const res = run(
      'React Hygiene',
      file(
        'src/components/StatusPoller.jsx',
        `import { useEffect } from 'react';\nexport function StatusPoller({ handler, fetchStatus }) {\n  useEffect(() => {\n    window.addEventListener('keydown', handler);\n    function poll() {\n      return fetchStatus();\n    }\n    const t = setInterval(poll, 5000);\n  }, [handler, fetchStatus]);\n  return null;\n}\n`
      )
    );
    some(res, /listener it never removes/);
    some(res, /timer it never clears/);
  });
  it('C6: return timerId (a value React rejects) does not vouch for two leaks', () => {
    const res = run(
      'React Hygiene',
      file(
        'src/components/SplashGate.jsx',
        `import { useEffect } from 'react';\nexport function SplashGate({ handleResize, dismiss }) {\n  useEffect(() => {\n    window.addEventListener('resize', handleResize);\n    const timerId = setTimeout(dismiss, 3000);\n    return timerId;\n  }, [handleResize, dismiss]);\n  return null;\n}\n`
      )
    );
    some(res, /listener it never removes/);
    some(res, /timer it never clears/);
  });
  it('C7: a concise arrow returning addEventListener (undefined) is not a cleanup', () => {
    some(
      run(
        'React Hygiene',
        file(
          'src/components/ScrollSpy.jsx',
          `import { useEffect } from 'react';\nexport function ScrollSpy({ onScroll }) {\n  useEffect(() => window.addEventListener('scroll', onScroll), [onScroll]);\n  return null;\n}\n`
        )
      ),
      /listener it never removes/
    );
  });
});

describe('Gate-2 C5/C19: cancel vocabulary is word-bounded and string-blind', () => {
  it('data vocabulary (lastActive, status=active in a URL) does not vouch for an uncancellable fetch', () => {
    const res = run(
      'React Hygiene',
      file(
        'src/components/PresenceBadge.jsx',
        `import { useEffect, useState } from 'react';\nexport function PresenceBadge({ userId }) {\n  const [presence, setPresence] = useState(null);\n  useEffect(() => {\n    async function load() {\n      const res = await fetch('/api/users/' + userId + '/presence?status=active');\n      const data = await res.json();\n      setPresence({ online: data.online, lastSeen: data.lastActive });\n    }\n    load();\n  }, [userId]);\n  return presence ? <b>online</b> : null;\n}\n`
      )
    );
    some(res, /without cancellation/);
  });
});

describe('Gate-2 C22: ref-stored timers count', () => {
  it('timerRef.current = setTimeout with no cleanup is a never-cleared timer', () => {
    some(
      run(
        'React Hygiene',
        file(
          'src/components/Ticker.jsx',
          `import { useEffect, useRef, useState } from 'react';\nexport function Ticker() {\n  const timerRef = useRef(null);\n  const [now, setNow] = useState(0);\n  useEffect(() => {\n    function tick() {\n      setNow(Date.now());\n      timerRef.current = setTimeout(tick, 1000);\n    }\n    timerRef.current = setTimeout(tick, 1000);\n  }, []);\n  return <span>{now}</span>;\n}\n`
        )
      ),
      /timer it never clears/
    );
  });
});

describe('Gate-2 C3/C4: framework deference is by import and per-route', () => {
  it('C3: the string fastify in a response body does not stand down Express 4 routes', () => {
    some(
      run(
        'Async Correctness',
        file(
          'src/server/routes.js',
          `const express = require('express');\nconst app = express();\napp.get('/health', (req, res) => res.json({ framework: 'express', migration: 'fastify planned Q4' }));\napp.post('/orders', async (req, res) => {\n  const order = await db.query('INSERT INTO orders (body) VALUES ($1) RETURNING *', [req.body]);\n  res.json(order);\n});\n`
        )
      ),
      /awaits without a try boundary/
    );
  });
  it('C4: one wrapped route does not exempt its unwrapped sibling', () => {
    const res = run(
      'Async Correctness',
      file(
        'src/server/userRoutes.js',
        `const router = require('express').Router();\nrouter.get('/users', asyncHandler(async (req, res) => {\n  res.json(await db.query('SELECT * FROM users LIMIT 50'));\n}));\nrouter.delete('/users/:id', async (req, res) => {\n  await db.query('DELETE FROM users WHERE id = $1', [req.params.id]);\n  res.status(204).end();\n});\n`
      )
    ).filter((x) => /awaits without a try boundary/.test(x.title));
    expect(res, titles(res)).toHaveLength(1);
  });
  it('a real fastify import still stands the check down', () => {
    none(
      run(
        'Async Correctness',
        file(
          'src/server/fastifyRoutes.js',
          `import Fastify from 'fastify';\nconst app = Fastify();\napp.post('/orders', async (req, res) => {\n  const order = await db.query('INSERT INTO orders (body) VALUES ($1)', [req.body]);\n  return order;\n});\n`
        )
      ),
      /awaits without a try boundary/
    );
  });
});

describe('Gate-2 C8/C9/C14/C21: serial-loop check reads code, not strings, in every loop form', () => {
  it('C8/C14: a parameterized SQL string (col = $1) does not self-suppress the loop', () => {
    some(
      run(
        'Async Correctness',
        file(
          'src/jobs/markSynced.js',
          `export async function markSynced(db, ids) {\n  for (const id of ids) {\n    await db.query('UPDATE users SET synced = true WHERE id = $1', [id]);\n  }\n}\n`
        )
      ),
      /runs serially/
    );
  });
  it('C9: a same-line error accumulator is not cross-iteration state', () => {
    some(
      run(
        'Async Correctness',
        file(
          'src/jobs/notify.js',
          `export async function notifyAll(webhookUrls, payload) {\n  let lastError = null;\n  for (const url of webhookUrls) {\n    await fetch(url, { method: 'POST', body: payload }).catch((e) => (lastError = e));\n  }\n  return lastError;\n}\n`
        )
      ),
      /runs serially/
    );
  });
  it('C21: C-style for and while loops are reachable', () => {
    some(
      run(
        'Async Correctness',
        file(
          'src/jobs/statuses.js',
          `export async function statuses(urls) {\n  const results = [];\n  for (let i = 0; i < urls.length; i++) {\n    const res = await fetch(urls[i]);\n    results.push(res.status);\n  }\n  return results;\n}\n`
        )
      ),
      /runs serially/
    );
    some(
      run(
        'Async Correctness',
        file(
          'src/jobs/drain.js',
          `export async function drain(urls) {\n  const out = [];\n  let j = 0;\n  while (j < urls.length) {\n    const res = await fetch(urls[j]);\n    out.push(res.ok);\n    j += 1;\n  }\n  return out;\n}\n`
        )
      ),
      /runs serially/
    );
  });
  it('cursor pagination still stands down: the reassigned cursor feeds the next await', () => {
    none(
      run(
        'Async Correctness',
        file(
          'src/jobs/export.js',
          `export async function exportAll(db) {\n  let cursor = null;\n  const rows = [];\n  for (const page of [1, 2, 3]) {\n    const batch = await db.query('SELECT * FROM t WHERE id > $1 LIMIT 100', [cursor]);\n    rows.push(...batch.rows);\n    cursor = batch.rows.at(-1).id;\n  }\n  return rows;\n}\n`
        )
      ),
      /runs serially/
    );
  });
});

describe('Gate-2 C10: logging a response is not a status check', () => {
  it('console.log(res) does not delegate the ok check', () => {
    some(
      run(
        'Async Correctness',
        file(
          'src/api/loadProducts.js',
          `export async function loadProducts() {\n  const res = await fetch('/api/products');\n  console.log(res);\n  const data = await res.json();\n  return data.products;\n}\n`
        )
      ),
      /without checking res\.ok/
    );
  });
  it('a real delegated helper still counts', () => {
    none(
      run(
        'Async Correctness',
        file(
          'src/api/loadOrders.js',
          `export async function loadOrders() {\n  const res = await fetch('/api/orders');\n  ensureOk(res);\n  const data = await res.json();\n  return data.orders;\n}\n`
        )
      ),
      /without checking res\.ok/
    );
  });
});

describe('Gate-2 C29: Promise.all in statement position floats', () => {
  it('a bare Promise.all statement is a floating promise', () => {
    some(
      run(
        'Async Correctness',
        file(
          'src/jobs/sync.js',
          `export function syncAll(records) {\n  Promise.all(records.map((r) => fetch('/api/sync', { method: 'POST', body: r })));\n}\n`
        )
      ),
      /Promise\.all.*not awaited/
    );
  });
});

describe('Gate-2 C2/C11/C20: swallow detection survives comments and log-message prose', () => {
  it('C2: a commented swallow fires at low, an uncommented one at medium', () => {
    const commented = run(
      'Error Handling',
      file(
        'src/api/load.js',
        `export async function load(setError) {\n  try {\n    return await fetch('/api/data');\n  } catch (err) {\n    console.error(err); // TODO: surface this\n  }\n}\n`
      )
    );
    expect(sev(commented, /swallows the error/), titles(commented)).toBe('low');
    const plain = run(
      'Error Handling',
      file(
        'src/api/load2.js',
        `export async function load2() {\n  try {\n    return await fetch('/api/data');\n  } catch (err) {\n    console.error(err);\n  }\n}\n`
      )
    );
    expect(sev(plain, /swallows the error/), titles(plain)).toBe('medium');
  });
  it('C11: the word metrics inside a log STRING is not instrumentation', () => {
    some(
      run(
        'Error Handling',
        file(
          'src/dashboard/loadMetrics.js',
          `export async function loadMetrics(render) {\n  let data = [];\n  try {\n    const res = await fetch('/api/metrics');\n    data = await res.json();\n  } catch (err) {\n    console.error('could not load metrics', err);\n  }\n  render(data);\n}\n`
        )
      ),
      /swallows the error/
    );
  });
  it('C20: narrating the failure ("please retry") is not retrying', () => {
    some(
      run(
        'Error Handling',
        file(
          'src/checkout/submit.js',
          `export async function submitOrder(order) {\n  try {\n    return await fetch('/api/orders', { method: 'POST', body: JSON.stringify(order) });\n  } catch (err) {\n    console.error('checkout failed, please retry', err);\n  }\n}\n`
        )
      ),
      /swallows the error/
    );
  });
  it('real metrics-emission handling still stands down', () => {
    none(
      run(
        'Error Handling',
        file(
          'src/cache/read.js',
          `export async function read(redis, metrics, key) {\n  try {\n    return await redis.get(key);\n  } catch (err) {\n    metrics.increment('cache.read_failure');\n  }\n  return null;\n}\n`
        )
      ),
      /swallows the error/
    );
  });
});

describe('Gate-2 C12/C27: promise-chain swallows fire, void marks intent at info', () => {
  it('C12: void x().catch(console.error) fires at info, not silence', () => {
    const res = run(
      'Error Handling',
      file(
        'src/server/checkout.js',
        `router.post('/checkout', (req, res) => {\n  void chargeCard(req.body.cardToken, req.body.amountCents).catch(console.error);\n  res.json({ ok: true });\n});\n`
      )
    );
    expect(sev(res, /logged and dropped/), titles(res)).toBe('info');
  });
  it('an unvoided .catch(console.error) stays medium', () => {
    const res = run(
      'Error Handling',
      file('src/store/prefetch.js', `fetch('/api/prefetch').catch(console.error);\n`)
    );
    expect(sev(res, /logged and dropped/), titles(res)).toBe('medium');
  });
  it('C27: .catch(() => {}) is a total swallow', () => {
    const res = run(
      'Error Handling',
      file(
        'src/store/session.js',
        `fetch('/api/session')\n  .then((res) => res.json())\n  .then((session) => store.setSession(session))\n  .catch(() => {});\n`
      )
    );
    expect(sev(res, /silenced by an empty/), titles(res)).toBe('medium');
  });
});

describe('Gate-2 C24/C25: Data & State delivers both promised shapes', () => {
  it('C24: a self-rescheduling setTimeout at a constant delay is fixed-rate polling', () => {
    some(
      run(
        'Data & State',
        file(
          'src/components/StatusBoard.jsx',
          `import { useEffect, useState } from 'react';\nexport function StatusBoard() {\n  const [jobs, setJobs] = useState([]);\n  useEffect(() => {\n    async function poll() {\n      const res = await fetch('/api/jobs');\n      if (res.ok) setJobs(await res.json());\n      setTimeout(poll, 3000);\n    }\n    poll();\n  }, []);\n  return <ul>{jobs.length}</ul>;\n}\n`
        )
      ),
      /polling with no backoff/i
    );
  });
  it('a variable delay (backoff in hand) stands down', () => {
    none(
      run(
        'Data & State',
        file(
          'src/components/RetryBoard.jsx',
          `import { useEffect, useState } from 'react';\nexport function RetryBoard() {\n  const [jobs, setJobs] = useState([]);\n  useEffect(() => {\n    let delay = 3000;\n    async function poll() {\n      const res = await fetch('/api/jobs');\n      if (res.ok) {\n        setJobs(await res.json());\n        delay = 3000;\n      } else {\n        delay = Math.min(delay * 2, 60000);\n      }\n      setTimeout(poll, delay);\n    }\n    poll();\n  }, []);\n  return <ul>{jobs.length}</ul>;\n}\n`
        )
      ),
      /polling with no backoff/i
    );
  });
  it('C25: a nested prop path still seeds state', () => {
    some(
      run(
        'Data & State',
        file(
          'src/components/ProfileCard.jsx',
          `import { useState } from 'react';\nexport function ProfileCard(props) {\n  const [displayName, setDisplayName] = useState(props.user.name);\n  return <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />;\n}\n`
        )
      ),
      /seeded from prop/
    );
  });
});

describe('Gate-2 C23: block-comment @ts-ignore counts', () => {
  it('/* @ts-ignore */ with no reason fires; an explained directive does not', () => {
    some(
      run(
        'TypeScript Hygiene',
        file(
          'src/lib/api-client.ts',
          `/* @ts-ignore */\nconst v = client.internals.cache;\nexport default v;\n`
        )
      ),
      /@ts-ignore with no explanation/
    );
    none(
      run(
        'TypeScript Hygiene',
        file(
          'src/lib/typed-client.ts',
          `// @ts-expect-error TODO(#123): lib types lag v5\nconst v = client.internals.cache;\nexport default v;\n`
        )
      ),
      /with no explanation/
    );
  });
});

describe('Gate-2 C26/C32: CommonJS and sub-path spellings of heavy imports', () => {
  it("C26: require('lodash') is the whole library", () => {
    some(
      run(
        'Performance Hazards',
        file(
          'server/report.js',
          `const _ = require('lodash');\nexport function report(rows) {\n  return _.groupBy(rows, 'region');\n}\n`
        )
      ),
      /Whole lodash imported/
    );
  });
  it('C32: moment sub-path builds are still moment', () => {
    some(
      run(
        'Performance Hazards',
        file(
          'server/dates.js',
          `const moment = require('moment/min/moment-with-locales');\nexport const stamp = () => moment().format();\n`
        )
      ),
      /moment\.js imported/
    );
  });
});

describe('Gate-2 C13/C30: A11y Semantics reads formatted JSX and CSS-in-JS', () => {
  it('C13: onClick on its own line still marks the non-interactive element', () => {
    some(
      run(
        'A11y Semantics',
        file(
          'src/components/GalleryCard.jsx',
          `export function GalleryCard({ item, onOpen }) {\n  return (\n    <span\n      className="card-open"\n      onClick={() => onOpen(item.id)}\n    >\n      open\n    </span>\n  );\n}\n`
        )
      ),
      /Click handler on a <span>/
    );
  });
  it('a keyboard path on the same tag still vouches across lines', () => {
    none(
      run(
        'A11y Semantics',
        file(
          'src/components/KeyCard.jsx',
          `export function KeyCard({ onOpen }) {\n  return (\n    <span\n      role="button"\n      tabIndex={0}\n      onClick={onOpen}\n      onKeyDown={(e) => e.key === 'Enter' && onOpen()}\n    >\n      open\n    </span>\n  );\n}\n`
        )
      ),
      /Click handler on a <span>/
    );
  });
  it('C30: outline: none inside a styled-components template fires', () => {
    some(
      run(
        'A11y Semantics',
        file(
          'src/components/NavLink.jsx',
          `import styled from 'styled-components';\nexport const NavLink = styled.a\`\n  color: inherit;\n  &:focus {\n    outline: none;\n  }\n\`;\n`
        )
      ),
      /Focus outline removed/
    );
  });
});

describe('Gate-2 C28/C31: Build & Config covers the common offenders', () => {
  const pkg = (deps, scripts) =>
    file(
      'package.json',
      JSON.stringify({
        name: 'app',
        engines: { node: '>=20' },
        dependencies: deps,
        devDependencies: { vite: '^5.0.0' },
        scripts,
      })
    );
  const lock = file('package-lock.json', '{}');
  it('C28: the Tailwind/PostCSS toolchain in dependencies is misfiled', () => {
    some(
      run(
        'Build & Config',
        pkg(
          {
            react: '^18.3.1',
            'react-dom': '^18.3.1',
            tailwindcss: '^3.4.10',
            postcss: '^8.4.41',
            autoprefixer: '^10.4.20',
          },
          { build: 'vite build' }
        ),
        lock
      ),
      /in dependencies/
    );
  });
  it('C31: || echo swallows a failure like || true; husky prepare stays exempt', () => {
    const res = run(
      'Build & Config',
      pkg(
        { react: '^18.3.1' },
        { lint: 'eslint src || echo lint issues', prepare: 'husky || true' }
      ),
      lock
    ).filter((x) => /ignores its own failure/.test(x.title));
    expect(res.map((x) => x.title).join(' | ')).toContain('"lint"');
    expect(res.map((x) => x.title).join(' | ')).not.toContain('"prepare"');
  });
});

describe('Gate-2 C18: the Prisma client is whatever the author named it', () => {
  it('const db = new PrismaClient() binds db for the delegate check', () => {
    some(
      run(
        'AI Hallucinations',
        file(
          'server/users.ts',
          `import { PrismaClient } from '@prisma/client';\nconst db = new PrismaClient();\nexport async function findByEmail(email) {\n  return db.user.findOne({ where: { email } });\n}\n`
        )
      ),
      /findOne is not a Prisma client method/
    );
  });
  it('real delegate methods on a renamed client stay clean', () => {
    none(
      run(
        'AI Hallucinations',
        file(
          'server/orders.ts',
          `import { PrismaClient } from '@prisma/client';\nconst db = new PrismaClient();\nexport async function order(id) {\n  return db.order.findUnique({ where: { id } });\n}\n`
        )
      ),
      /not a Prisma client method/
    );
  });
});

describe('Gate-2 C15/C16: the rate-limit lesson needs only the route', () => {
  it("C15: router.route('/login').post(handler) is a credential route", () => {
    some(
      run(
        'API Patterns',
        file(
          'server/routes/auth.js',
          `const router = require('express').Router();\nrouter.route('/login').post(async (req, res) => {\n  const user = await db.query('SELECT * FROM users WHERE email = $1', [req.body.email]);\n  res.json(user);\n});\nmodule.exports = router;\n`
        )
      ),
      /no rate limiting/
    );
  });
  it("C16: app.post('/login', controller.login) by reference is a credential route", () => {
    some(
      run(
        'API Patterns',
        file(
          'server/app.js',
          `const app = require('express')();\napp.post('/login', authController.login);\napp.post('/register', authController.register);\n`
        )
      ),
      /no rate limiting/
    );
  });
});

describe('Gate-2 C17: ORM spellings of UPDATE/DELETE with no WHERE', () => {
  it('prisma updateMany/deleteMany with no where touch every row', () => {
    const res = run(
      'Database Patterns',
      file(
        'server/billing/credits.ts',
        `export async function resetCredits(prisma) {\n  await prisma.credit.updateMany({ data: { balance: 0 } });\n  await prisma.trial.deleteMany();\n}\n`
      )
    );
    some(res, /updateMany with no where/);
    some(res, /deleteMany with no where/);
  });
  it('a scoped updateMany stands down', () => {
    none(
      run(
        'Database Patterns',
        file(
          'server/billing/expire.ts',
          `export async function expire(prisma, cutoff) {\n  await prisma.credit.updateMany({\n    where: { expiresAt: { lt: cutoff } },\n    data: { balance: 0 },\n  });\n}\n`
        )
      ),
      /with no where/
    );
  });
  it('a knex update chain with no .where() is UPDATE with no WHERE', () => {
    some(
      run(
        'Database Patterns',
        file(
          'server/db/users.js',
          `const knex = require('knex')(config);\nexport async function deactivateUser(id) {\n  await knex('users').update({ active: false });\n}\n`
        )
      ),
      /knex update\/delete with no/
    );
    none(
      run(
        'Database Patterns',
        file(
          'server/db/users-scoped.js',
          `const knex = require('knex')(config);\nexport async function deactivate(id) {\n  await knex('users').where({ id }).update({ active: false });\n}\n`
        )
      ),
      /knex update\/delete with no/
    );
  });
});

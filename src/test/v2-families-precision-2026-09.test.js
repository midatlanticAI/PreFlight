// src/test/v2-families-precision-2026-09.test.js
//
// Gate-1 pins for the v2 family build (2026-09-03): 59 confirmed precision
// findings from three contextless attackers, each independently reproduced
// by a second checker before its fix. Negatives are real-world idioms that
// drew findings; positives pin the recall each fix must not cost.

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

describe('React Hygiene: cleanup shapes the checks can and cannot read', () => {
  it('honors return unsubscribe / named cleanup / helper delegation / implicit return', () => {
    const cases = [
      `import { useEffect, useState } from 'react';\nexport function useStoreSync(store) {\n  const [snap, setSnap] = useState(store.getState());\n  useEffect(() => {\n    const unsubscribe = store.subscribe(() => setSnap(store.getState()));\n    return unsubscribe;\n  }, [store]);\n  return snap;\n}\n`,
      `import { useEffect } from 'react';\nexport function useShortcuts(onKeyDown) {\n  useEffect(() => {\n    window.addEventListener('keydown', onKeyDown);\n    function cleanup() {\n      window.removeEventListener('keydown', onKeyDown);\n    }\n    return cleanup;\n  }, [onKeyDown]);\n}\n`,
      `import { useEffect } from 'react';\nexport function useTheme(themeStore, apply) {\n  useEffect(() => themeStore.subscribe(apply), [themeStore, apply]);\n}\n`,
    ];
    for (const content of cases) {
      none(run('React Hygiene', file('src/hooks/h.jsx', content)), /never|no cleanup/);
    }
  });
  it('still flags a genuinely uncleaned listener', () => {
    some(
      run(
        'React Hygiene',
        file(
          'src/hooks/h.jsx',
          `import { useEffect } from 'react';\nexport function useResize(setW) {\n  useEffect(() => {\n    window.addEventListener('resize', () => setW(window.innerWidth));\n  }, []);\n}\n`
        )
      ),
      /listener it never removes/
    );
  });
  it('honors didCancel flags and axios CancelToken', () => {
    none(
      run(
        'React Hygiene',
        file(
          'src/UserCard.jsx',
          `import { useEffect, useState } from 'react';\nexport function UserCard({ id }) {\n  const [user, setUser] = useState(null);\n  useEffect(() => {\n    let didCancel = false;\n    fetch('/api/u/' + id).then((r) => r.json()).then((u) => {\n      if (!didCancel) setUser(u);\n    });\n    return () => {\n      didCancel = true;\n    };\n  }, [id]);\n  return <b>{user?.name}</b>;\n}\n`
        )
      ),
      /without cancellation/
    );
  });
  it('deps: concise arrows have deps; indexed deps are not literals; event-name state does not stale-close', () => {
    const res = run(
      'React Hygiene',
      file(
        'src/misc.jsx',
        `import { useEffect, useState } from 'react';\nexport function M({ steps }) {\n  const [mounted, setMounted] = useState(false);\n  const [error, setError] = useState(null);\n  useEffect(() => setMounted(true), []);\n  useEffect(() => {\n    setError(null);\n  }, [steps[0]]);\n  useEffect(() => {\n    const onError = (event) => setError(event.error);\n    window.addEventListener('error', onError);\n    return () => window.removeEventListener('error', onError);\n  }, []);\n  return <b>{mounted && String(error)}</b>;\n}\n`
      )
    );
    none(res, /no dependency array|fresh literal|stale state/);
  });
  it('render-prop APIs and doc-blessed guarded setters are not defects', () => {
    const res = run(
      'React Hygiene',
      file(
        'src/Form.jsx',
        `import { useState } from 'react';\nexport function List({ items, control, Controller }) {\n  const [prevItems, setPrevItems] = useState(items);\n  const [selection, setSelection] = useState(null);\n  if (items !== prevItems) {\n    setPrevItems(items);\n    setSelection(null);\n  }\n  return <Controller name="phone" control={control} render={({ field }) => <input {...field} />} />;\n}\n`
      )
    );
    none(res, /inline in a prop|during render/);
  });
  it('colocated App Router hooks need no directive; Vue projects are out of scope', () => {
    none(
      run(
        'React Hygiene',
        file('next.config.js', `module.exports = {};\n`),
        file(
          'app/dashboard/use-filters.ts',
          `import { useState, useCallback } from 'react';\nexport function useFilters() {\n  const [f, setF] = useState({});\n  return { f, set: useCallback((k, v) => setF((p) => ({ ...p, [k]: v })), []) };\n}\n`
        )
      ),
      /client-only/
    );
    expect(
      run(
        'React Hygiene',
        file('package.json', `{"dependencies":{"vue":"^3.4.0","vue-router":"^4.0.0"}}`),
        file(
          'src/composables/useAnalytics.js',
          `export function useAnalytics(options) {\n  if (typeof window !== 'undefined' && window.navigator.doNotTrack === '1') {\n    return useLocalBuffer(options);\n  }\n  return useCookieConsent(options);\n}\nfunction useLocalBuffer(o) { return o; }\nfunction useCookieConsent(o) { return o; }\n`
        )
      )
    ).toHaveLength(0);
  });
});

describe('Async Correctness: dependency, delegation, and framework truth', () => {
  it('cursor pagination and migrations are dependent loops', () => {
    const res = run(
      'Async Correctness',
      file(
        'src/db/export.js',
        `export async function exportAll(db, batchId) {\n  let cursor = 0;\n  const out = [];\n  while (cursor !== null) {\n    const page = await db.query('select * from audit where batch = $1 and id > $2 limit 100', [batchId, cursor]);\n    out.push(...page.rows);\n    cursor = page.rows.length ? page.rows[page.rows.length - 1].id : null;\n  }\n  return out;\n}\n`
      )
    );
    none(res, /serially/);
  });
  it('wrapped handlers and Fastify are already handled', () => {
    none(
      run(
        'Async Correctness',
        file(
          'src/server/users.js',
          `import asyncHandler from 'express-async-handler';\nexport function mount(router, db) {\n  router.get('/users/:id', asyncHandler(async (req, res) => {\n    const user = await db.query('select * from users where id = $1', [req.params.id]);\n    res.json(user.rows[0]);\n  }));\n}\n`
        )
      ),
      /try boundary/
    );
    none(
      run(
        'Async Correctness',
        file(
          'src/server/health.js',
          `import Fastify from 'fastify';\nconst server = Fastify({ logger: true });\nserver.get('/status/:service', async (request) => {\n  const record = await store.lookup(request.params.service);\n  return record;\n});\n`
        )
      ),
      /try boundary/
    );
  });
  it('res.send and socket.send are synchronous; delegated ok-checks count', () => {
    none(
      run(
        'Async Correctness',
        file(
          'src/server/pages.js',
          `export function mount(app, sockets) {\n  app.get('/health', (req, res) => {\n    res.send('ok');\n  });\n  for (const socket of sockets) {\n    socket.send('ping');\n  }\n}\n`
        )
      ),
      /not awaited/
    );
    none(
      run(
        'Async Correctness',
        file(
          'src/api/client.js',
          `import { ensureOk } from './http-util.js';\nexport async function loadUser(id) {\n  const res = await fetch('/api/user/' + id);\n  ensureOk(res);\n  return res.json();\n}\n`
        )
      ),
      /res\.ok/
    );
  });
  it('multer-bounded fan-out and guarded restores are fine', () => {
    none(
      run(
        'Async Correctness',
        file(
          'src/upload.js',
          `export function mount(router, upload, processPhoto) {\n  router.post('/photos', upload.array('photos', 3), async (req, res) => {\n    const out = await Promise.all(req.files.map((f) => processPhoto(f)));\n    res.json(out);\n  });\n}\n`
        )
      ),
      /request-sized/
    );
    none(
      run(
        'Async Correctness',
        file(
          'src/state/persist.js',
          `export function restoreSession() {\n  try {\n    const raw = localStorage.getItem('session');\n    if (!raw) return null;\n    const version = localStorage.getItem('session:v');\n    if (version !== '3') return null;\n    const expiry = localStorage.getItem('session:exp');\n    if (expiry && Number(expiry) < Date.now()) return null;\n    return JSON.parse(localStorage.getItem('session'));\n  } catch {\n    return null;\n  }\n}\n`
        )
      ),
      /JSON\.parse/
    );
  });
});

describe('Error Handling: handling vocabularies and file conventions', () => {
  it('metrics-recorded degradation, void fire-and-forget, and cause rethrows are handled', () => {
    const res = run(
      'Error Handling',
      file(
        'src/cache.js',
        `export async function profile(redis, db, metrics, id) {\n  let cached = null;\n  try {\n    cached = await redis.get('p:' + id);\n  } catch (err) {\n    metrics.increment('cache.read_failure');\n  }\n  if (cached) return JSON.parse(cached);\n  return db.query('select * from profiles where id = $1', [id]);\n}\n`
      )
    );
    none(res, /swallows/);
    // Gate-2 (C12): the void form is declared fire-and-forget — it teaches
    // at info (confirm the drop is intended) instead of standing down or
    // fining the Async Correctness family's own remediation at medium.
    const voided = run(
      'Error Handling',
      file(
        'src/bg.js',
        `setInterval(() => {\n  void queue.flush().catch(console.error);\n}, 60000);\n`
      )
    ).filter((x) => /logged and dropped/.test(x.title));
    expect(voided).toHaveLength(1);
    expect(voided[0].severity).toBe('info');
    none(
      run(
        'Error Handling',
        file(
          'src/load.js',
          `export async function load(read) {\n  try {\n    return await read();\n  } catch (err) {\n    throw new Error(err.message, { cause: err });\n  }\n}\n`
        )
      ),
      /drops the stack/
    );
  });
  it('response termination in catch is not resource cleanup; try/finally close equals with', () => {
    none(
      run(
        'Error Handling',
        file(
          'src/webhooks.js',
          `export async function handle(req, res, handleWebhook) {\n  try {\n    await handleWebhook(req.body);\n    res.status(204).end();\n  } catch (err) {\n    console.error('webhook failed', err);\n    res.status(500).end();\n  }\n}\n`
        )
      ),
      /catch, not finally|swallows/
    );
    none(
      run(
        'Error Handling',
        file(
          'scripts/manifest.py',
          `import json\n\ndef load(path):\n    f = open(path, 'rb')\n    try:\n        return json.load(f)\n    finally:\n        f.close()\n`
        )
      ),
      /with block/
    );
  });
  it('Next App Router error.tsx IS the boundary', () => {
    const jsx = (n) =>
      file(`app/c${n}/page.tsx`, `export default function P${n}() { return <div>p${n}</div>; }\n`);
    none(
      run(
        'Error Handling',
        jsx(1),
        jsx(2),
        jsx(3),
        file(
          'app/error.tsx',
          `'use client';\nexport default function Error({ error, reset }) {\n  return <button onClick={reset}>{String(error)}</button>;\n}\n`
        )
      ),
      /No error boundary/
    );
  });
});

describe('the smaller families: idioms that are the fix, not the finding', () => {
  it('F4: initial-named props, server components, heartbeats, POST pairs', () => {
    const ds = (path, content) => run('Data & State', file(path, content));
    none(
      ds(
        'src/Counter.jsx',
        `import { useState } from 'react';\nexport function Counter({ initialCount }) {\n  const [count, setCount] = useState(initialCount);\n  return <button onClick={() => setCount(count + 1)}>{count}</button>;\n}\n`
      ),
      /seeded from prop/
    );
    none(
      ds(
        'app/posts/page.tsx',
        `export default async function Page() {\n  const res = await fetch('https://api.acme.example/posts', { next: { revalidate: 60 } });\n  const posts = await res.json();\n  return <ul>{posts.map((p) => <li key={p.id}>{p.title}</li>)}</ul>;\n}\n`
      ),
      /during render/
    );
    none(
      ds(
        'src/heartbeat.js',
        `export function start(sessionId) {\n  setInterval(() => {\n    fetch('/api/heartbeat', { method: 'POST', body: sessionId, keepalive: true }).catch(() => {});\n  }, 30000);\n}\n`
      ),
      /polling/
    );
    none(
      ds(
        'src/posts-api.js',
        `export const saveDraft = (d) => fetch('/api/posts', { method: 'POST', body: JSON.stringify({ ...d, draft: true }) });\nexport const publishPost = (d) => fetch('/api/posts', { method: 'POST', body: JSON.stringify(d) });\n`
      ),
      /fetched from/
    );
  });
  it('F5: test-utils casts and call-result assertions are out of scope', () => {
    expect(
      run(
        'TypeScript Hygiene',
        file('src/test-utils/render.ts', `export const routerMock = { push: (() => {}) } as any;\n`)
      )
    ).toHaveLength(0);
    none(
      run(
        'TypeScript Hygiene',
        file('src/main.ts', `document.getElementById('root')!.appendChild(app);\n`)
      ),
      /Non-null/
    );
  });
  it('F6: styled and class-named images are sized elsewhere; <Img> is a component', () => {
    expect(
      run(
        'Performance Hazards',
        file(
          'src/Avatar.jsx',
          `import styles from './Avatar.module.css';\nexport const Avatar = ({ src, name }) => <img className={styles.avatar} src={src} alt={name} />;\n`
        ),
        file(
          'src/StyledAvatar.jsx',
          `const Img = styled.img\`width: 48px;\`;\nexport const A = ({ src, name }) => <Img src={src} alt={name} />;\n`
        )
      )
    ).toHaveLength(0);
  });
  it('F8: cross-file :focus-visible and component-boundary headings are conformant', () => {
    expect(
      run(
        'A11y Semantics',
        file('src/styles/reset.css', `:focus {\n  outline: none;\n}\n`),
        file('src/styles/focus.css', `:focus-visible {\n  outline: 2px solid var(--accent);\n}\n`),
        file(
          'src/marketing.jsx',
          `export const Hero = () => <header><h1>Product</h1></header>;\nexport const FooterColumn = () => <div><h3>Links</h3></div>;\n`
        )
      )
    ).toHaveLength(0);
  });
  it('F9: folder-upload prefixes, bun locks, husky prepare, ts-node runtime, monorepo engines, Astro pairs', () => {
    const bc = (...f) => run('Build & Config', ...f);
    none(
      bc(
        file(
          'my-app/package.json',
          `{"name":"x","dependencies":{"react":"^18"},"engines":{"node":">=20"}}`
        ),
        file('my-app/package-lock.json', `{}`),
        file('my-app/src/index.js', `console.log(1);`)
      ),
      /No lockfile/
    );
    none(
      bc(
        file(
          'package.json',
          `{"name":"x","dependencies":{"react":"^18"},"engines":{"node":">=20"}}`
        ),
        file('bun.lock', `{}`),
        file('bun.lockb', `binary`)
      ),
      /No lockfile|different package managers/
    );
    none(
      bc(
        file(
          'package.json',
          `{"name":"x","engines":{"node":">=20"},"scripts":{"prepare":"husky || true"},"dependencies":{"react":"^18"}}`
        ),
        file('package-lock.json', `{}`)
      ),
      /ignores its own failure/
    );
    none(
      bc(
        file(
          'package.json',
          `{"name":"x","engines":{"node":">=20"},"scripts":{"start":"ts-node src/server.ts"},"dependencies":{"ts-node":"^10","typescript":"^5"}}`
        ),
        file('package-lock.json', `{}`)
      ),
      /build-time package/
    );
    none(
      bc(
        file('apps/web/package.json', `{"name":"web","dependencies":{"react":"^18"}}`),
        file(
          'package.json',
          `{"name":"root","engines":{"node":">=20"},"workspaces":["apps/*"],"dependencies":{}}`
        ),
        file('package-lock.json', `{}`)
      ),
      /no Node engines/
    );
    none(
      bc(
        file(
          'package.json',
          `{"name":"x","engines":{"node":">=20"},"dependencies":{"astro":"^4"}}`
        ),
        file('package-lock.json', `{}`),
        file('astro.config.mjs', `export default {};`),
        file('svelte.config.js', `export default {};`)
      ),
      /different frameworks/
    );
  });
  it('F10: TS type imports, React 19.2, Prisma Mongo raw, $extends, ReadonlyURLSearchParams', () => {
    const ah = (...f) => run('AI Hallucinations', ...f);
    expect(
      ah(
        file(
          'src/Card.tsx',
          `import { FC, ReactNode, Dispatch, SetStateAction, useState } from 'react';\nexport const C: FC<{ children: ReactNode }> = ({ children }) => { const [v] = useState(0); return <div>{children}{v}</div>; };\n`
        )
      )
    ).toHaveLength(0);
    expect(
      ah(
        file(
          'src/Chat.jsx',
          `import { Activity, useEffectEvent, useState } from 'react';\nexport function Chat() { const [v] = useState(0); return <Activity mode="visible">{v}</Activity>; }\n`
        )
      )
    ).toHaveLength(0);
    expect(
      ah(
        file(
          'src/reports.ts',
          `export async function r(prisma) {\n  return prisma.user.findRaw({ filter: { age: { $gt: 25 } } });\n}\n`
        )
      )
    ).toHaveLength(0);
    expect(
      ah(
        file(
          'src/db.ts',
          `export const prisma = new PrismaClient().$extends({\n  model: { user: { async signUp(email) { return email; } } },\n});\nexport const go = (email) => prisma.user.signUp(email);\n`
        )
      )
    ).toHaveLength(0);
    expect(
      ah(
        file(
          'src/query.ts',
          `import { ReadonlyURLSearchParams } from 'next/navigation';\nexport const q = (p: ReadonlyURLSearchParams) => p.toString();\n`
        )
      )
    ).toHaveLength(0);
  });
  it('F10 still catches the genuinely invented', () => {
    some(
      run(
        'AI Hallucinations',
        file(
          'src/Feed.jsx',
          `import { useFetch } from 'react';\nexport const F = () => useFetch('/api');\n`
        )
      ),
      /useFetch/
    );
  });
  it('F11: class-validator, /authors, stream events, reference tables, to_thread', () => {
    const ap = (...f) => run('API Patterns', ...f);
    none(
      ap(
        file(
          'src/routes/users.ts',
          `export function mount(app, repo, CreateUserDto, plainToInstance, validateOrReject) {\n  app.post('/users', async (req, res) => {\n    try {\n      const dto = plainToInstance(CreateUserDto, req.body);\n      await validateOrReject(dto);\n      res.json(await repo.save(dto));\n    } catch (e) {\n      res.status(400).json({ error: 'invalid input' });\n    }\n  });\n}\n`
        )
      ),
      /without validation/
    );
    none(
      ap(
        file(
          'src/routes/authors.js',
          `export function mount(app, db, schema) {\n  app.post('/api/authors', async (req, res) => {\n    try {\n      const body = schema.parse(req.body);\n      res.json(await db.authors.create(body));\n    } catch (e) {\n      res.status(400).json({ error: 'invalid' });\n    }\n  });\n}\n`
        )
      ),
      /rate limiting/
    );
    none(
      ap(
        file(
          'src/routes/import.js',
          `export function mount(app, makeOut) {\n  app.post('/import', (req, res) => {\n    const out = makeOut();\n    req.pipe(out);\n    out.on('error', () => res.sendStatus(500));\n    out.on('finish', () => res.sendStatus(201));\n  });\n}\n`
        )
      ),
      /two responses/
    );
    none(
      ap(
        file(
          'src/routes/countries.js',
          `export function mount(app, pool) {\n  app.get('/api/countries', async (req, res) => {\n    try {\n      res.json(await pool.query('SELECT * FROM countries'));\n    } catch (e) {\n      res.status(500).json({ error: 'lookup failed' });\n    }\n  });\n}\n`
        )
      ),
      /whole table/
    );
    none(
      ap(
        file(
          'app/routes.py',
          `import asyncio\nimport psycopg2\n\nasync def create_user(payload):\n    try:\n        user = await asyncio.to_thread(insert_user, payload)\n    except psycopg2.errors.UniqueViolation:\n        return error_response(409)\n    return user\n`
        )
      ),
      /Blocking call/
    );
  });
  it('F12: concatenated WHERE, tool-managed migrations, seed scripts, telemetry pairs', () => {
    const db = (...f) => run('Database Patterns', ...f);
    none(
      db(
        file(
          'src/db/users.js',
          `export async function rename(pool, name, id) {\n  await pool.query('UPDATE users SET name = $1, updated_at = now() ' + 'WHERE id = $2', [name, id]);\n}\n`
        )
      ),
      /no WHERE/
    );
    none(
      db(
        file(
          'prisma/migrations/20240901_init/migration.sql',
          `-- CreateTable\nCREATE TABLE "User" (id SERIAL PRIMARY KEY);\n`
        )
      ),
      /re-runnable/
    );
    none(
      db(
        file(
          'scripts/reset-demo.js',
          `export async function reset(client) {\n  await client.query('DELETE FROM demo_orders');\n  await seed(client);\n}\n`
        )
      ),
      /no WHERE/
    );
    none(
      db(
        file(
          'src/track.js',
          `export const trackVisit = async (prisma, userId, path) => {\n  await prisma.pageView.create({ data: { userId, path } });\n  await prisma.user.update({ where: { id: userId }, data: { lastSeenAt: new Date() } });\n};\n`
        )
      ),
      /transaction/
    );
  });
  it('F12 still catches the real ones', () => {
    some(
      run(
        'Database Patterns',
        file(
          'server/admin.js',
          `export async function resetAll(db) {\n  await db.query('UPDATE users SET credits = 0');\n}\n`
        )
      ),
      /no WHERE/
    );
  });
});

// src/test/v2-families-f4-f12.test.js
//
// Consolidated suite for the eight smaller v2 families (F4-F6, F8-F12) —
// one file on purpose: each test file pays ~3s of jsdom startup, and eight
// small families in one file keeps the suite inside the CI budget the same
// way the per-family consolidation convention keeps probes out of
// one-file-per-check territory.
import { describe, it, expect } from 'vitest';
import { probeDataState } from '../lib/probes/v2/data-state.js';
import { probeTsHygiene } from '../lib/probes/v2/ts-hygiene.js';
import { probePerfHazards } from '../lib/probes/v2/perf.js';
import { probeA11ySemantics } from '../lib/probes/v2/a11y-semantics.js';
import { probeBuildConfig } from '../lib/probes/v2/build-config.js';
import { probeAiHallucinations } from '../lib/probes/v2/hallucinations.js';
import { probeApiPatterns } from '../lib/probes/v2/api-patterns.js';
import { probeDbPatterns } from '../lib/probes/v2/db-patterns.js';

const file = (path, content) => ({ path, content });
const titles = (res) => res.map((x) => `${x.severity}:${x.title}`).join(' | ');
const has = (res, re) => res.some((x) => re.test(x.title));

describe('F4 Data & State', () => {
  const run = (...f) => probeDataState(f);
  it('flags duplicate fetches, prop-seeded state, and missing queryKey', () => {
    const res = run(
      file(
        'src/Feed.jsx',
        `import { useState } from 'react';\nexport function Feed({ selectedId, load }) {\n  const [current, setCurrent] = useState(selectedId);\n  const a = () => fetch('/api/feed').then((r) => r.json());\n  const b = () => fetch('/api/feed').then((r) => r.json());\n  const q = useQuery({\n    queryFn: () => fetch('/api/feed'),\n  });\n  return <button onClick={() => setCurrent(current + 1)}>{current}</button>;\n}\n`
      )
    );
    expect(has(res, /fetched from 3 places/), titles(res)).toBe(true);
    expect(has(res, /seeded from prop selectedId/), titles(res)).toBe(true);
    expect(has(res, /without a queryKey/), titles(res)).toBe(true);
  });
  it('flags fixed-rate polling with fetch', () => {
    const res = run(
      file(
        'src/poll.js',
        `export function start(setV) {\n  setInterval(async () => {\n    const r = await fetch('/api/status');\n    setV(await r.json());\n  }, 3000);\n}\n`
      )
    );
    expect(has(res, /polling with no backoff/), titles(res)).toBe(true);
  });
  it('does NOT flag initialX naming or effect-synced state', () => {
    const res = run(
      file(
        'src/Ok.jsx',
        `import { useState, useEffect } from 'react';\nexport function Ok({ value }) {\n  const [v, setV] = useState(value);\n  useEffect(() => setV(value), [value]);\n  return <b>{v}</b>;\n}\n`
      )
    );
    expect(
      res.filter((x) => /seeded from prop/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
});

describe('F5 TypeScript Hygiene', () => {
  const run = (...f) => probeTsHygiene(f);
  it('flags directives without reasons, casts, and lax tsconfig', () => {
    const res = run(
      file(
        'src/api.ts',
        `// @ts-nocheck\nconst a = data as any;\nconst b = payload as unknown as User;\n// @ts-ignore\nconst c = maybe?.value!;\n`
      ),
      file('tsconfig.json', `{\n  "compilerOptions": {\n    "strict": false\n  }\n}\n`)
    );
    expect(has(res, /@ts-nocheck/), titles(res)).toBe(true);
    expect(has(res, /@ts-ignore with no explanation/), titles(res)).toBe(true);
    expect(has(res, /as any/), titles(res)).toBe(true);
    expect(has(res, /double cast/), titles(res)).toBe(true);
    expect(has(res, /contradicts optional chaining/), titles(res)).toBe(true);
    expect(has(res, /strict mode is off/), titles(res)).toBe(true);
  });
  it('does NOT flag an explained @ts-expect-error', () => {
    const res = run(
      file('src/x.ts', `// @ts-expect-error upstream types lag the v5 runtime (#412)\nuse(v);\n`)
    );
    expect(res, titles(res)).toHaveLength(0);
  });
});

describe('F6 Performance Hazards', () => {
  const run = (...f) => probePerfHazards(f);
  it('flags unsized images, whole-library imports, moment, document.write', () => {
    const res = run(
      file(
        'src/Hero.jsx',
        `import _ from 'lodash';\nimport moment from 'moment';\nexport const Hero = ({ src }) => {\n  document.write('<p>x</p>');\n  return <img src={src} />;\n};\n`
      )
    );
    expect(has(res, /no width and height/), titles(res)).toBe(true);
    expect(has(res, /Whole lodash imported/), titles(res)).toBe(true);
    expect(has(res, /moment\.js imported/), titles(res)).toBe(true);
    expect(has(res, /document\.write/), titles(res)).toBe(true);
  });
  it('does NOT flag sized images or scoped imports', () => {
    const res = run(
      file(
        'src/Hero.jsx',
        `import debounce from 'lodash/debounce';\nexport const Hero = ({ src }) => <img src={src} width={640} height={360} />;\n`
      )
    );
    expect(res, titles(res)).toHaveLength(0);
  });
});

describe('F8 A11y Semantics', () => {
  const run = (...f) => probeA11ySemantics(f);
  it('flags div clicks, positive tabIndex, heading skips, deleted outlines', () => {
    const res = run(
      file(
        'src/Panel.jsx',
        `export const Panel = ({ go }) => (\n  <section>\n    <h1>Title</h1>\n    <h4>Sub</h4>\n    <div onClick={go}>Open</div>\n    <input tabIndex={3} />\n  </section>\n);\n`
      ),
      file('src/app.css', `button:focus {\n  outline: none;\n}\n`)
    );
    expect(has(res, /no role or keyboard path/), titles(res)).toBe(true);
    expect(has(res, /overrides the natural tab order/), titles(res)).toBe(true);
    expect(has(res, /skips from h1 to h4/), titles(res)).toBe(true);
    expect(has(res, /outline removed/), titles(res)).toBe(true);
  });
  it('does NOT flag keyboard-complete custom controls or replaced outlines', () => {
    const res = run(
      file(
        'src/Panel.jsx',
        `export const Panel = ({ go }) => (\n  <div role="button" tabIndex={0} onClick={go} onKeyDown={(e) => e.key === 'Enter' && go()}>Open</div>\n);\n`
      ),
      file(
        'src/app.css',
        `button:focus {\n  outline: none;\n  box-shadow: 0 0 0 2px var(--ring);\n}\n`
      )
    );
    expect(res, titles(res)).toHaveLength(0);
  });
});

describe('F9 Build & Config', () => {
  const run = (...f) => probeBuildConfig(f);
  it('flags mixed lockfiles, misfiled deps, and || true scripts', () => {
    const res = run(
      file(
        'package.json',
        `{\n  "name": "x",\n  "dependencies": { "react": "^18", "typescript": "^5", "@types/node": "^20" },\n  "scripts": { "build": "tsc || true" }\n}\n`
      ),
      file('package-lock.json', `{}\n`),
      file('yarn.lock', `# yarn\n`)
    );
    expect(has(res, /Lockfiles from 2 different package managers/), titles(res)).toBe(true);
    expect(has(res, /build-time packages in dependencies/), titles(res)).toBe(true);
    expect(has(res, /ignores its own failure/), titles(res)).toBe(true);
  });
  it('flags no-lockfile and env-example gaps', () => {
    const res = run(
      file(
        'package.json',
        `{\n  "name": "x",\n  "dependencies": { "react": "^18" },\n  "engines": { "node": ">=20" }\n}\n`
      ),
      file('.gitignore', `.env\n`),
      file('server.js', `console.log(process.env.API_URL);\n`)
    );
    expect(has(res, /No lockfile committed/), titles(res)).toBe(true);
    expect(has(res, /no \.env\.example/), titles(res)).toBe(true);
  });
});

describe('F10 AI Hallucinations', () => {
  const run = (...f) => probeAiHallucinations(f);
  it('flags invented react exports, next exports, prisma methods', () => {
    const res = run(
      file(
        'src/Feed.jsx',
        `import { useFetch, useState } from 'react';\nimport { useNavigate } from 'next/navigation';\nexport async function load(prisma, id) {\n  return prisma.user.findOneOrThrow({ where: { id } });\n}\n`
      )
    );
    expect(has(res, /'useFetch' is not exported by react/), titles(res)).toBe(true);
    expect(has(res, /'useNavigate' is not exported by next\/navigation/), titles(res)).toBe(true);
    expect(has(res, /findOneOrThrow is not a Prisma client method/), titles(res)).toBe(true);
    expect(res.some((x) => /'useState'/.test(x.title))).toBe(false);
  });
  it('does NOT flag real exports and real client methods', () => {
    const res = run(
      file(
        'src/Ok.jsx',
        `import { useState, useTransition } from 'react';\nimport { useRouter, redirect } from 'next/navigation';\nexport async function load(prisma, id) {\n  return prisma.user.findUniqueOrThrow({ where: { id } });\n}\n`
      )
    );
    expect(res, titles(res)).toHaveLength(0);
  });
});

describe('F11 API Patterns', () => {
  const run = (...f) => probeApiPatterns(f);
  it('flags unvalidated writes, unlimited login, whole-table lists, double sends', () => {
    const res = run(
      file(
        'server/routes.js',
        `export function mount(app, db, prisma) {\n  app.post('/items', async (req, res) => {\n    const r = await db.query('INSERT INTO items (name) VALUES ($1)', [req.body.name]);\n    res.json(r);\n    res.json({ again: true });\n  });\n  app.post('/login', async (req, res) => {\n    res.json(await db.check(req.body));\n  });\n  app.get('/items', async (req, res) => {\n    res.json(await prisma.item.findMany());\n  });\n}\n`
      )
    );
    expect(has(res, /writes request body without validation/), titles(res)).toBe(true);
    expect(has(res, /no rate limiting/), titles(res)).toBe(true);
    expect(has(res, /returns the whole table/), titles(res)).toBe(true);
    expect(has(res, /two responses/), titles(res)).toBe(true);
  });
  it('quiets the rate-limit finding when a limiter exists in the project', () => {
    const res = run(
      file(
        'server/limiter.js',
        `import rateLimit from 'express-rate-limit';\nexport const limiter = rateLimit({ windowMs: 60000, max: 10 });\n`
      ),
      file(
        'server/routes.js',
        `export function mount(app, users) {\n  app.post('/login', async (req, res) => {\n    res.json(await users.check(req.body));\n  });\n}\n`
      )
    );
    expect(
      res.filter((x) => /rate limiting/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
  it('flags blocking calls in async Python handlers', () => {
    const res = run(
      file(
        'app/main.py',
        `import time\n\nasync def slow_endpoint(request):\n    time.sleep(2)\n    return {"ok": True}\n`
      )
    );
    expect(has(res, /Blocking call inside an async handler/), titles(res)).toBe(true);
  });
});

describe('F12 Database Patterns', () => {
  const run = (...f) => probeDbPatterns(f);
  it('flags WHERE-less writes, non-rerunnable migrations, missing transactions', () => {
    const res = run(
      file(
        'server/admin.js',
        `export async function resetAll(db) {\n  await db.query('UPDATE users SET credits = 0');\n}\nexport const transfer = async (prisma, a, b, amt) => {\n  await prisma.account.update({ where: { id: a }, data: { balance: { decrement: amt } } });\n  await prisma.account.update({ where: { id: b }, data: { balance: { increment: amt } } });\n};\n`
      ),
      file('migrations/002_payments.sql', `CREATE TABLE payments (id serial primary key);\n`)
    );
    expect(has(res, /UPDATE with no WHERE/), titles(res)).toBe(true);
    expect(has(res, /not re-runnable/), titles(res)).toBe(true);
    expect(has(res, /writes with no transaction/), titles(res)).toBe(true);
  });
  it('does NOT flag scoped writes, guarded migrations, or transactions', () => {
    const res = run(
      file(
        'server/ok.js',
        `export const transfer = async (prisma, a, b, amt) => {\n  await prisma.$transaction([\n    prisma.account.update({ where: { id: a }, data: { balance: { decrement: amt } } }),\n    prisma.account.update({ where: { id: b }, data: { balance: { increment: amt } } }),\n  ]);\n};\nexport async function resetOne(db, id) {\n  await db.query('UPDATE users SET credits = 0 WHERE id = $1', [id]);\n}\n`
      ),
      file('migrations/003_ok.sql', `CREATE TABLE IF NOT EXISTS refunds (id serial primary key);\n`)
    );
    expect(res, titles(res)).toHaveLength(0);
  });
});

describe('cross-family contract', () => {
  const ALL = [
    probeDataState,
    probeTsHygiene,
    probePerfHazards,
    probeA11ySemantics,
    probeBuildConfig,
    probeAiHallucinations,
    probeApiPatterns,
    probeDbPatterns,
  ];
  it('every family returns [] on empty input and arrays on garbage', () => {
    for (const fn of ALL) {
      expect(fn([])).toEqual([]);
      expect(fn([file('src/x.ts', `}}}((( as any @@`)])).toBeInstanceOf(Array);
      expect(
        fn([file('a/__tests__/x.test.jsx', `<img src={x} /> as any UPDATE users SET x=1`)])
      ).toEqual([]);
    }
  });
  it('no family exceeds high severity', () => {
    const messy = [
      file('src/m.ts', `const a = b as any;\n// @ts-nocheck\n`),
      file(
        'package.json',
        `{"name":"x","scripts":{"build":"x || true"},"dependencies":{"typescript":"^5"}}`
      ),
      file(
        'server/r.js',
        `app.post('/login', async (req, res) => { res.json(await db.q(req.body)); });`
      ),
    ];
    for (const fn of ALL) {
      for (const f of fn(messy)) {
        expect(['medium', 'low', 'info']).toContain(f.severity);
      }
    }
  });
});

// src/test/v2-async.test.js — F2 Async Correctness family suite.
import { describe, it, expect } from 'vitest';
import { probeAsyncCorrectness } from '../lib/probes/v2/async.js';

const file = (path, content) => ({ path, content });
const run = (...files) => probeAsyncCorrectness(files);
const has = (res, re) => res.some((x) => re.test(x.title));
const titles = (res) => res.map((x) => `${x.severity}:${x.title}`).join(' | ');

describe('serialized and dropped work', () => {
  it('flags awaited I/O in a loop', () => {
    const res = run(
      file(
        'src/fetchAll.js',
        `export async function fetchAll(items) {\n  const out = [];\n  for (const item of items) {\n    const r = await fetch('/api/item/' + item.id);\n    out.push(await r.json());\n  }\n  return out;\n}\n`
      )
    );
    expect(has(res, /runs serially/), titles(res)).toBe(true);
  });
  it('stands down on a /* serial */ marker', () => {
    const res = run(
      file(
        'src/migrate.js',
        `export async function migrate(steps, db) {\n  for (const step of steps) { /* serial */\n    await db.execute(step.sql);\n  }\n}\n`
      )
    );
    expect(
      res.filter((x) => /serially/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
  it('does NOT flag a loop with no I/O await', () => {
    const res = run(
      file(
        'src/sum.js',
        `export async function sum(jobs) {\n  let t = 0;\n  for (const j of jobs) {\n    t += j.value;\n  }\n  await save(t);\n  return t;\n}\nasync function save(t) { return t; }\n`
      )
    );
    expect(
      res.filter((x) => /serially/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
  it('flags forEach(async) and useEffect(async)', () => {
    const res = run(
      file(
        'src/each.jsx',
        `import { useEffect } from 'react';\nexport function useLoad(items, setV) {\n  useEffect(async () => {\n    items.forEach(async (i) => {\n      await fetch('/api/' + i);\n    });\n  }, [items]);\n}\n`
      )
    );
    expect(has(res, /forEach/), titles(res)).toBe(true);
    expect(has(res, /useEffect callback declared async/), titles(res)).toBe(true);
  });
  it('flags a floating known-async call (AST)', () => {
    const res = run(
      file(
        'src/audit.js',
        `export function record(db, entry) {\n  db.insertOne(entry);\n  return true;\n}\n`
      )
    );
    expect(has(res, /not awaited or handled/), titles(res)).toBe(true);
  });
  it('does NOT flag an awaited or returned call', () => {
    const res = run(
      file(
        'src/audit.js',
        `export async function record(db, entry) {\n  await db.insertOne(entry);\n  return db.updateOne(entry);\n}\n`
      )
    );
    expect(
      res.filter((x) => /not awaited/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
});

describe('response and input handling', () => {
  it('flags res.json() without an ok check', () => {
    const res = run(
      file(
        'src/user.js',
        `export async function loadUser(id) {\n  const res = await fetch('/api/user/' + id);\n  return await res.json();\n}\n`
      )
    );
    expect(has(res, /without checking res\.ok/), titles(res)).toBe(true);
  });
  it('does NOT flag when res.ok is checked', () => {
    const res = run(
      file(
        'src/user.js',
        `export async function loadUser(id) {\n  const res = await fetch('/api/user/' + id);\n  if (!res.ok) throw new Error(String(res.status));\n  return await res.json();\n}\n`
      )
    );
    expect(
      res.filter((x) => /res\.ok/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
  it('flags JSON.parse over storage without try', () => {
    const res = run(
      file('src/prefs.js', `export const load = () => JSON.parse(localStorage.getItem('prefs'));\n`)
    );
    expect(has(res, /JSON\.parse on external input/), titles(res)).toBe(true);
  });
  it('flags Promise.all over request-sized input', () => {
    const res = run(
      file(
        'server/import.js',
        `export async function importAll(req, save) {\n  await Promise.all(req.body.items.map((i) => save(i)));\n}\n`
      )
    );
    expect(has(res, /request-sized input/), titles(res)).toBe(true);
  });
});

describe('ownerless rejections', () => {
  it('flags new Promise(async), await/.then mixing, bare async main()', () => {
    const res = run(
      file(
        'src/boot.js',
        `async function main() {\n  const v = await load().then((x) => x.data);\n  const p = new Promise(async (resolve) => {\n    resolve(await v);\n  });\n  return p;\n}\nmain();\nasync function load() { return { data: 1 }; }\n`
      )
    );
    expect(has(res, /async executor/), titles(res)).toBe(true);
    expect(has(res, /await and \.then mixed/), titles(res)).toBe(true);
    expect(has(res, /main\(\) called without \.catch/), titles(res)).toBe(true);
  });
  it('flags a route handler awaiting without try', () => {
    const res = run(
      file(
        'server/routes.js',
        `export function mount(app, db) {\n  app.get('/items', async (req, res) => {\n    const rows = await db.query('select * from items');\n    res.json(rows);\n  });\n}\n`
      )
    );
    expect(has(res, /without a try boundary/), titles(res)).toBe(true);
  });
  it('does NOT flag a handler wrapped in try', () => {
    const res = run(
      file(
        'server/routes.js',
        `export function mount(app, db) {\n  app.get('/items', async (req, res) => {\n    try {\n      const rows = await db.query('select * from items');\n      res.json(rows);\n    } catch (err) {\n      res.status(500).json({ error: 'query failed' });\n    }\n  });\n}\n`
      )
    );
    expect(
      res.filter((x) => /try boundary/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
});

describe('family contract', () => {
  it('never exceeds high, stamps the probe name, survives garbage', () => {
    const res = run(
      file('src/x.js', `for (const a of b) { await fetch(a); }\nitems.forEach(async (x) => x);\n`)
    );
    expect(res.length).toBeGreaterThan(0);
    expect(res.every((x) => ['medium', 'low', 'info'].includes(x.severity))).toBe(true);
    expect(res.every((x) => x.probe === 'Async Correctness')).toBe(true);
    expect(run()).toEqual([]);
    expect(run(file('src/y.js', `async ((( => {`))).toBeInstanceOf(Array);
    expect(run(file('src/__tests__/z.test.js', `items.forEach(async (x) => x);`))).toEqual([]);
  });
});

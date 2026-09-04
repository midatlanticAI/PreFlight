// src/test/v2-errors.test.js — F3 Error Handling family suite.
import { describe, it, expect } from 'vitest';
import { probeErrorHandling } from '../lib/probes/v2/errors.js';

const file = (path, content) => ({ path, content });
const run = (...files) => probeErrorHandling(files);
const has = (res, re) => res.some((x) => re.test(x.title));
const titles = (res) => res.map((x) => `${x.severity}:${x.title}`).join(' | ');

describe('swallows and silent defaults', () => {
  it('flags an empty catch', () => {
    const res = run(
      file(
        'src/save.js',
        `export async function save(d) {\n  try {\n    await push(d);\n  } catch (err) {}\n}\nasync function push(d) { return d; }\n`
      )
    );
    expect(has(res, /Empty catch/), titles(res)).toBe(true);
  });
  it('drops a commented best-effort swallow to low', () => {
    const res = run(
      file(
        'src/rm.js',
        `export async function rm(p) {
  try {
    await del(p);
  } catch (removeError) {
    // best effort: the temp file may already be gone
  }
}
async function del(p) { return p; }
`
      )
    );
    const hit = res.find((x) => /swallows/.test(x.title));
    expect(hit, titles(res)).toBeDefined();
    expect(hit.severity).toBe('low');
  });
  it('bare catch returning a default teaches at info', () => {
    const res = run(
      file(
        'src/opt.js',
        `export function readPrefs() {
  try {
    return JSON.parse(process.env.PREFS);
  } catch {
    return null;
  }
}
`
      )
    );
    const hit = res.find((x) => /returns a default/.test(x.title));
    expect(hit, titles(res)).toBeDefined();
    expect(hit.severity).toBe('info');
  });
  it('flags console-only catch as a swallow', () => {
    const res = run(
      file(
        'src/save.js',
        `export async function save(d) {\n  try {\n    await push(d);\n  } catch (err) {\n    console.log(err);\n  }\n}\nasync function push(d) { return d; }\n`
      )
    );
    expect(has(res, /swallows the error/), titles(res)).toBe(true);
  });
  it('does NOT flag a catch that sets error state', () => {
    const res = run(
      file(
        'src/save.js',
        `export async function save(d, setError) {\n  try {\n    await push(d);\n  } catch (err) {\n    setError(err instanceof Error ? err.message : 'save failed');\n  }\n}\nasync function push(d) { return d; }\n`
      )
    );
    expect(
      res.filter((x) => /swallows|Empty/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
  it('flags a catch returning a silent default', () => {
    const res = run(
      file(
        'src/load.js',
        `export async function load() {\n  try {\n    return await getAll();\n  } catch (err) {\n    return [];\n  }\n}\nasync function getAll() { return [1]; }\n`
      )
    );
    expect(has(res, /returns a default/), titles(res)).toBe(true);
  });
  it('flags .catch(console.error)', () => {
    const res = run(
      file('src/fire.js', `send().catch(console.error);\nasync function send() {}\n`)
    );
    expect(has(res, /logged and dropped/), titles(res)).toBe(true);
  });
});

describe('signal damage and structure', () => {
  it('flags throw of a string and a bare rethrow', () => {
    const res = run(
      file(
        'src/v.js',
        `export function check(v) {\n  try {\n    if (!v) throw 'missing value';\n    return v;\n  } catch (e) {\n    throw e;\n  }\n}\n`
      )
    );
    expect(has(res, /Non-Error value thrown/), titles(res)).toBe(true);
    expect(has(res, /only rethrows/), titles(res)).toBe(true);
  });
  it('flags a stack-dropping rethrow', () => {
    const res = run(
      file(
        'src/w.js',
        `export async function w(job) {\n  try {\n    return await job();\n  } catch (e) {\n    throw new Error(e.message);\n  }\n}\n`
      )
    );
    expect(has(res, /drops the stack/), titles(res)).toBe(true);
  });
  it('flags cleanup-in-catch (try/finally-no-catch was removed on corpus evidence)', () => {
    const res = run(
      file(
        'src/db.js',
        `export async function q(pool, sql) {\n  const conn = await pool.acquire();\n  try {\n    return await conn.query(sql);\n  } finally {\n    conn.release();\n  }\n}\nexport async function q2(conn, sql) {\n  try {\n    return await conn.query(sql);\n  } catch (e) {\n    conn.close();\n    throw new Error('query failed', { cause: e });\n  }\n}\n`
      )
    );
    expect(
      res.filter((x) => /no catch/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
    expect(has(res, /catch, not finally/), titles(res)).toBe(true);
  });
  it('flags a python open() outside with', () => {
    const res = run(file('scripts/etl.py', `f = open("data.csv")\nrows = f.read()\nf.close()\n`));
    expect(has(res, /without a with block/), titles(res)).toBe(true);
  });
  it('does NOT flag with open(...)', () => {
    const res = run(file('scripts/etl.py', `with open("data.csv") as f:\n    rows = f.read()\n`));
    expect(res, titles(res)).toHaveLength(0);
  });
});

describe('the missing boundary', () => {
  it('flags a React app with no error boundary', () => {
    const jsx = (n) => file(`src/C${n}.jsx`, `export const C${n} = () => <div>c${n}</div>;\n`);
    const res = run(jsx(1), jsx(2), jsx(3), jsx(4));
    expect(has(res, /No error boundary/), titles(res)).toBe(true);
  });
  it('does NOT flag when a boundary exists', () => {
    const jsx = (n) => file(`src/C${n}.jsx`, `export const C${n} = () => <div>c${n}</div>;\n`);
    const res = run(
      jsx(1),
      jsx(2),
      jsx(3),
      file(
        'src/Boundary.jsx',
        `import { ErrorBoundary } from 'react-error-boundary';\nexport const Root = ({ children }) => <ErrorBoundary fallback={<p>failed</p>}>{children}</ErrorBoundary>;\n`
      )
    );
    expect(
      res.filter((x) => /boundary/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
});

describe('family contract', () => {
  it('never exceeds high, stamps the probe, survives garbage and tests', () => {
    const res = run(file('src/x.js', `try {\n  await a();\n} catch (e) {}\n`));
    expect(res.length).toBeGreaterThan(0);
    expect(res.every((x) => ['medium', 'low', 'info'].includes(x.severity))).toBe(true);
    expect(res.every((x) => x.probe === 'Error Handling')).toBe(true);
    expect(run()).toEqual([]);
    expect(run(file('src/y.js', `catch catch {{{`))).toBeInstanceOf(Array);
    expect(run(file('src/x.spec.js', `try { a(); } catch (e) {}`))).toEqual([]);
  });
});

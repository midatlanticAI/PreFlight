// Functional tests for the v0.5 OWASP-framed probe additions in src/lib/probes/v05.js.
// Mirror of the per-probe coverage in probes.test.js but kept separate so the v05
// module is self-contained at the test layer too.

import { describe, it, expect } from 'vitest';
import {
  probeSQLInjectionTemplateLiterals,
  probePathTraversal,
  probeWeakRandomness,
  probeStackTraceLeaks,
  probeSubresourceIntegrity,
} from '../lib/probes/v05.js';

const file = (path, content) => ({ path, content });

describe('probeSQLInjectionTemplateLiterals', () => {
  it('flags db.query with template-literal interpolation', () => {
    const f = probeSQLInjectionTemplateLiterals([
      file('src/api/users.js', 'const r = await db.query(`SELECT * FROM users WHERE id = ${id}`);'),
    ]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
    expect(f[0].cwe).toBe('CWE-89');
  });

  it('flags client.execute with template-literal interpolation', () => {
    const f = probeSQLInjectionTemplateLiterals([
      file('src/db.ts', 'await client.execute(`INSERT INTO orders VALUES (${id}, ${total})`);'),
    ]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('does NOT flag parameterized sql`...` tagged template (postgres / slonik convention)', () => {
    const f = probeSQLInjectionTemplateLiterals([
      file('src/db.js', 'const rows = await sql`SELECT * FROM users WHERE id = ${id}`;'),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag db.query with no interpolation', () => {
    const f = probeSQLInjectionTemplateLiterals([
      file('src/db.js', 'await db.query(`SELECT 1`);'),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag in test files', () => {
    const f = probeSQLInjectionTemplateLiterals([
      file('src/test/foo.test.js', 'await db.query(`SELECT * FROM users WHERE id = ${id}`);'),
    ]);
    expect(f).toEqual([]);
  });
});

describe('probePathTraversal', () => {
  it('flags fs.readFile built from req.body input', () => {
    const f = probePathTraversal([
      file('src/api/download.js', `
        export async function POST(req) {
          const { name } = req.body;
          const content = await fs.readFile(path.join('/var/uploads', name), 'utf8');
          return Response.json({ content });
        }
      `),
    ]);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].cwe).toBe('CWE-22');
  });

  it('does NOT flag fs.readFile against a hardcoded path', () => {
    const f = probePathTraversal([
      file('src/api/config.js', 'const c = await fs.readFile("/etc/config.json", "utf8");'),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag when path.normalize / allowlist is nearby', () => {
    const f = probePathTraversal([
      file('src/api/safe.js', `
        const ALLOWED = new Set(['a.md', 'b.md']);
        const { name } = req.body;
        if (!ALLOWED.has(name)) return new Response('not found', { status: 404 });
        const c = await fs.readFile(path.join('/var/docs', name), 'utf8');
      `),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag in test files', () => {
    const f = probePathTraversal([
      file('src/test/foo.test.js', 'const c = await fs.readFile(req.body.path);'),
    ]);
    expect(f).toEqual([]);
  });
});

describe('probeWeakRandomness', () => {
  it('flags Math.random in a token-generation context', () => {
    const f = probeWeakRandomness([
      file(
        'src/auth/reset.js',
        `
        function generateResetToken() {
          return Math.random().toString(36).slice(2);
        }
      `
      ),
    ]);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].cwe).toBe('CWE-338');
  });

  it('flags Math.random near "secret" / "csrf" / "session"', () => {
    const f = probeWeakRandomness([
      file('src/csrf.js', 'const csrf = Math.random().toString(36);'),
    ]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('does NOT flag Math.random in animation context', () => {
    const f = probeWeakRandomness([
      file(
        'src/anim.js',
        `
        function jitter() {
          const delay = Math.random() * 200;
          return delay;
        }
      `
      ),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag Math.random without a security context', () => {
    const f = probeWeakRandomness([file('src/x.js', 'const n = Math.random();')]);
    expect(f).toEqual([]);
  });

  it('does NOT flag in test files', () => {
    const f = probeWeakRandomness([
      file('src/test/foo.test.js', 'const token = Math.random();'),
    ]);
    expect(f).toEqual([]);
  });
});

describe('probeStackTraceLeaks', () => {
  it('flags res.json that includes err.stack', () => {
    const f = probeStackTraceLeaks([
      file(
        'src/api/users.js',
        `
        app.get('/users', async (req, res) => {
          try { await loadUsers(); } catch (err) {
            res.status(500).json({ error: err.message, stack: err.stack });
          }
        });
      `
      ),
    ]);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].cwe).toBe('CWE-209');
  });

  it('flags Response.json that includes err.stack', () => {
    const f = probeStackTraceLeaks([
      file(
        'src/api/route.ts',
        `
        export async function GET(req) {
          try { return Response.json(await doThing()); }
          catch (err) { return Response.json({ error: String(err), stack: err.stack }, { status: 500 }); }
        }
      `
      ),
    ]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('does NOT flag when behind a NODE_ENV !== "production" guard', () => {
    const f = probeStackTraceLeaks([
      file(
        'src/api/route.js',
        `
        app.use((err, req, res, next) => {
          const body = { error: 'Internal Server Error' };
          if (process.env.NODE_ENV !== 'production') {
            body.stack = err.stack;
          }
          res.status(500).json(body);
        });
      `
      ),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag in test files', () => {
    const f = probeStackTraceLeaks([
      file('src/test/foo.test.js', 'res.status(500).json({ stack: err.stack });'),
    ]);
    expect(f).toEqual([]);
  });
});

describe('probeSubresourceIntegrity', () => {
  it('flags cross-origin <script src> missing integrity', () => {
    const f = probeSubresourceIntegrity([
      file('index.html', '<script src="https://cdn.example/lib.js"></script>'),
    ]);
    expect(f.length).toBe(1);
    expect(f[0].cwe).toBe('CWE-353');
  });

  it('flags cross-origin <link rel="stylesheet"> missing integrity', () => {
    const f = probeSubresourceIntegrity([
      file('index.html', '<link rel="stylesheet" href="https://cdn.example/styles.css">'),
    ]);
    expect(f.length).toBe(1);
  });

  it('does NOT flag cross-origin script WITH integrity', () => {
    const f = probeSubresourceIntegrity([
      file(
        'index.html',
        '<script src="https://cdn.example/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>'
      ),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag same-origin scripts', () => {
    const f = probeSubresourceIntegrity([
      file('index.html', '<script src="/static/app.js"></script>'),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag relative-path scripts', () => {
    const f = probeSubresourceIntegrity([
      file('index.html', '<script src="./app.js"></script>'),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag in test files', () => {
    const f = probeSubresourceIntegrity([
      file('src/test/foo.test.js', '<script src="https://cdn.example/lib.js"></script>'),
    ]);
    expect(f).toEqual([]);
  });
});

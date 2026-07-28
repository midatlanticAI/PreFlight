/**
 * SQL injection: the wrapped call and the two-step build.
 *
 * Both were silent, and both are how the code is actually written. Prettier
 * puts the template on the line after `db.query(`, and a query long enough to
 * be worth wrapping is a query long enough to be worth naming, so
 * `const sql = ...; db.query(sql)` is the normal shape rather than the clever
 * one. The regex probe needed the backtick on the callee's line; the taint
 * engine had a shell sink and a filesystem sink but no SQL sink, which is why
 * the identical two-step shape was caught for exec and invisible for queries.
 *
 * The negatives matter more than the positives here. Every one of them is a
 * fix this probe recommends, and `db.query(text, [id])` in particular is the
 * parameterised form: flagging it would report the fix as the bug.
 */

import { describe, it, expect } from 'vitest';
import { probeSQLInjectionTemplateLiterals, probeTaintFlow } from '../lib/probes.js';

const f = (content, path = 'server/routes/users.js') => [{ path, content }];
const sqlish = (findings) => findings.filter((x) => /sql|inject/i.test(`${x.probe} ${x.title}`));

describe('SQL injection — the wrapped call', () => {
  const cases = [
    [
      'template opens on the next line',
      'export async function h(req){\n  const r = await db.query(\n    `SELECT * FROM users WHERE id = ${req.params.id}`\n  );\n  return r;\n}\n',
    ],
    [
      'prettier wraps the query over several lines',
      'export async function h(req){\n  const r = await db.query(\n\n    `SELECT *\n     FROM users\n     WHERE id = ${req.params.id}`\n  );\n  return r;\n}\n',
    ],
    [
      'a comment sits between the paren and the literal',
      'export async function h(req){\n  const r = await db.query(\n    // the id comes from the route\n    `SELECT * FROM users WHERE id = ${req.params.id}`\n  );\n  return r;\n}\n',
    ],
    [
      'concatenation into $executeRawUnsafe',
      'export async function h(t){\n  return prisma.$executeRawUnsafe("DELETE FROM e WHERE t = " + t);\n}\n',
    ],
    [
      // The quote that makes the injection worse is what used to hide it: the
      // literal class terminated at the first quote of either kind, so the
      // inner ' ended the match before it reached the +.
      'the literal contains the quote that closes the SQL string',
      'export async function h(req){\n  return db.query("SELECT * FROM t WHERE a = \'" + req.query.x + "\'");\n}\n',
    ],
  ];
  for (const [name, src] of cases) {
    it(name, () => {
      expect(sqlish(probeSQLInjectionTemplateLiterals(f(src)))).not.toHaveLength(0);
    });
  }
});

describe('SQL injection — the two-step build', () => {
  it('a template assembled into a const then queried', () => {
    const src =
      'export async function h(req){\n  const sql = `SELECT * FROM users WHERE id = ${req.params.id}`;\n  return db.query(sql);\n}\n';
    expect(probeTaintFlow(f(src)).some((x) => x.cwe === 'CWE-89')).toBe(true);
  });

  it('a concatenation assembled into a const then queried', () => {
    const src =
      'export async function h(req){\n  const email = req.query.email;\n  const sql = "SELECT id FROM c WHERE email=\'" + email + "\'";\n  return db.query(sql);\n}\n';
    expect(probeTaintFlow(f(src)).some((x) => x.cwe === 'CWE-89')).toBe(true);
  });
});

describe('SQL injection — the fixes stay silent', () => {
  const safe = [
    [
      'parameterised query',
      'export async function h(req){\n  return db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);\n}\n',
    ],
    // The bound parameter is argument two. A sink that read every argument
    // would report this, which is the fix, as the bug.
    [
      'two-step with bound parameters',
      'export async function h(req){\n  const sql = "SELECT * FROM users WHERE id = $1";\n  return db.query(sql, [req.params.id]);\n}\n',
    ],
    [
      'a wrapped template with nothing interpolated',
      'export async function h(){\n  return db.query(\n    `SELECT id FROM users`\n  );\n}\n',
    ],
    [
      '$queryRawUnsafe with bound parameters',
      'export async function h(req){\n  return prisma.$queryRawUnsafe("SELECT * FROM t WHERE a = $1", req.query.x);\n}\n',
    ],
    [
      'a knex builder chain',
      'export async function h(req){\n  return knex("users").where({ id: req.params.id });\n}\n',
    ],
    [
      'concatenation of a module constant',
      'const TABLE = "users";\nexport async function h(){\n  return db.query("SELECT * FROM " + TABLE);\n}\n',
    ],
  ];
  for (const [name, src] of safe) {
    it(name, () => {
      expect(sqlish(probeSQLInjectionTemplateLiterals(f(src)))).toHaveLength(0);
      expect(probeTaintFlow(f(src)).filter((x) => x.cwe === 'CWE-89')).toHaveLength(0);
    });
  }
});

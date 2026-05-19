---
title: SQL injection via template literals
slug: sql-injection
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - SQL Injection
sources:
  - title: OWASP A03 — Injection
    url: https://owasp.org/Top10/A03_2021-Injection/
  - title: OWASP SQL Injection Prevention Cheat Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
  - title: CWE-89 — SQL Injection
    url: https://cwe.mitre.org/data/definitions/89.html
  - title: Bobby Tables — query parameterization by language
    url: https://bobby-tables.com/
summary: A `db.query(\`SELECT ... ${user}\`)` interpolates untrusted input into the SQL string at parse time. Switch to parameterized queries. The fix is one line per call site.
---

## What this is

```ts
// Injection waiting for an attacker.
const user = req.query.username;
const rows = await db.query(`SELECT * FROM users WHERE name = '${user}'`);
```

`user` is a string the attacker controls. Sending `?username=' OR '1'='1` produces:

```sql
SELECT * FROM users WHERE name = '' OR '1'='1'
```

Every row returned. With `; DROP TABLE users; --`, the second statement runs (depending on driver). With `' UNION SELECT password FROM admins --`, every admin password returned. The variants are well documented.

The reason this works: the database parser sees one big string. It cannot tell which characters came from the developer and which came from the user. The fix removes that ambiguity entirely by sending the structure and the values separately.

## Why it matters

SQL injection is one of the oldest vulnerability classes and still in the OWASP Top 10. The blast radius is the whole database the query has access to. For a typical SaaS, that includes every user row, every payment record, every internal table the application user can touch.

In AI-built apps the pattern appears most often because:

- Tutorials use template literals as the shortest example that "works."
- The model defaults to the same shortest example.
- The viber pasting the output sees a working endpoint and ships it.

ORMs (Prisma, Drizzle, Knex) make the correct pattern just as short, but the path of least resistance for someone unfamiliar with the ORM is `db.query()` with interpolation.

## What the failure looks like

PreFlight scans `.js` / `.jsx` / `.ts` / `.tsx` / `.py` / `.go` source for two shapes:

- **High-confidence**: `db.query(\`...${...}...\`)`, `client.execute(...)`, `connection.raw(...)`, and similar with template-literal arguments containing interpolations.
- **Heuristic**: bare `query(\`...\`)`or`execute(\`...\`)` calls where the template contains SQL keywords (`SELECT`, `INSERT`, `UPDATE`, `DELETE`).

Tagged template literals from known parameterizing libraries (the `sql` tag from `postgres`, `slonik`, Drizzle's `sql`) are explicitly allowlisted; those tags do parameterize the interpolations.

## What the fix looks like

**Driver-level parameterized queries.**

```ts
// pg
const { rows } = await db.query('SELECT * FROM users WHERE name = $1', [user]);

// mysql2
const [rows] = await db.execute('SELECT * FROM users WHERE name = ?', [user]);

// sqlite (better-sqlite3)
const rows = db.prepare('SELECT * FROM users WHERE name = ?').all(user);
```

Each driver has its own placeholder syntax (`$1`, `?`, `:name`). The shape is identical: the SQL string contains placeholders; the values arrive separately. The database parses the SQL once and binds the values without re-parsing.

**ORM-level.**

```ts
// Prisma
const user = await prisma.user.findUnique({ where: { name: userName } });

// Drizzle
const result = await db.select().from(users).where(eq(users.name, userName));

// Knex
const rows = await knex('users').where('name', userName);
```

Every modern ORM treats parameterization as the default. You get it for free.

**Parameterizing tagged templates.**

```ts
// `postgres` library
import postgres from 'postgres';
const sql = postgres();
const rows = await sql`SELECT * FROM users WHERE name = ${userName}`;
```

This looks like the unsafe pattern but is not. The `sql` tag preprocesses the template to extract the interpolations as parameters before sending to the database. PreFlight allowlists the `sql`, `pg`, `postgres`, `slonik`, and `drizzle` tags by name; if you build your own tagged-template wrapper, ensure it parameterizes and consider naming it consistently so the probe recognizes it.

## When raw SQL is genuinely needed

Migrations and admin scripts sometimes need raw DDL or special-case queries. Two rules:

- Migrations should not contain user input. The schema is fixed; the values come from the developer.
- Admin scripts that genuinely need to interpolate (a dynamic column name from a config) should validate the input against an explicit allowlist before substituting.

```ts
const ALLOWED_COLUMNS = new Set(['name', 'email', 'created_at']);
if (!ALLOWED_COLUMNS.has(orderBy)) throw new Error('invalid column');
const rows = await db.query(`SELECT * FROM users ORDER BY ${orderBy} DESC`);
```

The column name is interpolated only after passing the allowlist. The user does not get to invent column names.

## Related

- [API route auth](/learn/patterns/api-route-auth) covers the authorization layer SQL-touching endpoints sit on top of.
- [AI code smells](/learn/patterns/ai-code-smells) covers `any` types that often co-locate with unparameterized SQL.

## Sources

OWASP A03:2021 ranks injection vulnerabilities in the top tier. The OWASP SQL injection prevention cheat sheet is the canonical defensive reference. CWE-89 names the class. Bobby Tables documents the parameterization syntax for every common driver and language.

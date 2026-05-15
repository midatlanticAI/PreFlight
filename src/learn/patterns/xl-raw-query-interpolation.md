---
title: Raw query interpolation (XL-002)
slug: xl-raw-query-interpolation
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Python Raw SQL Interpolation
  - JS SQL Injection (XL-002)
sources:
  - title: CWE-89 — SQL Injection
    url: https://cwe.mitre.org/data/definitions/89.html
  - title: OWASP A03 — Injection
    url: https://owasp.org/Top10/A03_2021-Injection/
  - title: OWASP SQL Injection Prevention Cheat Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
  - title: Bobby Tables — parameterization by language
    url: https://bobby-tables.com/
summary: An f-string, percent-format, .format(), or string concat that feeds a raw-SQL surface puts the user value into the query at parse time instead of binding it as data. The shared family is XL-002; adapters differ only in which raw-SQL call each language exposes.
---

## What this is

A SQL string and the values inside it are two different things. A
parameterized query sends the string to the database to be parsed once,
then sends the values separately to be treated strictly as data. String
interpolation collapses that separation: the user value becomes part of
the text the database parses, so a value containing SQL syntax becomes
SQL.

The raw-SQL surface differs by language and framework, the bug does not:

- Python: `cursor.execute(f"...{x}")`, Django `.extra(where=[f"..."])`,
  `RawSQL(f"...")`, `Model.objects.raw(f"...")`, SQLAlchemy
  `text(f"...")`.
- Go: `db.Query(fmt.Sprintf("...%s", x))`.
- Java: `createQuery("..." + x)`.
- Ruby: `where("name = '#{x}'")`, `find_by_sql`.
- PHP: `$pdo->query("... $x")` without a prepare.

Same family (XL-002), one concept, per-language detectors.

## Why AI emits it

Autocomplete optimizes for the shortest legible line. An f-string is
shorter and reads more naturally than a bound parameter, so "filter where
the column equals a user value with a complex condition" produces
interpolation before it produces a placeholder. The parameterized API is
more verbose, so the model skips it unless explicitly told to be secure,
and often even then.

## The mental model that produces the bug

"The query is just a string and the value goes in the string." There is
no model of parse-time versus bind-time. The user value is treated as
text to format, not as data to hand the driver separately.

## What the fix looks like

Bind the value as a parameter. The placeholder syntax differs by driver;
the principle does not.

- DB-API: `cursor.execute("... WHERE x = %s", [value])`.
- Django: `Model.objects.raw("... %s", [value])`, or stay in the ORM.
- SQLAlchemy: `text("... :id").bindparams(id=value)`.
- Go: `db.Query("... WHERE x = $1", value)`.

The value never enters the SQL text. The driver parses the query once and
treats every bound value as opaque data. A value full of quotes and
semicolons is then just a string that does not match a row.

## Related

- [Unsafe deserialization](/learn/patterns/xl-unsafe-deserialization)
  is the same boundary blindness applied to object bytes.

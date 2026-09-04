---
title: Database patterns
slug: database-patterns
type: pattern
last_updated: 2026-09-03
draft: false
related_probe_ids:
  - Database Patterns
sources:
  - title: 'PostgreSQL — UPDATE'
    url: https://www.postgresql.org/docs/current/sql-update.html
  - title: 'PostgreSQL — CREATE TABLE (IF NOT EXISTS)'
    url: https://www.postgresql.org/docs/current/sql-createtable.html
  - title: 'Prisma — Transactions'
    url: https://www.prisma.io/docs/orm/prisma-client/queries/transactions
summary: Statements that behave until the data does. UPDATE and DELETE with no WHERE touch every row every time. A migration without IF NOT EXISTS wedges on its first retry. Two dependent writes without a transaction leave half a change when the second one fails.
---

## What this is

Database code has a property UI code does not: the blast radius of a small mistake is the whole table. These are the three shapes where generated code routinely writes the small mistake.

## Why it matters

**`UPDATE users SET credits = 0`** with no WHERE is the classic "reset one user, reset them all". It runs clean in the demo where the table holds one row.

**A migration that cannot run twice** turns a half-applied deploy into a wedged migration chain: the retry hits "already exists" and everything behind it queues up.

**Two dependent writes, no transaction**: the order lands and its items do not, the debit posts and the credit does not. A transaction makes them one decision.

## What the probe does not do

Row-level security is owned by the Supabase RLS probe, SQL built by interpolation is owned by the injection probes, and query-in-loop is owned by Async Correctness. Whether a Prisma field is unique lives in the schema, so findUnique misuse is out of scope.

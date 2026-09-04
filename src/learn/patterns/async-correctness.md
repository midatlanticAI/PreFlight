---
title: Async correctness
slug: async-correctness
type: pattern
last_updated: 2026-09-03
draft: false
related_probe_ids:
  - Async Correctness
sources:
  - title: 'MDN — Using promises'
    url: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Using_promises
  - title: 'MDN — fetch() and response.ok'
    url: https://developer.mozilla.org/en-US/docs/Web/API/Response/ok
  - title: 'MDN — Promise.all()'
    url: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/all
  - title: 'Node.js — Unhandled rejections'
    url: https://nodejs.org/api/process.html#event-unhandledrejection
summary: The event loop is the engine block, and await is not an incantation. Serialized loops that wanted to be parallel, forEach callbacks whose promises fall on the floor, fetch chains that crash on the first 500, rejections nobody owns. The shape of the code barely changes; the cost does.
---

## What this is

`await` reads like it makes asynchrony go away. It does not; it schedules it. AI tools lean on the reading, so generated code awaits inside loops when it meant to fan out, passes async callbacks to `forEach` which cannot wait for them, parses fetch responses that arrived as error pages, and starts work whose failure nobody will ever hear about.

## Why it matters

**A loop with await runs single-file.** Ten items, ten round trips, one at a time: the total is the sum of every latency. `await Promise.all(items.map(async ...))` runs them together. The code barely changes; the bill does. Independent analysis of AI-authored pull requests found excessive serialized I/O among the most common generated defects.

**`forEach` cannot wait.** It ignores the promises its callback returns, so nothing downstream waits for the work and a rejection in any iteration is unhandled. `for...of` awaits in order; `Promise.all` over a `map` fans out.

**`fetch` only rejects on network failure.** A 500 resolves normally, `res.json()` then throws on an HTML error page, or worse, hands back an error body as data. The check is one line: `if (!res.ok) throw new Error(String(res.status))`.

**Rejections need an owner.** An async `main()` invoked bare, a save started in statement position and never awaited, an effect callback declared `async` so React mistakes its promise for a cleanup function. Each is a place a real failure becomes silence.

## What the probe looks for

- Awaited I/O inside `for`/`while` loops. If iterations genuinely depend on each other, mark the loop with `/* serial */` and the finding stands down.
- `.forEach(async ...)` and `useEffect(async ...)`.
- `new Promise(async ...)`: a throw inside rejects the wrong promise.
- `Promise.all` fanned out over request-sized input, which hands your concurrency limit to the caller.
- Fetch responses parsed without an `ok`/`status` check, and `JSON.parse` over storage or request input with no try.
- Route handlers that await with no try boundary, async `main()` with no `.catch`, and known-async calls whose result is dropped in statement position.

## What the probe does not do

Without type information it cannot know whether an arbitrary call returns a promise, so the floating-promise check names only a small set of unambiguous callees rather than guessing. Whether a `Promise.race` arm is a timeout, and whether an awaited value was a promise at all, are type facts it declines to invent.

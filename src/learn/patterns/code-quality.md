---
title: Code quality signals
slug: code-quality
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Code Quality
  - AI Code Smells
sources:
  - title: 'CWE-489 — Active Debug Code'
    url: https://cwe.mitre.org/data/definitions/489.html
  - title: 'Node.js — Best practices for unhandled promise rejection'
    url: https://nodejs.org/api/process.html#event-unhandledrejection
  - title: 'MDN — try...catch with async/await'
    url: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function
summary: Four signals that correlate with sloppy code paths in production: console.log in shipped code, oversized files, unhandled promise rejections, and async without try. Not security findings on their own; they cluster with security findings.
---

## What this is

Four code-quality signals Pre-Flight scans for:

**`console.log` (and friends) in production code paths.** Console statements left in code:

- bloat the bundle (minifiers don't always strip them);
- leak diagnostic data to user DevTools (sometimes including secrets);
- confuse users who happen to open DevTools.

The probe excludes test files and explicit debug paths.

**Oversized files.** A single source file over ~1500 lines is a yellow signal; over ~5000 lines is a red one. Oversized files correlate with the developer (or AI tool) having lost track of what's in the file, which correlates with security gaps slipping past review.

**Unhandled promise rejections.** A promise without a `.catch()` or `await` inside `try {}`:

```ts
fetch('/api/foo').then(r => r.json()).then(processData);
// network error or processData throws? Unhandled rejection.
```

Unhandled rejections cause silent data loss in browsers and process crashes in Node 15+.

**`async` without `try`:**

```ts
async function handle(req) {
  const data = await fetch('/api/foo').then(r => r.json());
  return data.value;
}
```

If anything throws, the function rejects. The caller may or may not handle it. Often: not.

## Why it matters

None of these are security vulnerabilities individually. They are signals of code paths where the developer was not thinking about failure modes, which correlates strongly with security issues clustering nearby. An empty catch (covered in [AI Code Smells](/learn/patterns/ai-code-smells)) plus an unhandled rejection plus a missing input validation usually appear together.

The console.log finding is slightly different. Leaving `console.log(userToken)` in production code path is a direct credential leak: every user with DevTools open sees the token printed in their console.

## What the failure looks like

Pre-Flight scans for:

- `console.log`, `console.debug`, `console.info`, `console.warn`, `console.error`, `console.trace` in production-source files (not in `src/test/`, not in scripts excluded by the project's preflight-config).
- Source files over `FILE_SIZE_WARN_LINES` (1500) and `FILE_SIZE_FAIL_LINES` (5000) thresholds.
- Promise chains without trailing `.catch()`.
- `async` functions whose body lacks any `try` block when the body contains `await` calls.

## What the fix looks like

**Console statements:** route through a logger that respects an env-driven log level, or strip at build time.

```ts
import { log } from '@/lib/logger';
log.debug('charging', { amount });  // dev only
```

Or in Vite:

```ts
// vite.config.js
define: {
  'console.log': process.env.NODE_ENV === 'production' ? '(()=>{})' : 'console.log',
}
```

**Oversized files:** split by responsibility. A 3000-line `App.jsx` typically contains a router, two or three views, a handful of hooks, and several formatters. Each becomes its own file with a clear export.

**Unhandled promises:**

```ts
fetch('/api/foo')
  .then(r => r.json())
  .then(processData)
  .catch(e => log.error('foo fetch failed', e));
```

Or:

```ts
try {
  const data = await (await fetch('/api/foo')).json();
  processData(data);
} catch (e) {
  log.error('foo fetch failed', e);
}
```

**Async without try:** decide what should happen on throw and write that.

```ts
async function handle(req) {
  try {
    const data = await (await fetch('/api/foo')).json();
    return data.value;
  } catch (e) {
    log.error('handle failed', { req, error: e });
    throw new HandlerError({ cause: e });
  }
}
```

## Related

- [AI code smells](/learn/patterns/ai-code-smells) covers empty catch blocks and `any` types, which co-locate with these signals.
- [Hardcoded secrets in source](/learn/patterns/secret-scanner) covers the case where `console.log` accidentally prints a credential.

## Sources

CWE-489 covers active debug code (console.log being the most common form). MDN's async/await error-handling docs cover the unhandled-promise pattern.

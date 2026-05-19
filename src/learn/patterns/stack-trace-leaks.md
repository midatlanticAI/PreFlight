---
title: Stack traces in production error responses
slug: stack-trace-leaks
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Stack Trace Leaks
sources:
  - title: OWASP A09 — Security Logging and Monitoring Failures
    url: https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
  - title: OWASP A04 — Insecure Design
    url: https://owasp.org/Top10/A04_2021-Insecure_Design/
  - title: CWE-209 — Generation of Error Message Containing Sensitive Information
    url: https://cwe.mitre.org/data/definitions/209.html
  - title: CWE-497 — Exposure of Sensitive System Information
    url: https://cwe.mitre.org/data/definitions/497.html
summary: An error handler that returns `err.stack` to the client leaks file paths, dependency versions, and call chains. The fix is one if-statement away.
---

## What this is

```ts
// Leaks server internals.
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});
```

Or in Next.js:

```ts
export async function GET(req: Request) {
  try {
    return Response.json(await doThing());
  } catch (err) {
    return Response.json({ error: String(err), stack: err.stack }, { status: 500 });
  }
}
```

When the function throws, the response includes the full Error stack. The stack contains:

- The file path the error was thrown from, including the server's working directory.
- The node_modules path, often disclosing the dependency manager (`pnpm-store`, `.yarn/cache`).
- Line and column numbers in your source.
- The package versions of every library on the call stack.
- Sometimes the literal arguments to the failing call (in V8-style format).

A request that probes for an error condition (a bad JSON body, a missing query param, an invalid ID) returns the full stack on the unhandled branch. The attacker learns the server's directory layout, the framework versions, and the call structure. None of this is dangerous individually; together it accelerates exploitation by hours.

## Why it matters

Stack-trace exposure is the reconnaissance side of an attack chain. The vulnerability that lets the attacker into the system might be unrelated; the stack trace tells them which CVEs to look up, which file paths to try, and which library versions to target. CWE-209 (generation of error message containing sensitive information) is the named class.

The pattern also degrades observability: when the same error response that the client gets is the one being logged, two failure modes get conflated, and the developer has less to work with when triaging real production issues.

## What the failure looks like

PreFlight scans for response writes (`res.send`, `res.json`, `res.body =`, `Response.json`, `new Response`, `ctx.json`, `reply.send`) where the body contains `err.stack`, `error.stack`, `e.stack`, or `JSON.stringify(err)` (which serializes the stack along with the message).

Cases inside `if (process.env.NODE_ENV !== 'production')` guards or `__DEV__` / `isDev` checks are explicitly skipped. Those are intentional dev surfaces.

## What the fix looks like

**Two-channel error handling.** Log the full error server-side; return a sanitized response to the client.

```ts
import { log } from './lib/logger';

app.use((err, req, res, next) => {
  // 1. Log everything server-side
  log.error('request failed', {
    path: req.path,
    method: req.method,
    error: { message: err.message, stack: err.stack, code: err.code },
  });

  // 2. Return a generic, opaque response to the client
  res.status(500).json({ error: 'Internal Server Error', requestId: req.id });
});
```

The client gets the status code and a request ID (so support can correlate user-reported issues to log entries). The server keeps the stack trace, the timing, the headers, and everything else useful for diagnosis.

**For Next.js route handlers:**

```ts
export async function GET(req: Request) {
  try {
    return Response.json(await doThing());
  } catch (err) {
    log.error('GET /foo failed', { error: err });
    return Response.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
```

**Express plus dev convenience.** If the team wants the rich error response during development:

```ts
app.use((err, req, res, next) => {
  log.error('request failed', { error: err });
  const body = { error: 'Internal Server Error' };
  if (process.env.NODE_ENV !== 'production') {
    body.message = err.message;
    body.stack = err.stack;
  }
  res.status(500).json(body);
});
```

The `process.env.NODE_ENV !== 'production'` gate is the load-bearing check. PreFlight skips findings inside this guard.

## A related anti-pattern: 4xx errors that leak

The pattern shows up for non-500 errors too. A `400 Bad Request` that includes a Zod validation report can disclose the entire schema (every accepted field, the type of each). That is sometimes useful for legitimate clients and sometimes a reconnaissance gift for an attacker. The same two-channel approach applies: log the full validation report, return a minimal-field response.

```ts
const result = schema.safeParse(body);
if (!result.success) {
  log.warn('validation failed', { errors: result.error.flatten() });
  return Response.json({ error: 'Invalid request body' }, { status: 400 });
}
```

## Related

- [API route auth](/learn/patterns/api-route-auth) covers the authorization layer that prevents most error-disclosure attacks from being useful.
- [Code quality](/learn/patterns/code-quality) covers the broader observability discipline around logging.
- [AI code smells](/learn/patterns/ai-code-smells) covers empty catch blocks, the related antipattern where errors are dropped entirely.

## Sources

OWASP A09:2021 covers security-logging failures (the right-channel side). CWE-209 and CWE-497 name the specific information-disclosure classes.

---
title: Error handling
slug: error-handling
type: pattern
last_updated: 2026-09-03
draft: false
related_probe_ids:
  - Error Handling
sources:
  - title: 'CWE-1069 — Empty Exception Block'
    url: https://cwe.mitre.org/data/definitions/1069.html
  - title: 'CWE-755 — Improper Handling of Exceptional Conditions'
    url: https://cwe.mitre.org/data/definitions/755.html
  - title: 'MDN — Error.cause'
    url: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error/cause
  - title: 'React — Catching rendering errors with an error boundary'
    url: https://react.dev/reference/react/Component#catching-rendering-errors-with-an-error-boundary
  - title: 'Python — The with statement'
    url: https://docs.python.org/3/reference/compound_stmts.html#the-with-statement
summary: Errors are signals. Generated code treats them like garbage to hide. Catches that swallow, catches that log and walk away, catches that return an empty array so the screen shows nothing and nobody learns why. The most expensive line a vibe coder ships is catch (e) { console.log(e) }.
---

## What this is

Prompts like "make this not crash" produce minimum-viable error handling, and tutorial code logs errors because a tutorial cannot show real recovery. Large-scale analysis of AI-authored commits puts broad exception handling in the top five most frequent code smells across hundreds of thousands of introduced issues. The result in generated apps is uniform: every kind of failure, network, auth, parse, logic, collapses into the same silent shrug.

## Why it matters

A catch-all that logs and moves on hides every future bug behind it. The stack trace you need at 2am is in the browser console of a user you will never talk to, and the app keeps running in an undefined state, which is the worst kind of bug to chase: "it seems to work but the wrong thing is on the screen."

A catch that returns `[]` is quieter still. The screen renders empty, the user assumes there is nothing, and the failure is now invisible to both of you.

And in React, one throw during render with no error boundary unmounts the entire tree. White screen, no message, nothing to click.

## What the probe looks for

- **Swallows.** Empty catch blocks, catches whose only use of the error is to log it, `.catch(console.error)` on a promise chain.
- **Silent defaults.** Catches that return `[]`, `{}`, `null` or `false` without recording anything.
- **Signal damage.** Throwing strings or object literals instead of `Error`. Rethrowing as `new Error(e.message)`, which keeps the words and drops the stack. A bare `throw e` that adds nothing. A nested catch shadowing the outer error's name.
- **Structural holes.** `try { await ... } finally { ... }` with no catch, which cleans up and then lets the rejection sail on while reading as handled. Cleanup placed in the catch, so the success path leaks the same resource. In Python, files opened outside `with`.
- **The missing boundary.** A React app of any size with no error boundary anywhere.

## What the probe does not do

It does not grade your error messages, judge whether a try block was necessary, or classify an error's kind. Those are design reviews, not detectable defects, and pretending otherwise would bury the real findings in noise.

## The fix pattern

Catch is a question. The answer is never a shrug.

```js
try {
  const res = await fetch('/api/user');
  if (!res.ok) throw new Error(`user fetch failed: ${res.status}`);
  setUser(await res.json());
} catch (err) {
  setError(err instanceof Error ? err.message : 'Unknown error');
}
```

Read the signal and decide: show the user something true, retry, or rethrow with context (`new Error('loading profile failed', { cause: err })`) so an upstream boundary can. The one option that is never right is making the light go out without doing anything else.

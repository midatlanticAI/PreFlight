---
title: React hygiene
slug: react-hygiene
type: pattern
last_updated: 2026-09-03
draft: false
related_probe_ids:
  - React Hygiene
sources:
  - title: 'React — Synchronizing with Effects'
    url: https://react.dev/learn/synchronizing-with-effects
  - title: 'React — Rules of Hooks'
    url: https://react.dev/reference/rules/rules-of-hooks
  - title: 'React — Rendering Lists (key)'
    url: https://react.dev/learn/rendering-lists
  - title: 'CWE-401 — Missing Release of Memory after Effective Lifetime'
    url: https://cwe.mitre.org/data/definitions/401.html
  - title: 'Next.js — Server and Client Components'
    url: https://nextjs.org/docs/app/building-your-application/rendering/client-components
summary: The hooks-era mistakes AI tools reproduce from a corpus that predates hooks discipline. Effects that add listeners, timers, sockets and observers without cleanup. Dependency arrays that lie or do not exist. Components defined inside components. Index keys on lists that reorder. Each one works in the demo and misbehaves in use.
---

## What this is

Hooks shipped in 2019 and changed React's contract: an effect is a subscription to outside things, and every subscription owes a cancellation. The training data that AI tools learned from is full of code written before that discipline settled, so generated components routinely open taps they never close.

This probe reads your components for those shapes. An effect that calls `addEventListener` and returns no `removeEventListener`. A `setInterval` with no `clearInterval` in the cleanup. A WebSocket opened on mount and never closed. An effect with no dependency array setting state after every render. A component declared inside another component's body, remade from scratch on every render. A list keyed by its array index.

## Why it matters

None of these crash on first render, which is why they survive the demo. They surface as the app is used: a dozen hot reloads stack a dozen resize handlers, navigating away mid-fetch writes state into an unmounted component, reordering a list checks the wrong row's checkbox, and a component defined inline loses its state every render because React sees a brand-new type each time.

The cleanup family is the highest-yield fix in React codebases. An independent 500-repository static analysis found missing-cleanup patterns in 86 percent of the repos it scanned. The fix is almost always two lines: keep the handle, return a function that releases it.

## What the probe looks for

Each finding names the exact shape and the two-line fix. The families:

- **Effects that never clean up.** Listeners, timers, subscriptions, sockets, observers created inside `useEffect` with no matching release in the returned cleanup function.
- **Dependency arrays that lie.** No array at all on an effect that sets state. A fresh object or arrow literal inside the array, defeating the comparison every render. An empty array over a callback that reads state, freezing it at its first value.
- **Fetches without cancellation.** An effect that awaits a fetch with no AbortController and no cancelled flag races its own unmount.
- **Structure mistakes.** Hooks called inside conditions or loops. State setters called during render. Components defined inside components. Anonymous components in props.
- **Rendering mistakes.** Array index as the key of a dynamic list. `ref.current` rendered as content. A context provider fed a fresh object every render. `React.lazy` with no `Suspense` boundary in sight.
- **App Router boundaries.** A file under `app/` in a Next.js project using hooks or browser globals without the `"use client"` directive.

## What the probe does not do

It does not run your components, so it cannot see leaks that only assemble at runtime, and it does not attempt the judgment calls: whether an effect should have been an event handler is a design question, not a detectable defect. `dangerouslySetInnerHTML` is deliberately left to the Code Injection probe, which already owns it.

## The fix pattern

The cleanup shape is always the same. Name the resource, release it in the return:

```js
useEffect(() => {
  const onResize = () => setWidth(window.innerWidth);
  window.addEventListener('resize', onResize);
  return () => window.removeEventListener('resize', onResize);
}, []);
```

Every `addEventListener` is a contract. The cleanup is your signature.

---
title: Data and state
slug: data-state
type: pattern
last_updated: 2026-09-03
draft: false
related_probe_ids:
  - Data & State
sources:
  - title: 'React — You Might Not Need an Effect (deriving vs storing)'
    url: https://react.dev/learn/you-might-not-need-an-effect
  - title: 'TanStack Query — Query Keys'
    url: https://tanstack.com/query/latest/docs/framework/react/guides/query-keys
  - title: 'MDN — setInterval'
    url: https://developer.mozilla.org/en-US/docs/Web/API/Window/setInterval
summary: The distance between "the data appears" and "the data is managed". The same URL fetched from three places, fetches fired during render, polling that hammers a failing server at full rate, and state seeded from a prop that silently stops tracking it.
---

## What this is

Generated components fetch eagerly and manage reluctantly. Each component loads its own copy of the data, the loading happens wherever the code generator happened to put it, and updates arrive on a fixed timer whether the server is healthy or dying.

## Why it matters

**The same URL in three places** is three round trips and three chances to disagree mid-flight. One shared hook or loader makes it one request with one answer.

**A fetch in the component body** runs on every render, and if its result sets state, the state causes the next render. The request storm looks like a slow app; the network tab shows the truth.

**Fixed-rate polling has a failure mode**: when the server slows, the poller keeps hitting it at full speed, at the exact moment it needs less traffic. A self-rescheduling timeout that stretches its delay on failure costs three lines.

**`useState(someProp)` reads the prop once**, at first mount. When the parent later passes a new value, the copy keeps the old one, and the bug report says "it does not update until I refresh". Derive from the prop, or name the state `initialX` so the one-time read is a visible decision.

## What the probe does not do

Cache invalidation strategy, optimistic updates, store architecture: design, not defects. Supabase row-level security has its own dedicated probe, and effect cleanup belongs to React Hygiene.

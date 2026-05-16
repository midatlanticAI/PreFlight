---
title: Modular SPA
slug: modular-spa
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: React — Thinking in components
    url: https://react.dev/learn/thinking-in-react
  - title: CWE-1047 — Modules with Circular Dependencies
    url: https://cwe.mitre.org/data/definitions/1047.html
summary: The healthy SPA. A React/Vue/Svelte app split across many files, no single file owning the world. This is what good looks like and the contrast that makes the monolith shape legible.
---

## What this shape is

A single-page app spread across several source files: components in
their own directory, helpers separated from views, no one file holding
the majority of the code. The classifier reports it as a Modular SPA
(or Small SPA when there are only a few files).

## Scanner behavior

Pre-Flight classifies this shape (informational). It does not raise a
shape-specific finding for it, because there is nothing to act on: this
is the target the monolith finding is pointing you toward. The language
and security probes still run on every file.

## Why this is the one to aim for

The monolith shape is a security problem because review fatigue hides
findings and modules cannot be tested in isolation. The modular SPA is
the same app with those problems removed: a security-relevant change
lands in a small file, reads as a small diff, and can carry its own
test. The architecture is not just tidier, it is reviewable, and
reviewable is the precondition for being secure.

## Where it still goes wrong

Modular is not automatically safe. The failure modes shift rather than
disappear:

- Circular imports between modules reintroduce the "load everything to
  understand anything" problem the split was meant to solve.
- A shared utility that everything imports becomes a single point where
  one unsafe change reaches the whole app.
- Boundaries that exist as folders but not as rules drift back toward a
  monolith one convenient cross-import at a time.

## How to keep the shape

Keep files small enough to read in one sitting, keep the dependency
direction flowing one way (leaves do not import the app), and let any
file that crosses roughly 500 lines be the signal to find its seam.

## Related

- [Monolithic SPA](/learn/shapes/monolithic-spa) is what this shape
  prevents, and why the scanner flags the other end of the spectrum.

---
title: Monolithic SPA
slug: monolithic-spa
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: CWE-1041 — Use of Redundant Code
    url: https://cwe.mitre.org/data/definitions/1041.html
  - title: CWE-1120 — Excessive Code Complexity
    url: https://cwe.mitre.org/data/definitions/1120.html
summary: The "everything in one giant file" shape AI tools default to. Why a 4000-line single-file app is a security problem and not only a tidiness one, the seams to cut on, and the habit that keeps the architecture reviewable.
---

## What this shape is

One source file, or a handful, carrying the whole application: routing,
state, data fetching, every component, the styles, the helpers. The
Architecture probe flags it when the largest source file crosses the
line where a human stops being able to hold it in their head, and it
reports the exact line count it saw.

## Scanner behavior

PreFlight flags this shape: the Architecture probe raises a
low-severity finding with the largest file's exact line count. It is one
of the four shapes the scanner acts on rather than only classifying,
because past a certain size the shape actively hides other findings.

## Why AI defaults to it

A model writes the file it is asked to write. "Add a settings page"
lands in the file that is open. Nothing in the prompt ever asks the
assistant to stop and say "this file is too big now, let us split it,"
so it never does. Left alone, the single file grows every turn.

## Why this is a security problem, not only a tidiness one

This shape is on the security track, not the style track, for four
concrete reasons:

- Review fatigue hides real findings. A five-line auth change inside a
  4000-line diff does not get read closely. The bug that ships is the
  one nobody could see for the noise around it.
- Test isolation becomes impossible. When a module cannot be imported
  on its own it cannot be tested on its own, so the security-relevant
  branches (the error path, the unauthenticated path) are the ones that
  never get a test.
- The blast radius of any change is the whole file. An edit meant for
  the export helper sits in the same unit as the token check.
- AI-assisted refactors get worse as the file grows. Past roughly 1500
  lines the assistant's quality drops, because unrelated context
  competes for attention. The tool you would reach for to fix the
  problem is the tool the problem disables.

## What the scanner sees and says

The Architecture probe classifies the project, reports the largest
source file's line count and the total source-file count, and emits a
low-severity finding when the shape is monolithic. Low severity is
deliberate: the shape is not itself a vulnerability, it is the
condition under which vulnerabilities stop being visible.

## How to fix it

Cut on the natural seams, bottom-up:

- One file per probe or feature, one for formatters, one for history,
  one for theme, components in their own directory.
- Move leaves first (small helpers), then groups, then the main
  component last. Each move is a commit that still passes the suite.
- Keep the public import surface stable. Re-export from the old path
  during the transition so callers do not change while code moves.

The habit that prevents the shape from returning: keep source files
under about 500 lines. When a file crosses it, that is the signal to
find the seam, not a someday task.

## When this shape is fine

A file under about 500 lines is usually better left whole. Genuinely
coupled code, a five-step wizard whose steps share one state machine,
can belong together even when it runs long. Splitting before there is a
real seam costs more than it saves. The goal is reviewability, not a
file count for its own sake.

## Related

- The [Code Quality](/learn/patterns/code-quality) pattern covers the
  per-function smells that accumulate fastest inside a monolith.

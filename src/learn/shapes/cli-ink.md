---
title: CLI tool with a terminal UI (Ink)
slug: cli-ink
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: Ink — React for CLIs
    url: https://github.com/vadimdemedes/ink
  - title: CWE-78 — OS Command Injection
    url: https://cwe.mitre.org/data/definitions/78.html
summary: A CLI that renders its interface with React-for-terminals (Ink). The React part is a distraction from the real surface, which is still the shell and the filesystem of whoever ran it.
---

## What this shape is

A package with a `bin` entry that also depends on React and Ink: a
command-line tool whose UI is rendered as terminal output via React
components. The classifier separates this from an SPA because there is
no browser; the React is for the terminal.

## Scanner behavior

PreFlight classifies this shape (informational). It does not raise a
shape-specific finding for it; the language and injection probes run on
the source the same as for a plain CLI.

## The failure mode: same as a CLI, with a misleading skin

The Ink layer makes the tool look like a UI app, which can lead a vibe
coder to reason about it like one. The threat model is unchanged from a
plain CLI:

- It runs with the invoking user's privileges. There is no renderer
  sandbox; "components" here are just terminal drawing.
- Arguments and prompts are untrusted input. A value typed into an Ink
  text input that flows into a shell command is the same command
  injection as any other CLI; the React state in between does not
  sanitize it.
- It is still installed from a registry, so the supply-chain and
  install-script risks of any CLI apply.

## When the shape is fine

Ink is a good fit for interactive developer tools that benefit from a
richer terminal UI. It is safe under the same rules as any CLI: argv
not shell strings, bounded paths, a reviewed dependency surface. Do not
let the component model imply a sandbox that is not there.

## Related

- [CLI tool](/learn/shapes/cli) covers the shared threat model in full.

---
title: CLI tool
slug: cli
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: CWE-78 — OS Command Injection
    url: https://cwe.mitre.org/data/definitions/78.html
  - title: CWE-88 — Argument Injection
    url: https://cwe.mitre.org/data/definitions/88.html
summary: A package with a bin entry and no UI framework. The risk is not a browser, it is the shell, the filesystem, and the fact that other people's scripts will pass it untrusted arguments.
---

## What this shape is

A command-line tool: `package.json` declares a `bin`, there is no front
end. The classifier detects the bin entry and reports it as a CLI.

## Scanner behavior

PreFlight classifies this shape (informational). It does not raise a
shape-specific finding for it; the language and injection probes run on
the source.

## The failure mode: a CLI runs with the user's privileges

A CLI has no sandbox. It runs as whoever invoked it, with their
filesystem and their shell. The vibe-coded mistakes follow from
forgetting that its arguments are untrusted input:

- Building a shell string from an argument and running it (`exec`,
  `system`, backticks, `child_process.exec`) is command injection. The
  fix is the argv form that never invokes a shell.
- Joining an argument into a filesystem path without normalizing is
  path traversal against the invoking user's own files.
- A CLI installed from a package registry is supply-chain reachable: a
  postinstall script or a typosquatted dependency runs on every machine
  that installs it.

## When the shape is fine

A CLI is the right tool for automation and developer tooling. It is
safe when arguments are treated as data (argv, not shell strings),
paths are normalized and bounded, and the dependency surface is pinned
and reviewed because installs execute code.

## Related

- [CLI tool with a terminal UI (Ink)](/learn/shapes/cli-ink) is the same
  shape with a React-rendered terminal interface layered on.
- [Path Traversal](/learn/patterns/path-traversal) covers the
  filesystem half of the CLI input problem.

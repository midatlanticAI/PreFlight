---
title: Component / utility library
slug: library
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: CWE-1104 — Use of Unmaintained Third Party Components
    url: https://cwe.mitre.org/data/definitions/1104.html
  - title: npm — about semantic versioning
    url: https://docs.npmjs.com/about-semantic-versioning
summary: Code meant to be consumed, not deployed. The security posture inverts: you are not protecting an app, you are an input to everyone else's, so your supply-chain hygiene is now their risk.
---

## What this shape is

A package built to be imported by other projects: Vite library mode, a
Storybook, or a `package.json` with `exports`/`main` and no
`index.html`. The classifier reports it as a Library.

## Scanner behavior

PreFlight classifies this shape (informational). It does not raise a
shape-specific finding for it; the language and supply-chain probes run
on the source.

## The failure mode: you are someone else's dependency

A library has no users of its own; it has consumers, and its security
properties become theirs. The mental shift vibe coders miss:

- A library should hold no secrets. There is no environment to read
  from at someone else's runtime; a key committed here is published to
  every consumer and to the registry.
- Your dependency tree is appended to theirs. An unpinned or
  typosquatted dependency in a library is a supply-chain compromise of
  every app that installs it. The Compromised Packages and Slopsquat
  probes matter more here, not less.
- Install scripts run on the consumer's machine. A postinstall in a
  library executes in CI and on developer laptops you will never see.
- A breaking change shipped as a patch version breaks consumers
  silently; semver discipline is a safety property, not just etiquette.

## When the shape is fine

A library is the right shape for shared code with more than one
consumer. It is safe when it carries no secrets, pins and reviews its
own dependencies, avoids install scripts, and treats its public API and
version numbers as a contract.

## Related

- [Slopsquat / Typosquat](/learn/patterns/slopsquat-typosquat) and
  [Compromised Packages](/learn/patterns/package-json-supply-chain)
  explain why a library's dependency hygiene is its consumers' attack
  surface.

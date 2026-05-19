---
title: Microservices monorepo
slug: monorepo
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: pnpm workspaces
    url: https://pnpm.io/workspaces
  - title: Yarn workspaces
    url: https://yarnpkg.com/features/workspaces
  - title: CWE-1120 — Excessive Code Complexity
    url: https://cwe.mitre.org/data/definitions/1120.html
summary: Multiple package.json files in one repository, services meant to ship independently. At this scale boundary discipline matters more than any single check, and a broken boundary is a security boundary that does not exist.
---

## What this shape is

One repository, several package.json files, services intended to deploy
on their own schedules. The Architecture probe flags it when it finds
multiple package.json files and reports that it saw them.

## Scanner behavior

PreFlight flags this shape: the Architecture probe raises an
informational finding stating the boundary discipline this scale
requires. It is one of the four shapes the scanner acts on rather than
only classifying, because the boundary it depends on is a security
boundary.

## Why AI defaults to it

A monorepo is the path of least resistance once a project grows a second
service. The model adds `apps/api` next to `apps/web` because that is
where the code goes, and the workspace appears without anyone deciding
the boundary rules. The structure exists; the discipline that makes the
structure safe does not arrive with it.

## Why this is a security problem, not only a layout one

A service boundary is also a trust boundary. When the boundary is not
enforced, the security model that depends on it is fiction:

- A relative import that reaches into a sibling service couples two
  things that were supposed to deploy and be reasoned about separately.
  An auth change in one service silently changes another.
- "Services that never actually share code" still share a lockfile and a
  dependency graph, so a compromised or typosquatted package pulled for
  one service is resolved for all of them.
- Duplicated types drift. When the same shape is redefined in three
  services, the validation in one does not match the validation in
  another, and the gap is where malformed input gets through.
- Version and ownership ambiguity means no service can say what it ships
  or who reviews it, which is the precondition for an unreviewed change
  reaching production.

## What the scanner sees and says

The Architecture probe classifies the project as a monorepo (or a
server-rendered monorepo), reports the multiple package.json files it
found, and emits an informational finding. The level is informational
because the shape is a decision, not a defect. What it points at is the
discipline the shape requires to stay safe.

## How to fix it

- Every service has its own package.json with an explicit name and
  version. No service inherits its identity from the workspace root.
- Cross-service imports go through the published package name only,
  never a relative path into a sibling. Enforce it with an import or
  workspace-boundary lint rule so the rule is mechanical, not a habit.
- Shared types live in one dedicated package. They are imported, not
  copied.
- The lockfile is at the root. Let the package manager hoist; do not
  hand-maintain per-service lockfiles.
- Each service has its own README, test suite, and CI matrix entry, so
  ownership and what-ships are unambiguous.
- Use atomic cross-service refactors. They are the reason to keep the
  monorepo; avoiding them removes the only payoff while keeping the
  risk.

## When to break it back apart

When services genuinely never share code, never refactor together, and
the boundary rules are not being enforced, the monorepo is providing the
risk without the benefit. At that point separate repositories make the
boundary real by making it physical.

## Related

- [Slopsquat / Typosquat](/learn/patterns/slopsquat-typosquat) and
  [Compromised Packages](/learn/patterns/package-json-supply-chain)
  explain why a shared dependency graph turns one bad install into
  everyone's problem.

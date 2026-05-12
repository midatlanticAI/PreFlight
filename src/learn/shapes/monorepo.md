---
title: Microservices monorepo
slug: monorepo
type: shape
last_updated: 2026-05-12
draft: true
sources:
  - title: pnpm workspaces
    url: https://pnpm.io/workspaces
  - title: Yarn workspaces
    url: https://yarnpkg.com/features/workspaces
summary: Multiple `package.json` files in one repository, services intended to ship independently. Boundary discipline matters more than any other check at this scale.
---

> _Draft — content coming soon._
>
> Will cover: why monorepos exist (atomic refactors across services, shared
> types, one CI per repo), why they fail (cross-service relative imports, lock
> file sprawl, services that never actually share code), the boundary checks
> every monorepo should enforce (named-package imports only, dedicated types
> package, ESLint workspace constraints), and the moment to break a monorepo
> back into separate repos.

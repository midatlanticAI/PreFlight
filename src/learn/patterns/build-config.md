---
title: Build and config
slug: build-config
type: pattern
last_updated: 2026-09-03
draft: false
related_probe_ids:
  - Build & Config
sources:
  - title: 'npm — package-lock.json'
    url: https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
  - title: 'npm — package.json engines'
    url: https://docs.npmjs.com/cli/v10/configuring-npm/package-json#engines
  - title: 'npm — dependencies and devDependencies'
    url: https://docs.npmjs.com/cli/v10/configuring-npm/package-json#dependencies
summary: The project-level facts that decide whether "works on my machine" survives a second machine. Missing or duplicated lockfiles, no Node version pinned, build tools shipped to production, a build script that reports success on failure, and an ignored .env with no example documenting it.
---

## What this is

Config debt is invisible until the second machine: the new laptop, the CI runner, the teammate. Then the project installs a different tree, runs on a different Node, or crashes asking for environment variables nobody wrote down.

## Why it matters

**No lockfile** means every install re-resolves every version range. Today\'s deploy and last week\'s can run different code, including a compromised patch release published in between. **Two lockfiles** is the same problem wearing a disguise: whichever manager runs second believes its own file.

**`build: "tsc || true"`** turns a failing build green. CI then ships whatever the failure left behind, and the first sign is production.

**`.env` ignored with no `.env.example`** gives the next clone a crash with no checklist. The example file with names and placeholders is the map; committing it costs nothing because it holds nothing.

## What the probe does not do

Whether a dependency is outdated needs the registry. Which lint rules a project disables is a judgment call. Both are deliberately out of scope.

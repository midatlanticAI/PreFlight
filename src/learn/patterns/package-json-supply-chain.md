---
title: package.json supply-chain hooks
slug: package-json-supply-chain
type: pattern
last_updated: 2026-05-12
draft: true
related_probe_ids:
  - Package.json
  - Compromised Packages
related_incident_slugs:
  - sapphire-sleet-axios-2026-03
sources:
  - title: npm install scripts docs
    url: https://docs.npmjs.com/cli/v10/using-npm/scripts
  - title: CISA — Software Supply Chain Security
    url: https://www.cisa.gov/topics/cyber-threats-and-advisories/software-supply-chain-security
  - title: CWE-506 — Embedded Malicious Code
    url: https://cwe.mitre.org/data/definitions/506.html
summary: 'postinstall, preinstall, and prepare script hooks plus non-registry git dependencies — the two execution surfaces every recent npm worm has used.'
---

> _Draft — content coming soon._
>
> Will cover: why npm install scripts execute arbitrary code on every `npm
install` (even transitively, even from a sub-dependency), the lifecycle
> events to be paranoid about (`preinstall`, `install`, `postinstall`,
> `prepare`), why `ignore-scripts=true` in `.npmrc` is a defense-in-depth win
> for CI, and the registry-only-dependency policy that closes the
> `git+https://` exfil channel.

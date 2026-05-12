---
title: Slopsquat and typosquat packages
slug: slopsquat-typosquat
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Slopsquat / Typosquat
  - Compromised Packages
related_incident_slugs:
  - sapphire-sleet-axios-2026-03
sources:
  - title: 'Lasso Security — Slopsquatting (term coined)'
    url: https://www.lasso.security/blog/slopsquatting
  - title: 'CWE-1357 — Reliance on Insufficiently Trustworthy Component'
    url: https://cwe.mitre.org/data/definitions/1357.html
  - title: 'npm Docs — Avoiding broken dependencies'
    url: https://docs.npmjs.com/cli/v10/commands/npm-install
summary: Two related supply-chain attacks. Typosquatting registers a package name one letter off from a popular one (`lodahs` for `lodash`). Slopsquatting registers a name an LLM commonly hallucinates that doesn't exist (`auth-tool`, `api-helper`). Both wait for an unwary install.
---

## What this is

Two attack patterns on package registries:

**Typosquatting**: register a package whose name is a common typo of a popular package.

```
real:        lodash     express    request    react
typosquat:   lodahs     expreess   requst     reactt
```

A `npm install lodahs` runs the postinstall hook of `lodahs`, which is whatever the attacker wanted to run. The package may even implement a subset of the original's API so the developer doesn't immediately notice the mistake.

**Slopsquatting** (term coined by Lasso Security in 2024): register a package whose name an LLM commonly hallucinates but that does not exist in the registry. When a vibe-coder asks a model "what library should I use for X" and the model invents a plausible-sounding package name, the attacker registers that name. The next time the model hallucinates the same name, the developer pastes the install command and gets the attacker's package.

LLMs hallucinate package names following recognizable patterns: `auth-helper`, `api-tool`, `db-utils`, `string-helpers`, `validator-pro`. Pre-Flight's heuristic targets this shape directly.

## Why it matters

A successful slopsquat or typosquat runs the attacker's postinstall script with the developer's user-level permissions. Same blast radius as the named-incident supply-chain compromises ([Sapphire Sleet axios](/learn/incidents/sapphire-sleet-axios-2026-03), Mini Shai-Hulud waves): credential exfiltration, persistence drops, token theft, lateral movement to other packages the developer maintains.

The distinguishing property of these attacks is that they target the install itself, not a popular package. The attacker doesn't need to compromise a maintainer; they just need a developer (or an LLM serving developers) to make a typo or a hallucination.

## What the failure looks like

Pre-Flight scans `package.json` and lockfiles for:

- Known typosquats from a curated list (`lodahs`, `expreess`, `reactt`, `axioss`, `requst`, etc.).
- Generic-shape heuristics for likely slopsquats: `<thing>-tool`, `<thing>-helper`, `<thing>-utils`, `<thing>-pro`, `<thing>-validator`, `<thing>-handler` patterns plus a few others. These produce a lower-confidence finding because the heuristic is noisy.

## What the fix looks like

Three motions.

**Verify the package before installing it.** Look up the package on the registry. Check:

- The publish date (a new package with the suspicious-shape name is much more likely to be malicious than an established one).
- The download count (typosquats often have very low downloads).
- The maintainer (does the maintainer have a track record? Other reputable packages?).
- The repo link (does it resolve to a real GitHub repo with code that matches the package?).

If any of those raise questions, do not install. Replace the suspicious name with the real package's actual name from the source you trust (the project's docs, a search-engine result for the project, etc.).

**Pin and lock.** Once you have the correct package, pin a known-good version in `package.json` and commit the lockfile. Future installs see the same package; the typosquat or slopsquat does not get a chance to substitute.

**Set `min-release-age=604800` in `.npmrc`.** A seven-day cooldown means most slopsquats are taken down before any install can reach them. See [package.json supply-chain hooks](/learn/patterns/package-json-supply-chain) for the full configuration.

**Verify LLM-suggested packages exist before you install them.** If an LLM tells you to install `auth-tool` and you cannot find it on the npm registry, the LLM hallucinated. If you can find it but it was published last week with no downloads, an attacker registered the hallucination ahead of you. Either way, do not install. Search the actual ecosystem (Awesome lists, the project docs you are integrating with, etc.) for the real package name.

## Related

- [package.json supply-chain hooks](/learn/patterns/package-json-supply-chain) covers the installation-time execution surface these attacks exploit.
- [Sapphire Sleet axios incident](/learn/incidents/sapphire-sleet-axios-2026-03) and the Mini Shai-Hulud waves are worked examples of what happens when the attack lands.

## Sources

Lasso Security coined the "slopsquatting" term. CWE-1357 names the broader trust class. npm's documentation covers the canonical install flow that these attacks intercept.

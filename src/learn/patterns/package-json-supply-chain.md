---
title: package.json supply-chain hooks
slug: package-json-supply-chain
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Package.json
  - Compromised Packages
  - Package Manager Hardening
related_incident_slugs:
  - mini-shai-hulud-tanstack-2026-05
  - sapphire-sleet-axios-2026-03
sources:
  - title: npm install scripts docs
    url: https://docs.npmjs.com/cli/v10/using-npm/scripts
  - title: npm config reference (ignore-scripts, min-release-age)
    url: https://docs.npmjs.com/cli/v10/using-npm/config
  - title: CISA — Software Supply Chain Security
    url: https://www.cisa.gov/topics/cyber-threats-and-advisories/software-supply-chain-security
  - title: CWE-506 — Embedded Malicious Code
    url: https://cwe.mitre.org/data/definitions/506.html
  - title: OWASP A06:2021 — Vulnerable and Outdated Components
    url: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
summary: 'postinstall, preinstall, and prepare script hooks plus non-registry git dependencies. The two execution surfaces every recent npm worm has used.'
---

## What the pattern is.

Your `package.json` has a field called `"scripts"`. Inside it can sit any of:

```json
{
  "scripts": {
    "preinstall": "...",
    "install": "...",
    "postinstall": "...",
    "prepare": "..."
  }
}
```

When someone runs `npm install` in a project that depends on yours, the four lifecycle events above can each run arbitrary shell on their machine. That's not a misconfiguration. That's the design. npm scripts exist to let packages run native build steps, generate platform-specific binaries, and so on.

The problem is that the same execution surface is what every recent npm supply-chain worm has used to spread:

- Shai-Hulud (Sept 2025): postinstall hook ran a payload that stole maintainer tokens and republished to other packages the maintainer owned.
- Mini Shai-Hulud SAP / Bitwarden CLI (April 2026): same family of postinstall script, different drop-files.
- Mini Shai-Hulud TanStack (May 11, 2026): worm published 84 malicious versions across 42 @tanstack/\* packages in six minutes. The postinstall scripts wrote `tanstack_runner.js`, `.claude/router_runtime.js`, and a `gh-token-monitor` dead-man-switch to disk.

In every case, anyone who ran `npm install` against an affected version executed attacker code with their own user permissions. CI runners. Developer laptops. Build pipelines. Each install is a fresh execution.

There's a second execution surface in the same file: where a dependency comes from. The `dependencies` and `devDependencies` blocks can reference:

```json
{
  "dependencies": {
    "ok-pkg": "1.2.3",
    "git-pkg": "git+https://example.com/repo.git",
    "http-pkg": "http://example.com/tarball.tgz",
    "file-pkg": "file:../local"
  }
}
```

The bottom three skip the npm registry entirely. They pull from whatever URL or path you point them at. There's no signature, no audit, no min-release-age. If the URL gets repointed (or the local path swapped out for one a build script wrote), you're installing whatever's there now.

## Why your AI assistant gives you this.

Models are statistical, and the statistical answer to "how do I include this dependency" sometimes includes a `git+https://` URL because the documentation it trained on used one. The statistical answer to "the install isn't working" sometimes includes adding a `postinstall` hook that calls `curl | sh` because forum posts solved similar problems that way.

None of this is the model trying to do anything malicious. It's pattern completion. The pattern that completes to "install script that pipes a remote URL to a shell" is a pattern that exists in the training data, because it exists in the wild, because real packages do that. The model has no concept of "this pattern is the same one Shai-Hulud used."

## What Pre-Flight checks.

Pre-Flight's `Package.json` probe flags three shapes in your manifest:

1. **postinstall / preinstall / install / prepare hooks** that invoke `curl`, `wget`, `bash -c`, `sh -e`, or pipe a remote URL to a shell. Any of these is a critical-severity finding.
2. **Non-registry dependency specs** that start with `git+`, `http:`, or `file:`. These bypass the registry's signing and revocation channels.
3. **Floating versions** like `*` or `latest`. A floating version means whatever was published most recently. Most recently sometimes means malicious.

Pre-Flight's `Compromised Packages` probe checks every `dependencies` and `devDependencies` entry against the hard-coded list of ~170 known-malicious versions from named 2025-2026 incidents. If you installed `axios@1.14.1` on March 18, 2026 (the Sapphire Sleet window), the probe tells you specifically that version, from that date, has documented post-install behavior, and points you at the incident page.

Pre-Flight's `Package Manager Hardening` probe is the prevention layer. It checks for the presence of an `.npmrc` with the two settings that close the install-script blast radius:

```ini
ignore-scripts=true
min-release-age=604800
```

`ignore-scripts=true` disables lifecycle scripts entirely for that install. CI runners almost never need them. Developer machines can selectively enable them for packages that legitimately have native build steps (`--foreground-scripts` per install, or a wrapper script).

`min-release-age=604800` means npm refuses to install any package version published in the last seven days. Every recent npm worm has had a discovery-to-takedown window measured in hours. A seven-day cooldown means your install simply doesn't see the malicious version. It's pulled before your install gets there.

## What to do right now.

If Pre-Flight is flagging any of these in your repo:

- A `postinstall` or `preinstall` hook you didn't deliberately write. **Remove it.** Then look at what it was going to run. If it was `node setup.mjs`, look at that script. If it was `curl ... | sh`, you have a problem that's bigger than `package.json`.
- A `git+https://` dependency in production. **Replace it with a registry version, or vendor the code in.** A git dependency is an unsigned tarball pulled from a server you don't control.
- A floating `*` or `latest` dependency version. **Pin it.** Choose a specific version, run your tests, commit the change. Then move to a `^` or `~` if you want bounded updates.
- A missing `.npmrc` with hardening. **Add one.** The two-line minimum is above. The `min-release-age` directive specifically would have prevented the May 11, 2026 TanStack worm from reaching any CI or developer machine that had it set — the worm's six-minute publication window was orders of magnitude shorter than seven days.

## Why this matters more than it used to.

Five years ago, "npm packages can run arbitrary code on install" was a footnote in security guides. The footnote graduated. Shai-Hulud spread to thousands of packages. The TanStack worm hit 12-million-weekly-downloads-tier dependencies. The same execution surface has now been used four times in eight months to ship credential-stealing malware to working developers.

The fix is not "don't use npm." The fix is to know which two execution surfaces exist, what they do, and how to close them. That's all this pattern is about.

Related field reports describe how this pattern fired in production, with timelines, blast radius, and the specific defensive sequence each incident demanded.

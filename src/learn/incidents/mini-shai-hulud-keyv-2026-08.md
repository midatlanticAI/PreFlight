---
title: 'Mini Shai-Hulud Takes the keyv and Cacheable Families'
slug: 'mini-shai-hulud-keyv-2026-08'
type: 'incident'
last_updated: '2026-08-07'
summary: 'On August 4, 2026, a hijacked maintainer GitHub account published malicious versions across the keyv and cacheable package families, libraries with roughly two billion combined monthly downloads, and the Shai-Hulud worm rode them into hundreds of downstream packages within hours. The persistence hides in AI coding agent configuration, and the dead-man-switch from the May wave is back, so the response sequence matters as much as the detection.'
draft: false
campaign: 'Mini Shai-Hulud'
attack_date: '2026-08-04'
related_probe_ids:
  - 'Compromised Packages'
  - 'Malicious Artifacts'
  - 'Package Manager Hardening'
related_incident_slugs:
  - mini-shai-hulud-tanstack-2026-05
  - mini-shai-hulud-sap-npm-2026-04
  - unconfirmed-npm-window-2026-07
sources:
  - title: 'Cyber Security Agency of Singapore, Advisory AD-2026-009 (official advisory)'
    url: 'https://www.csa.gov.sg/alerts-and-advisories/advisories/ad-2026-009/'
  - title: 'OSV MAL-2026-11524 (keyv 6.0.0)'
    url: 'https://api.osv.dev/v1/vulns/MAL-2026-11524'
  - title: 'OSV MAL-2026-11970 (file-entry-cache 11.1.6)'
    url: 'https://api.osv.dev/v1/vulns/MAL-2026-11970'
  - title: 'GitHub Advisory Database, npm malware advisories'
    url: 'https://github.com/advisories?query=type%3Amalware+ecosystem%3Anpm'
  - title: 'The Hacker News, Keyv-Linked npm Worm Poisons Hundreds of Packages'
    url: 'https://thehackernews.com/2026/08/keyv-linked-npm-worm-poisons-hundreds.html'
  - title: 'CWE-506, Embedded Malicious Code'
    url: 'https://cwe.mitre.org/data/definitions/506.html'
---

# Mini Shai-Hulud Takes the keyv and Cacheable Families

On August 4, 2026, starting at roughly 09:30 UTC, an attacker who had taken over the GitHub account of the maintainer behind keyv and cacheable published malicious versions across both package families. keyv, flat-cache, and file-entry-cache each see roughly 150 million weekly downloads, the latter two shipping inside the eslint dependency tree. The official advisory puts the campaign at more than 1,300 compromised package versions with two billion combined monthly downloads. Independent tracking, counting while the worm was still spreading, reached 2,234 poisoned versions across 444 package names.

The publishing window for the core packages was under an hour. Automated detection flagged the first malicious version within minutes. The worm had already jumped.

If you installed any affected version on a developer machine, a CI runner, or a container build host on or after August 4, your environment is compromised, and the order of your response matters.

## If you might be affected, read this first

This wave carries the same host-level dead-man-switch as the May TanStack wave: a `gh-token-monitor` process that polls GitHub to check whether the stolen tokens are still valid, and reacts destructively when it sees the revocation. Standard incident-response instinct is to revoke compromised tokens immediately. Doing that while the implant is still running is what the implant is waiting for.

The sequence:

1. **Isolate the machine from the network first.** The monitor cannot see a token revocation from an offline machine.
2. **Remove the implants before touching any credential.** Check for `~/.local/bin/gh-token-monitor.sh`, the macOS LaunchAgent labeled `com.user.gh-token-monitor`, a Linux systemd user service named `gh-token-monitor.service`, and the agent-configuration files listed in the indicators section below.
3. **Identify which tokens were exposed.** Anything in the install environment: npm tokens, GitHub Personal Access Tokens, cloud credentials for AWS/GCP/Azure, SSH keys, `.env` files, Kubernetes service account tokens, Vault tokens, CI secrets.
4. **Revoke from a clean machine.** Not from the compromised one.
5. **Audit what the stolen tokens did.** The worm publishes with your credentials. Look for npm releases and repository writes you did not make.
6. **Rebuild.** The persistence survives package uninstalls. Full wipe.

PreFlight's **Malicious Artifacts** probe scans for the on-disk indicators this malware leaves behind. The **Compromised Packages** probe flags every advisory-listed version.

## How the attack worked

No pipeline exploit this time. The May TanStack wave needed a three-step chain through GitHub Actions, cache poisoning, and trusted publishing. The August wave needed one thing: the maintainer's GitHub account.

With the account in hand, the attacker pushed malicious commits directly to the main branch of the keyv repository, manipulated tags, and cut releases through the project's own publishing pipeline. The releases carried valid provenance for the same reason the TanStack ones did: they were built by the real pipeline from the real repository. The pipeline did exactly what it was configured to do. The code it was given had already been poisoned.

The publishing timeline, from independent tracking of the registry:

- **09:30 to 09:32 UTC:** the scoped `@keyv/*` adapter packages publish version 6.0.0
- **09:35:** `keyv@6.0.0` publishes with the malicious `preinstall` hook
- **09:38:** `@thiennq/docs-viewer@1.6.2`, an out-of-namespace package, publishes with the same payload, the first sign the worm was already using harvested credentials
- **09:39:** force pushes and tag manipulation land on the keyv repository
- **10:09 to 10:14:** the cacheable family bursts out in a five-minute window: `cacheable`, `flat-cache`, `file-entry-cache`, `cacheable-request`, `cache-manager`, the `@cacheable/*` scope, and `ecto`

From there the worm did what Shai-Hulud does: harvested npm tokens and GitHub credentials from every machine that installed an affected version, then used them to publish poisoned versions of whatever packages those victims could write to. That is how 22 packages became 444.

## The malware itself

The infection chain starts with one line in `package.json`: `"preinstall": "node setup.mjs"`. The dropper downloads a standalone Bun runtime into a staging directory matching `bun-dl-*`, then uses it to execute a heavily obfuscated payload of roughly 728 KB, shipped as `Math_Symbol.js` or `math_init.js`.

The payload:

- Harvests credentials from the install environment: npm and GitHub tokens, cloud keys, SSH keys, `.env` files, Kubernetes and Vault tokens, CI secrets.
- Exfiltrates through GitHub dead-drop repositories created with stolen tokens, marked with the description `"Shai-Hulud: Here We Go Again"`, with a fallback endpoint at `npm-cache.com:443/router`.
- Probes the cloud metadata service at `169.254.169.254` when it lands on a cloud-hosted runner, going after instance credentials.
- Republishes malicious versions of packages the victim can write to, using the victim's own npm token or trusted-publishing identity.
- Writes persistence that has nothing to do with npm: a `SessionStart` hook in `.claude/settings.json`, a `folderOpen` task in `.vscode/tasks.json`, and the `gh-token-monitor` dead-man-switch at the host level.

The agent-configuration persistence deserves a pause. A hook in `.claude/settings.json` runs every time a coding agent session starts in that directory. A `folderOpen` task in `.vscode/tasks.json` runs every time the editor opens the folder. Both survive `npm uninstall`, both survive dependency updates, and both live in files that most security tooling and most code review never reads. The IronWorm campaign used the same trick in May. It is now a pattern, not a one-off.

## The version list, read off the advisory

Every version below was read directly from its own malware advisory in the OSV database and cross-checked against the registry on August 7. All of them have been removed from npm: none of these versions resolve anymore, and in every case the package's current latest version sits immediately below the malicious one.

- `keyv` 6.0.0
- `@keyv/redis`, `@keyv/sqlite`, `@keyv/mongo`, `@keyv/postgres`, `@keyv/mysql`, `@keyv/memcache`, `@keyv/etcd`, `@keyv/valkey`, `@keyv/compress-brotli`, `@keyv/compress-gzip`, all 6.0.0
- `flat-cache` 6.1.24
- `file-entry-cache` 11.1.6
- `cacheable-request` 13.0.20
- `cacheable` 2.5.1
- `cache-manager` 7.2.10
- `@cacheable/memory` 2.2.1
- `@cacheable/node-cache` 3.1.2
- `@cacheable/utils` 2.5.1
- `@cacheable/net` 2.1.1
- `ecto` 5.0.1
- `@thiennq/docs-viewer` 1.6.2, 1.6.3, 1.6.4

One version that is deliberately not on that list: secondary reporting names `file-entry-cache` 11.1.7 as malicious. The advisory lists 11.1.6 only. A version adjacent to a malicious one is not malicious, and the review that produced [the unconfirmed-majority field report](/learn/incidents/unconfirmed-npm-window-2026-07) found exactly this error shape, an extra version attributed to a package that its advisory does not carry, in earlier intel. The manifest ships what the advisory says.

The other 400-plus packages in the wave are the worm's long tail: whatever the harvested credentials could reach. That list was still moving when the advisories were written, and no curated manifest tracks it honestly. Tail coverage belongs to behavior: an install hook that fetches and executes, a payload that writes itself into agent configuration, a package that publishes credential-harvesting code. Those checks do not need the package's name in advance.

## What to learn

**One maintainer account is a namespace-wide blast radius.** The May wave burned a CI pipeline vulnerability chain. This wave burned a password. Everything downstream of a maintainer, which for keyv and flat-cache means a measurable fraction of the JavaScript ecosystem, inherits the security of that one account. As a consumer you cannot fix that. You can decide how fast you swallow new versions.

**Release cooldowns would have covered this entire window.** The malicious versions lived on the registry for hours. A package-manager cooldown (`minimumReleaseAge` in pnpm, `min-release-age` in an `.npmrc`) of even three days means your installs never saw them. The trade is real: a cooldown also delays legitimate security patches. For most teams the math still favors the cooldown, because maintainer-account compromises detonate in hours and are cleaned up in days, while the patches you urgently need in that window are rare.

**Install-time execution is still the active surface.** The whole chain fires from a `preinstall` hook, before any application code runs. `--ignore-scripts` in CI, with an explicit trusted step for the packages that genuinely need lifecycle hooks, removes the detonator.

**Agent configuration is part of your security surface.** `.claude/settings.json` and `.vscode/tasks.json` are execution surfaces that survive every package-level cleanup. Audit them in every repository you work in, especially after any incident, and treat unexplained changes to them the way you would treat an unexplained change to a CI workflow file.

## Indicators of compromise (reference)

**Files dropped on infected machines:**

- `setup.mjs` (SHA-256: `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668`, npm tarball variant)
- `setup.mjs` (SHA-256: `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb`, agent-config variant)
- `Math_Symbol.js` / `math_init.js` (SHA-256: `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc`)
- Staging directories matching `bun-dl-*`, plus an unexpected Bun binary on a machine that never installed Bun

**Persistence:**

- `SessionStart` hook added to `.claude/settings.json`
- `folderOpen` task added to `.vscode/tasks.json`
- `~/.local/bin/gh-token-monitor.sh`
- macOS LaunchAgent label: `com.user.gh-token-monitor`
- Linux systemd user service: `gh-token-monitor.service`

**Process chain:**

- `node setup.mjs` spawning a Bun download, then Bun executing the payload

**Network IOCs (block at DNS/proxy level, from the official advisory):**

- `npm-cache.com` (exfiltration endpoint at `npm-cache.com:443/router`)
- `pypi-get.com`
- `js-mirror.com`
- `eth-mainnet.nodereal.io`, `go.getblock.io`, `eth.llamarpc.com`
- Unexpected requests to `169.254.169.254` from install-time processes

**GitHub repository description string:**

- `"Shai-Hulud: Here We Go Again"`

The PreFlight **Compromised Packages** probe flags any lockfile or manifest resolving an advisory-listed version. The **Malicious Artifacts** probe detects the on-disk persistence files, including the agent-configuration hooks. If either probe fires, return to the top of this report and follow the sequence.

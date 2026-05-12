---
title: 'Sapphire Sleet: axios poisoned via a transitive dependency'
slug: 'sapphire-sleet-axios-2026-03'
type: 'incident'
last_updated: '2026-05-12'
draft: false
summary: 'On March 31, 2026, the DPRK-aligned actor Sapphire Sleet published axios 1.14.1 and 0.30.4 with a hostile dependency on plain-crypto-js. Any install pulled a RAT through axios postinstall. The incident moved npm cooldown advice from "nice to have" to default-on in CI hardening guides.'
campaign: 'Sapphire Sleet'
threat_actor: 'Sapphire Sleet (DPRK-aligned)'
attack_date: '2026-03-31'
related_probe_ids:
  - 'Compromised Packages'
  - 'Package.json'
  - 'Package Manager Hardening'
related_incident_slugs:
  - mini-shai-hulud-sap-npm-2026-04
  - intercom-client-bitwarden-cli-2026-04
  - mini-shai-hulud-tanstack-2026-05
sources:
  - title: 'CISA advisories (Sapphire Sleet activity)'
    url: 'https://www.cisa.gov/news-events/cybersecurity-advisories'
  - title: 'Microsoft Threat Intelligence on Sapphire Sleet'
    url: 'https://www.microsoft.com/en-us/security/blog/threat-intelligence/'
  - title: 'Google Threat Intelligence Group (Mandiant) — DPRK supply-chain ops'
    url: 'https://cloud.google.com/blog/topics/threat-intelligence'
  - title: 'npm advisories (search by package name)'
    url: 'https://www.npmjs.com/advisories'
  - title: 'CWE-1357 — Reliance on Insufficiently Trustworthy Component'
    url: 'https://cwe.mitre.org/data/definitions/1357.html'
  - title: 'CWE-506 — Embedded Malicious Code'
    url: 'https://cwe.mitre.org/data/definitions/506.html'
  - title: 'OWASP A06 — Vulnerable and Outdated Components'
    url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'
---

## What happened

On March 31, 2026, two malicious versions of `axios` reached the npm registry: `axios@1.14.1` (the latest-stream version, which auto-updates in many `^1` ranges) and `axios@0.30.4` (a backport into the still-actively-installed 0.x line). Both were signed by a maintainer account that had been taken over earlier in the week, almost certainly via credential phishing tied to the DPRK-aligned threat group known as Sapphire Sleet.

The diff was small. Neither malicious version changed any of the canonical axios files in a way a casual reader would notice. The hostile content arrived through a new transitive dependency named `plain-crypto-js`, which the malicious versions added as a runtime dependency. The library presented itself as a thin wrapper over Node's built-in `crypto` module. It was not. The package contained a remote-access trojan whose initial loader ran inside the consumer's `npm install` process via a `postinstall` script.

The blast radius mechanics: any project with a dependency range like `"axios": "^1"` that ran `npm install` between approximately 14:00 UTC and the npm takedown around 19:30 UTC on March 31 pulled the compromised version and executed the trojan. CI runs that ran `npm ci` during that window were hit identically. Developer machines on Slack DMs and Twitter started reporting unfamiliar files in `~/.cache/` and outbound connections to obscure C2 endpoints within hours.

The trojan's primary objective was credential exfiltration. Specifically, it walked `~/.npmrc`, `~/.docker/config.json`, `~/.aws/credentials`, every `.env*` file in the cwd, and the host's GitHub token cache, then posted what it found to a C2 over HTTPS. Stolen npm tokens were the second-stage payload: with valid maintainer credentials in hand, the same actor moved laterally to publish poisoned versions of additional packages those maintainers owned. The Mini Shai-Hulud waves later that spring drew from the same playbook with new tooling.

## Why it worked

The attack composed three weaknesses that exist in every npm ecosystem, not specific to axios:

**Transitive trust is implicit.** A consumer who audits `axios` does not necessarily audit `axios`'s dependency tree on every install. `plain-crypto-js` was a name nobody had reviewed because it did not exist before March 31. By the time it did exist, `axios@1.14.1` already depended on it. The full dependency tree was honored by `npm install` automatically. There was no prompt, no warning, no review step.

**Postinstall scripts execute by default.** The trojan's loader was a single line in `package.json`:

```json
"scripts": {
  "postinstall": "node ./scripts/setup.js"
}
```

`npm install` ran that script as the current user with no sandbox, no permission prompt, no isolation. The script in turn unpacked the payload, registered persistence, and started the C2 beacon. The full attack chain executed before the `npm install` command returned. The default of "scripts run automatically" is what makes the attack one-step.

**Package versions go live the second they are published, with no cooldown.** A maintainer (or anyone holding the maintainer's npm token) can publish a new version of a popular package and have it served from the registry within seconds. There is no review queue, no waiting period, no peer-sign-off. The window between "malicious version published" and "compromised builds running in CI" was about 90 minutes for the fastest-moving consumers.

## What the response looked like

The npm security team pulled the affected versions within hours of the first credible report and seized the maintainer account. By the morning of April 1, both `axios@1.14.1` and `axios@0.30.4` were unpublished. `plain-crypto-js` was unpublished a few hours later.

The remediation playbook that worked for affected teams, in order:

1. **Identify exposure.** Any team whose lockfile or CI cache contained either malicious version was treated as compromised on the machine that installed it. Lockfile audit: `grep -RE 'axios.*(1\.14\.1|0\.30\.4)' .` plus a check of CI cache layers from the relevant time window.
2. **Rotate every credential touched by the affected hosts.** npm tokens, GitHub tokens (org and personal), Docker registry tokens, AWS keys, GCP service account keys, every cloud provider credential cached locally, and every secret in `.env*` files on the affected machines. The C2 had what the trojan could reach; the safe assumption is that everything in those files was exfiltrated.
3. **Force-republish lockfile.** `npm install --package-lock-only` with a known-good version of axios pinned (`"axios": "1.13.0"` or `"axios": "0.30.3"`, depending on which line the project tracked). Verify the lockfile no longer contains references to `plain-crypto-js`.
4. **Audit downstream artifacts.** Any container images, deploy bundles, or release tarballs built between March 31 and April 1 were rebuilt and republished. Some teams ran their entire prod fleet on images that contained the trojan for 24 to 48 hours before the rebuild rolled out.
5. **Audit GitHub repo activity for the affected accounts.** The exfiltrated tokens could push, create releases, and modify settings on every repo the developer had access to. A spike in commits or new branches from the developer's account during the window was a sign of a second-stage compromise.

The teams that came out of the incident cleanly were not the ones with the most advanced tooling. They were the ones who already had `min-release-age=604800` in their `.npmrc`. Every machine with that setting refused to install any version of any package published in the last seven days. The poisoned axios versions never reached those installs.

## What to do differently

Three concrete settings, all of which Pre-Flight checks for via its [Package Manager Hardening](/learn/patterns/package-json-supply-chain) probe.

**Set `min-release-age` to seven days in CI.** In `.npmrc`:

```
min-release-age=604800
```

This means npm refuses to install any version of any package published in the last seven days. Every recent supply-chain worm has had a discovery-to-takedown window measured in hours. A seven-day cooldown moves the attack window past the typical detection-and-response cycle. The cost is a one-week delay before you can install a brand-new release of a dependency; for most teams, that delay is invisible.

**Set `ignore-scripts=true` in CI environments.** In `.npmrc`:

```
ignore-scripts=true
```

This disables all lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`) for packages installed via npm. Developer machines may still need scripts on for native module builds, but CI runners almost never do. The combination of `ignore-scripts=true` in CI and `min-release-age=604800` everywhere closes the two execution surfaces every recent npm worm has used.

**Pin to specific versions in production lockfiles, then audit the diff on every dependency bump.** A `"^1.14.0"` range allows `1.14.1` to land without any human review. A pinned `"1.14.0"` requires a deliberate bump and a lockfile diff. The diff is what catches new transitive dependencies showing up. `plain-crypto-js` appearing in a dependency tree review would have been a five-second "we don't use this; what is it" check.

## Related patterns and shapes

- [package.json supply-chain hooks](/learn/patterns/package-json-supply-chain) covers the execution-surface mechanics in more depth, with the explicit script-hook-blocking and cooldown configuration.
- [Hardcoded secrets in source](/learn/patterns/secret-scanner) covers the credential-leak side: the trojan's payload was credential exfiltration, and every credential left in source or in a tracked `.env` file was part of the take.
- [Mini Shai-Hulud TanStack incident](/learn/incidents/mini-shai-hulud-tanstack-2026-05) is the May 2026 successor wave that used the same script-hook-on-install pattern at much larger scale (170+ packages).
- [Mini Shai-Hulud SAP incident](/learn/incidents/mini-shai-hulud-sap-npm-2026-04) is the April 2026 intermediate wave from the same actor family.

## Sources

The CISA, Microsoft, and Mandiant references at the top of this file are the authoritative published writeups on Sapphire Sleet's broader supply-chain activity through 2025 and 2026. The npm advisories database holds the specific takedown records for the affected versions. CWE-506 and CWE-1357 name the underlying vulnerability classes. OWASP A06:2021 ranks vulnerable and outdated components as the sixth most impactful application-security risk; the axios case is a worked example of why the ranking has not dropped.

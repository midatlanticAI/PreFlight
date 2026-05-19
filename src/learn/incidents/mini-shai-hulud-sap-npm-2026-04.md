---
title: 'Mini Shai-Hulud hits the SAP CAP toolchain'
slug: 'mini-shai-hulud-sap-npm-2026-04'
type: 'incident'
last_updated: '2026-05-12'
draft: false
summary: 'April 29, 2026: the second confirmed wave of the Mini Shai-Hulud worm. Targeted SAP CAP toolchain packages including @cap-js/sqlite and @cap-js/db-service. Same threat actor (TeamPCP) that would later run the May 11 TanStack wave at 4x scale. 1,800+ machines compromised, credentials exfiltrated from ~1,200 GitHub repositories.'
campaign: 'Mini Shai-Hulud'
threat_actor: 'TeamPCP'
attack_date: '2026-04-29'
related_probe_ids:
  - 'Compromised Packages'
  - 'Malicious Artifacts'
  - 'Package.json'
related_incident_slugs:
  - sapphire-sleet-axios-2026-03
  - intercom-client-bitwarden-cli-2026-04
  - mini-shai-hulud-tanstack-2026-05
sources:
  - title: 'SecurityWeek — 1,800 Hit in Mini Shai-Hulud Attack on SAP, Lightning, Intercom'
    url: 'https://www.securityweek.com/1800-hit-in-mini-shai-hulud-attack-on-sap-lightning-intercom/'
  - title: 'The Hacker News — SAP-Related npm Packages Compromised'
    url: 'https://thehackernews.com/2026/04/sap-related-npm-packages-compromised.html'
  - title: 'GitHub Advisory Database — npm package compromises'
    url: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm'
  - title: 'CISA advisories'
    url: 'https://www.cisa.gov/news-events/cybersecurity-advisories'
  - title: 'CWE-506 — Embedded Malicious Code'
    url: 'https://cwe.mitre.org/data/definitions/506.html'
  - title: 'CWE-829 — Inclusion of Functionality from Untrusted Control Sphere'
    url: 'https://cwe.mitre.org/data/definitions/829.html'
---

## What happened

On April 29, 2026, the threat actor that calls itself TeamPCP published compromised versions of packages in the SAP CAP (Cloud Application Programming) toolchain on npm. The headline packages were `@cap-js/sqlite` and `@cap-js/db-service`, both used in production enterprise Node.js applications built against SAP's HANA and S/4HANA platforms.

The worm pattern that would later run at much larger scale during the May 11 TanStack wave debuted here in production form. The compromised packages carried a postinstall script that:

1. Walked the developer's home directory for `.npmrc`, `.gitconfig`, GitHub token caches (`~/.config/gh/hosts.yml`), and any `.env*` files in the project tree.
2. Extracted every credential it found.
3. Posted them to a C2 endpoint over HTTPS.
4. Wrote a persistence loader to disk under `.claude/` and `.vscode/` folders so the payload survived `npm uninstall`.
5. Where the developer had a writable npm token, used it to republish poisoned versions of other packages the developer maintained. (This is the worm-spreads-itself step that gives the campaign its name.)

By the time SecurityWeek and others reported the campaign, approximately 1,800 distinct hosts had run the postinstall payload, and credentials had been exfiltrated from roughly 1,200 GitHub repositories. The credentials in question were not limited to npm tokens. Anything in `.env*` files on the affected machines was taken. For SAP CAP shops specifically, that meant HANA database credentials, internal S/4HANA service-user tokens, and the OAuth secrets for any integrated third-party services.

## Why it worked

Three reasons. None of them new; all of them amplified.

**SAP CAP packages are enterprise-targeted, which means slow rotation cadence.** A developer working on an SAP CAP application is typically inside an enterprise procurement cycle. Dependency upgrades go through approval, testing, and release windows that measure in weeks or months. Many CAP shops were running on `^1.0` style ranges that auto-bumped to the malicious version the moment it was published, because the next dependency-audit cycle was not scheduled for another sprint.

**The postinstall persistence pattern was new to this campaign.** Prior worms (including the original Shai-Hulud of September 2025) limited persistence to in-memory or session-scoped artifacts. TeamPCP introduced a disk-persistence trick: the worm wrote a JavaScript loader to `.claude/router_runtime.js`, `.claude/setup.mjs`, and `.vscode/setup.mjs`. Those files are sometimes auto-loaded by AI coding assistants and IDE extensions, which means the worm got a second execution chance even after the developer uninstalled the original package. The May 2026 TanStack wave reused this pattern at scale; PreFlight's [Malicious Artifacts probe](/learn/patterns/package-json-supply-chain) keys on the same drop-file paths.

**Credential scope was wider than the developer expected.** A "GitHub PAT for CI" with `repo` scope can read every private repository the developer has access to. A `service_role` Supabase key in `.env.local` is the entire database to the holder. A Stripe `sk_live_` is production charge access. The worm did not need to escalate; it just needed to find the credential and walk away with it. The enterprise SAP context meant the credentials it found were often production-grade and broadly-scoped.

## What the response looked like

npm pulled the affected packages within hours of the first credible report. SAP's CAP team posted a security advisory the same day. Affected teams' response playbook, in order:

1. **Lockfile audit.** Search every project for the affected packages and versions. `grep -RE '@cap-js/(sqlite|db-service)' .` plus a check of installed versions against the named-malicious list.
2. **Forensic check for the persistence drops.** Look for `.claude/router_runtime.js`, `.claude/setup.mjs`, `.vscode/setup.mjs`, `tanstack_runner.js`, and `router_init.js` on every developer machine and CI runner. The presence of any of those files is a compromise indicator. PreFlight's [Malicious Artifacts probe](/learn/patterns/package-json-supply-chain) scans for these specifically.
3. **Credential rotation across the full footprint.** GitHub PATs (every developer; the worm took the org-wide scope), npm tokens, HANA service-user credentials, every secret in `.env*`, every cloud-provider credential cached on an affected host. The shorter version: anything a process running as the developer's user could read should be treated as exfiltrated.
4. **Repo audit for unauthorized pushes.** The stolen GitHub tokens were used in some cases to push new commits to the developer's repositories. A spike in pushes from the developer's account during the April 29-30 window was a hard indicator. Affected teams reverted unauthorized commits and force-revoked the tokens before merging legitimate work.
5. **CI runner reimage.** The persistence drops survived `npm uninstall`. The cleanest remediation for CI runners was to rebuild the runner image from a known-good base and re-secret it.

The teams that came through with the least disruption had two things in common: they had `ignore-scripts=true` in their `.npmrc` for CI runners (which prevented the postinstall from executing on those machines at all), and they had `min-release-age=604800` somewhere in their dependency pipeline (which delayed the malicious versions long enough for npm to pull them before any production install).

## What to do differently

The remediation list is identical to the [Sapphire Sleet incident](/learn/incidents/sapphire-sleet-axios-2026-03), with one addition specific to this campaign.

**Audit for the persistence drop files on every machine.** The worm writes itself to disk locations that are not under `node_modules`. A normal `rm -rf node_modules && npm install` does not clean it up. PreFlight's Malicious Artifacts probe catches:

```
.claude/router_runtime.js
.claude/setup.mjs
.vscode/setup.mjs
tanstack_runner.js
router_init.js
```

Plus the in-source IOCs:

```
__DAEMONIZED              # the worm's reentry guard
filev2.getsession.org     # exfil endpoint
seed1.getsession.org / seed2 / seed3
gh-token-monitor          # the dead-man-switch script name
com.user.gh-token-monitor # the LaunchAgent / systemd unit identifier
```

A `grep -RE 'filev2\.getsession\.org|__DAEMONIZED|gh-token-monitor' ~` returning any hit means the host was compromised. Treat accordingly.

**The other two motions are the same as Sapphire Sleet.** Cooldown (`min-release-age=604800`) plus script-blocking (`ignore-scripts=true`) on CI. PreFlight's [Package Manager Hardening probe](/learn/patterns/package-json-supply-chain) flags missing entries for both.

## Related patterns and shapes

- [package.json supply-chain hooks](/learn/patterns/package-json-supply-chain) covers the execution-surface mechanics and the defensive configuration.
- [Hardcoded secrets in source](/learn/patterns/secret-scanner) covers the credential-leak side, which was the payload of every wave including this one.
- [Sapphire Sleet axios incident](/learn/incidents/sapphire-sleet-axios-2026-03) is the March 2026 predecessor that demonstrated the postinstall-RAT pattern at smaller scale.
- [Intercom-client and Bitwarden CLI incidents](/learn/incidents/intercom-client-bitwarden-cli-2026-04) is the parallel April 2026 wave from the same actor family.
- [Mini Shai-Hulud TanStack incident](/learn/incidents/mini-shai-hulud-tanstack-2026-05) is the May 11, 2026 wave that used the same persistence-drop pattern at 4x the package count.

## Sources

The SecurityWeek and Hacker News writeups are the primary published accounts. GitHub's Advisory Database carries the per-package takedown records. CISA's general supply-chain advisories cover the broader 2025-2026 npm worm series. CWE-506 (embedded malicious code) and CWE-829 (inclusion of functionality from untrusted control sphere) name the underlying vulnerability classes.

---
title: Post-infection malicious artifacts
slug: malicious-artifacts
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Malicious Artifacts
  - Compromised Packages
related_incident_slugs:
  - mini-shai-hulud-tanstack-2026-05
  - mini-shai-hulud-sap-npm-2026-04
sources:
  - title: 'CWE-506 — Embedded Malicious Code'
    url: https://cwe.mitre.org/data/definitions/506.html
  - title: 'CWE-829 — Inclusion of Functionality from Untrusted Control Sphere'
    url: https://cwe.mitre.org/data/definitions/829.html
summary: Drop files and content IOCs left behind by the 2026 Mini Shai-Hulud npm worms. Finding any of these in your repo means a developer machine was compromised; the artifacts survive `npm uninstall` and that's the point.
---

## What this is

Once an npm postinstall worm has executed on a developer's machine, it writes itself to disk in locations that survive `npm uninstall`. Pre-Flight scans for the specific paths and content signatures the Mini Shai-Hulud campaign (May 2026 TanStack wave, April 2026 SAP wave) uses.

**Drop files** (critical-severity if found):

```
.claude/router_runtime.js
.claude/setup.mjs
.vscode/setup.mjs
tanstack_runner.js
router_init.js
```

These get auto-loaded by AI coding assistants and IDE extensions on startup, giving the worm a fresh execution chance every time the developer opens the project.

**Content IOCs** (critical-severity if found in any scanned file):

```
__DAEMONIZED                            # the worm's reentry guard
filev2.getsession.org                   # Session-messenger exfil endpoint
seed1.getsession.org, seed2..., seed3...
gh-token-monitor                        # dead-man-switch script name
com.user.gh-token-monitor               # LaunchAgent / systemd user service name
claude@users.noreply.github.com         # spoofed commit author the worm uses
@tanstack/setup                         # malicious commit-SHA pin name
```

A `grep` finding any of these in any tracked file in the repo is the indicator. The worm leaves these traces deliberately because removing them is harder than reinstalling node_modules.

## Why it matters

If Pre-Flight finds any of these in a scanned repo, the assumption is that the developer who committed those files was compromised by one of the 2026 worm waves. The blast radius is everything that machine has touched since the compromise: GitHub repos the developer can push to, npm packages the developer maintains, cloud-provider credentials cached on the machine, and any secret the developer's user account had access to.

The dead-man-switch (`gh-token-monitor` / `com.user.gh-token-monitor`) is particularly nasty: it's a LaunchAgent (on macOS) or a systemd user service (on Linux) that runs periodically and checks whether the stolen GitHub token is still valid. If the token returns 40x (the user revoked it), the script runs `rm -rf ~/` as a punishment for getting caught. Anyone removing one of these compromises needs to disable the LaunchAgent / systemd unit first.

## What the failure looks like

Pre-Flight flags any file matching the drop-file paths as a critical finding. It also scans every other file for the content IOC strings. Both are exact matches, so the false-positive rate is essentially zero.

The probe is named "Malicious Artifacts" specifically because the findings represent already-completed compromises, not vulnerabilities. A finding here is a forensic discovery, not a remediation task in the usual sense.

## What the fix looks like

This pattern is the rare one where the "fix" is incident response, not a code change.

1. **Disable the dead-man-switch first.** Before doing anything else:

   ```bash
   # macOS
   launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist

   # Linux (systemd user service)
   systemctl --user stop gh-token-monitor.service
   systemctl --user disable gh-token-monitor.service
   ```

2. **Treat the host as compromised.** Reimage if possible. At minimum, rebuild from a known-good state.

3. **Rotate every credential the host could reach.** GitHub PATs, npm tokens, every cloud-provider credential, every secret in any `.env*` file, every API key the developer has used. See [Sapphire Sleet axios incident](/learn/incidents/sapphire-sleet-axios-2026-03) for the rotation sequence and [Hardcoded secrets in source](/learn/patterns/secret-scanner) for the per-provider rotation steps.

4. **Audit the GitHub account for unauthorized commits.** The compromise often pushes commits using the spoofed `claude@users.noreply.github.com` author or a known-developer's signature. Look for commits that don't match the developer's normal pattern in the 24-72 hours after the compromise window.

5. **Audit npm-published packages.** If the developer publishes any packages, the worm may have used their npm token to publish poisoned versions of those packages. Check each one against the registry's version history.

6. **Remove the drop files and IOC strings from the repo.** Once the host is clean and credentials are rotated, scrub the artifacts from version control. A `git filter-repo` or BFG run can remove them from history.

## Related

- [Mini Shai-Hulud TanStack incident](/learn/incidents/mini-shai-hulud-tanstack-2026-05) is the most recent and largest wave that produces these artifacts.
- [Mini Shai-Hulud SAP incident](/learn/incidents/mini-shai-hulud-sap-npm-2026-04) is the April 2026 wave that first used this persistence pattern.
- [package.json supply-chain hooks](/learn/patterns/package-json-supply-chain) covers the install-time execution surface that gets the worm onto the host in the first place.

## Sources

CWE-506 (embedded malicious code) and CWE-829 (inclusion of functionality from untrusted control sphere) name the underlying classes. The 2026 field reports above document the campaign-specific artifacts each variant leaves behind.

---
title: 'Mini Shai-Hulud Strikes the TanStack Ecosystem'
slug: 'mini-shai-hulud-tanstack-2026-05'
type: 'incident'
last_updated: '2026-05-12'
summary: '84 malicious versions across 42 @tanstack/* packages published in a six-minute window on May 11, 2026, exploiting GitHub Actions to publish with valid SLSA provenance. If you installed any affected version on May 11, your machine and CI environment should be treated as compromised, and there is a specific defensive sequence that matters.'
draft: false
cve: 'CVE-2026-45321'
cvss: 9.6
campaign: 'Mini Shai-Hulud'
threat_actor: 'TeamPCP'
attack_date: '2026-05-11'
related_probe_ids:
  - 'Compromised Packages'
  - 'Malicious Artifacts'
  - 'GitHub Actions'
related_incident_slugs:
  - mini-shai-hulud-sap-npm-2026-04
  - intercom-client-bitwarden-cli-2026-04
sources:
  - title: 'TanStack Issue #7383 (initial report)'
    url: 'https://github.com/TanStack/router/issues/7383'
  - title: 'StepSecurity — Mini Shai-Hulud Is Back'
    url: 'https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem'
  - title: 'Socket — TanStack npm Packages Compromised'
    url: 'https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack'
  - title: 'Wiz — Mini Shai-Hulud Strikes Again'
    url: 'https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised'
  - title: 'Snyk — TanStack npm Packages Hit by Mini Shai-Hulud'
    url: 'https://snyk.io/blog/tanstack-npm-packages-compromised/'
  - title: 'Semgrep — TanStack Router Packages Hit'
    url: 'https://semgrep.dev/blog/2026/tanstack-router-packages-hit-by-coordinated-supply-chain-attack/'
  - title: 'Aikido — Mini Shai-Hulud Is Back'
    url: 'https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised'
  - title: 'Upwind — Shai-Hulud Across TanStack'
    url: 'https://www.upwind.io/feed/shai-hulud-tanstack-supply-chain-worm'
  - title: 'The Hacker News — Mini Shai-Hulud Compromises TanStack, Mistral AI, Guardrails'
    url: 'https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html'
  - title: 'GHSA-g7cv-rxg3-hmpx'
    url: 'https://github.com/advisories/GHSA-g7cv-rxg3-hmpx'
  - title: 'OX Security — Shai-Hulud, Here We Go Again (170+ Packages Hit)'
    url: 'https://www.ox.security/shai-hulud-here-we-go-again-170-packages-hit-across-npm-pypi/'
  - title: 'Microsoft Threat Intelligence — MistralAI PyPI compromise (May 12, 2026)'
    url: 'https://gbhackers.com/microsoft-mistralai-pypi-package-compromised/'
---

# Mini Shai-Hulud Strikes the TanStack Ecosystem

On May 11, 2026, between 19:20 and 19:26 UTC, a threat actor calling itself TeamPCP published 84 malicious versions across 42 packages in the `@tanstack/*` npm namespace, including `@tanstack/react-router`, which has roughly 12 million weekly downloads. The window was six minutes. By the end of the day, the same campaign had spread to packages in `@uipath/*`, `@mistralai/*`, `@squawk/*`, `@tallyui/*`, `@beproduct/*`, `@draftlab/*`, `@draftauth/*`, `@taskflow-corp/*`, `@tolka/*`, unscoped names like `safe-action` and `cmux-agent-mcp`, plus PyPI packages including `guardrails-ai@0.10.1` and `mistralai`. OX Security puts the total at 170+ packages with a cumulative 518 million monthly downloads, and the spread is still moving as of this writing.

If you installed any affected version on a developer machine, a CI runner, or a container build host on May 11, your environment is compromised. There is a specific sequence to follow.

## If you might be affected, read this first

The malware installs a daemon on infected machines that polls GitHub every 60 seconds to check whether the stolen tokens it exfiltrated are still valid. When it sees a `401` or `403` response (the signature of a revoked token), it attempts to run `rm -rf ~/` against the user's home directory.

This is a dead-man-switch. Standard incident-response instinct is to revoke compromised tokens immediately. Doing that on an infected machine triggers the destruction.

The correct sequence:

1. **Isolate the machine from the network first.** Disconnect Wi-Fi, pull the ethernet cable, disable cellular tethering. The daemon cannot reach GitHub to check token status from an offline machine.
2. **Image the system if possible.** Disk image for forensic preservation. Skip this step only if you have nothing recoverable and time is critical.
3. **Identify which tokens were exposed.** Anything that lived in the install environment: npm tokens, GitHub Personal Access Tokens, AWS/GCP/Azure credentials, SSH keys, `.env` files, Kubernetes service account tokens, HashiCorp Vault tokens, third-party API keys (Stripe, Slack, Twilio, etc.).
4. **Revoke tokens from a clean machine.** Do not log in from the compromised machine to revoke. The daemon auto-exits after 24 hours, so if you can wait that long with the machine offline, the destructive handler stops being a threat.
5. **Audit recent activity for each revoked token.** Look for npm publishes, GitHub Actions runs, repository writes, cloud API calls. The malware uses stolen tokens to propagate; you may find malicious activity authored by your own credentials.
6. **Rebuild the machine.** Do not attempt to clean it in place. The malware writes persistence into `.claude/`, `.vscode/`, LaunchAgent or systemd unit files, and modifies shell config files. Full wipe.

Pre-Flight's **Malicious Artifacts** probe scans for the on-disk indicators this malware leaves behind. Run it against your home directory if you suspect infection. The list of indicators is at the bottom of this report.

## How the attack worked

The compromise chained three GitHub Actions vulnerabilities. None of them alone would have been sufficient.

**Step one: the orphan fork.** On May 10, a GitHub account named `zblgg` (user ID 127806521) created a fork of the TanStack/router repository. The fork was renamed to `zblgg/configuration` specifically to avoid appearing in TanStack/router's fork-list searches.

**Step two: the Pwn Request.** The attacker opened a pull request against TanStack/router. The repository's CI used `pull_request_target` as a workflow trigger, a known dangerous pattern sometimes called the "Pwn Request" attack. Unlike `pull_request`, the `pull_request_target` trigger runs with write permissions and access to secrets, and when configured to check out the PR head ref, it executes attacker-controlled code with those privileges.

**Step three: cache poisoning.** The attacker's PR code did not directly publish anything. It poisoned the GitHub Actions cache by writing a malicious pnpm store, then exited cleanly. When legitimate maintainer PRs merged to `main` over the following hours, the release workflow restored the poisoned cache. Attacker-controlled binaries then extracted the OIDC token directly from the Actions runner's process memory at `/proc/<pid>/mem`.

The OIDC token granted permission to publish to npm. The attacker used it to publish 84 malicious versions across 42 packages in six minutes, all signed with valid SLSA provenance attestations, because Sigstore correctly verified that the build pipeline was the official TanStack pipeline. The malicious code had been smuggled into the build inputs through cache poisoning rather than through compromising the publish workflow itself.

TanStack confirmed in their postmortem that no npm tokens were stolen, two-factor authentication was enabled across the team, and the npm publish workflow itself was not directly compromised. The attack worked by abusing the trusted publishing infrastructure rather than by stealing publishing credentials.

This is the first documented case of malicious packages carrying valid SLSA provenance. Sigstore verified that the artifacts were built from the trusted source repository through the trusted build pipeline. SLSA verifies the build pipeline. It does not verify the code being built. If your verification logic stops at provenance, this attack passes it.

## The malware itself

The malicious packages each contained a new file named `router_init.js`, a 2.3 MB heavily obfuscated JavaScript payload. The package metadata also added an `optionalDependencies` entry resolving to an orphan commit at `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`, which served as the dropper. The orphan commit added a package named `@tanstack/setup` with a `prepare` lifecycle hook that ran `bun run tanstack_runner.js && exit 1`. Because npm executes lifecycle hooks during install of git-based dependencies, the dropper fired automatically the moment any affected package was installed.

The payload:

- Downloaded the Bun JavaScript runtime if not present, then used it to execute the obfuscated stealer.
- Harvested credentials from the install environment: `.env` files, environment variables, AWS/GCP/Azure cloud credentials, GitHub and npm tokens, SSH keys, Kubernetes service account tokens, HashiCorp Vault tokens, common API keys.
- Exfiltrated through three redundant channels: a typosquat domain `git-tanstack.com`, the decentralized Session messenger network (the full Session protocol stack including the signalservice Protocol Buffers schema is embedded directly in the 2.3 MB payload), and GitHub API dead drops where stolen tokens are used to create repositories with the description `"Shai-Hulud: Here We Go Again"`. As of yesterday, 400+ such repositories existed.
- Installed the `gh-token-monitor` daemon on macOS (via LaunchAgent labeled `com.user.gh-token-monitor`) and Linux (via systemd). The daemon polls GitHub every 60 seconds to check whether stolen tokens are still valid. On token revocation (40x response), it attempts `rm -rf ~/`. The daemon auto-exits after 24 hours.
- Wrote persistence files into `.claude/router_runtime.js`, `.claude/setup.mjs`, and `.vscode/setup.mjs`, surviving `npm uninstall` of the malicious packages.
- Used stolen npm tokens and GitHub OIDC tokens to attempt to publish malicious versions of additional packages the victim had write access to, propagating worm-style across the npm ecosystem.
- Spoofed commit authorship to impersonate Anthropic's Claude Code (`claude@users.noreply.github.com`) on injected commits, attempting to blend into legitimate AI-assisted development activity.

Geographic and language targeting: the malware checks system locale and terminates without exfiltrating data if it detects a Russian-language environment. The PyPI variant carried in `mistralai` adds country-aware logic. Microsoft's analysis identified a `1-in-6` chance of executing `rm -rf /` when the system fingerprints as Israel or Iran.

## The spread beyond TanStack

Within hours of the initial six-minute publishing window, the worm propagated to additional namespaces via tokens it had already harvested. By end of day on May 11:

- **`@uipath/*` packages** including `apollo-core`, CLI tools, and agent SDKs (UiPath enterprise automation platform)
- **`@mistralai/mistralai`**, the official TypeScript Mistral AI client (npm), and the parallel `mistralai` PyPI package
- **`guardrails-ai@0.10.1`**, a Python LLM guardrails package. Notable because the malicious code executes on `import`, not just `install`. Downloads `transformers.pyz` from `git-tanstack.com` to `/tmp/`, then loads it.
- **Multiple smaller namespaces and unscoped packages** including `safe-action`, `ts-dna`, `cross-stitch`, `cmux-agent-mcp`, `agentwork-cli`, `git-branch-selector`, `wot-api`, `git-git-git`, `nextmove-mcp`, `ml-toolkit-ts`

The Mini Shai-Hulud campaign that began with SAP-related npm packages in late April 2026 (`mbt`, `@cap-js/sqlite`, etc.) is the same campaign. Same threat actor, same toolchain. The TanStack wave is the fourth in the broader Shai-Hulud worm series. Earlier waves in September and November 2025 used the same worm framework but were not attributed to TeamPCP specifically.

## What's new in this wave

Three things make this iteration of Mini Shai-Hulud worse than the previous three.

**Valid SLSA provenance.** No prior supply chain attack has demonstrated this capability. If your defensive posture treated SLSA attestations as a trust ceiling, that ceiling just dropped. Provenance attestations verify build process, not build inputs. A cache-poisoning attack against the inputs slips through.

**Dead-man-switch.** The retaliation-on-revocation pattern means standard incident response sequencing can destroy a compromised machine. This is the first campaign in the Shai-Hulud series to weaponize the response itself.

**Targeted destructive payload.** Geographic and locale fingerprinting plus probabilistic destruction logic (the `1-in-6` chance of `rm -rf /` in the Mistral AI PyPI variant) crosses a line that previous Mini Shai-Hulud iterations did not. The earlier waves stole credentials. This wave also tries to brick specific machines.

## What to learn

Three takeaways that generalize past this specific incident.

**Lockfile hygiene is not optional.** Floating dependency versions (`*`, `latest`, `>1.0`) mean your install today is not the install you tested yesterday. A pinned lockfile, committed to source, with `npm ci` (or `pnpm install --frozen-lockfile`) in CI, would have prevented automatic installation of the malicious versions for any project that wasn't actively updating dependencies between 19:20 and detection. This won't help you on `npm install` against a fresh lockfile, but it prevents the worm's propagation through CI environments that install on every build.

**Install-time execution is the active surface, not application runtime.** Lifecycle hooks (`preinstall`, `install`, `postinstall`, `prepare`) run before any application code. Most supply chain malware in 2025-2026 lives here. The `--ignore-scripts` npm flag disables these, at the cost of breaking some packages that legitimately need them (native modules, etc.). For CI environments, run with `--ignore-scripts` and use a separate explicitly-trusted build step for the packages that actually need install hooks. For developer machines, consider package-manager-level cooldown (`.npmrc` with `min-release-age=10080` for a 7-day cooldown). This would have blocked TanStack's malicious versions from installing during the active propagation window.

**Editor and shell configuration are persistence surfaces.** The malware writes to `.claude/`, `.vscode/`, and LaunchAgent/systemd units specifically because these survive package uninstalls and reboots. Treat these directories as part of your security surface. Audit them periodically, especially after any incident.

## Indicators of compromise (reference)

**Files dropped on infected machines:**

- `.claude/router_runtime.js`
- `.claude/setup.mjs`
- `.vscode/setup.mjs`
- `tanstack_runner.js`
- `router_init.js` (SHA-256: `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`)

**Daemon / persistence:**

- `gh-token-monitor` process
- macOS LaunchAgent label: `com.user.gh-token-monitor`
- Linux systemd unit (varies)

**Code markers in any scanned file:**

- `__DAEMONIZED` guard variable
- Spoofed commit author: `claude@users.noreply.github.com`
- Orphan commit pin: `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`

**Network IOCs (block at DNS/proxy level):**

- `git-tanstack.com`
- `filev2.getsession.org`
- `seed1.getsession.org`, `seed2.getsession.org`, `seed3.getsession.org`

**GitHub repository description string:**

- `"Shai-Hulud: Here We Go Again"`

**Suspicious GitHub account associated with the dropper:**

- `voicproducoes` (publishes repos named "A Mini Shai-Hulud has Appeared", likely compromised account)

The Pre-Flight **Compromised Packages** probe will flag any installation of affected `@tanstack/*`, `@uipath/*`, `@mistralai/*`, `guardrails-ai`, or other listed package versions. The **Malicious Artifacts** probe will detect the on-disk persistence files. For the network IOCs, block at your DNS provider or corporate proxy. Pre-Flight cannot make network reachability decisions for you.

If your machine triggered findings in either probe, return to the top of this report and follow the operational sequence.

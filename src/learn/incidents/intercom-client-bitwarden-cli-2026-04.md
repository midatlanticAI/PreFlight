---
title: 'Bitwarden CLI and intercom-client: April 2026 credential-stealer wave'
slug: 'intercom-client-bitwarden-cli-2026-04'
type: 'incident'
last_updated: '2026-05-12'
draft: false
summary: 'Two April 2026 supply-chain incidents from overlapping actor groups. Bitwarden CLI 2026.4.0 (April 22) shipped a backdoored release of the official password-manager CLI that explicitly hunted Claude, Cursor, and Codex credentials. Seven days later, intercom-client 7.0.4 / 7.0.5 and lightning 2.6.2 / 2.6.3 (April 29) carried the same Mini Shai-Hulud credential stealer with combined ~8.3M downloads exposure.'
campaign: 'Mini Shai-Hulud (intercom + lightning) / Bitwarden CLI compromise'
attack_date: '2026-04-22'
related_probe_ids:
  - 'Compromised Packages'
  - 'Malicious Artifacts'
  - 'Package Manager Hardening'
related_incident_slugs:
  - sapphire-sleet-axios-2026-03
  - mini-shai-hulud-sap-npm-2026-04
  - mini-shai-hulud-tanstack-2026-05
sources:
  - title: 'Bitwarden security advisories'
    url: 'https://bitwarden.com/blog/category/security/'
  - title: 'SecurityWeek — 1,800 Hit in Mini Shai-Hulud Attack on SAP, Lightning, Intercom'
    url: 'https://www.securityweek.com/1800-hit-in-mini-shai-hulud-attack-on-sap-lightning-intercom/'
  - title: 'The Hacker News — Bitwarden CLI Backdoored'
    url: 'https://thehackernews.com/2026/04/bitwarden-cli-backdoored.html'
  - title: 'npm Advisories Database'
    url: 'https://www.npmjs.com/advisories'
  - title: 'GitHub Advisory Database — npm'
    url: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm'
  - title: 'CWE-506 — Embedded Malicious Code'
    url: 'https://cwe.mitre.org/data/definitions/506.html'
  - title: 'CWE-522 — Insufficiently Protected Credentials'
    url: 'https://cwe.mitre.org/data/definitions/522.html'
---

## What happened

Two related-but-distinct compromises landed within a week of each other in late April 2026. Both targeted developer credentials. Both used the npm registry as a delivery vector. The notable property of the pair is that the Bitwarden CLI incident specifically named AI coding assistants as the credential type of interest, which was the first time a public supply-chain campaign had AI-tooling cred theft as a documented objective rather than a secondary outcome.

**Bitwarden CLI 2026.4.0 (April 22, 2026).** A compromised release of the official Bitwarden command-line interface, distributed via the standard `@bitwarden/cli` npm package. The release included a post-execution hook that activated when the user ran `bw unlock` or `bw sync` against any vault. The hook walked the local filesystem for credentials specific to AI coding assistants: Claude API keys (`~/.config/claude/`, `~/.anthropic/`), Cursor session tokens (`~/.cursor/User/`), Codex / GitHub Copilot tokens (`~/.config/github-copilot/hosts.json`), and any Anthropic / OpenAI / xAI API keys exported in `.env*` files in the cwd. Stolen credentials posted to a C2 over HTTPS within the same process that triggered the hook, so the network traffic was indistinguishable from a normal Bitwarden sync at the connection level.

The Bitwarden security team pulled the malicious release approximately 18 hours after first reports. The compromise vector appears to have been a build-pipeline injection on a release-signing host, not a maintainer credential theft. Bitwarden's release infrastructure had a CI step that pulled a dependency from a registry mirror; the mirror was compromised; the injected code arrived in the final signed CLI binary.

**intercom-client 7.0.4 and 7.0.5, lightning 2.6.2 and 2.6.3 (April 29, 2026).** Same day as the SAP CAP wave from TeamPCP. The intercom-client and lightning npm packages (combined ~8.3M downloads across recent versions) shipped with the standard Mini Shai-Hulud postinstall payload: credential exfiltration plus the disk-persistence drops described in the [SAP CAP incident](/learn/incidents/mini-shai-hulud-sap-npm-2026-04). The intercom-client compromise was particularly costly because the package is bundled into many SaaS user-engagement integrations, which meant CI pipelines for downstream products triggered the postinstall every time they rebuilt.

## Why it worked

**Bitwarden CLI was a trust-chain attack, not a credential theft.** Bitwarden itself is a security product. The CLI is signed and distributed by Bitwarden, not by a third-party maintainer. The actor did not need to steal a maintainer's credentials; they injected hostile code into Bitwarden's own build pipeline via a compromised dependency mirror. This is the supply-chain-of-the-supply-chain pattern: the consumer trusted Bitwarden, Bitwarden trusted its build mirror, the mirror was the foothold. CWE-1357 (Reliance on Insufficiently Trustworthy Component) describes the class.

**The AI-tooling credential angle was new.** Prior worms went after npm tokens, GitHub PATs, AWS keys, and the standard cloud-provider credential pile. The Bitwarden CLI compromise added a new tier: API keys for Anthropic, OpenAI, and similar, plus session tokens for AI coding assistants. Two reasons this matters: (1) those credentials are typically high-value because they grant API access that bills per token, and (2) they are often less-protected than cloud-provider credentials because the threat model around them is newer. Many developers held `sk-ant-` and `sk-proj-` keys in plaintext in `.env.local` files at home directory paths the Bitwarden hook could read.

**The intercom-client incident worked for the same reasons as the parallel SAP CAP wave**, with the additional amplifier that intercom-client is a transitively-included package in many SaaS apps. A developer building on top of an intercom integration may not have intercom-client in their direct dependencies, but it shows up in their lockfile through some `analytics-toolkit` or `user-engagement-helper` higher up the chain. PreFlight's [Package.json probe](/learn/patterns/package-json-supply-chain) flags any project whose lockfile resolves intercom-client to the affected versions, including transitive resolutions.

## What the response looked like

For Bitwarden CLI:

1. Bitwarden published an out-of-band security advisory naming the affected release (`2026.4.0`) and the build hash. Users were instructed to downgrade to `2026.3.x` or wait for the upcoming patched `2026.4.1`.
2. Users who had run `bw unlock` against the malicious CLI were told to treat every credential currently in their Bitwarden vault as exfiltrated. The hook walked everything the unlocked CLI could read, which on the Bitwarden CLI is the full vault by design.
3. Bitwarden rotated its release-signing keys and rebuilt its build pipeline against a known-good dependency snapshot.
4. The compromised registry mirror was identified and removed from the build pipeline's configuration.

For intercom-client / lightning:

1. npm took down the affected versions within hours of the first credible reports.
2. Maintainers republished known-good versions (intercom-client `7.0.6`, lightning `2.6.4`) with the patch advanced past the malicious window.
3. Downstream products that auto-rebuilt during the malicious window (April 29 14:00 UTC to April 30 02:00 UTC, approximately) were treated as compromised at the build-artifact level. Image rebuilds and credential rotation followed the same playbook as the SAP CAP wave.

## What to do differently

Four motions. Three are repeated from the prior incidents in this series; one is specific to the AI-tooling credential angle introduced by the Bitwarden compromise.

**Apply `min-release-age=604800` and `ignore-scripts=true` to every CI runner.** Same configuration as discussed in [Sapphire Sleet](/learn/incidents/sapphire-sleet-axios-2026-03) and [Mini Shai-Hulud SAP](/learn/incidents/mini-shai-hulud-sap-npm-2026-04). The combination prevents the entire class of incidents from reaching CI builds.

**Audit for the Malicious Artifacts persistence drops on every developer machine.** Same `.claude/router_runtime.js`, `.vscode/setup.mjs`, `__DAEMONIZED`, `filev2.getsession.org` signatures PreFlight scans for. The intercom-client wave used the identical persistence pattern as the SAP CAP wave because it was the same actor family.

**Pin and lockfile-audit transitive dependencies.** A `npm ls intercom-client` plus `npm ls lightning` against a representative project's lockfile catches the transitive-inclusion case. If either resolves to an affected version, the project is exposed even if neither package is in the direct dependencies.

**Move AI-tooling credentials out of plaintext `.env` files.** This is the motion specific to the Bitwarden compromise. API keys for Anthropic, OpenAI, xAI, Mistral, DeepSeek, Groq, and any future provider should live in a secret manager (1Password CLI, vault, GCP/AWS Secrets Manager, or even a `.env` file encrypted at rest with `git-crypt` or `sops`). The Bitwarden hook walked `~/.config/claude/`, `~/.cursor/`, and every `.env*` it could find. A credential that lived inside a secret manager was unreadable to the hook. A credential in `.env.local` was exfiltrated in plaintext.

```bash
# Pattern: load secrets at process start from a secret manager, not from a tracked file.

# 1Password CLI
export ANTHROPIC_API_KEY=$(op read "op://Personal/anthropic/credential")
export OPENAI_API_KEY=$(op read "op://Personal/openai/credential")

# Or with the `op run` wrapper that loads env from a template at process start:
op run --env-file=.env.tpl -- npm run dev
```

The cost is one additional line per credential. The benefit is that a process running as the user but not authenticated to the secret manager cannot read the credential.

## Related patterns and shapes

- [package.json supply-chain hooks](/learn/patterns/package-json-supply-chain) covers the postinstall execution surface that both compromises used.
- [Hardcoded secrets in source](/learn/patterns/secret-scanner) covers the broader credential-leak class. The April wave was a worked example of why plaintext-in-`.env` is a credential leak waiting for a process to read it.
- [Sapphire Sleet axios incident](/learn/incidents/sapphire-sleet-axios-2026-03) is the March 2026 predecessor that demonstrated the credential-exfiltration playbook.
- [Mini Shai-Hulud SAP incident](/learn/incidents/mini-shai-hulud-sap-npm-2026-04) is the parallel April 29 wave from the same actor family.
- [Mini Shai-Hulud TanStack incident](/learn/incidents/mini-shai-hulud-tanstack-2026-05) is the May 11 successor wave that hit the JavaScript framework ecosystem at much larger scale.

## Sources

Bitwarden's security blog carries the official advisory and patch notes for the CLI compromise. SecurityWeek and the Hacker News cover both incidents from the supply-chain reporting angle. The npm and GitHub Advisory databases hold the per-package takedown records. CWE-506 (embedded malicious code) names the malicious-package class; CWE-522 (insufficiently protected credentials) names the plaintext-credential class the Bitwarden hook exploited; CWE-1357 (reliance on insufficiently trustworthy component) names the trust-chain class the Bitwarden build-pipeline injection exploited.

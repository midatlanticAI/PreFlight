---
title: 'intercom-client and Bitwarden CLI — April 2026 Credential-Stealer Wave'
slug: 'intercom-client-bitwarden-cli-2026-04'
type: 'incident'
last_updated: '2026-05-12'
draft: true
summary: 'Two notable April 2026 supply-chain incidents — Bitwarden CLI 2026.4.0 (April 22) hunting Claude / Cursor / Codex credentials, and intercom-client 7.0.4 / 7.0.5 (April 29) carrying the Mini Shai-Hulud credential stealer.'
campaign: 'Mini Shai-Hulud / Bitwarden CLI compromise'
attack_date: '2026-04-22'
related_probe_ids:
  - 'Compromised Packages'
related_incident_slugs:
  - mini-shai-hulud-sap-npm-2026-04
  - mini-shai-hulud-tanstack-2026-05
sources:
  - title: 'OX Security — 8.3M Downloads Compromised: Lightning & Intercom-Client Infected'
    url: 'https://www.ox.security/8-3m-downloads-compromised-lightning-intercom-client-infected-in-latest-shai-hulud-attack/'
  - title: 'OX Security — Shai-Hulud: The Third Coming, Bitwarden CLI Backdoored'
    url: 'https://www.ox.security/shai-hulud-the-third-coming-bitwarden-cli-backdoored/'
---

> _Draft — content coming soon._
>
> Will cover the two April 2026 incidents Pre-Flight ships threat-intel for:
>
> **Bitwarden CLI 2026.4.0 (April 22, 2026).** Compromised version of the official
> password-manager CLI explicitly hunted AI coding assistant credentials — Claude,
> Cursor, and Codex. Notable for naming AI-tooling cred theft as a specific objective.
>
> **`intercom-client` 7.0.4 / 7.0.5 and `lightning` 2.6.2 / 2.6.3 (April 29, 2026).**
> 8.3M downloads compromised across the two packages. Same Mini Shai-Hulud
> credential stealer that later showed up in the SAP CAP wave and the May 11
> TanStack wave.

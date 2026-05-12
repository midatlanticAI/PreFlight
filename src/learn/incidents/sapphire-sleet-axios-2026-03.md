---
title: Sapphire Sleet — Axios supply-chain compromise
slug: sapphire-sleet-axios-2026-03
type: incident
last_updated: 2026-05-12
draft: true
related_probe_ids:
  - Compromised Packages
sources:
  - title: CISA advisory on Sapphire Sleet (DPRK)
    url: https://www.cisa.gov/news-events/cybersecurity-advisories
  - title: Google Threat Intelligence Group writeup
    url: https://cloud.google.com/blog/topics/threat-intelligence
summary: March 31, 2026 — DPRK-aligned actor poisoned `axios@1.14.1` and `axios@0.30.4` via a malicious `plain-crypto-js` dependency. One of the first 2026 supply-chain incidents Pre-Flight ships threat-intel for.
---

> _Draft — content coming soon._
>
> Will cover: the attack chain (plain-crypto-js injected into axios at publish
> time, RAT installed at npm install via the post-install hook), the time-to-
> detection window, the affected version range, how to know if you're hit (lock
> file scan, registry-installed-version diff), the credential-rotation
> playbook, and why this single incident moved npm cooldown advice from
> "nice to have" to "default-on" in CI hardening guides.

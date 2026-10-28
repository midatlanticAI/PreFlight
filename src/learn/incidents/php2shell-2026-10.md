---
title: 'php2shell: Remote Code Execution in the PHP Engine, Exploited Within Days'
slug: 'php2shell-2026-10'
type: 'incident'
last_updated: '2026-10-28'
summary: 'On October 21, 2026 the PHP project released fixes for two engine bugs, CVE-2026-109618 and CVE-2026-109619, that allow unauthenticated remote code execution in every SAPI that serves web requests. Honeypots saw exploitation within three days and CISA added both to its Known Exploited Vulnerabilities catalog on October 26. The bug is in PHP itself, so the application on top does not matter: WordPress, Laravel, a vibe-coded admin panel, all equally exposed until the runtime moves to 8.2.35, 8.3.36, 8.4.27 or 8.5.12.'
draft: false
campaign: 'php2shell'
attack_date: '2026-10-21'
related_probe_ids:
  - 'PHP Runtime Version'
related_incident_slugs:
  - litellm-pypi-2026-10
sources:
  - title: 'PHP security advisory, October 21, 2026'
    url: 'https://www.php.net/archive/2026.php#2026-10-21-5'
  - title: 'CISA alert: Critical Vulnerabilities in PHP Require Immediate Patching (revised October 26, 2026)'
    url: 'https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching'
  - title: 'The PHP Foundation: the security release and how PHP security is being strengthened'
    url: 'https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/'
  - title: 'GHSA-w8hw-w9fx-j79w (CVE-2026-109618)'
    url: 'https://github.com/advisories/GHSA-w8hw-w9fx-j79w'
  - title: 'GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)'
    url: 'https://github.com/advisories/GHSA-6wmf-4rv5-p3rp'
  - title: 'The Hacker News: CISA Confirms Active Exploitation of Two PHP2Shell Flaws'
    url: 'https://thehackernews.com/2026/10/cisa-confirms-active-exploitation-of.html'
  - title: 'CWE-1395, Dependency on Vulnerable Third-Party Component'
    url: 'https://cwe.mitre.org/data/definitions/1395.html'
---

# php2shell: Remote Code Execution in the PHP Engine, Exploited Within Days

On October 20, 2026 the PHP project pre-announced two critical fixes, both rated 9.2 on CVSS v4. On October 21 it shipped them: PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35, with the fix also in the 8.6.0 RC4 build. By October 24 researchers were reporting successful remote code execution against honeypot systems, and on October 26 CISA added CVE-2026-109618 and CVE-2026-109619 to its Known Exploited Vulnerabilities catalog.

The two bugs sit in the engine's request lifecycle, not in any framework or application. CVE-2026-109618: an out-of-memory condition can interrupt PHP while internal request data is only partly initialised, and the cleanup that follows treats the invalid data as valid. CVE-2026-109619: request-owned internal state can survive after its backing memory is freed, and a later request on the same worker can use that stale state before normal initialisation resets it. Either path ends with an unauthenticated request running code with the web worker's privileges, before any application code has executed.

## If you run PHP anywhere, read this first

1. **Inventory.** Every system that runs PHP, including PHP embedded in something else: a WordPress marketing site, a Laravel API, a legacy admin tool, a container somebody built once. CISA's first instruction is to find them all.
2. **Update.** 8.2.35, 8.3.36, 8.4.27 or 8.5.12, prioritising anything internet-facing. The PHP advisory says there are no complete mitigations and updating is the only safe choice.
3. **If you cannot update today, take it offline.** That is CISA's guidance, and it applies with extra force to PHP 8.1 and older, which receive no releases from the project. The security team published source backport branches (`PHP-7.4-CVE-2026-109618-109619`, `PHP-8.0-…`, `PHP-8.1-…`) for people who build from source, and some distributions ship backports; if that is what runs in production, confirm it rather than assume it.
4. **While the update is scheduled, reduce exposure.** For CVE-2026-109618: `memory_limit=-1` set via `php_admin_value` in the FPM pool or Apache config, a low `post_max_size` (8M with no uploads, 32M with), and request limits enforced at the web server or proxy. For CVE-2026-109619: `session.upload_progress.enabled=0`, and on 8.5 `fatal_error_backtraces=0`, set in `php.ini`, the pool, or the server config, then every worker restarted. `ini_set()` and `.user.ini` do not count.
5. **Look back.** CISA's detection guidance: PHP worker processes spawning shells or downloading tools. A SIGMA rule is published in CISA's repository.

## Why this matters for an app built with AI tools

A generated app rarely picks PHP. A generated app very often sits next to one: the WordPress site the business already had, the Laravel back office a contractor built, the PHP image a prompt produced because the tutorial used it. Those are the hosts in the inventory that nobody owns, and this bug does not care what the application is.

The deployment artefacts in a repository say exactly what will run. `FROM php:8.3.10-fpm` in a Dockerfile, `8.2.20` in a `.php-version` file, `php 8.4.12` in `.tool-versions`, `"platform": { "php": "8.1.29" }` in composer config. Each of those pins is a decision to stop time, and this week every one of them needs remaking. PreFlight's **PHP Runtime Version** probe reports a pin below the fix for its branch at the line where the pin was made, and reports a pin on 8.1 or older as a version with no fix to move to.

What the probe deliberately does not do: report a floating tag like `php:8.3-fpm`. That tag resolves to whatever was current when the image was last pulled, and a scanner that cannot see the pull date should not guess. Rebuild the image and the tag does the right thing; the probe's job is the pins that will not.

## What PHP is changing

The PHP Foundation's post alongside the release describes the longer-term response: a security team reorganised around the engine's request lifecycle, the memory-limit and session code paths that both bugs ran through getting a dedicated review, and backports for unsupported branches published as source for the first time. A separate informational advisory on October 23 (CVE-2026-115560, session upload progress under a runtime serializer change) is being handled in the regular release cycle and is not part of this pair.

## The lesson

Framework patches are a habit by now. Runtime patches are not, because the runtime is usually a base image somebody chose once. The fix here is a version string in a file you already have in the repository. Change it, rebuild, deploy, and then set a reminder to look at the pin again, because the next one of these will not announce itself either.

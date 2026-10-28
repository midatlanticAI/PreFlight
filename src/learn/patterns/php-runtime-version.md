---
title: PHP runtime pinned below the php2shell fix
slug: php-runtime-version
type: pattern
last_updated: 2026-10-28
draft: false
related_probe_ids:
  - PHP Runtime Version
  - Compromised Packages
sources:
  - title: 'PHP security advisory, October 21, 2026 (CVE-2026-109618, CVE-2026-109619)'
    url: https://www.php.net/archive/2026.php#2026-10-21-5
  - title: 'CISA alert, Critical Vulnerabilities in PHP Require Immediate Patching'
    url: https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
  - title: 'The PHP Foundation on the release and what changes next'
    url: https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/
  - title: 'CWE-1395, Dependency on Vulnerable Third-Party Component'
    url: https://cwe.mitre.org/data/definitions/1395.html
summary: A Dockerfile, .php-version, .tool-versions or composer platform pin that names a PHP release below 8.2.35, 8.3.36, 8.4.27 or 8.5.12, or any PHP 8.1 or older. Those versions carry CVE-2026-109618 and CVE-2026-109619, unauthenticated remote code execution in the engine itself, exploited in the wild and with no complete mitigation other than updating.
---

## What this is

On October 21, 2026 the PHP project shipped a security release for two bugs in the engine's request handling. CVE-2026-109618 lets an out-of-memory condition interrupt a request while internal data is half-initialised, and the cleanup then treats that data as valid. CVE-2026-109619 lets request-owned state survive after its memory is freed, so the next request on the same worker can use it. Both allow an unauthenticated request to run code as the web worker, before any application code executes. The pair was named php2shell by the researchers who found it.

This is a bug in PHP, not in WordPress, Laravel, Drupal or anything you wrote. Every installation that serves web requests is affected: PHP-FPM, Apache with mod_php (rated highest risk by the PHP team, with a demonstrated exploit), php-cgi, FrankenPHP, LiteSpeed. CISA added both CVEs to its Known Exploited Vulnerabilities catalog on October 26.

Fixed in 8.2.35, 8.3.36, 8.4.27 and 8.5.12. PHP 8.1 and older receive no releases from the project; the security team published source backport branches for 7.4, 8.0 and 8.1 for people who build from source, and some distributions ship their own backports.

## What the failure looks like

A static scanner cannot see what a server runs. It can see what the repository tells the server to run, and those statements are exact:

```dockerfile
FROM php:8.3.10-fpm-alpine
```

```
# .php-version
8.2.20
```

```
# .tool-versions
php 8.4.12
```

```json
{ "config": { "platform": { "php": "8.1.29" } } }
```

Each of these is a pin below the fix for its branch, or a branch with no fix. PreFlight reports them as critical. A floating image tag (`php:8.3-fpm`) resolves to whatever was current when the image was pulled; the scanner cannot know the pull date, so it says nothing about floating tags rather than guess. `composer.json`'s `require.php` is a constraint, not a runtime, and is not read.

## What the fix looks like

Move the pin and redeploy. The PHP advisory is direct about this: there are no complete mitigations, updating is the only safe choice.

```dockerfile
FROM php:8.3.36-fpm-alpine
```

Then rebuild the image and roll it out; a changed Dockerfile that has not been built is the same server it was yesterday.

If you are on 8.1 or older, the pin cannot be patched in place. Move to a supported branch. If that cannot happen today, CISA's guidance is to take the PHP-based system offline until it can, or to put a web application firewall in front as an interim measure that reduces, not removes, exposure.

The ini settings in the advisory (`memory_limit=-1`, a low `post_max_size`, `session.upload_progress.enabled=0`, and on 8.5 `fatal_error_backtraces=0`) reduce exposure while the update is scheduled. They are not a substitute for it, and `ini_set()` or `.user.ini` do not count: they have to be in `php.ini`, the FPM pool, or the server config, followed by a worker restart.

## Why a scanner reports a version number

The usual objection: "the image gets rebuilt, it will pick up the fix." It will, when the tag floats. A pinned patch version is a decision somebody made to stop time, usually for a good reason, and that decision now needs remaking. Reporting it at the line where it was made is the whole value of the check.

## Related

- [Compromised packages](/learn/patterns/package-json-supply-chain) covers dependency versions with a published advisory; this pattern is the same idea applied to the runtime under them.
- [php2shell field report](/learn/incidents/php2shell-2026-10) has the timeline and the response order.

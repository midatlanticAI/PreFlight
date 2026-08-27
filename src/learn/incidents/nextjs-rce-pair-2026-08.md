---
title: 'Two unauthenticated RCEs in Next.js, and the audit that said clean'
slug: 'nextjs-rce-pair-2026-08'
type: 'incident'
last_updated: '2026-08-26'
draft: false
summary: 'On August 25, 2026, Next.js shipped 15.5.24 and 16.3.3 to close two unauthenticated remote code execution advisories. One reaches back to Next 10.0.0 through the Image Optimization API. The other affects Windows-hosted servers and has no workaround. The second half of this report is about what happened the next day, when the aggregated advisory feeds had not caught up yet and the reflex check still reported nothing.'
campaign: 'Vendor security release'
attack_date: '2026-08-25'
related_probe_ids:
  - 'Compromised Packages'
  - 'Package Manager Hardening'
related_incident_slugs:
  - unconfirmed-npm-window-2026-07
  - mini-shai-hulud-keyv-2026-08
sources:
  - title: 'Next.js, August 2026 security release (vendor advisory)'
    url: 'https://nextjs.org/blog/august-2026-security-release'
  - title: 'GHSA-p293-qw3h-jr36, Next.js path traversal to RCE on Windows'
    url: 'https://github.com/vercel/next.js/security/advisories/GHSA-p293-qw3h-jr36'
  - title: 'GHSA-2xp9-vwfh-vxw4, Next.js image optimization RCE'
    url: 'https://github.com/vercel/next.js/security/advisories/GHSA-2xp9-vwfh-vxw4'
  - title: 'CVE-2026-75604'
    url: 'https://www.cve.org/CVERecord?id=CVE-2026-75604'
  - title: 'npm registry, next package metadata'
    url: 'https://registry.npmjs.org/next'
  - title: 'CWE-22, Improper Limitation of a Pathname to a Restricted Directory'
    url: 'https://cwe.mitre.org/data/definitions/22.html'
---

## What happened

On August 25, 2026, the Next.js team published a security release and two
advisories. Both describe unauthenticated remote code execution. The fixed
releases are 15.5.24 on the maintenance line and 16.3.3 on the active line, and
the npm registry records both as published that same day.

The first, CVE-2026-75604 (GHSA-p293-qw3h-jr36), is a path traversal weakness,
CWE-22, in applications that use both the Pages Router and the App Router
without Cache Components. The advisory states it allows unauthenticated remote
code execution when the Next.js server runs on a Windows filesystem, and that
Linux and macOS are not affected. The affected ranges given are 13.4 up to
15.5.24, and 16.0 up to 16.3.3. The advisory states there is no known
workaround for affected Windows-hosted applications, which means upgrading is
the whole remediation.

The second, GHSA-2xp9-vwfh-vxw4, concerns the Image Optimization API. The
advisory describes a flaw in the libheif library underneath sharp that allows
unauthenticated remote code execution when an attacker-controlled AVIF image is
processed. The patched releases mitigate it by disabling AVIF optimization
until the upstream fix lands. The affected floor here is Next 10.0.0, which
reaches back considerably further than the first issue. No CVE was assigned to
the Next.js advisory itself.

Two details are worth holding onto. The Windows issue is rated with high attack
complexity; the AVIF issue is rated low. And the router combination in the
first advisory, Pages plus App without Cache Components, is a common accident
rather than a deliberate architecture. It is what a partial migration looks
like when it stops halfway.

## The part that happened the next day

On August 26, one day after both advisories were public and both fixed
versions were live on npm, a direct query to the OSV API for the npm package
`next` returned nothing newer than an advisory published on July 22. Neither
critical had been ingested yet.

This is a point-in-time observation on one date, not a standing claim about any
feed. Aggregators backfill, and by the time this is read the gap will have
closed. The reason it is recorded here is what it means for the reflex action.

A developer who reached for a dependency audit that morning, which is the
sensible reflex and the one an AI assistant will suggest, would have been told
their Next.js application was clean while two unauthenticated remote code
execution advisories stood open against it. The information existed. It was
published by the vendor, on the vendor's own blog and security advisory pages,
and the fixed versions were sitting on the registry. It had not yet arrived in
the place the tooling was looking.

The days immediately after disclosure are when a vulnerability is most
dangerous, because the advisory is public and the fix is not yet deployed
everywhere. That is the same window in which aggregated feeds are least likely
to have caught up. A passing audit during those days is not evidence of safety.
It is evidence that the feed has not ingested the advisory yet.

## What to check in your own project

First, find out what version you are actually running, which is not always the
version in package.json:

```bash
npm ls next
```

If it is below 15.5.24 on the 15 line, or below 16.3.3 on 16, upgrade. If you
are on 14 or 13.4, the upgrade path is to 15.5.24 or later.

Then answer three questions about your deployment, because they change how
urgent this is:

1. **Does the server run on Windows?** If yes, CVE-2026-75604 applies and the
   advisory offers no workaround. If your production host is Linux, that one
   does not apply to production, though it still applies to a Windows machine
   running a local production build.
2. **Do you have both a `pages/` and an `app/` directory?** That combination is
   the precondition for the first advisory. A migration that was started and
   not finished lands exactly here.
3. **Do you use `next/image` on images that users supply?** Avatar uploads,
   profile photos, anything a visitor can put a file into. That is the path for
   the AVIF issue, and it needs no authentication and no user interaction.

If you cannot upgrade today, the second issue can be reduced by not passing
user-supplied images through the optimizer. The first cannot, so a Windows host
running an affected range should be treated as the priority.

## What PreFlight does about it

Nothing yet, and that is worth saying plainly rather than implying otherwise.

PreFlight's version-aware dependency probe is deliberately scoped to malicious
releases. It reads a curated manifest of package versions that were published
by an attacker, and it reports them as CWE-506, embedded malicious code. A
legitimate release of Next.js that happens to contain a bug is not malware, and
reporting it under that probe would be wrong in both the severity and the
remediation text.

What is missing is a second, separate manifest: known-vulnerable version ranges
for legitimate packages, with its own probe and its own wording. The existing
semantic version matching is reusable, though it currently compares against a
list of exact versions rather than an open range like `>=13.4 <15.5.24`, so
range comparison is the real work.

The feed lag above is the argument for maintaining such a manifest from vendor
advisories rather than waiting for an aggregator. It is also the argument for a
sourcing rule: for a fast-moving advisory, the vendor's own security page and
the package registry are ahead of the aggregators, and the absence of an entry
in a feed is not evidence that nothing is wrong.

Until that ships, this is a manual check. The three questions above take about
a minute, and the upgrade is a version bump.

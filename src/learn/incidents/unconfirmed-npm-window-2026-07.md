---
title: 'The unconfirmed majority: reading supply-chain intel, May to July 2026'
slug: 'unconfirmed-npm-window-2026-07'
type: 'incident'
last_updated: '2026-07-25'
draft: false
summary: 'A review of the May 12 to July 25, 2026 npm window produced a long list of claimed compromises and three that could be confirmed against a primary advisory. This is a field report about the gap between those two numbers, why it is growing, and how to check a supply-chain claim before you act on it.'
campaign: 'Multiple claimed campaigns, most unconfirmed'
attack_date: '2026-05-19'
related_probe_ids:
  - 'Compromised Packages'
  - 'Malicious Artifacts'
  - 'Package Manager Hardening'
related_incident_slugs:
  - mini-shai-hulud-tanstack-2026-05
  - intercom-client-bitwarden-cli-2026-04
  - sapphire-sleet-axios-2026-03
sources:
  - title: 'TanStack postmortem: npm supply chain compromise'
    url: 'https://tanstack.com/blog/npm-supply-chain-compromise-postmortem'
  - title: 'GitHub Advisory GHSA-g7cv-rxg3-hmpx (TanStack affected versions)'
    url: 'https://github.com/advisories/GHSA-g7cv-rxg3-hmpx'
  - title: 'OSV MAL-2026-3652 (supabase-javascript)'
    url: 'https://api.osv.dev/v1/vulns/MAL-2026-3652'
  - title: 'OSV MAL-2026-5479 (mcp-server-github)'
    url: 'https://api.osv.dev/v1/vulns/MAL-2026-5479'
  - title: 'Red Hat Security Bulletin RHSB-2026-006'
    url: 'https://access.redhat.com/security/vulnerabilities/RHSB-2026-006'
  - title: 'GitHub Advisory Database, npm malware advisories'
    url: 'https://github.com/advisories?query=type%3Amalware+ecosystem%3Anpm'
  - title: 'CWE-506, Embedded Malicious Code'
    url: 'https://cwe.mitre.org/data/definitions/506.html'
---

## What happened

This report is not about a compromise. It is about a review that went sideways, and what that says about the state of supply-chain reporting.

PreFlight keeps a manifest of known-compromised package versions. Every few months it gets reviewed against what has been published since the last pass. The review covering May 12 through July 25, 2026 started with a research sweep that returned a large, well-organized document: named campaigns, exact version strings, attribution, citations, thousands of packages.

Three entries survived contact with a primary source.

That ratio is the finding. Not because the research was careless, but because the shape of its errors turns out to be predictable, and the same shape is now showing up anywhere threat intel is assembled at speed.

## What was confirmed

Three additions, each read directly off an advisory rather than a summary of one.

**`echarts-for-react` 3.1.7 and 3.2.7.** Malware published through a compromised maintainer account on May 19, 2026. The advisory's own guidance is blunt: any machine that installed or ran the package should be treated as fully compromised, and every secret on it should be rotated from a different machine.

**`supabase-javascript` 2.98.3.** An impersonation package. It is not the official Supabase client, it clones the real project's metadata to look like it, and it ships a packed executable that registers itself as a session-start hook for an AI coding assistant. That last detail matters more than the package does: the payload's persistence lives in agent configuration, so it survives uninstalling the package.

**`mcp-server-github` 0.0.1 and 0.0.2.** An unscoped squat on the official scoped MCP server package. A postinstall hook reports hostname, working directory, Node version and package-manager user agent to an attacker-controlled endpoint. It fires on `npx`, before any tool call happens.

## What could not be confirmed

The research also described, with version-level specificity, campaigns that a primary source would not corroborate.

A wave of roughly three hundred packages in a charting library's namespace, clustered around the `echarts-for-react` compromise. The anchor is real. The roster is not confirmed. One named sibling package, checked directly, has no malware advisory at all.

A scope takeover of between eighty-nine and one hundred forty-five packages belonging to an AI agent framework, attributed to a named state actor. The advisory database returns nothing for that namespace.

Malicious releases of a code-obfuscation toolchain and of an API specification tooling suite. Zero advisories for the first. For the second, only unrelated vulnerabilities from 2021.

One case sits in between. A vendor security bulletin confirms that thirty-two packages in its own npm namespace were compromised, names the campaign, and gives the timeline. It does not publish which versions. The incident is real and documented, and it still cannot become a manifest entry, because an entry needs a version string and there is not one to copy.

Unconfirmed is not the same as false. Several of these are plausible. They are simply not yet checkable, and a detection tool does not get to act on plausible.

## The two claims that were wrong

Two items were specific enough to disprove outright, and both are worth studying because of how they failed.

The first was a marker version, reported as having been published across every package in the May 11 TanStack wave alongside that wave's real malicious releases. The advisory the victim's own postmortem points to lists forty-two packages with exactly two versions each. The marker version appears nowhere in it. Several of those packages have live release lines low enough that the invented number could ship legitimately later, which would have turned a detection tool into an accuser of an innocent release.

The second was a warning that the manifest's coverage of that same wave was probably half missing, reasoned from the fact that the wave landed one day before the previous review date. A direct comparison of the shipped data against the advisory found forty-two packages for forty-two, every version string matching, nothing extra. The coverage was already complete. The warning was inference presented as observation.

A third, smaller error had the same shape as the first: a third malicious version attributed to `echarts-for-react` that its advisory does not list.

## The pattern worth carrying

The errors were not randomly distributed. Every individual advisory lookup that got checked was exact. The package existed, the versions matched, the campaign name was right. The failures lived entirely in the layer above: marker versions spanning a wave, package counts, groupings, and confident statements about what was missing.

That is a useful thing to know, because it says the failure mode is not fabricated sources. It is fabricated _structure_. Summarizing pressure produces tidy patterns, and a tidy pattern is exactly what a version list is not. Real waves are ragged. Forty-two packages with two versions each, and nothing else, is what the ground truth looked like. A marker version shared across all of them is what a summary of that ground truth wants to look like.

Apply the same suspicion to any intel that arrives already organized. The organization is the part most likely to be invented.

## How to check a claim before acting on it

The check is short and it does not require a subscription to anything.

1. **Find the advisory, not the article.** For npm and PyPI, the advisory databases are public and queryable by package name. An article about a compromise should lead to one. If nothing anywhere leads to one, that is information.
2. **Read the version list yourself.** Not the summary of it. Compare character by character against what you have installed. A version that is adjacent to a malicious one is not malicious.
3. **Prefer the victim's postmortem when it exists.** Projects that get compromised increasingly publish detailed writeups, and they are the most accurate account of what shipped, because the maintainers had to enumerate it to clean it up.
4. **Check your lockfile, not your manifest.** A range in `package.json` says what is permitted. The lockfile says what installed. Those are different questions and only the second one describes your actual exposure.
5. **When the answer is "cannot confirm," stop there.** Do not upgrade a maybe into a yes because the maybe is scary.

## What the manifest can and cannot be

There is a scale problem underneath all of this that is worth being honest about.

The public malware feed for npm runs to dozens of new advisories per day. Read a day of it and the character is immediately clear: disposable names, keyword spam, squats with no downstream users, packages that exist to be counted rather than installed. No curated list of named packages can track that volume, and chasing it would be the wrong goal anyway.

A manifest of known-compromised versions is for the other category. A package that real dependency trees already depend on, whose maintainer account or build identity was taken over. That list is short, it is checkable, and it is the one where an exact version string changes what a developer should do this afternoon.

Everything else belongs to behavior. Install hooks that fetch and execute. Payloads that write themselves into agent configuration so they outlive the package. Names one edit away from a package that has ten million weekly downloads. Those checks do not need to know a package's name in advance, which is the only property that scales against a feed like this one.

## What to learn

Supply-chain intel is getting faster to produce and harder to verify at the same time, and those two curves are not going to stop diverging. The response is not to distrust everything. It is to be clear with yourself about which of two things you have in hand.

A lead tells you where to look. An entry tells you what to do. They feel similar when both arrive in the same well-formatted paragraph, and treating one as the other is how a security tool starts making confident claims about packages that were never touched.

For the version list a scanner acts on, the standard is the boring one. Someone read the advisory. The version strings came from that advisory. If nobody read it, it does not ship.

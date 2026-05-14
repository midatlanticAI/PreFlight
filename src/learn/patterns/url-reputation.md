---
title: External URL hygiene
slug: url-reputation
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - URL Reputation
sources:
  - title: 'VirusTotal — Domain reputation'
    url: https://www.virustotal.com/
  - title: 'urlhaus (abuse.ch)'
    url: https://urlhaus.abuse.ch/
  - title: 'CWE-829 — Inclusion of Functionality from Untrusted Control Sphere'
    url: https://cwe.mitre.org/data/definitions/829.html
summary: External URLs flagged ONLY when they trip an objective signal — raw-IP endpoints, suspicious TLDs (.tk, .xyz, .gq, etc.), URL shorteners, or HTTP-only links. Generic HTTPS URLs on unfamiliar hosts are NOT findings. A signal to verify, not a verdict.
---

## What this is

Pre-Flight extracts every external HTTP/HTTPS URL from the project's source and emits a finding only when the URL trips one of four objective signals. A generic HTTPS URL on a host the probe doesn't recognize is **not** a finding. (The pre-v0.6 behavior emitted an `info` finding for every unrecognized host, which produced a wall of noise on real projects that legitimately reference dozens of third-party domains.)

The signals:

- **Raw IP URLs** — `http://1.2.3.4/...`. Real APIs use hostnames. A raw IP in source is either a developer leaving a debug endpoint, a placeholder that wasn't replaced, or a deliberately-obscured destination. Severity: medium.
- **Suspicious TLDs** — `.tk`, `.xyz`, `.gq`, `.ml`, `.cf`, `.top`, `.click`, `.zip`, `.mov`, and others disproportionately used by abuse infrastructure because they offer free or near-free registration with minimal verification. Severity: medium.
- **URL shorteners** — `bit.ly`, `tinyurl.com`, `goo.gl`, `t.co`, `ow.ly`, and others. A shortener in source hides the destination. The target at write-time may differ from the target at run-time. Severity: medium.
- **HTTP-only** — plain `http://` URL, no `https://` alternative seen for the same host. Either downgrade-prone or pointing at infrastructure that doesn't support TLS. Severity: low.

The probe also excludes: URLs inside `// comments` and JSDoc bodies (documentation, not runtime endpoints), URLs inside `remediation:` / `description:` / `learn_more:` / `source:` string-literal contexts (probe meta, not endpoints), the project's own homepage (`package.json#homepage`), self-domains declared in `.preflight.yml`, IANA-reserved example hosts (`example.com`, `localhost`, etc.), and RFC 5737 documentation-IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

## Why it matters

A domain you trusted at write-time may not be the domain you trust at run-time. Common evolutions:

- Domain sold to a new owner with different intentions.
- Domain expired and re-registered by an adversary (called "domain hijacking" or "expired-domain takeover").
- Domain compromised because the owner's account got phished.
- Domain working as intended but the destination behavior changed (a "fetch this config" URL that used to return JSON now returns a malicious script).

The URL Reputation probe doesn't catch these directly. It catches the patterns where these are more likely. A `.tk` URL in production code is not necessarily malicious, but it's worth a five-second check.

## What the failure looks like

A finding fires only when at least one of the four signals matches. Severity:

- HTTP-only with no TLS: **low**.
- Raw IP, suspicious TLD, or URL shortener: **medium**.

Every finding links to one-click VirusTotal, urlhaus, and whois lookups so the verification is immediate.

Each unique host is grouped into a single finding (the evidence field lists the first three occurrence locations) so a host referenced ten times doesn't produce ten duplicate entries.

## What the fix looks like

For each flagged URL, ask:

- Is this URL load-bearing in production code, or is it a comment / docstring / fallback?
- Does the URL still resolve to what the developer intended?
- Does the domain's WHOIS history match the developer's expectation?

If the URL is fine, suppress the finding (Pre-Flight supports per-finding suppression with notes).

If the URL is suspicious, replace it with a known-good alternative or remove the code path entirely.

For URLs that pass external reputation checks but are still worth tightening:

- Replace raw-IP URLs with hostnames that resolve to them. Hostnames can be re-pointed; raw IPs can't.
- Replace `http://` with `https://` wherever possible.
- Replace URL shorteners with the unshortened destination.
- Avoid `.tk` / `.xyz` / `.gq` infrastructure for anything customer-facing.

## Related

- [SSRF and open redirects](/learn/patterns/ssrf-open-redirect) covers the case where the URL is user-supplied rather than developer-supplied.
- [package.json supply-chain hooks](/learn/patterns/package-json-supply-chain) covers the parallel case for non-registry URLs in dependency specs.

## Sources

VirusTotal and urlhaus (abuse.ch) are the standard external reputation checks. CWE-829 names the broader class of pulling functionality from untrusted sources.

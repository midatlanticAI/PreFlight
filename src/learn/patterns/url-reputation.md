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
summary: External URLs referenced in source flagged when they match patterns associated with abuse: raw-IP URLs, suspicious TLDs (.tk, .xyz, .gq), URL shorteners, http-only links. A signal to verify, not a verdict.
---

## What this is

Pre-Flight extracts every external HTTP/HTTPS URL from the project's source and runs heuristics over each. The probe is informational by design; a finding asks you to verify, not to patch.

The heuristics:

- **Raw IP URLs**: `http://203.0.113.42/...`. Real APIs use hostnames. A raw IP in source is either a developer leaving a debug endpoint, a placeholder that wasn't replaced, or a deliberately-obscured destination.
- **Suspicious TLDs**: `.tk`, `.xyz`, `.gq`, `.ml`, `.cf`, `.top`. These TLDs are disproportionately used by abuse infrastructure because they offer free or near-free registration with minimal verification.
- **URL shorteners**: `bit.ly`, `tinyurl.com`, `goo.gl`, and others. A shortener in source hides the destination. The destination at write-time may differ from the destination at run-time.
- **`http://` (not `https://`)**: plain HTTP in source. Either downgrade-prone or pointing at infrastructure that doesn't support TLS, both of which warrant a check.

The probe avoids known-safe hosts (`github.com`, `npmjs.com`, `cloudflare.com`, major cloud provider domains, etc.) to keep the noise level reasonable.

## Why it matters

A domain you trusted at write-time may not be the domain you trust at run-time. Common evolutions:

- Domain sold to a new owner with different intentions.
- Domain expired and re-registered by an adversary (called "domain hijacking" or "expired-domain takeover").
- Domain compromised because the owner's account got phished.
- Domain working as intended but the destination behavior changed (a "fetch this config" URL that used to return JSON now returns a malicious script).

The URL Reputation probe doesn't catch these directly. It catches the patterns where these are more likely. A `.tk` URL in production code is not necessarily malicious, but it's worth a five-second check.

## What the failure looks like

Each external URL produces a finding at info / low / medium severity based on which heuristics match:

- One heuristic match: info.
- Multiple heuristic matches: low or medium.

Pre-Flight links each finding to one-click VirusTotal, urlhaus, and whois lookups so the verification is immediate.

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

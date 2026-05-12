---
title: Auth weaknesses — JWT alg-none and friends
slug: auth-weakness
type: pattern
last_updated: 2026-05-12
draft: true
related_probe_ids:
  - Auth Weakness
sources:
  - title: OWASP JWT cheat sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
  - title: CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
    url: https://cwe.mitre.org/data/definitions/327.html
summary: 'JWTs signed with algorithm-none (unsigned, forgeable), JWT verification with a weak or hardcoded secret, and the AI-tooling shorthand patterns that produce both.'
---

> _Draft — content coming soon._
>
> Will cover: the alg-none class of vulnerability (CVE-2015-9235 and the long
> tail of repeat offenders), why AI tools regenerate it (they reach for the
> simplest example that compiles), the canonical fix (`HS256` with a strong
> rotated secret, or `RS256` with a key pair), and the audit habit of grep-
> ing every JWT-touching file for the literal string `algorithm: 'none'`
> before merging.

---
title: GDPR Article 32 / 25 (security and privacy by design)
slug: compliance-gdpr
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids: []
sources:
  - title: Regulation (EU) 2016/679 (GDPR) — full text
    url: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679
  - title: GDPR Article 32 — Security of processing
    url: https://eur-lex.europa.eu/eli/reg/2016/679/oj
summary: GDPR Article 32 requires security appropriate to risk, and Article 25 requires data protection by design. The technical half of those duties is partly code-visible. Pre-Flight maps a subset of its probes to Article 32 as an interpretation layer, never a certification.
---

## What this is

The GDPR governs processing of personal data of people in the EU.
Article 32 requires technical and organisational measures appropriate to
the risk, and names encryption and the ability to ensure
confidentiality, integrity, and availability. Article 25 requires data
protection by design and by default.

## Why an AI-generated app in this domain must care

"Appropriate to the risk" is judged against the state of the art. An app
that interpolates user input into SQL, ships a disabled TLS check, or
hard-codes a key is below that bar for any non-trivial personal-data
processing, regardless of intent.

## What Pre-Flight does and does not do here

Pre-Flight is in scan scope for the code-detectable, technical slice of
Article 32 / 25. The probe families map to Article 32 as `indicative`
references: the pattern is associated with the security-of-processing
duty, but whether it is a violation depends on the data processed and
the risk assessment, which only a human can perform.

Pre-Flight does not certify GDPR compliance. Lawful basis, data subject
rights, DPIAs, records of processing, and international transfer
mechanisms are out of scan scope. They are a much larger duty than the
code.

## What a reviewer looks for

Evidence that security measures match the risk: encryption in transit
and at rest, sound authentication, minimised and validated input, and a
documented assessment. A Pre-Flight `indicative` finding is a pointer
into that assessment.

## Not legal advice

This page explains how Pre-Flight relates findings to GDPR article text.
It is not legal advice and not a compliance attestation. Confirm
obligations with a data protection professional.

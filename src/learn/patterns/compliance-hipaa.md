---
title: HIPAA Security Rule (technical safeguards)
slug: compliance-hipaa
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids: []
sources:
  - title: 45 CFR 164.312 — Technical safeguards
    url: https://www.ecfr.gov/current/title-45/section-164.312
  - title: HHS — HIPAA Security Rule guidance
    url: https://www.hhs.gov/hipaa/for-professionals/security/index.html
summary: HIPAA's Security Rule sets technical safeguards for electronic protected health information. Some of those safeguards are visible in source code. PreFlight maps a subset of its probes to specific 45 CFR 164.312 clauses as an interpretation layer, never a certification.
---

## What this is

The HIPAA Security Rule (45 CFR Part 164, Subpart C) requires covered
entities and business associates to protect electronic protected health
information (ePHI). The technical safeguards in 164.312 are the part that
shows up in code: access control, integrity, transmission security, and
person-or-entity authentication.

## Why an AI-generated app in this domain must care

A prototype that handles patient data inherits HIPAA obligations the
moment it touches real ePHI. AI scaffolding optimises for "runs locally,"
not for the encryption and authentication 164.312 expects. The gap is
usually invisible until an auditor or a breach makes it visible.

## What PreFlight does and does not do here

PreFlight is in scan scope for HIPAA technical safeguards that are
code-detectable. The v0.5 probe families carry an interpretation layer
mapping a finding to a clause:

- TLS verification disabled and JWT signature not verified map to
  164.312(e)(1) transmission security and 164.312(d) entity
  authentication as `direct` references: the pattern is itself the
  control failure.
- Unsafe deserialization, raw-query interpolation, and hardcoded secrets
  map to 164.312(c)(1) integrity and 164.312(d) as `indicative`
  references: the pattern is associated with the clause but a human must
  judge whether the data in scope is ePHI.

PreFlight does not certify HIPAA compliance. It surfaces a code pattern
and the clause a reviewer should think about. The administrative and
physical safeguards, risk analysis, and Business Associate Agreements
that HIPAA also requires are out of scan scope entirely.

## What an auditor looks for

Encryption of ePHI in transit and at rest, unique user identification,
authentication that actually verifies identity, audit controls, and an
integrity mechanism. An `indicative` PreFlight finding is a prompt to
check one of these, not a verdict.

## Not legal advice

This page explains how PreFlight relates its findings to HIPAA clause
text. It is not legal advice and not a compliance attestation. Confirm
scope and obligations with qualified counsel.

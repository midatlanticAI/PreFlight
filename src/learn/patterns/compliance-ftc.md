---
title: FTC Act Section 5 and the Safeguards Rule — taught, not scanned
slug: compliance-ftc
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids: []
sources:
  - title: FTC Act Section 5 — Unfair or deceptive acts or practices
    url: https://www.ftc.gov/legal-library/browse/statutes/federal-trade-commission-act
  - title: FTC Safeguards Rule (16 CFR Part 314)
    url: https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314
summary: The FTC enforces against deceptive data practices and, for financial institutions, the Safeguards Rule. Liability turns on representations and an overall security program, not a code line. PreFlight teaches this area but does not scan for it.
---

## What this is

Under Section 5 of the FTC Act, a security claim a product makes that is
not true can be an unfair or deceptive practice. The Safeguards Rule (16
CFR Part 314) requires non-bank financial institutions to maintain a
written information security program.

## Why an AI-generated app in this domain must care

The most common FTC exposure for a young product is a privacy or
security promise in marketing copy that the implementation does not
keep. "Bank-grade encryption" on a site that disables TLS verification
is the textbook example.

## Why PreFlight does not scan for FTC obligations

FTC exposure depends on what a company claims, its overall written
security program, and reasonableness in context. Those are not code
properties. PreFlight maps no probe to the FTC Act or the Safeguards
Rule.

What PreFlight can do is show whether the security reality matches the
claim: a disabled TLS check or a hardcoded key is a security finding
that may make a public security promise untrue. The finding is labelled
as security, and the gap to the marketing claim is a judgement for the
team and its counsel.

## What a reviewer looks for

Consistency between public representations and the implemented controls,
plus a documented security program proportionate to the data. Reviewed
against statements and process, not a regex.

## Not legal advice

This page explains why FTC obligations are out of scan scope. It is not
legal advice. Consult counsel on advertising and data-security claims.

---
title: FDA 21 CFR Part 11 / SaMD — taught, not scanned
slug: compliance-fda
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids: []
sources:
  - title: 21 CFR Part 11 — Electronic records; electronic signatures
    url: https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11
  - title: FDA — Software as a Medical Device (SaMD)
    url: https://www.fda.gov/medical-devices/digital-health-center-excellence/software-medical-device-samd
summary: FDA rules for electronic records (21 CFR Part 11) and Software as a Medical Device hinge on validation, intended use, and risk classification. None of that is a code pattern. PreFlight teaches this area but does not scan for it.
---

## What this is

21 CFR Part 11 sets requirements for trustworthy electronic records and
signatures in FDA-regulated contexts: validation, audit trails,
authority checks, and signature integrity. Software as a Medical Device
(SaMD) adds intended-use and risk-classification obligations.

## Why an AI-generated app in this domain must care

If a tool influences a clinical decision or holds regulated electronic
records, its regulatory burden is set by intended use and risk class,
which drive validation and quality-system obligations far beyond
application security.

## Why PreFlight does not scan for FDA rules

Part 11 and SaMD conformance is established through validation
documentation, a quality management system, risk files, and intended-use
statements. A static code scan cannot evaluate validation status or
intended use, so PreFlight maps no probe to FDA rules.

Generic security probes still apply to the software as security
findings, and an audit trail being absent in code may be relevant
evidence, but PreFlight does not present these as Part 11 conclusions.

## What a reviewer looks for

A validation plan and results, controlled audit trails, signature
manifest integrity, and a risk classification consistent with intended
use. These are documentation and process artifacts.

## Not legal advice

This page explains why FDA software rules are out of scan scope. It is
not regulatory advice. Engage regulatory affairs and quality
professionals.

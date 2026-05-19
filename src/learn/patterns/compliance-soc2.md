---
title: SOC 2 (Trust Services Criteria, readiness indicators)
slug: compliance-soc2
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids: []
sources:
  - title: AICPA — SOC suite of services
    url: https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services
  - title: AICPA — Trust Services Criteria
    url: https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
summary: SOC 2 reports on controls against the AICPA Trust Services Criteria. It is an attestation by an auditor, not a code property. PreFlight maps a few probes to the Common Criteria as readiness indicators only, never an opinion.
---

## What this is

SOC 2 is an attestation report: an independent CPA firm forms an opinion
on whether an organisation's controls meet the Trust Services Criteria
(security, availability, processing integrity, confidentiality,
privacy). The Common Criteria CC6.x cover logical and physical access.

## Why an AI-generated app in this domain must care

A startup pursuing SOC 2 will have an auditor test logical access
controls. Hard-coded credentials and disabled transport security are the
kind of finding that produces an exception in CC6.1 / CC6.7 testing, and
they are cheaper to fix before the audit than during it.

## What PreFlight does and does not do here

PreFlight is in scan scope only as a readiness indicator. Hardcoded
secrets and weak authentication map to CC6.1 (logical access), and
disabled TLS verification maps to CC6.7 (transmission), both as
`indicative` references.

PreFlight does not produce or replace a SOC 2 report. An attestation is
an auditor's opinion over a period of time across people, process, and
technology. A clean PreFlight scan is one input a readiness assessment
might use, nothing more.

## What an auditor looks for

Documented, operating controls over access provisioning, authentication,
encryption, change management, and monitoring, with evidence across the
report period. A PreFlight finding is a pre-audit signal, not control
evidence.

## Not legal advice

This page explains how PreFlight relates findings to the Trust Services
Criteria. It is not an attestation and not professional advice. Engage a
licensed CPA firm for SOC 2.

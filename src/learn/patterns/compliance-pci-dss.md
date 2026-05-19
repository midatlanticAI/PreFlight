---
title: PCI DSS v4.0 (the code-visible requirements)
slug: compliance-pci-dss
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids: []
sources:
  - title: PCI Security Standards Council — Document Library
    url: https://www.pcisecuritystandards.org/document_library/
  - title: PCI DSS — official standards site
    url: https://www.pcisecuritystandards.org/
summary: PCI DSS v4.0 governs systems that store, process, or transmit cardholder data. A few of its requirements are visible in source code. PreFlight maps a subset of its probes to PCI requirements as an interpretation layer, never a certification.
---

## What this is

PCI DSS (Payment Card Industry Data Security Standard) v4.0 applies to
any system in the cardholder data environment. Most of its 12
requirement areas are process and network controls. A few are
code-visible: injection defenses (Req 6.2.4), strong cryptography for
data in transit (Req 4.2.1), and not hard-coding authentication
credentials (Req 8.3.x).

## Why an AI-generated app in this domain must care

The moment a prototype takes a card number it is in scope. AI tools
emit string-built SQL, disabled TLS verification, and inline keys
because those are the shortest paths to a running demo. Each is named,
directly or by category, in PCI DSS.

## What PreFlight does and does not do here

PreFlight is in scan scope for the code-detectable PCI requirements.
The raw-query family maps to Req 6.2.4 as a `direct` reference (SQL
injection is the canonical injection flaw). TLS verification disabled
maps to Req 4.2.1 as `direct`. Hardcoded secrets map to Req 8.3.1 /
8.6.2 as `indicative` (the weight depends on what the credential
unlocks).

PreFlight does not certify PCI compliance, complete a SAQ, or replace a
QSA assessment. Network segmentation, key management lifecycle, logging
retention, and the rest of the 12 requirements are out of scan scope.

## What an assessor looks for

Parameterised queries, TLS configured and verified, no shared or
hard-coded credentials, and evidence the cardholder data environment is
scoped and segmented. A PreFlight finding is an input to that review,
not the review itself.

## Not legal advice

This page explains how PreFlight relates findings to PCI DSS
requirement text. It is not a compliance attestation. Engage a QSA for
formal assessment.

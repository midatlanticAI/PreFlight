---
title: SOX Section 404 (financial controls) — taught, not scanned
slug: compliance-sox
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids: []
sources:
  - title: Sarbanes-Oxley Act of 2002 — full text
    url: https://www.govinfo.gov/content/pkg/PLAW-107publ204/html/PLAW-107publ204.htm
  - title: SEC — Sarbanes-Oxley Section 404
    url: https://www.sec.gov/rules-regulations/2003/06/managements-reports-internal-control-over-financial-reporting
summary: SOX Section 404 requires public companies to assess internal control over financial reporting. Whether a control is effective is an audit conclusion about process, not a code property. PreFlight teaches SOX but does not scan for it.
---

## What this is

The Sarbanes-Oxley Act, Section 404, requires management and an external
auditor to report on the effectiveness of internal control over
financial reporting (ICFR). For software, the relevant controls are
change management, access segregation, and audit trails over
financially-relevant systems.

## Why an AI-generated app in this domain must care

If a system feeds the financial close, its change and access controls
are in ICFR scope. The risk in an AI-built tool is usually missing
segregation of duties and missing audit trails, not a single code line.

## Why PreFlight does not scan for SOX

SOX effectiveness is concluded from how changes are approved and
deployed, who can alter financial data, and whether the audit trail is
complete and reviewed, over a reporting period. That is process
evidence, not a static code pattern. PreFlight maps no probe to SOX.

The underlying security probes still apply to a financial app as
security findings. They are not, and are not labelled as, SOX controls.

## What an auditor looks for

Documented change approval, enforced segregation of duties, immutable
and reviewed audit logs, and access recertification, tested across the
period. None of this is derivable from source alone.

## Not legal advice

This page explains SOX's shape and why it is out of scan scope. It is
not legal or audit advice. Engage qualified auditors and counsel.

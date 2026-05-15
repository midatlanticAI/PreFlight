---
title: FERPA (education records) — why Pre-Flight teaches but does not scan
slug: compliance-ferpa
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids: []
sources:
  - title: 20 U.S.C. 1232g — FERPA statute
    url: https://www.govinfo.gov/content/pkg/USCODE-2021-title20/html/USCODE-2021-title20-chap31-subchapIII-part4-sec1232g.htm
  - title: 34 CFR Part 99 — FERPA regulations
    url: https://www.ecfr.gov/current/title-34/subtitle-A/part-99
summary: FERPA governs the privacy of student education records. Whether a system is FERPA-compliant depends on consent, disclosure, and institutional policy, not on a code pattern. Pre-Flight teaches FERPA but does not scan for it.
---

## What this is

FERPA (the Family Educational Rights and Privacy Act) protects the
privacy of student education records held by schools that receive
federal funding. It governs who may access records, what disclosures are
permitted, and the rights of students and parents.

## Why an AI-generated app in this domain must care

An ed-tech prototype that stores grades, attendance, or disciplinary
records is handling education records. FERPA obligations attach to how
those records are disclosed and consented to, not only to how they are
stored. Building the consent and access model wrong is the common
failure, and it is an architecture and policy problem.

## Why Pre-Flight does not scan for FERPA

FERPA compliance is determined by consent flows, disclosure logging,
institutional agreements, and the legitimate-educational-interest test.
None of that is reliably detectable from source code. A static scanner
that claimed to check FERPA would be making a claim it cannot support.
Pre-Flight does not map any probe to FERPA.

What Pre-Flight can still help with is the generic security underneath:
the same hardcoded-secret, raw-SQL, and transport probes apply to an
ed-tech app like any other. Those findings are security findings, not
FERPA findings, and the tool labels them as such.

## What a reviewer looks for

A defensible record of consent and disclosure, role-scoped access to
education records, and agreements with any third-party processors. These
are reviewed against policy and data flow, not a regex.

## Not legal advice

This page is education about FERPA's shape and why it is out of scan
scope. It is not legal advice. Consult counsel experienced in education
privacy.

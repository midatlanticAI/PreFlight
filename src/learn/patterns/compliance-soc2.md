---
title: SOC 2 (Trust Services Criteria, readiness indicators)
slug: compliance-soc2
type: pattern
last_updated: 2026-08-25
draft: false
related_probe_ids: []
sources:
  - title: AICPA — SOC suite of services
    url: https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services
  - title: AICPA — Trust Services Criteria
    url: https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
  - title: NIST SP 800-218 — Secure Software Development Framework v1.1
    url: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf
  - title: OWASP Application Security Verification Standard
    url: https://owasp.org/www-project-application-security-verification-standard/
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

## Where static analysis stops and testing begins

The boundary is not a matter of tool quality. It is a category line, and
NIST SP 800-218 draws it in the open.

PW.7 covers reviewing and analysing human readable code. Its second task,
PW.7.2, lists using a static analysis tool to check code for
vulnerabilities as an implementation example, and it requires that
discovered issues be recorded and triaged in the team's workflow, not
merely displayed.

PW.8 is a separate practice covering the testing of executable code,
described as finding vulnerabilities not identified by previous reviews
or analysis. Dynamic testing and penetration testing live there.

The split explains what no static tool can reach. Deciding whether tenant
B may read tenant A's invoice requires two authenticated sessions and a
model of who is entitled to what. That state does not exist in a file.
A scanner reads code shapes. A tester reads running behaviour. Reporting
the second from the first would be a guess wearing a finding's clothes.

## What a static tool has to do to be worth anything at this level

Four properties, none of which are about detection breadth.

The mapping must be reachable. A regulatory reference is worth nothing if
it is filed under a name that never appears on a finding. An empty
compliance report reads as a clean one, which is the most misleading
output this kind of view can produce.

The scope must be declared by the person, not inferred by the tool.
Whether an app falls under a regime is a fact about the business. A
scanner that decides HIPAA applies because it matched the word "patient"
is asserting authority it does not have.

The relationship must survive being written down. A pattern that is
itself the clause failure and a pattern that merely suggests one are
different claims. Collapsing `indicative` into `direct` inflates a hint
into a violation, and an auditor will find the seam.

It has to run more than once. PW.7.2 and RV.1.2 both describe analysis as
something configured to run on a regular or continuous basis. A scan run
the week before fieldwork is an anecdote. The same scan wired into a
repository, producing the same answer on every commit, is closer to the
repeatable evidence CC7.1 contemplates.

## What SOC 2 actually asks for, and what it does not

The Trust Services Criteria do not name penetration testing as a
requirement. CC4.1 requires management to use a variety of ongoing and or
separate evaluations to determine whether internal control is present and
functioning, and its points of focus give penetration testing as an
example of such an evaluation. That is why most auditors expect one, and
also why the framing matters. The obligation is evaluation. The pentest
is the customary way of discharging it, not the text of the rule.

Read that criterion closely, because the conjunction is doing work.
CC4.1 contemplates ongoing evaluations and separate evaluations. Ongoing
evaluations are the ones built into normal operations, running as the
process runs. Automated code analysis wired into a repository, producing
the same answer on every commit, sits squarely in that category. It is
not a lesser substitute for the criterion. It is one of the two things
the criterion asks for.

What static analysis does not supply is the separate evaluation. The
distinction has nothing to do with who built the tool. A scanner can be
entirely independent of the audited entity, third party, open source, and
identical for every user, and the evaluation it powers is still a self
assessment when the engineering team is the one running it, reading it,
and deciding what the results mean. Separate evaluations turn on the
objectivity of the evaluator, not the provenance of the instrument.

Two properties do carry weight, and they are properties of the tool
rather than the reviewer. A deterministic scanner produces the same
result when someone else re-runs it, so a finding is reproducible instead
of a screenshot to be taken on trust. A scanner with no backend produces
a result nobody could have edited in transit. Both are useful to a
reviewer assessing whether the evidence in front of them means anything.

So the standing is real and it is specific. Findings under CC6.1 and
CC6.7 are technical safeguards a scanner observes directly. Evidence that
code analysis runs continuously speaks to CC7.1 and to the ongoing half
of CC4.1. The separate half still belongs to someone with distance from
the code.

The practical value sits before any of that. The low and informational
tail of an application penetration test is largely statically visible:
credentials in source, transport verification switched off, tokens that
decode without verification. Clearing that tail first is not compliance
work. It is refusing to pay a specialist to tell you something a free
pass already knew.

## What an auditor looks for

Documented, operating controls over access provisioning, authentication,
encryption, change management, and monitoring, with evidence across the
report period. A PreFlight finding is a pre-audit signal, not control
evidence.

## Not legal advice

This page explains how PreFlight relates findings to the Trust Services
Criteria. It is not an attestation and not professional advice. Engage a
licensed CPA firm for SOC 2.

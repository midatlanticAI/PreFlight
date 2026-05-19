---
title: EU AI Act — taught, not scanned
slug: compliance-eu-ai-act
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids: []
sources:
  - title: Regulation (EU) 2024/1689 — the AI Act, full text
    url: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689
  - title: European Commission — AI Act overview
    url: https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai
summary: The EU AI Act regulates AI systems by risk tier, with obligations around data governance, transparency, human oversight, and risk management. Conformance is a system-level and documentation question, not a code pattern. PreFlight teaches the AI Act but does not scan for it.
---

## What this is

Regulation (EU) 2024/1689, the AI Act, classifies AI systems by risk
(prohibited, high-risk, limited, minimal) and attaches obligations
accordingly: risk management, data governance, technical documentation,
logging, transparency, and human oversight for high-risk systems.

## Why an AI-generated app in this domain must care

A team shipping an AI feature into the EU needs to know its risk tier
first. A high-risk classification brings a substantial documentation and
oversight burden that is mostly organisational, decided long before any
single source file.

## Why PreFlight does not scan for the AI Act

AI Act conformance depends on intended purpose, risk classification,
data governance practices, and a conformity assessment. A static code
scan cannot determine a system's risk tier or evaluate a risk-management
process, so PreFlight maps no probe to the AI Act.

The general security and prompt-handling probes PreFlight does run are
relevant engineering hygiene for any AI system, but they are security
and quality findings, not AI Act conclusions, and the tool does not
present them as such.

## What a reviewer looks for

A documented risk classification, data governance and bias controls
proportionate to that tier, logging and human-oversight design, and
technical documentation. These are assessed against the system and its
documentation, not its regexes.

## Not legal advice

This page explains the AI Act's shape and why it is out of scan scope.
It is not legal advice. Engage counsel familiar with EU AI regulation.

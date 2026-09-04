---
title: AI hallucinations
slug: ai-hallucinations
type: pattern
last_updated: 2026-09-03
draft: false
related_probe_ids:
  - AI Hallucinations
sources:
  - title: 'USENIX Security 2025 — We Have a Package for You! (slopsquatting study)'
    url: https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen
  - title: 'React — API reference (the real export list)'
    url: https://react.dev/reference/react
  - title: 'Prisma — Model queries (the real client methods)'
    url: https://www.prisma.io/docs/orm/prisma-client/queries/crud
  - title: 'Next.js — next/navigation'
    url: https://nextjs.org/docs/app/api-reference/functions/use-router
summary: APIs that read right and do not exist. useFetch imported from react, prisma.user.findOneOrThrow, a next/navigation export from a version of Next that never shipped. Each is undefined at runtime, and an invented package name is exactly what a squatter registers.
---

## What this is

A large 2025 study measured it directly: across 576,000 generated samples, roughly one in five suggested packages did not exist. The same failure appears inside real libraries as invented exports and invented methods, because the model completes what a plausible API would look like, not what the installed one is.

## Why it matters

The cheap failure is a crash: the import is `undefined`, the method throws. The expensive failure is the package manager: an invented name that reads plausibly is exactly what gets typo-registered, and installing it hands the squatter a postinstall script on your machine. The study found invented names were consistent across re-prompts, which makes them targetable.

## What the probe looks for

Closed vocabularies only, where absence is a fact rather than a guess: named imports from `react` outside its real export list, named imports from `next/navigation` outside its list, and Prisma model methods outside the client\'s fixed set. Suggested-but-nonexistent npm packages are deliberately out of scope for a client-side scanner; the supply-chain probe owns the squatting patterns that follow from them.

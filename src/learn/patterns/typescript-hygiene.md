---
title: TypeScript hygiene
slug: typescript-hygiene
type: pattern
last_updated: 2026-09-03
draft: false
related_probe_ids:
  - TypeScript Hygiene
sources:
  - title: 'TypeScript — tsconfig strict'
    url: https://www.typescriptlang.org/tsconfig/#strict
  - title: 'TypeScript — @ts-expect-error and @ts-ignore'
    url: https://www.typescriptlang.org/docs/handbook/release-notes/typescript-3-9.html#-ts-expect-error-comments
  - title: 'TypeScript — type assertions'
    url: https://www.typescriptlang.org/docs/handbook/2/everyday-types.html#type-assertions
summary: The compiler is the one reviewer AI code always has, and these are the shapes that fire the reviewer. as any ends checking for everything downstream of it, as unknown as T launders any value into any type, and @ts-ignore with no reason hides a real bug behind a library quirk.
---

## What this is

When generated code and the type checker disagree, the fastest way to green is to silence the checker. `as any`, `as unknown as T`, `// @ts-ignore`, `strict: false`. Each one is the same trade: the error moves from this line, where the context still exists, to a runtime stack trace weeks later, where it does not.

## Why it matters

`any` is contagious: everything reached through an `any` value is unchecked, and everything assigned from those is too. One cast quietly switches off the checker for a whole call chain.

The double cast is the stronger spelling of the same thing. `as unknown as User` accepts literally any value; if the shapes really overlapped, one assertion would have compiled.

Directives are debt without a ledger when they carry no reason. `@ts-expect-error` at least expires: the day the underlying error is fixed, the directive itself errors and asks to be deleted. `@ts-ignore` never does.

## What the probe does not do

Anything that needs the checker itself: implicit anys, wrong narrowing, generic constraints. PreFlight reads source, not types; run `tsc --noEmit` for the reviewer this page is about.

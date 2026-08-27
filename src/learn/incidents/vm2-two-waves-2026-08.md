---
title: 'vm2 3.11.6 was the fix, and then it was the target'
slug: 'vm2-two-waves-2026-08'
type: 'incident'
last_updated: '2026-08-26'
draft: false
summary: 'On August 17, 2026, five vm2 advisories went public and the answer was to upgrade to 3.11.6. On August 24, ten more were published, several of them naming 3.11.6 as the affected version, one at CVSS 10.0 described as an incomplete fix for the first round. A developer who patched promptly spent a week on the single version the second wave was aimed at. This is a field report about what that says for sandboxing untrusted code in a Node process at all.'
campaign: 'Sandbox escape disclosure'
attack_date: '2026-08-17'
related_probe_ids:
  - 'Compromised Packages'
  - 'Taint Flow'
  - 'Code Quality'
related_incident_slugs:
  - nextjs-rce-pair-2026-08
  - unconfirmed-npm-window-2026-07
sources:
  - title: 'vm2 security advisories (maintainer)'
    url: 'https://github.com/patriksimek/vm2/security/advisories'
  - title: 'GHSA-647f-g98j-qq25, incomplete fix for the Error.cause escape'
    url: 'https://github.com/patriksimek/vm2/security/advisories/GHSA-647f-g98j-qq25'
  - title: 'GHSA-cfcw-xp6x-25gj, sandbox breakout via host proto mutators'
    url: 'https://github.com/advisories/GHSA-cfcw-xp6x-25gj'
  - title: 'GHSA-m283-3h24-438v, Error.cause sanitization'
    url: 'https://github.com/advisories/GHSA-m283-3h24-438v'
  - title: 'vm2 releases'
    url: 'https://github.com/patriksimek/vm2/releases'
  - title: 'npm registry, vm2 package metadata'
    url: 'https://registry.npmjs.org/vm2'
  - title: 'CWE-265, Privilege Issues'
    url: 'https://cwe.mitre.org/data/definitions/265.html'
---

## What happened

Two waves, one week apart, against the same package.

On August 17, 2026, five advisories were published covering vm2 up to and
including 3.11.5. Three are critical. A sandbox breakout through dangerous host
prototype mutators, CVE-2026-47698, carries CVSS 9.8. Missing sanitization of
`Error.cause` enabling a sandbox escape to remote code execution,
CVE-2026-47686, carries 9.9. And a `NodeVM` configured with `builtin: ['*']`
exposing `os` and `dns`, GHSA-m5w8-4gq2-6f8x, carries 9.3.

The remedy was version 3.11.6. The npm registry records it as published on
August 14, so the fix was already available when the advisories went public.
Anyone paying attention that week did the right thing and upgraded.

On August 24, the maintainer published ten further advisories. Several name
3.11.6 explicitly as the affected version. One of them, GHSA-647f-g98j-qq25,
carries CVSS 10.0 and is described as an incomplete fix for the `Error.cause`
issue from the first wave, bypassable through `call` and `apply` indirection.
The release notes for 3.11.7 say it closed twenty advisories. The registry
records 3.11.7 as published on August 24.

So the sequence for a diligent developer was: patch on the 17th, land on
3.11.6, and spend the following week running the exact version that the
highest-severity advisory of the second wave was written against.

One date note, since the records differ. The advisory detail pages render the
first wave as August 14, while the OSV publication timestamps read August 17.
The fix shipped on the 14th and the advisories became public on the 17th. This
report uses the publication timestamps for when the information became
available.

## Why this shape keeps working

vm2 is what gets reached for when a requirement says "let users write their own
formula", or "evaluate this expression safely", or "support plugins". It
presents itself as the safe alternative to `eval`, and that framing is the
problem, because it invites code that would never have been written if the
answer had been "you cannot do this safely in-process".

The specific escapes vary and the pattern does not. A JavaScript sandbox inside
a Node process is trying to hold a boundary inside a single heap, where the
untrusted code and the host share prototypes, error objects and built-in
functions. Every one of those shared surfaces is a candidate path out.
`Error.cause` was one. Prototype mutators were another. The second wave found
that the fix for the first had left a way around through `call` and `apply`.

This is why the interesting lesson is not the version number. Patching once is
not the same as being patched. A one-time upgrade is a snapshot of a moving
target, and for a package whose entire purpose is a boundary that keeps being
crossed, the snapshot expires quickly.

The durable question is not "which vm2 version am I on" but "why is untrusted
code running in this process at all". If the answer is a formula field or a
plugin hook, the options that hold are a separate process with an OS-level
sandbox, a real isolate boundary, or an expression language that is not
JavaScript and cannot reach a JavaScript object graph.

## What to check in your own project

Find out whether vm2 is in your tree at all. It arrives transitively more often
than people expect:

```bash
npm ls vm2
```

If it is there and you are below 3.11.7, upgrade. If you are on 3.11.6
specifically, treat it as urgent rather than current, because that is the
version the second wave names.

```bash
npm install vm2@^3.11.7
```

Then ask the question the upgrade does not answer. Find the code that uses it:

```bash
grep -rn "from 'vm2'\|require('vm2')" --include=*.js --include=*.ts .
```

For each hit, work out what the untrusted input is and who supplies it. If a
value that reaches `NodeVM` or `VM` came from a request body, a database row
that a user wrote, an uploaded file, or a model's output, then the sandbox is
load bearing and its history is your history. If the input is entirely
first-party and never crosses a trust boundary, the exposure is smaller and the
right fix may simply be to stop using a sandbox for something that does not
need one.

Two configurations from the advisories are worth grepping for directly:

```bash
grep -rn "builtin:\s*\[\s*['\"]\*" --include=*.js --include=*.ts .
```

A wildcard builtin list hands the sandboxed code the Node standard library,
which is the opposite of a sandbox.

## What PreFlight does about it

Today, partially, and by a different route than a version check.

PreFlight has no known-vulnerable-version manifest, so it will not tell you
that you are on 3.11.6 rather than 3.11.7. That capability is the same gap
described in the Next.js report from the same week, and vm2 is the cleanest
possible test case for it, because the correct floor is a single exact version.

What PreFlight can already reason about is the code around the sandbox. The
taint engine tracks a request-derived value through a function and into a sink,
and its cross-file pass follows that value into a helper in another module,
which is where a sandbox wrapper usually lives. That reaches the question that
actually matters: does attacker-controlled input arrive at the thing you are
trusting to contain it.

There is also a case for a probe that flags any vm2 import at all, at a
severity that does not depend on the version. The argument for it is the shape
of this report: twenty advisories closed in one release, and a critical
regression in the fix for a critical. The argument against is that a project
using vm2 for entirely first-party input is not in danger, and a finding that
fires regardless of context is a finding people learn to dismiss. That decision
is not made yet, and this report is part of the evidence for it.

Neither of those is a substitute for the check above. Run `npm ls vm2`, and if
it is there, go and read the code that uses it.

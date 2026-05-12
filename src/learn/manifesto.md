---
title: Vibe-Aware
slug: manifesto
type: manifesto
last_updated: 2026-05-12
draft: false
summary: The Pre-Flight philosophy. Why AI-built apps need a different kind of audit, and what "Vibe-Aware" means in practice.
---

## The problem we built Pre-Flight for.

A new class of developer ships every day. They have an idea, they describe it to a model, and the model writes the code. The code runs. The app deploys. It looks the part. It usually works.

That last word is doing a lot of heavy lifting.

The code an AI wrote for you is, on average, structurally fine and semantically plausible. It also, on average, has a meaningful chance of:

- exposing a hardcoded API key in a client bundle,
- importing a package that doesn't exist (or worse, a typosquat of one that does),
- shipping a Supabase table with no row-level security,
- accepting a JWT with `algorithm: "none"`,
- pulling a `.cursorrules` file with hidden bidirectional Unicode that rewrites the agent's instructions,
- or doing something fundamentally broken that the test suite never had a chance to catch because the model wrote the tests too.

These aren't exotic failure modes. They're the median failure modes. Industry studies show roughly 45% of AI-generated code samples introduce at least one OWASP Top 10 issue. Pre-Flight exists because the people most likely to ship that code are the ones least likely to be running a static analysis suite, paying a security platform, or filing a procurement ticket to get one approved.

## What "Vibe-Aware" means.

Vibe coding is real. People build real products from natural-language prompts, ship them to real users, and take real money for them. That ecosystem is not going away. It's going to grow. The question is whether the audit tooling grows with it or stays where it is.

Vibe-Aware is the stance Pre-Flight takes about that audience:

- **You are not failing because you "don't know security."** You're failing because the model that wrote your code doesn't either, and nobody told you what to look for. Pre-Flight tells you what to look for.
- **You don't need a server, an account, or a security team.** Open the page. Paste the URL or drop the folder. Get the findings. The whole audit fits in a browser tab and lasts as long as the tab does. Nothing leaves your machine. There is no server that could leak the data, because there is no server.
- **You learn the pattern, not just the line.** Every finding links to a write-up that explains what the pattern is, why it's bad, what the field has seen happen when it goes wrong, and how to fix it. We are not trying to be the gate that blocks your merge. We are trying to be the moment you understood why the gate exists.
- **The threat intel is named, dated, and current.** When Pre-Flight says a package version is compromised, it points to the named incident, the threat actor, the date, the CVE. When it flags a rules-file backdoor, it points to the demonstrated attack. We don't traffic in generic "could be dangerous." We traffic in "this exact failure happened to this exact ecosystem on this exact date, and here's the evidence trail."

## Why a browser tab.

The first version of Pre-Flight was going to be a CLI. It would have been faster to ship, easier to test, more comfortable for the people writing it. We didn't ship that, because the audience we care about is people who don't run CLIs.

The browser is the only universal install target left. It's where the AI tools that wrote the code live. It's where the deploy preview opens. It's where the documentation gets read. Putting the audit in the same surface is the lowest-friction way to put it where the user already is, when the user is most likely to listen.

A browser tab also forces a discipline. There is no privileged backend you can lean on. There is no API key you can quietly require. The tool's claim that "nothing leaves your machine" is enforced by architecture, not by promise. Every probe is a pure function over text. Every finding is constructed in the tab. Every export is a download.

If we ever build a backend, the day we build it is the day we stop being able to make that claim. So we don't build one.

## What Pre-Flight is not.

- **Not a dynamic scanner.** We don't run your code. We don't probe your endpoints. We don't generate payloads. Static analysis only.
- **Not a license compliance tool, an SBOM generator, or a vulnerability triage queue.** Those are great tools. They are also not what's missing from the workflow of the developer we built this for.
- **Not a free trial of a paid product.** The browser tool is free. It is going to stay free. Optional features that need bring-your-own-key access (the Explain & Verify pass, the agent-prompt formatting) are free too. There is no tier you unlock. There is no signup wall.
- **Not a replacement for code review.** A pre-flight check is a thing pilots do before takeoff. It doesn't replace the engineer who designed the airplane. It catches the class of failure that the engineer assumed someone else was watching for.

## What we ask from you.

If you use this and it catches something real, tell us. If it flags something that isn't real, tell us harder. If a finding is right but the explanation is opaque, that's the finding we want to know about most, because the explanation is the whole point.

Pre-Flight is built by Mid-Atlantic AI. The code is MIT. The threat-intel manifest is CC-BY-4.0. Take what's useful. Build something better if you can.

Just make sure your pre-flight check happens before takeoff.

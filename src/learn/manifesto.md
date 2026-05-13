---
title: Vibe-Aware
slug: manifesto
type: manifesto
last_updated: 2026-05-12
draft: false
summary: The Pre-Flight philosophy. Why AI-built apps need a different kind of audit, and what "Vibe-Aware" means in practice.
---

I built Pre-Flight because your AI is dumb, it makes mistakes, and you don't know it's setting you up for security failures.

Vibe coders are a new class of developer, and they ship every day. They have an idea, they describe it to a model, and the model writes the code. The code runs. The app deploys. It looks the part. It even usually works, if only on the surface.

That last part is where everything goes sideways for many including me many times.

The code your AI wrote for you is, on average, structurally fine and semantically plausible. LLMs, especially frontier models like ChatGPT, Claude, and Gemini, have come a long way since the advent of generative AI. Yet and still, on average, has a high chance of:

- Following your directions blindly, without regard for actual best practices
- exposing a hardcoded API key in a client bundle
- importing a package that doesn't exist (or worse, a typosquat\* which is malicious)
- shipping a Supabase table with no row-level security
- accepting a JWT with algorithm: "none"
- pulling a .cursorrules file with hidden bidirectional Unicode that rewrites the agent's instructions
- or doing something so fundamentally broken that the test suite never had a chance to catch it because the model wrote the tests too.
- These and other issues are more common in vibe-coded projects but also happen in engineer developed codebases as well, though not nearly as commonly as generally the learning is geared towards giving strong understandings of why these things matter and how to prevent or avoid them. This is a gap this app is built to address even if only on a small scale and small scope.

\* We will help you learn what typosquat and other AI and LLM security terms are and what they mean.

**Typosquat** — "Typosquatting is a type of social engineering attack which targets internet users who incorrectly type a URL into their web browser rather than using a search engine. Example: inadvertently mistyping the name of popular websites into their web browser, e.g. gooogle.com instead of google.com." ([Kaspersky](https://usa.kaspersky.com/resource-center/definitions/what-is-typosquatting))

These aren't one and done failure modes. This is the average across the industry. Studies have shown roughly 45% of AI-generated code samples introduce at least one OWASP Top 10 issue. Pre-Flight exists because the people most likely to ship that code are the ones least likely to be running a static analysis suite, paying a security platform, or filing a procurement ticket to get one approved. In short many of us are running on hopes and dreams, empty wallets, and a desire to affect change and be the one to become successful. They are people like you and me.

## What "Vibe-Aware" means.

Vibe coding is real. People build real products from natural-language prompts, ship them to real users, and take real money for them. That's all the real it needs to be. That ecosystem is not going away. It's going to grow. The question is whether you learn and or use tooling that allows you to grow with it or stays stuck in the same place.

Vibe-Aware is the stance I and by proxy Pre-Flight takes about that audience:

- Your project isn't failing because your LLM "doesn't know security." You're failing because the model that wrote your code does know security, and lack of time in the game or practiced experience meant nobody told you what to ask for.

  Pre-Flight is here to help you learn what to look for.

- You don't need a server, an account, or a security team. Open the page. Write your Git repo name github.com/&lt;yourgithubhandle&gt;/&lt;yourprojectname&gt;.git, or you can pull the folder from a local project. Then hit Scan. That's it.

  The whole audit fits in your favorite browser. Nothing leaves your machine.

  This is by intentional design and part of the driving force behind this being FREE and OPEN SOURCE.

- You can learn the pattern, not language. Every finding should be linked to a write-up that explains what the pattern is, why it's bad, what the field has seen happen when it goes wrong, and how to fix it. We are not trying to be the gate that blocks your merge. We are trying to be the reason you go from something you quickly vibe coded to something viable to take to market, or demo, or put into use knowing you have some sense of peace that the code you generated isn't going to ruin you.

- Our threat data is named, dated, and current. When Pre-Flight says a package version is compromised, we will point you to the named incident, the threat actor, the date, the CVE. When it flags a rules-file backdoor, it points to the demonstrated attack. I'm actively trying to avoid generic "could be dangerous." Our language is "This has been documented as happening before, here's the evidence trail and what we know about it."

## Why a browser tab.

Pre-Flight was just me wondering about a problem I had run into a bunch over my time building vibeware. It turned into an actual project where I get to express my intentions for how I deal with people and my care to help. The people who need this help are building in the same place we go to meet them to help complete the cycle.

The browser is the only universal install target left. It's where the AI tools that wrote the code live. It's where the deploy preview opens. It's where the documentation gets read. Putting the audit in the same surface is the lowest-friction way to put it where you already are, when you are most likely to understand.

A browser tab also forces visibility. There is no invisible backend your data goes to. There is no API key you can get exposed. Pre-Flight's claim that "nothing leaves your machine" is enforced by architecture, not by my word. Every probe is a pure function over text. Every finding is constructed in the tab. Every export is a download.

## What Pre-Flight isn't.

- This isn't a dynamic scanner. That would be a DAST (dynamic application security testing). We do SAST (static application security testing). We aren't running your code. We don't probe your endpoints. We don't generate payloads. Static analysis only.

- This isn't license compliance tool, an SBOM generator, or a vulnerability triage queue. Those are great tools. They are also not what's missing from the workflow of the developer we built this for. These tools are elsewhere if you need them. Maybe I'll make a list that I vetted for you all.

- This is a FREE PRODUCT. There is no free trial. The browser tool is free. It is going to stay free. There are optional AI features that require you to BYOK (bring your own key) to access (the Explain & Verify pass, the agent-prompt formatting). These cost whatever your AI provider charges. We don't charge a cent. There is currently no sales surface whatsoever for the tool. There may be some paid features down the road later, but this core system will never not be FREE AND OPEN SOURCE.

- This is NOT a replacement for professional code review. A pre-flight check is something pilots do before takeoff to ensure the plane is safe. It doesn't replace the engineer who designed the airplane. It catches the class of failure that the engineer assumed someone else was watching for.

## What I ask from you.

If you use this and it catches something real, tell me. If it flags something that isn't real, tell me more. If a finding is right but the explanation is opaque, AI-sloppy, or hard to understand, that's the thing I want to know about most, because the explanation is the whole point.

Pre-Flight is an active project by Mid-Atlantic AI. The code is MIT. The threat-intel manifest is CC-BY-4.0. Take it, fork it, integrate it, run it inside whatever you're building. The work is the contribution. Whatever you do with it after is up to you.

Just don't forget to do your pre-flight check before takeoff.

John  
Mid-Atlantic AI  
2026-05-12

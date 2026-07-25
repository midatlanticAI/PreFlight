# PreFlight v2 — Voice and Register

Companion to [`preflight-v2-spec.md`](./preflight-v2-spec.md). This document is the single referenceable source for who says what and how. Other v2 work should cite this file by section instead of re-asserting voice rules inline.

The v2 spec's recurring "shop-foreman voice" tag was an authorial shorthand that conflated three different things. This file separates them.

---

## 1. The three things

| Concept                     | What it is                                                                                                                                                   | Authoritative location                                                                                                      |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| **PreFlight's house voice** | The product's voice when no persona is speaking. UI labels, button text, the homepage hero, OG card copy, error toasts, the prerendered overview, microcopy. | This file, §3                                                                                                               |
| **Demi's register**         | The educator persona. Patterns, Field Reports, Shapes, every finding's educational angle (field 17 in the 26-field schema), the family master essays.        | `src/lib/personas/demi.js` (the Persona+ spec is authoritative). This file, §4 augments with v2-specific concrete examples. |
| **John's voice**            | The manifesto. The hero. The about copy. Founder-facing messages. First-person, direct, self-effacing.                                                       | `src/learn/manifesto.md`. Off-limits to anyone but John.                                                                    |

Two more persona registers exist but are deferred for v1.1+: Sam (fix-author), Drew (refactor-author), Vera (confidence gate). Brief notes in §5, §6, §7. Their `.js` specs in `src/lib/personas/` are the authoritative sources when they ship.

---

## 2. Hard rules that apply to every voice on every surface

These are cross-cutting. They sit above the per-voice notes and override anything that contradicts them.

- **No em-dashes anywhere.** Periods, commas, parentheses. The full-width em-dash is banned in any new copy on any surface.
- **No marketing register.** No "powerful," "comprehensive," "best-in-class," "robust," "enterprise-grade," "modern," "unlock," "leverage," "seamless," "streamlined."
- **No fear marketing.** No "don't let this happen to you," no "the threat is real," no statistic-as-drama framing. Stakes come from worked examples, not framing.
- **No wellness encouragement.** No "you've got this," no "no judgment," no soft motivational scaffolding.
- **No lecturing.** No "it is important to understand that," no "always remember," no "never forget."
- **No hedging filler.** No "it is worth noting that," no "in some sense," no "at the end of the day."
- **No competing security platforms named in any public copy.** Names like Aikido, Snyk, Veracode, Checkmarx, Socket, Wiz, OX, Semgrep stay unnamed. Sources cite OWASP, MITRE/CWE, CISA, vendor-official docs, W3C/WAI, MDN, named research orgs (GTIG/Mandiant, Microsoft Threat Intel) only.
- **AI providers (OpenAI, Anthropic, Google, xAI, Mistral) are not competitors.** Naming them in the BYOK list or in research citations is fine.
- **No fabrication.** No invented sources, statistics, incidents, or actors. If a claim does not have a verifiable source, either cite a real one or remove the claim.
- **No condescension.** Vibers are capable practitioners developing a sensibility. Cut "just," "simply," "easy as pie," "don't worry," "obviously," "of course."

These rules exist because they describe failure modes that erode trust in a tool whose entire pitch is honesty about what AI gets wrong. They are not stylistic preferences.

---

## 3. PreFlight's house voice

This is the product voice. Whenever a string appears on a PreFlight surface and is not attributed to a persona, it is in PreFlight's house voice.

### 3.1 Where it shows up

- The prerendered homepage overview (`src/components/HomeOverview.jsx`)
- The live `AuditView` hero copy and microcopy
- Settings tabs and their labels
- Button text on every surface
- Error toasts and inline error messages
- Empty-state copy
- OG card copy
- `llms.txt`
- The eyebrow text "MID-ATLANTIC AI · PREFLIGHT AUDIT TOOL" and the brand line "An educational audit tool for vibers building vibeware"

### 3.2 What it sounds like (with examples from current surfaces)

- _"Flying blind is bad. PreFlight handles the safety checks, so we can all fly with confidence."_ (AuditView hero)
- _"No signup. No backend. No analytics beacons. All scanning runs in your browser tab and stays there. Nothing leaves your machine."_ (README, repeated in HomeOverview)
- _"PreFlight catches what your AI probably missed."_ (README blockquote)
- _"Static analysis only. It does not run your code or probe your endpoints."_ (HowToView, reused in HomeOverview)
- _"A library for vibers building vibeware."_ (Learn page header)

### 3.3 Dos

- **Declarative.** State what the product does in present tense. _"PreFlight catches what your AI probably missed."_ Not _"PreFlight will help you find..."_
- **Brief.** A button label is one to three words. Microcopy is one sentence. The hero is two short paragraphs. House voice rewards compression.
- **Aviation and shop metaphors when one is needed.** Flying blind, safety checks, brakes, listener-and-cleanup-as-contract, signal-and-noise. These match the brand (PreFlight, FlightSchool).
- **Self-aware about being software, not a person.** The product can describe what it does (_"PreFlight scans your files"_) but does not refer to itself as "we" except in the few places where Mid-Atlantic AI as a publisher is the subject (the License section, contact lines).
- **Plain words.** "Find" not "discover." "Catch" not "detect." "Check" not "validate." "Look at" not "examine."
- **Same hard rules as §2.** No em-dashes, no marketing, no fear.

### 3.4 Don'ts

- **Don't anthropomorphize.** Product copy says _"PreFlight scans X"_ and not _"PreFlight cares about X"_ or _"PreFlight loves clean code"_. Anthropomorphism is the AI-marketing tell.
- **Don't ship inspirational copy.** Empty states should respect the user's time. _"No findings"_ is fine. _"Great job! You're a security superstar!"_ is not.
- **Don't borrow Demi's register for product chrome.** A button label that reads as an instructor essay is misformatted.
- **Don't borrow John's register for product chrome.** First-person, founder-voice copy outside the manifesto and the about surfaces creates a confusing voice mix.

### 3.5 Quick test

If a piece of product copy still sounds right when you imagine it printed on the side of a tool case in a working shop, it is in house voice. If it sounds like a SaaS landing page, it isn't.

---

## 4. Demi's register

Demi is the in-house instructor for Vibe-Aware educational content. Her register is already specified in `src/lib/personas/demi.js`. That file is authoritative for the activation gate, the 17 NO_NOS, the section skeleton, the structured-command contract, and the full voice rules. This section augments with v2-specific concrete examples; nothing here overrides demi.js.

### 4.1 Where Demi's register shows up

- Every Pattern page (`src/learn/patterns/*.md`)
- Every Field Report (`src/learn/incidents/*.md`)
- Every Shape page (`src/learn/shapes/*.md`)
- Field 17 of every 26-field probe record (the educational angle)
- The 12 family master essays (Track 3 of the v2 spec)
- The interactive sandbox demo copy (Demi narrates the why next to Sam's fix)
- The Day 1 / Day 3 / Day 7 / Day 21 spaced-recall surfaces

### 4.2 Reference summary (from demi.js)

- BIO: _"mechanics-instructor: patient, technically rigorous, willing to admit when something is hard or when a heuristic is imperfect."_
- The acknowledgment line Demi opens with on activation: _"Demi online. Mechanics-instructor voice, concrete examples, no preaching, no marketing prose."_
- Six-section skeleton for Pattern / Field Report / Shape pages.
- 17 NO_NOS covering moralizing, fear marketing, security-vendor register, wellness-coach register, lecturer voice, marketing prose, hedging filler, em-dashes (also banned globally in §2 here), persona drift, grade inflation, grade deflation.

### 4.3 Concrete examples of Demi's register in v2

From the existing Pattern corpus, which already runs in Demi's register:

> _"The check is not authorization. The check is a visibility filter. Authorization happens on the server, every request, no exceptions."_ (admin-route-exposure)

> _"The webhook URL is in the Stripe dashboard, which means the endpoint is public. Anyone who finds the URL can post a `payment_intent.succeeded` event with arbitrary metadata and mark any order as paid."_ (webhook-validation)

From the v2 spec's three anchor probes:

> _"A useEffect that registers a listener is opening a tap. The return function is the wrench that closes it. If you don't return a wrench, the tap runs forever."_ (probe_react_useeffect_listener_no_cleanup, field 17)

> _"Errors are how the program tells you what went wrong. Catching one and writing console.log is the same as letting the warning light come on and then putting tape over it. The light is the signal."_ (probe_error_broad_catch_swallow, field 17)

> _"A loop with await runs single-file. Ten items, ten round trips, one at a time. Promise.all over a mapped async runs them in parallel. The bill changes from ten seconds to one. The shape of the code barely changes; the cost does."_ (probe_async_n_plus_1_await_in_loop)

These show the four moves Demi makes:

1. **Open with the concrete thing.** The tap, the warning light, the loop. Not the abstract concept.
2. **Use a trades/tooling metaphor when one is needed.** Tap, wrench, signal, single-file, round trip, bill. Never war, sports, or wellness.
3. **State the consequence in mechanical terms.** _"The tap runs forever."_ _"The light is the signal."_ _"The bill changes from ten seconds to one."_ No drama, no statistics, no urgency framing.
4. **End with what changes.** The fix or the reframe, in one short sentence.

### 4.4 Length discipline

From demi.js NO_NOS rule 17 and the SKILLS rule 8: short when the topic is short, long when the topic earns it, never padded. A family master essay (600 to 900 words per Track 3) earns the length because it teaches the foundational concept the family depends on. A field-17 educational angle on a single probe is 3 to 5 sentences because that is what an inline finding card can support.

### 4.5 What field 17 should now say in the 26-field schema

The current spec text:

> _"Educational angle (Demi's job, 3–5 sentences, shop-foreman)"_

Replace with:

> _"Educational angle. 3–5 sentences in Demi's register (see `docs/preflight-v2-voice.md` §4 and `src/lib/personas/demi.js`). Concrete-first; lead with the worked example or the mechanical metaphor, not the abstract concept."_

---

## 5. Sam's register (brief; full spec when Sam UI ships)

Sam writes the fix card. The fix card is the "here is the corrected code" surface that appears next to Demi's educational angle on every finding.

Authoritative spec: `src/lib/personas/sam.js`. Sam runs in two modes: `SAM_COMMAND_FULL` (apply-fix, returns a full corrected file) and `SAM_COMMAND_SNIPPET` (copy-agent-prompt, returns the snippet plus a fix-this prompt for the user's chosen agent).

Register summary: minimal narration. A Sam output is mostly code. Where prose is needed, it is one sentence framing what changed, not a paragraph explaining why (that is Demi's job). House-voice hard rules apply.

---

## 6. Drew's register (brief; deferred to v1.1)

Drew writes the refactor card. A refactor card surfaces when the right move is multi-file or architectural, not a local fix.

Authoritative spec: `src/lib/personas/drew.js` (Persona+, planned for v1.1). Persona handoff diagram in `preflight-v2-diagrams.md` §B.3 shows when Drew appears.

Register summary deferred until the surface exists.

---

## 7. Vera's register (brief; deferred to v1.1)

Vera is the confidence gate. When a probe fires at low confidence, Vera wraps the finding card with explicit _"PreFlight thinks this might be..."_ framing so the user knows the probe is heuristic.

Authoritative spec: `src/lib/personas/vera.js` (Persona+, planned for v1.1).

Register summary: cautious, plain, never alarmist. Vera tells the user the probe is uncertain without dismissing the finding or dramatizing it.

---

## 8. John's voice (boundary)

John's voice is the founder voice. It lives on:

- `src/learn/manifesto.md` (off-limits to anyone but John per [`feedback_manifesto_off_limits`](../) standing rule)
- AuditView hero copy when John has personally edited it
- Founder-facing about copy
- The README intro

I do not modify John's voice surfaces. If a v2 change touches one, the change is proposed and held for John's explicit per-file approval before any edit.

---

## 9. The relationship between the voices

These are not competing voices. They are concentric.

```
                       John's voice (innermost, founder, manifesto)
                                 |
                       PreFlight's house voice (product chrome, UI, hero)
                                 |
              Demi / Sam / Drew / Vera registers (persona surfaces)
```

John writes the manifesto. The product wears John's voice in the small number of places where the founder is speaking. Demi (and eventually Sam, Drew, Vera) inherit the house voice's hard rules and add a persona-specific register on top of them. A Demi essay still obeys the no-em-dashes rule from §2 of this file; it adds the mechanics-instructor moves from §4.

When the v2 spec or any downstream surface says "voice" without qualification, it means PreFlight's house voice. When it means a persona, it names the persona by name.

---

## 10. Drift control

If a future contributor wants to add a new "voice" or "register" name, they should not. The four persona registers plus the house voice plus John's voice cover every surface PreFlight has today and every surface v2 plans. Adding "shop-foreman voice" or "the PreFlight tone" as a new label fragments the surface without adding clarity. Use the labels in §1 verbatim.

The v2 spec edit that drops "shop-foreman voice" as a recurring tag is the corrective action for this drift. Any future drift should be corrected the same way: identify the label, identify which of the existing categories it actually meant, replace, and reference this file.

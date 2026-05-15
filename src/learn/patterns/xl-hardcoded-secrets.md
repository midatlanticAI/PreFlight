---
title: Hardcoded secrets and policy text (XL-006)
slug: xl-hardcoded-secrets
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Python Hardcoded Secret
  - JS Secret Scanner (XL-006)
sources:
  - title: CWE-798 — Use of Hard-coded Credentials
    url: https://cwe.mitre.org/data/definitions/798.html
  - title: OWASP A07 — Identification and Authentication Failures
    url: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
  - title: OWASP LLM02 — Sensitive Information Disclosure
    url: https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/
  - title: GitHub — about secret scanning
    url: https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning
summary: A provider-key-shaped literal in source, or a system prompt bundled into a shipped client, is a credential one git clone away from anyone. The shared family is XL-006; adapters differ by language and by what counts as a bundled asset.
---

## What this is

A secret in source is not a secret. Git history is permanent. A key that
was committed and then deleted is still in the history, still in every
clone, still in every fork. The same applies to LLM system prompts and
judge policies bundled into a client binary or a shipped front-end: once
it is in the artifact the user downloads, it is readable.

What counts as the secret surface differs by language and packaging:

- Every language: provider key literals (OpenAI `sk-`, Anthropic
  `sk-ant-`, Google `AIza`, xAI `xai-`, Groq `gsk_`), connection strings
  with embedded passwords, `api_key="..."` in a client constructor.
- Mobile (Kotlin/Swift/Dart): keys in `BuildConfig`,
  `Info.plist`, or Flutter `assets/`.
- Any client bundle: `system_prompt.txt`, `judge_criteria.md`,
  `tool_policy.json` shipped to the user.

Same family (XL-006), one concept, per-language and per-packaging
detectors.

## Why AI emits it

"Just hard-code it for now" prototypes get shipped. The vibe tools emit a
pasted key inline when the user pastes it; autocomplete fills it from the
clipboard; the placeholder that was meant to be replaced before launch
never gets replaced because nothing forces the issue.

## The mental model that produces the bug

"I will move it to an env var later." Later does not arrive on its own.
The prototype works with the literal in place, the demo passes, and the
literal ships because nothing in the loop made the env var the path of
least resistance.

## What the fix looks like

Read the secret from the environment, and store the value in a secret
manager.

- `api_key=os.environ["OPENAI_API_KEY"]`, never a literal.
- Mobile: do not bundle long-lived credentials in a binary at all. Use a
  backend-mediated signed request, or a short-lived token exchange.
- System prompts: fetch from the server at runtime, do not ship them in
  the client.

Rotate anything that was ever committed. Deleting the line does not
un-leak the value; the only safe assumption is that a committed secret is
already compromised, so the fix is always "rotate, then move to env."

## Related

- [TLS verification disabled](/learn/patterns/xl-tls-verification-disabled)
  is the same "ship the shortcut" reflex applied to transport security.

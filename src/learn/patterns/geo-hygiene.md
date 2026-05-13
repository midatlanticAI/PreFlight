---
title: GEO hygiene (AI crawler indexability)
slug: geo-hygiene
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - GEO Hygiene
sources:
  - title: 'llmstxt.org — proposed standard for AI-search indexability'
    url: https://llmstxt.org/
  - title: 'OpenAI — GPTBot and crawler controls'
    url: https://platform.openai.com/docs/bots
  - title: 'Anthropic — ClaudeBot user agent'
    url: https://docs.anthropic.com/en/docs/build-with-claude/agents-and-tools
  - title: 'Perplexity — PerplexityBot'
    url: https://www.perplexity.ai/help-center/en/articles/10352974-perplexitybot
summary: Generative Engine Optimization (GEO). Whether AI search tools can read your site. Missing AI-bot allowlists in robots.txt, missing llms.txt for AI-search indexing, and the broader set of AI-crawler-specific signals.
---

## What this is

GEO is what SEO becomes when the consumer of the site is an AI search tool (ChatGPT search, Perplexity, Claude with web access, Gemini, etc.) rather than a human looking at a search results page. The signals partly overlap with SEO and partly diverge.

The signals Pre-Flight checks:

**`robots.txt` AI-bot allowlist.** Generic `Disallow: /` blocks every bot, including the AI crawlers. Sites that want to be answer-cited by AI search need to allow the specific user agents:

```
User-agent: GPTBot
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: cohere-ai
Allow: /
```

A site without these allows defaults to deny for any crawler that respects `Disallow`, which is most of the reputable ones.

**`llms.txt`.** A proposed standard (llmstxt.org) for sites to publish an LLM-friendly index of their content at `/llms.txt`. It is essentially a Markdown table of contents listing the canonical URLs the site author wants AI tools to read. Adoption is uneven but growing through 2026.

**Structured author and content metadata.** AI search tools rely heavily on JSON-LD `Article`, `Organization`, and `WebPage` types. Missing structured data means AI-generated answers cite the site with less confidence or attribute incorrectly.

## Why it matters

If you want to show up in AI-generated answers (or you definitely don't want to), GEO is how you control that. Sites with no GEO signals get unpredictable treatment: some AI tools fall back to scraping, some skip the site entirely, some cite it as "unattributed source" without a working link.

For products whose discoverability matters in 2026, this is the new SEO. For products whose content should NOT be in AI training corpora, the same signals are used in the other direction (`Disallow` instead of `Allow`).

## What the failure looks like

Pre-Flight scans `public/robots.txt` and the site root for `llms.txt`. Findings:

- `robots.txt` with no explicit allow for any of GPTBot / ClaudeBot / PerplexityBot / Google-Extended.
- No `llms.txt` present.
- `robots.txt` doesn't exist at all.

These are info-level findings. The probe surfaces them as opportunities, not security risks.

## What the fix looks like

**Decide your stance first.** Either you want AI crawlers indexing your content (most documentation, marketing, and reference sites), or you don't (some proprietary content, paid-only material, things you don't want to train on). The decision drives the configuration.

**For "I want to be indexed":**

```
# public/robots.txt
User-agent: *
Allow: /

User-agent: GPTBot
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: cohere-ai
Allow: /

Sitemap: https://example.com/sitemap.xml
```

Plus a `public/llms.txt`:

```markdown
# Site Name

> One-sentence description of what the site is.

## Main pages

- [Home](https://example.com/)
- [Docs](https://example.com/docs)
- [Pricing](https://example.com/pricing)

## Reference

- [API docs](https://example.com/api)
```

**For "I don't want AI to train on this":**

```
User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

# ... etc per bot
```

Note: opt-out compliance is voluntary. Reputable bots respect it; not every crawler will.

## Related

- [SEO hygiene](/learn/patterns/seo-hygiene) covers the human-search equivalent.
- [URL reputation](/learn/patterns/url-reputation) covers external-URL hygiene that often pairs with site-level GEO.

## Sources

llmstxt.org is the proposed standard. OpenAI, Anthropic, and Perplexity publish their bot user agents and the controls for opting in or out. Google's Google-Extended controls the AI side of Google's crawler stack separately from the search index.

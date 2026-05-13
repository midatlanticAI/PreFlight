---
title: SEO hygiene
slug: seo-hygiene
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - SEO Hygiene
sources:
  - title: 'Google Search Central — Search Essentials'
    url: https://developers.google.com/search/docs/essentials
  - title: 'schema.org — JSON-LD vocabulary'
    url: https://schema.org/
  - title: 'OpenGraph protocol'
    url: https://ogp.me/
  - title: 'Twitter Cards documentation'
    url: https://developer.twitter.com/en/docs/twitter-for-websites/cards
summary: Missing canonical, OpenGraph, Twitter cards, description meta, robots, or JSON-LD on production pages. None of these are security findings; they're search-discoverability findings that ship together.
---

## What this is

A handful of meta-tag and JSON-LD signals search engines, social platforms, and AI crawlers use to render preview cards, decide which page is canonical for a query, and structure indexable data. The signals are not optional in the practical sense; missing them means worse representation in every consumer surface.

**`<link rel="canonical">`.** Tells search engines which URL is the canonical version of duplicate content. Missing canonical on a page reachable from multiple URLs (with vs. without trailing slash, with vs. without query params) costs ranking.

**OpenGraph meta tags.** `og:title`, `og:description`, `og:image`, `og:url`. Drives the preview card on Facebook, LinkedIn, iMessage, and most chat platforms.

**Twitter Cards.** `twitter:card`, `twitter:title`, `twitter:description`, `twitter:image`. Drives the preview card on Twitter / X.

**`<meta name="description">`.** The blurb under the title in search results.

**`<meta name="robots">`.** Per-page robots directive. Pages that should not be indexed (admin panels, drafts) need `noindex`.

**JSON-LD structured data.** Schema.org-typed JSON in a `<script type="application/ld+json">` block. Tells search engines what kind of page this is (Article, Product, FAQPage, Organization) and produces rich-result snippets.

## Why it matters

Not a security pattern. The blast radius is "every time anyone shares this URL, the preview looks bad," "the page does not show up for queries you'd want it to," and "the page shows up for queries you don't want it to."

For products that depend on search and shareable links, these are revenue findings, not security findings.

## What the failure looks like

Pre-Flight scans HTML for the canonical signals on what looks like a primary landing page. Missing any of:

- `<link rel="canonical" href="...">`
- `<meta name="description" content="...">`
- `<meta property="og:title" content="...">` (and `og:description`, `og:image`, `og:url`)
- `<meta name="twitter:card" content="...">`
- At least one `<script type="application/ld+json">` block with valid JSON-LD

is a low / info finding. The probe is intentionally lenient on internal pages and admin views.

## What the fix looks like

A boilerplate `<head>` for a public page:

```html
<head>
  <title>Page Title — Site Name</title>
  <meta name="description" content="One-sentence summary of this page's content." />
  <link rel="canonical" href="https://example.com/this-page" />

  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://example.com/this-page" />
  <meta property="og:title" content="Page Title" />
  <meta property="og:description" content="One-sentence summary" />
  <meta property="og:image" content="https://example.com/og-card.png" />

  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="Page Title" />
  <meta name="twitter:description" content="One-sentence summary" />
  <meta name="twitter:image" content="https://example.com/og-card.png" />

  <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "WebPage",
      "name": "Page Title",
      "description": "One-sentence summary",
      "url": "https://example.com/this-page"
    }
  </script>
</head>
```

For Next.js, the App Router's `generateMetadata` produces the same tags from a JS object. For Astro, Hugo, and other static-site generators, the equivalent comes from frontmatter.

## Related

- [GEO hygiene](/learn/patterns/geo-hygiene) covers the AI-crawler equivalent of search-engine optimization.
- [A11y landmarks](/learn/patterns/a11y-landmarks) covers the accessibility layer that pairs with semantic HTML.

## Sources

Google Search Central is the authoritative reference for search-engine indexing. The OpenGraph protocol, Twitter Cards docs, and schema.org are the authoritative references for the respective preview / structured-data formats.

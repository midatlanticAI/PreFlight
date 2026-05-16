---
title: Static HTML with a build tool
slug: static-html-build
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: MDN — Content Security Policy
    url: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
  - title: WCAG 2.2
    url: https://www.w3.org/TR/WCAG22/
  - title: OWASP Secure Headers Project
    url: https://owasp.org/www-project-secure-headers/
summary: A landing-page-with-bundler shape, Vite or esbuild emitting plain HTML/CSS/JS. The minimum-viable hardening that turns "a static site, nothing to attack" into one that actually survives a CSP and a Lighthouse pass.
---

## What this shape is

HTML, CSS, and JavaScript built by a bundler and served as files. No
server logic at request time. The Architecture probe classifies it as
static HTML (with or without a build step) and emits an informational
hardening checklist rather than a defect, because the shape is a
decision, not a bug.

## Why AI defaults to it

Asked for "a landing page," a model produces exactly the page and stops.
The shape is correct and minimal. What it omits is everything that is
not visible in the browser on the happy path: the document metadata, the
content-security policy, the cache and asset hygiene. None of that was
asked for, so none of it appears.

## Why "it is just static, nothing to attack" is wrong

A static site still runs attacker-reachable code in a victim's browser.
The risks are smaller in number, not smaller in consequence:

- Without a Content-Security-Policy, any injected markup (a reflected
  query value, a third-party widget, a compromised dependency) runs as
  inline script. CSP is the single control that turns "XSS" into
  "blocked."
- A missing `lang`, viewport, title, or description is an accessibility
  and discoverability failure that the A11y and SEO probes treat as
  real findings, because for this shape they are the product.
- Unhashed asset filenames mean a deploy serves stale, possibly
  vulnerable, cached JavaScript to returning users.
- Inline event handlers and unminified bundles widen the exact surface
  CSP exists to close.

## What the scanner sees and says

The Architecture probe surfaces a minimum-viable hardening checklist for
this shape, and the HTML Hygiene, SEO Hygiene, and A11y Landmarks probes
each check the individual items. The checklist is the scanner stating
plainly what "done" means for a static site, so the absence of a server
is not mistaken for the absence of a security posture.

## The hardening checklist

- A Content-Security-Policy via a meta tag or, better, a response
  header. This is the load-bearing item.
- `<meta name="viewport">`, `lang` on `<html>`, a `<title>`, a
  `<meta name="description">`, and Open Graph / Twitter Card tags.
- Minified CSS and HTML for production (Vite and esbuild do this).
- Cache-busting filename hashes on CSS and JS so a deploy invalidates
  old assets.
- Non-critical JavaScript deferred with `defer` or `type="module"`.
- One source of truth across robots.txt, sitemap.xml, llms.txt, the OG
  tags, and the canonical link, so crawlers and AI agents see a
  consistent site.

## When the minimal shape is enough

A throwaway internal page or a demo does not need the full checklist.
The line is exposure: the moment the page is public and represents you,
the CSP and the metadata stop being optional, because that is the moment
someone other than you can reach it.

## Related

- [Security Headers](/learn/patterns/security-headers) and
  [HTML Hygiene](/learn/patterns/html-hygiene) cover the CSP and
  document-metadata items in depth.

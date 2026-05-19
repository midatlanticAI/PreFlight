---
title: iframe sandbox attribute
slug: iframe-sandbox
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Iframe Sandbox
  - HTML Hygiene
sources:
  - title: 'MDN — iframe sandbox attribute'
    url: https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#attr-sandbox
  - title: 'OWASP HTML5 Security Cheat Sheet'
    url: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
  - title: 'CWE-1021 — Improper Restriction of Rendered UI Layers'
    url: https://cwe.mitre.org/data/definitions/1021.html
  - title: 'OWASP A05 — Security Misconfiguration'
    url: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
summary: A `<iframe src="...">` without a `sandbox` attribute lets the embedded page run scripts, navigate the top window, submit forms, and call `window.parent`. The sandbox attribute is the per-iframe permission system; the default state is "everything allowed."
---

## What this is

```html
<!-- Unsandboxed: full DOM access, scripts, top navigation, forms, popups, same-origin. -->
<iframe src="https://embed.example.com/widget"></iframe>
```

```html
<!-- Sandboxed: nothing allowed except what's explicitly granted. -->
<iframe src="https://embed.example.com/widget" sandbox="allow-scripts allow-same-origin"></iframe>
```

`sandbox` is an HTML attribute that switches the iframe from "everything allowed" to "nothing allowed, then add capabilities back one at a time." The empty `sandbox=""` is the maximum restriction: no scripts, no forms, no popups, no top-level navigation, no plugins, fresh origin.

You add tokens to relax the restriction. `allow-scripts` allows JavaScript. `allow-forms` allows form submissions. `allow-popups` allows `window.open`. `allow-same-origin` keeps the iframe's origin (rather than treating it as a unique opaque origin). `allow-top-navigation` allows the iframe to navigate the top window.

## Why it matters

An unsandboxed cross-origin iframe can:

- Navigate the top window via `window.top.location = '...'`. Phishing redirect from inside a trusted page.
- Submit forms on behalf of the user (CSRF amplifier).
- Open popups (tabnabbing variants).
- Access `window.parent` and the parent's DOM if the iframe origin matches (the same-origin policy is the only barrier, and it's not always there).
- Trigger downloads.
- Auto-play media.

The blast radius depends on what the iframe is. A `youtube.com` embed is generally well-behaved; an `https://random-widget.example` is a third party that has full DOM-adjacent capability inside your page.

For first-party iframes, the sandbox attribute is still the right default. It bounds the failure mode if the iframe ever gets compromised (CDN, third-party script, etc.).

## What the failure looks like

PreFlight scans HTML / JSX / TSX / Astro / Vue / Svelte for `<iframe>` tags without a `sandbox` attribute. Cross-origin iframes (any `src` starting with `http://`, `https://`, or `//`) are flagged at high severity. Same-origin iframes get medium.

## What the fix looks like

Add `sandbox=""` and add back only what's needed.

**Static embed of a video (most permissive case among useful sandboxes):**

```html
<iframe
  src="https://www.youtube.com/embed/dQw4w9WgXcQ"
  sandbox="allow-scripts allow-same-origin allow-presentation"
  allowfullscreen
></iframe>
```

**Code playground (CodePen / CodeSandbox style):**

```html
<iframe
  src="https://codesandbox.io/embed/example"
  sandbox="allow-scripts allow-same-origin allow-forms"
></iframe>
```

**OAuth provider login:**

```html
<iframe
  src="https://accounts.example.com/login"
  sandbox="allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox"
></iframe>
```

**Pure content (article preview, static document):**

```html
<iframe src="https://docs.example.com/page" sandbox=""></iframe>
```

The discipline: start at `sandbox=""`, run the embed, see what breaks, add the minimum token to fix it. Most embeds need `allow-scripts` and not much else.

## A specific footgun: allow-scripts + allow-same-origin

For cross-origin iframes, combining `allow-scripts` and `allow-same-origin` defeats the origin isolation. The iframe gets to run scripts AND keeps its real origin, which means scripts inside the iframe can access the iframe's actual origin's storage, including any auth state on that origin. For first-party iframes this is fine; for cross-origin it's worth a second look.

MDN's documentation flags this combination explicitly.

## A related defense: the `csp` attribute (newer)

Newer browsers support a `csp` attribute on `<iframe>` that applies a Content Security Policy to the embedded page from the parent. This is more granular than sandbox and is worth using on cross-origin iframes where you control neither the embedded page's CSP nor its source.

```html
<iframe
  src="https://embed.example.com/widget"
  sandbox="allow-scripts"
  csp="default-src 'self' embed.example.com"
></iframe>
```

## Related

- [HTML hygiene](/learn/patterns/html-hygiene) covers the broader HTML-quality layer, including `target="_blank"` without `rel="noopener"` (a related cross-origin discipline).
- [Security headers](/learn/patterns/security-headers) covers the page-level CSP that protects the parent.

## Sources

MDN's iframe sandbox documentation is the authoritative reference for the token list. CWE-1021 names the class. OWASP A05:2021 covers the broader misconfiguration category.

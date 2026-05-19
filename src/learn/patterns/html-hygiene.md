---
title: HTML hygiene
slug: html-hygiene
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - HTML Hygiene
  - Security Headers
sources:
  - title: 'MDN — target="_blank" and security'
    url: https://developer.mozilla.org/en-US/docs/Web/HTML/Element/a#security_and_privacy
  - title: 'MDN — Mixed content'
    url: https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content
  - title: 'MDN — Content Security Policy'
    url: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
  - title: 'CWE-1022 — Use of Web Link to Untrusted Target with window.opener Access'
    url: https://cwe.mitre.org/data/definitions/1022.html
summary: A cluster of HTML antipatterns: inline event handlers, `target="_blank"` without `rel="noopener"`, mixed content on HTTPS pages, inline `<script>` without CSP, forms posting over plain HTTP. Each is a defense-in-depth bypass.
---

## What this is

Six patterns PreFlight scans for in `.html`, `.jsx`, `.tsx`, `.vue`, and `.svelte` files:

**Inline event handlers:**

```html
<button onclick="doThing()">click</button>
```

Inline event handlers run inline JavaScript. Strict CSPs refuse to execute them. Code review skims over them because they look like attributes.

**`target="_blank"` without `rel="noopener"`:**

```html
<a href="https://external.example" target="_blank">link</a>
```

The opened page can call `window.opener.location = '...'` and navigate the original tab to a phishing page. Tabnabbing.

**Mixed content:**

```html
<!-- on an https:// page -->
<script src="http://cdn.example/foo.js"></script>
```

Plain-HTTP resources on HTTPS pages. The script is modifiable by any network attacker between the user and the origin.

**Inline `<script>` without CSP:**

```html
<script>
  fetch('/api/me').then(...);
</script>
```

Inline scripts work, but they make CSP impossible to tighten. If there's no CSP, this looks fine; with CSP, inline scripts have to be allowed via `unsafe-inline` (defeats the point) or `nonce`-tagged (extra build complexity).

**Forms posting over HTTP:**

```html
<form action="http://api.example/login" method="POST"></form>
```

Credentials submitted in cleartext over the wire. Any network observer reads them.

**`eval()` / `new Function()` inside `<script>`:**

```html
<script>
  const result = eval(userInput);
</script>
```

Same risk as [Auth weaknesses](/learn/patterns/auth-weakness) covers, surfaced in HTML context.

## Why it matters

Each pattern is a defense-in-depth bypass rather than a primary exploit. Inline handlers and inline scripts make CSP toothless. `target="_blank"` without `noopener` turns every external link into a tabnabbing vector. Mixed content destroys HTTPS guarantees for resources that arrive over plain HTTP.

In isolation, any one of these is a small risk. PreFlight flags them because they accumulate; a page with all six is operating without the browser-level controls modern web security depends on.

## What the failure looks like

PreFlight scans HTML and JSX/TSX for the six patterns. JSX uses the same DOM attributes, so `onClick="..."` (string handler) on a JSX element produces the same finding as the HTML form.

## What the fix looks like

**Inline event handlers:** move to a script with addEventListener.

```html
<button id="thing-btn">click</button>
<script>
  document.getElementById('thing-btn').addEventListener('click', doThing);
</script>
```

Or in JSX:

```tsx
<button onClick={doThing}>click</button> // function reference, not string
```

**`target="_blank"`:** add `rel="noopener noreferrer"`.

```html
<a href="https://external.example" target="_blank" rel="noopener noreferrer">link</a>
```

**Mixed content:** use `https://` everywhere. If a third-party only ships HTTP, host the asset yourself.

**Inline `<script>`:** move to an external file with a CSP nonce or hash.

```html
<script src="/static/init.js"></script>
```

**Forms over HTTP:** post over HTTPS. Forms touching credentials must always be HTTPS.

**eval / new Function inside `<script>`:** see [Auth weaknesses](/learn/patterns/auth-weakness) for the broader fix.

## Related

- [Security headers](/learn/patterns/security-headers) covers the CSP that bounds inline-script and other risks.
- [Auth weaknesses](/learn/patterns/auth-weakness) covers `eval` and `dangerouslySetInnerHTML` from the auth-side.

## Sources

MDN's docs on `target="_blank"` security, mixed content, and CSP are the authoritative references. CWE-1022 names the tabnabbing class.

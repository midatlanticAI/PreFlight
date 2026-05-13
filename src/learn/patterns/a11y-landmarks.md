---
title: A11y landmarks and target sizes
slug: a11y-landmarks
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - A11y Landmarks
sources:
  - title: 'W3C WAI — Web Content Accessibility Guidelines (WCAG) 2.2'
    url: https://www.w3.org/TR/WCAG22/
  - title: 'MDN — ARIA landmarks'
    url: https://developer.mozilla.org/en-US/docs/Web/Accessibility/ARIA/Roles#landmark_roles
  - title: 'WCAG 2.5.8 — Target Size (Minimum)'
    url: https://www.w3.org/TR/WCAG22/#target-size-minimum
  - title: 'WCAG 2.4.1 — Bypass Blocks'
    url: https://www.w3.org/TR/WCAG22/#bypass-blocks
summary: Missing landmark elements (header, nav, main, footer), skip-to-content links, focus indicators, and 24×24 touch-target floors. The accessibility signals that turn rendered HTML from "viewable" into "usable by everyone."
---

## What this is

The minimum accessibility signals every public-facing page should have. Each maps to a WCAG 2.2 success criterion:

**Landmarks.** Semantic elements that screen readers and other assistive tech navigate by:

```html
<header>...</header>
<nav>...</nav>
<main>...</main>
<aside>...</aside>
<footer>...</footer>
```

Or their ARIA equivalents (`role="banner"`, `role="navigation"`, `role="main"`, `role="complementary"`, `role="contentinfo"`). Pages built as one big `<div>` are unnavigable.

**Skip-to-content link.** First focusable element on the page, hidden until focused:

```html
<a class="skip-link" href="#main">Skip to content</a>
<main id="main">...</main>
```

Keyboard users jump past the nav with one keystroke.

**Focus-visible outlines.** Every interactive element has a visible focus state. `outline: none` on a button is the antipattern; `:focus-visible` with a visible outline is the fix.

**Minimum target size (WCAG 2.2 SC 2.5.8).** Every interactive target is at least 24×24 CSS pixels. WCAG AAA recommends 44×44.

**Language attribute.** `<html lang="en">` (or appropriate language code). Screen readers use this to choose a pronunciation engine.

## Why it matters

About 15-20% of users have some form of disability that benefits from accessible design. The blast radius of bad accessibility is "this percentage of your audience cannot effectively use the site." It's not a security finding, but it's a usability finding with the same shape (a system that works for some users and not others).

Legal exposure is a secondary concern: ADA / Section 508 in the US, EAA in Europe. Most public-facing commercial sites fall under at least one regulation that mandates a minimum accessibility floor.

## What the failure looks like

Pre-Flight scans rendered HTML for:

- Absence of `<header>`, `<nav>`, `<main>`, `<footer>` (or their ARIA-role equivalents) on what appears to be a top-level page.
- Absence of a skip-to-content link.
- `outline: none` on focusable elements without a `:focus-visible` replacement.
- Interactive elements (`<button>`, `<a>`, `<input>` of clickable type) with a CSS-computed size smaller than 24×24.
- `<html>` without a `lang` attribute.

## What the fix looks like

A reasonable baseline `<body>`:

```html
<body>
  <a class="skip-link" href="#main">Skip to content</a>

  <header>
    <a href="/">Site Name</a>
    <nav>
      <ul>
        <li><a href="/about">About</a></li>
        <li><a href="/docs">Docs</a></li>
      </ul>
    </nav>
  </header>

  <main id="main">
    <h1>Page Title</h1>
    <!-- page content -->
  </main>

  <footer>
    <p>© 2026 Site Name</p>
  </footer>
</body>
```

With the matching CSS:

```css
*:focus-visible {
  outline: 2px solid #f26b1f;
  outline-offset: 2px;
}

.skip-link {
  position: absolute;
  top: -100px;
  left: 8px;
  background: #f26b1f;
  color: #fff;
  padding: 10px 16px;
  z-index: 1000;
}
.skip-link:focus {
  top: 8px;
}

button,
[role='button'],
a,
input[type='submit'] {
  min-height: 24px;
  min-width: 24px;
}

@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}
```

And the language attribute on `<html>`:

```html
<html lang="en"></html>
```

## Related

- [HTML hygiene](/learn/patterns/html-hygiene) covers the broader HTML quality layer that pairs with accessibility.
- [SEO hygiene](/learn/patterns/seo-hygiene) covers the parallel discoverability signals.

## Sources

WCAG 2.2 is the authoritative reference. MDN's ARIA landmarks doc and the specific WCAG success criteria pages cover individual requirements.

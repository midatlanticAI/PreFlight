---
title: A11y semantics
slug: a11y-semantics
type: pattern
last_updated: 2026-09-03
draft: false
related_probe_ids:
  - A11y Semantics
sources:
  - title: 'WAI — ARIA Authoring Practices, button pattern'
    url: https://www.w3.org/WAI/ARIA/apg/patterns/button/
  - title: 'MDN — tabindex'
    url: https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/tabindex
  - title: 'WebAIM — The WebAIM Million'
    url: https://webaim.org/projects/million/
  - title: 'MDN — :focus-visible'
    url: https://developer.mozilla.org/en-US/docs/Web/CSS/:focus-visible
summary: The element-level failures the WebAIM Million keeps finding on most homepages. Click handlers on divs the keyboard cannot reach, positive tabIndex hijacking the tab order, heading levels that skip, focus outlines deleted with nothing in their place.
---

## What this is

A `<button>` brings a tab stop, Enter and Space activation, and a role announcement for free. A `<div onClick>` brings none of them, and generated UI code reaches for the div because the styling starts from zero. The rest of this family is the same story: semantics deleted for visual convenience.

## Why it matters

For keyboard and screen reader users these are not polish, they are the interface. A control that cannot be tabbed to does not exist. A deleted focus outline turns the page dark for anyone navigating without a mouse. A skipped heading level reads as a missing section to someone skimming by structure.

## What the probe looks for

Click handlers on non-interactive elements with no role and no keyboard path. `tabIndex` above zero. Heading levels that jump. `outline: none` with no visible replacement.

## What the probe does not do

Landmarks, alt text, form labels and skip links are owned by the A11y Landmarks probe. Color contrast needs rendered pixels. Focus management in modals and route changes is behavior, and belongs to a running-page check, not a source scan.

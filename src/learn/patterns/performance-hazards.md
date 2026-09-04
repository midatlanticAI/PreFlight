---
title: Performance hazards
slug: performance-hazards
type: pattern
last_updated: 2026-09-03
draft: false
related_probe_ids:
  - Performance Hazards
sources:
  - title: 'web.dev — Cumulative Layout Shift'
    url: https://web.dev/articles/cls
  - title: 'web.dev — optimize CLS (image dimensions)'
    url: https://web.dev/articles/optimize-cls
  - title: 'Moment.js — Project Status'
    url: https://momentjs.com/docs/#/-project-status/
  - title: 'MDN — document.write'
    url: https://developer.mozilla.org/en-US/docs/Web/API/Document/write
summary: Bundle and layout costs paid without noticing. A whole utility library shipped for one helper, moment.js in code written this year, images with no reserved box shifting the page under the reader's finger, document.write blocking the parser.
---

## What this is

None of these break the demo. They tax every user a little, on every load, forever: kilobytes for helpers never called, layout shifts scored directly against the page, a parser stalled by an API deprecated for a decade.

## Why it matters

**An `<img>` without width and height** reserves zero space until the file arrives, then pushes everything below it down. That jump is Cumulative Layout Shift, it is measured by the field data your ranking sees, and it is the thing users misclick through. Two attributes reserve the box before the bytes arrive.

**`import _ from 'lodash'`** ships the entire library to pay for `debounce`. The scoped import gets the same helper for around one percent of the size.

**moment.js is in maintenance mode by its own maintainers**, who point new projects elsewhere. It is heavy, mutable, and drags locale data with it. `Intl` and `Date` cover the basics; date-fns or dayjs cover the rest.

## What the probe does not do

"Heavy work in render", virtualization thresholds, memoization judgment: runtime quantities. Profile first; the probe only calls what is mechanical.

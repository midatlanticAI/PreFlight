---
title: Desktop app (Electron)
slug: desktop-electron
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: Electron — security checklist
    url: https://www.electronjs.org/docs/latest/tutorial/security
  - title: CWE-829 — Inclusion of Functionality from an Untrusted Control Sphere
    url: https://cwe.mitre.org/data/definitions/829.html
summary: A Node-backed desktop shell. The opposite default from Tauri: the renderer can reach Node unless you explicitly close that door, so nodeIntegration and contextIsolation are the load-bearing settings.
---

## What this shape is

An Electron app: a Chromium renderer plus a Node main process. The
classifier detects the electron dependency and reports it. Unlike Tauri,
the dangerous capability is present by default and must be switched off.

## Scanner behavior

PreFlight classifies this shape (informational). It does not raise a
shape-specific finding for it; the JavaScript probes run on both the
main and renderer code.

## The failure mode: the default is the danger

Electron's renderer runs web content. Whether that content can reach the
operating system depends on two settings most vibe-coded apps never
touch:

- `nodeIntegration: true` (or not setting it correctly on older
  versions) lets page JavaScript call Node APIs directly. Any XSS in
  the renderer is now arbitrary code on the user's machine.
- `contextIsolation: false` lets page scripts reach into the preload
  bridge and the internals it exposes, defeating the boundary preload
  was meant to create.
- Loading remote content into a window with these defaults turns a
  third-party page into a local shell.

## How to keep it safe

Disable `nodeIntegration`, enable `contextIsolation`, expose only a
minimal, validated API through `contextBridge` in the preload, and load
only bundled local content (or tightly controlled origins). Treat the
renderer as hostile, exactly as you would a browser tab, because it is
one.

## Related

- [Desktop app (Tauri)](/learn/shapes/desktop-tauri) is the same product
  shape with the safer default: no Node in the webview at all.

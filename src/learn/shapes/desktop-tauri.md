---
title: Desktop app (Tauri)
slug: desktop-tauri
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: Tauri — security
    url: https://tauri.app/security/
  - title: CWE-829 — Inclusion of Functionality from an Untrusted Control Sphere
    url: https://cwe.mitre.org/data/definitions/829.html
summary: A Rust-backed desktop shell with a webview UI. Safer-by-default than Electron because there is no Node in the webview, but the allowlist is the new boundary and widening it to "make it work" is the failure.
---

## What this shape is

A `src-tauri/` Rust core hosting a webview front end. The classifier
detects the Tauri directory and reports it. The security model is
deliberately not Electron's: the webview has no Node, and the front end
can only reach the host through commands you expose.

## Scanner behavior

Pre-Flight classifies this shape (informational). It does not raise a
shape-specific finding for it; the Rust adapters run on the `src-tauri`
core and the web probes run on the UI.

## The failure mode: the allowlist is the boundary

Tauri's safety comes from the front end being unable to touch the host
except through the capabilities you grant. The vibe-coded failure is
widening that grant to make a feature work:

- An allowlist that enables broad shell execution or a filesystem scope
  of `**` hands a webview-reachable bug a path to host command
  execution. When remote or untrusted content can load in that webview,
  it is remote code execution.
- A window pointed at a remote `https://` origin instead of the bundled
  app, combined with a broad allowlist, turns "render this page" into
  "run host commands from that page."
- Commands that take a path or a shell string from the front end
  without validation re-expose the host the architecture was protecting.

## When to use it

Tauri is the right shape when you want a small, native-feeling desktop
app and are willing to keep the capability surface narrow. It is safe
when the allowlist grants the minimum, windows load only bundled
content, and exposed commands validate their inputs like any other
trust boundary.

## Related

- [Desktop app (Electron)](/learn/shapes/desktop-electron) is the same
  product shape with the opposite default: Node is present unless you
  remove it.

---
title: Mobile app (React Native / Expo)
slug: mobile
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: OWASP Mobile Top 10
    url: https://owasp.org/www-project-mobile-top-10/
  - title: OWASP MASVS
    url: https://mas.owasp.org/MASVS/
  - title: CWE-312 — Cleartext Storage of Sensitive Information
    url: https://cwe.mitre.org/data/definitions/312.html
summary: A React Native / Expo app that ships to a device. The defining shift: the binary is in the attacker's hands, so anything bundled or stored insecurely is extractable, and there is no server boundary protecting the client.
---

## What this shape is

A React Native or Expo project that builds to an installable app. The
classifier detects the manifest and reports it as Mobile.

## Scanner behavior

PreFlight classifies this shape (informational). It does not raise a
shape-specific finding for it, but the JavaScript and the native-layer
probes (and, for the platform code, the Swift / Kotlin language
adapters) still run on the source.

## The failure mode: the device is hostile territory

The mental model that breaks vibe-coded mobile apps is treating the
client like a trusted environment:

- Anything bundled ships in the package. A hardcoded API key or secret
  is recoverable with a zip tool and `strings`. The XL-006 family
  covers this; on mobile it is the default mistake, not an edge case.
- Default key-value storage is plaintext. AsyncStorage / SharedPreferences
  / UserDefaults are not secure. Tokens and credentials belong in the
  Keychain / Keystore (encrypted, device-bound), not in a plist or XML
  file on the device.
- Disabling certificate validation to make a dev server work ships to
  production and turns every user's network into a listening post.
- A WebView with JavaScript enabled and a native bridge, loading remote
  content, is JS-to-native code execution from attacker-controlled
  HTML.

## When the shape is fine, with discipline

Mobile is the right shape when you need a device app. It is safe when
the team accepts that the client cannot keep a secret: privileged calls
go through a backend, secrets stay server-side, storage uses the
platform secure store, and TLS verification is never relaxed in a
shipped build.

## Related

- [Hardcoded secrets and policy text](/learn/patterns/xl-hardcoded-secrets)
  and [TLS verification disabled](/learn/patterns/xl-tls-verification-disabled)
  are the two that bite mobile hardest.

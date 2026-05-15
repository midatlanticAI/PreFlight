---
title: TLS verification disabled (XL-004)
slug: xl-tls-verification-disabled
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Python TLS Verification Disabled
sources:
  - title: CWE-295 — Improper Certificate Validation
    url: https://cwe.mitre.org/data/definitions/295.html
  - title: OWASP A02 — Cryptographic Failures
    url: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
  - title: Python requests — SSL cert verification
    url: https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification
summary: Turning off certificate verification to make a request stop failing means a network attacker can transparently man-in-the-middle every call over that client. The shared family is XL-004; adapters differ only in each language's disable flag.
---

## What this is

TLS gives you two things: an encrypted channel, and proof that the other
end is who it claims to be. Certificate verification is the proof half.
Disable it and you still have encryption, but you have no idea who you
encrypted the channel to. A network attacker between you and the server
presents their own certificate, your client accepts it, and they read and
rewrite everything.

The disable flag differs by language, the consequence does not:

- Python: `requests.get(url, verify=False)`,
  `httpx.Client(verify=False)`, `urllib3.disable_warnings()`.
- Go: `tls.Config{InsecureSkipVerify: true}`.
- Java: an always-true `X509TrustManager` / `HostnameVerifier`.
- C#: a `ServerCertificateValidationCallback` returning `true`.
- Rust: `danger_accept_invalid_certs(true)`.
- Kotlin/Android: `cleartextTraffic="true"` or a trust-all OkHttp manager.

Same family (XL-004), one concept, per-language detectors.

## Why AI emits it

A self-signed cert or a corporate proxy breaks the request. The first
remediation in the training corpus is to turn verification off, because
almost every "fix my SSL error" answer the model learned from does
exactly that. The correct fix (point the client at the right CA bundle,
or fix the cert chain) is longer and context-specific, so it loses to the
one-keyword fix.

## The mental model that produces the bug

"It works when I turn off the cert check, so the cert check was the
problem." The local-dev shortcut survives into production because nothing
fails loudly afterward. Encryption still happens, the request still
succeeds, and the missing identity check is invisible until someone
exploits it.

## What the fix looks like

Keep verification on. Fix what actually broke.

- Self-signed dev cert: pass the CA path,
  `requests.get(url, verify="/path/to/ca.pem")`.
- Corporate proxy MITM: install the proxy's CA into the trust store the
  client uses, do not disable the check.
- Expired or misconfigured server cert: fix the server. A client
  workaround hides a real outage.

`verify=False` is never the answer in code that ships. If a value is
assigned to `verify`, it should be a path, not `False`.

## Related

- [Hardcoded secrets](/learn/patterns/xl-hardcoded-secrets) is the other
  half of the same "make it work now, ship the shortcut" reflex.

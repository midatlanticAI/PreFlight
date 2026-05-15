---
title: Authentication and token verification weakness (XL-013)
slug: xl-auth-token-verification
type: pattern
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - JS Auth Token Verification (XL-013)
sources:
  - title: CWE-347 — Improper Verification of Cryptographic Signature
    url: https://cwe.mitre.org/data/definitions/347.html
  - title: CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
    url: https://cwe.mitre.org/data/definitions/327.html
  - title: OWASP A07 — Identification and Authentication Failures
    url: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
  - title: OWASP JSON Web Token Cheat Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
  - title: RFC 7519 — JSON Web Token (JWT)
    url: https://datatracker.ietf.org/doc/html/rfc7519
summary: A token that decodes is not a token that was verified. alg:none accepts unsigned tokens, and jwt.verify() with no key skips signature checking in some libraries. Both let an attacker forge any identity. The shared family is XL-013; adapters differ by language and JWT library surface.
---

## What this is

A signed token has two parts that matter: the claims (who the bearer says
they are) and the signature (proof the claims were issued by your server
and not edited). Verification is the step that checks the signature
against your key. Decoding is not verification. A token whose claims you
can read is not a token whose signature you have checked.

Two patterns skip the check:

- `algorithm: 'none'` (quoted or unquoted). The "none" algorithm is a
  real JWT algorithm that means "unsigned." A token signed with `none`
  has no signature to forge. An attacker writes `{ "sub": "admin" }`,
  sets the algorithm to `none`, and your server accepts it.
- `jwt.verify(token)` with no key argument. Depending on the library and
  version, a verify call with no key may decode without checking the
  signature at all, which is the same outcome as `none`.

The library surface differs by language, the bug does not:

- Node: `jsonwebtoken` `jwt.verify(token)` with no secret, or
  `{ algorithm: 'none' }` in sign options.
- Python: `jwt.decode(token, options={"verify_signature": False})`,
  PyJWT `algorithms=["none"]`.
- Java: a `JwtParser` built without `setSigningKey`.
- Ruby: `JWT.decode(token, nil, false)`.

Same family (XL-013), one concept: the signature was never checked.

## Why AI emits it

Asked to "make auth work," a model reaches for the shortest code that
returns a usable token and a populated user object. Both of these
patterns do exactly that. The demo logs in, the user object is correct,
nothing throws. The failure mode only appears when someone deliberately
forges a token, and there is no test for that in a prototype, so the hole
ships invisibly.

## The mental model that produces the bug

"The token decodes and the user comes back, so auth works." There is no
mental model separating decode from verify. The token round-trips in
local testing because local testing never sends a forged one.

## What the fix looks like

Verify with a real algorithm and a real key, every time.

- Node: `jwt.verify(token, process.env.JWT_SECRET)` for HS256, or the
  public key for RS256. Never `{ algorithm: 'none' }`.
- Pin the accepted algorithms explicitly: pass
  `{ algorithms: ['HS256'] }` so a token claiming `none` or a swapped
  algorithm is rejected before the signature step.
- Python: `jwt.decode(token, key, algorithms=["HS256"])`, never
  `verify_signature: False` outside a test.

The signature is checked against your key on every request. A token your
server did not sign does not verify, regardless of what its claims say.

## Related

- [Hardcoded secrets and policy text](/learn/patterns/xl-hardcoded-secrets)
  is the matching failure on the key side: a strong verify step does not
  help if the signing secret is committed to the repo.

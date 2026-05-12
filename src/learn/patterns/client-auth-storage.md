---
title: Auth tokens in localStorage
slug: client-auth-storage
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Client Auth Storage
  - Cookie Security
sources:
  - title: OWASP — HTML5 Security Cheat Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
  - title: OWASP — Session Management Cheat Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
  - title: CWE-922 — Insecure Storage of Sensitive Information
    url: https://cwe.mitre.org/data/definitions/922.html
summary: `localStorage.setItem('jwt', token)` puts the session in a JavaScript-readable place. Every XSS becomes session theft. Use httpOnly cookies.
---

## What this is

The pattern:

```ts
const res = await fetch('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) });
const { token } = await res.json();
localStorage.setItem('jwt', token);  // session is now readable by any JS on the page
```

`localStorage` is a JavaScript-accessible key-value store scoped to the origin. Any script running on the page can read it. That includes XSS payloads.

## Why it matters

XSS plus localStorage token equals session theft. The threat model is not "we are confident there is no XSS." Every real application ships with the possibility of an XSS, whether through a third-party script, an analytics tag, a user-generated content surface, or a future regression. The defense is to make the cookie unreadable by JavaScript so XSS cannot exfiltrate it.

`HttpOnly` cookies are unreadable by JavaScript. localStorage is the opposite of that.

The variant most often seen in vibe-built apps: the login response sets a JWT in localStorage and the client adds it to every fetch as a `Bearer` header. The pattern works. It also turns every script on every page into a potential exfiltration vector.

## What the failure looks like

Pre-Flight scans for:

```ts
localStorage.setItem('jwt', ...)
localStorage.setItem('session', ...)
localStorage.setItem('auth', ...)
localStorage.setItem('access_token', ...)
localStorage.setItem('refresh_token', ...)
sessionStorage.setItem('jwt', ...)  // same problem
```

Storage of user preferences, theme settings, or non-credential state is fine.

## What the fix looks like

Use cookies for session tokens, with all three security flags set.

**Login handler sets the cookie server-side:**

```ts
// app/api/login/route.ts
export async function POST(req: Request) {
  const { email, password } = await req.json();
  const user = await verifyCredentials(email, password);
  if (!user) return new Response('Unauthorized', { status: 401 });

  const token = await signJwt({ sub: user.id });
  const res = new Response(JSON.stringify({ ok: true }));
  res.headers.set('Set-Cookie',
    `session=${token}; Max-Age=2592000; Path=/; HttpOnly; Secure; SameSite=Lax`);
  return res;
}
```

**Client-side does not handle the token.** The browser sends the cookie automatically on every same-site request.

**API route handlers read the cookie:**

```ts
const cookie = req.headers.get('cookie');
const token = cookie?.match(/session=([^;]+)/)?.[1];
const session = await verifyJwt(token);
```

The fix means every request is automatically authenticated and the token is unreachable by page JavaScript. The XSS that would have stolen the localStorage token now sees nothing.

## When localStorage tokens make sense (the narrow case)

Mobile / native wrappers (Capacitor, Electron) where the token is genuinely scoped to the embedded WebView and you have a different threat model. Public APIs with no cookie path (the API and the SPA are on different domains, neither owns a cookie scope you control). In both cases, the discipline that matters is "no third-party scripts on the page" so the XSS attack surface stays small.

For the typical SPA on the same domain as its API: cookies are the answer.

## Related

- [Cookie security](/learn/patterns/cookie-security) covers the `HttpOnly` / `Secure` / `SameSite` flags the cookie needs.
- [Auth weaknesses](/learn/patterns/auth-weakness) covers the JWT signing / verification primitives both options rely on.

## Sources

OWASP's HTML5 security cheat sheet explicitly recommends against localStorage for session tokens. The session management cheat sheet covers the broader discipline. CWE-922 names the vulnerability class.

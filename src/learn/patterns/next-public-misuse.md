---
title: NEXT_PUBLIC_ env-var leakage
slug: next-public-misuse
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - NEXT_PUBLIC_ Misuse
  - Secret Scanner
related_incident_slugs:
  - sapphire-sleet-axios-2026-03
sources:
  - title: Next.js Docs — Environment variables
    url: https://nextjs.org/docs/app/building-your-application/configuring/environment-variables
  - title: Next.js Docs — Server and Client Components
    url: https://nextjs.org/docs/app/building-your-application/rendering/composition-patterns
  - title: CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
    url: https://cwe.mitre.org/data/definitions/200.html
  - title: OWASP A04 — Insecure Design
    url: https://owasp.org/Top10/A04_2021-Insecure_Design/
summary: Next.js inlines any environment variable prefixed with NEXT_PUBLIC_ into the client bundle at build time. Server-only secrets accidentally given that prefix end up in JavaScript every visitor downloads.
---

## What this is

Next.js has a build-time convention. Any environment variable whose name starts with `NEXT_PUBLIC_` is substituted into the client JavaScript bundle as a literal string during `next build`. Any variable without the prefix is server-only. The mechanism is a webpack `DefinePlugin` pass that runs before bundling.

That means this `.env.production`:

```
NEXT_PUBLIC_APP_URL=https://example.com
NEXT_PUBLIC_STRIPE_SECRET=sk_live_<your-key-here>
STRIPE_SECRET_KEY=sk_live_<your-key-here>
```

Produces a client bundle containing the first two values as literal strings. Open DevTools, search the loaded JavaScript for `sk_live_`, and you find them. The third value (without the prefix) stays on the server.

The prefix is the entire access-control mechanism. There is no "private" flag, no runtime check, no fallback. Whatever name you give the variable is whatever access you grant.

## Why it matters

The pattern produces three failure shapes:

**Server secrets given the prefix.** `NEXT_PUBLIC_DATABASE_URL=postgres://admin:hunter2@db/prod` ships your database connection string to every visitor. `NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...` ships your payment-charging credential. `NEXT_PUBLIC_OPENAI_KEY=sk-proj-...` ships an LLM credential anyone can drain.

**Non-secret-looking names that happen to be secrets.** `NEXT_PUBLIC_API_AUTH=eyJhbGciOiJIUzI1NiJ9...` is a JWT and the bearer can call anything the token grants. `NEXT_PUBLIC_INTERNAL_URL=https://internal.corp/api` is a network-pivot hint that gets indexed by anyone scraping the bundle.

**Service-role credentials in the wrong env file.** Supabase has both an `anon` key (intentionally public, the access control happens at the RLS layer) and a `service_role` key (bypasses RLS, never meant to leave the server). `NEXT_PUBLIC_SUPABASE_ANON_KEY` is fine. `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` is the entire database to anyone who can read your page.

Once the bundle ships, every visitor has the secret on their disk. Rotation is the only remediation, just like any other leaked key. The Stripe key cannot be un-shipped.

## What the failure looks like

The two shapes PreFlight checks for:

**Danger-name variables.** Any `NEXT_PUBLIC_*` whose name contains a fragment PreFlight recognizes as server-only territory: `SECRET`, `PRIVATE`, `SERVICE_ROLE`, `DATABASE_URL`, `STRIPE_SECRET`, `OPENAI`, `ANTHROPIC`, `JWT_SECRET`, `WEBHOOK_SECRET`, `ADMIN`, and similar. The presence of the prefix on a variable named like a server secret is the finding.

**Danger-value variables.** Any `NEXT_PUBLIC_*` whose value matches a known secret shape: `sk_live_*`, `sk_test_*`, `sk-ant-*`, `sk-proj-*`, `eyJhbGciOiJIUzI...` (JWT), `postgres://user:pass@`, or a private-key block. Variables named anything (even something benign-sounding) but holding a credential-shaped value are still findings.

Both shapes apply to every common Next.js env file: `.env`, `.env.local`, `.env.production`, `.env.development`. PreFlight scans the file content, not just the filename.

## Why AI coding tools produce this

Models trained on tutorial blog posts have seen the `NEXT_PUBLIC_` convention applied unevenly. Some tutorials use it correctly (anon keys, public URLs, public Stripe publishable keys). Other tutorials use it incorrectly because the author was iterating fast and the code "worked." A model asked to wire up payments takes the shortest path that compiles, and the shortest path that compiles often includes `NEXT_PUBLIC_STRIPE_KEY` because the import side then resolves at build time without a server component dance.

The viber pasting the output sees a working checkout flow. The bundle ships. Visitors get a fresh copy of the production Stripe key on first load.

## What the fix looks like

Three motions.

**Rename the variable. Drop the prefix.**

```diff
- NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_...
+ STRIPE_SECRET_KEY=sk_live_...
```

Then update every usage in the source to read the unprefixed name. Server components, route handlers, and `getServerSideProps` can all access `process.env.STRIPE_SECRET_KEY` directly. Client components cannot, which is the point.

If the value was already in a production build, treat it as leaked and rotate at the provider before continuing. The build went out; the bytes are downloaded; the key is gone.

**Move the call to a server boundary.**

A client component that needs to charge Stripe should not hold the secret key. It should call a route handler that holds the key.

```ts
// app/api/checkout/route.ts (server-only)
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(req: Request) {
  const { amount } = await req.json();
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{ price_data: { currency: 'usd', unit_amount: amount, product_data: { name: 'item' } }, quantity: 1 }],
    mode: 'payment',
    success_url: ...,
    cancel_url: ...,
  });
  return Response.json({ id: session.id });
}
```

```tsx
// app/checkout/page.tsx (client)
'use client';
const r = await fetch('/api/checkout', { method: 'POST', body: JSON.stringify({ amount: 1999 }) });
const { id } = await r.json();
stripe.redirectToCheckout({ sessionId: id });
```

The client gets the session ID, not the API key. The session ID is single-use and scoped to the one checkout flow.

**Keep the prefix where it actually belongs.**

Three things legitimately live behind `NEXT_PUBLIC_`:

- A public URL the client needs to know about (`NEXT_PUBLIC_APP_URL`, `NEXT_PUBLIC_API_BASE`).
- A Stripe publishable key (`NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_...`). The publishable key is designed to be public; the secret key is not.
- A Supabase anon key (`NEXT_PUBLIC_SUPABASE_ANON_KEY`). The anon key is designed to work in a browser against an RLS-protected database. See the [Supabase RLS pattern](/learn/patterns/supabase-rls) for the access-control side.
- Public analytics IDs (`NEXT_PUBLIC_GA_ID`, `NEXT_PUBLIC_POSTHOG_KEY`). These are scoped to read-only event ingestion.

If a variable does not fit one of those categories, it does not get the prefix.

## How to check existing builds

Open your latest production bundle in DevTools, view the largest JavaScript file, and search for `sk_live_`, `sk-proj-`, `sk-ant-`, `eyJhbGciOiJIUzI`, and `postgres://`. If any match, those values are in the bundle. The variable producing them needs to come out of the public namespace and the credential needs to be rotated.

A faster check from the repo:

```bash
grep -RE '^NEXT_PUBLIC_[A-Z0-9_]*(SECRET|PRIVATE|SERVICE_ROLE|DATABASE_URL|STRIPE_SECRET|OPENAI|ANTHROPIC|JWT_SECRET|ADMIN)' .env* 2>/dev/null
```

A non-empty result is a finding.

## Related

- [Hardcoded secrets in source](/learn/patterns/secret-scanner) covers the broader class. The `NEXT_PUBLIC_` pattern is a specific Next.js footgun for the same underlying mistake.
- [Sapphire Sleet axios incident](/learn/incidents/sapphire-sleet-axios-2026-03) is one of the named 2026 supply-chain incidents that hunted for credentials in any reachable file, including bundled JS.

## Sources

The Next.js environment-variables doc is the authoritative reference for the build-time substitution behavior. The Server-and-Client-Components doc is the authoritative reference for where server secrets should live. CWE-200 names the vulnerability class. OWASP A04 covers the broader insecure-design category this pattern fits inside.

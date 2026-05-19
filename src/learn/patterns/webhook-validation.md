---
title: Unverified webhooks
slug: webhook-validation
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Webhook Validation
sources:
  - title: Stripe Docs — Verifying webhook signatures
    url: https://stripe.com/docs/webhooks#verify-events
  - title: GitHub Docs — Securing your webhooks
    url: https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
  - title: CWE-345 — Insufficient Verification of Data Authenticity
    url: https://cwe.mitre.org/data/definitions/345.html
summary: Webhook handlers that trust the request body without verifying the signature. Anyone with the endpoint URL can post fake events. Stripe, GitHub, Twilio, and every reputable webhook provider sign their payloads; verify on receipt.
---

## What this is

A webhook handler that processes events without checking who sent them:

```ts
// Stripe webhook, no signature check — anyone can post fake events.
export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === 'payment_intent.succeeded') {
    await db.orders.update({
      where: { id: event.data.object.metadata.orderId },
      data: { paid: true },
    });
  }
  return new Response('ok');
}
```

The webhook URL is in the Stripe dashboard, which means the endpoint is public. Anyone who finds the URL can post a `payment_intent.succeeded` event with arbitrary metadata and mark any order as paid.

## Why it matters

Webhooks are unauthenticated by default. The provider does not log in to your API. They post a JSON body with no headers other than what the provider chose to send. Some of those headers are a signature. Without verifying the signature, the handler is trusting any HTTP POST that arrives at the URL.

The blast radius depends on what the handler does. A "mark order as paid" webhook means free orders. A "grant subscription" webhook means free service. A "user signed up" webhook means whatever side effects sign-up triggers. A "tag user as enterprise" webhook means privilege escalation.

## What the failure looks like

PreFlight scans for:

- Stripe webhook handlers (typically `stripe-webhook.js`, `/api/stripe/webhook`, or matching imports) that call `req.json()` without `stripe.webhooks.constructEvent`.
- GitHub webhook handlers that read the body without checking `X-Hub-Signature-256`.
- Generic webhook handlers in known-named files (`/api/webhook`, `/api/webhooks/*`) without any signature-verification call.

## What the fix looks like

**Stripe:**

```ts
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const sig = req.headers.get('stripe-signature');
  const body = await req.text();
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(body, sig!, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch {
    return new Response('Invalid signature', { status: 400 });
  }
  // event is now verified. Process it.
}
```

**GitHub:**

```ts
import crypto from 'node:crypto';

function verifyGitHubSignature(body: string, signatureHeader: string, secret: string) {
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signatureHeader), Buffer.from(expected));
}

export async function POST(req: Request) {
  const body = await req.text();
  const sig = req.headers.get('x-hub-signature-256');
  if (!sig || !verifyGitHubSignature(body, sig, process.env.GH_WEBHOOK_SECRET!)) {
    return new Response('Invalid signature', { status: 400 });
  }
  // body is now verified. JSON.parse it.
}
```

Three rules:

- Use the provider's own verification helper when one is available (`stripe.webhooks.constructEvent`). It handles edge cases like multiple signatures during key rotation that ad-hoc HMAC checks miss.
- Use `crypto.timingSafeEqual` for HMAC comparisons. Plain `===` is vulnerable to timing attacks that leak the expected signature one byte at a time.
- Read the raw body for verification. Many web frameworks parse the JSON before the handler runs; you need the raw bytes to recompute the signature.

## Related

- [API route auth](/learn/patterns/api-route-auth) covers the general authorization discipline that webhooks are a special case of (signature-based authentication rather than session-based).
- [Hardcoded secrets in source](/learn/patterns/secret-scanner) covers the webhook secret itself, which should never be in source.

## Sources

Stripe and GitHub's webhook docs are the authoritative references for their respective verification flows. CWE-345 names the underlying class.

---
title: AI code smells
slug: ai-code-smells
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - AI Code Smells
sources:
  - title: 'Empty catch blocks (CWE-390)'
    url: https://cwe.mitre.org/data/definitions/390.html
  - title: 'TypeScript Handbook — Strict Type Checking'
    url: https://www.typescriptlang.org/docs/handbook/2/everyday-types.html
  - title: 'OWASP A04 — Insecure Design'
    url: https://owasp.org/Top10/A04_2021-Insecure_Design/
summary: Two patterns AI tools produce often that correlate strongly with security gaps. Empty catch blocks (errors swallowed silently) and heavy `any` usage in TypeScript (input validation skipped). Both are statistical signals of "the model gave up here," and gaps follow.
---

## What this is

Two specific code shapes Pre-Flight scans for because they correlate with under-validated code:

**Empty catch blocks.**

```ts
try {
  await chargeCard(amount);
} catch {
  // ...
}
```

The error from `chargeCard` is gone. The function returned. Whatever called it sees success. The user is told the charge worked. The charge did not work.

Empty catches in security-touching code are particularly bad because the failure mode of the call is the case where the rest of the program assumes success. A signature-verification function that throws gets swallowed, and the caller proceeds as if the signature was valid.

**Heavy `any` usage in TypeScript.**

```ts
function handleWebhook(payload: any) {
  const order = payload.order;
  await db.orders.update({ id: order.id, paid: order.paid });
}
```

`any` disables every type guarantee. The compiler will not catch a missing field, a wrong type, a nested undefined, or a malicious shape. Input validation that would normally happen via the type system happens nowhere. The function trusts the shape of `payload`. The shape of `payload` is whatever an attacker can post to the webhook.

## Why it matters

Industry studies on AI-generated code show ~45% of samples introduce at least one OWASP Top 10 issue. Empty catches and pervasive `any` are not the issues themselves; they are markers for "this section of the code was generated without consideration of what failure modes look like." Findings here often co-locate with the actual vulnerabilities.

The patterns also explicitly defeat defense-in-depth. An empty catch turns "verify signature, then process" into "process unconditionally." A pervasive `any` turns "validate input shape at the type boundary" into "trust whatever came in."

## What the failure looks like

Pre-Flight scans for:

- `catch {}` or `catch (e) {}` with no body other than whitespace or a comment.
- `: any` in TypeScript function parameters, especially handlers, route handlers, and webhook endpoints.

Note: the AI Code Smells probe is informational. It surfaces patterns worth a second look, not patterns that are themselves exploits. The expected response is "go look at this code path more carefully" rather than "patch immediately."

## What the fix looks like

**Empty catches:** decide what should happen on failure and write it.

```ts
try {
  await chargeCard(amount);
} catch (e) {
  log.error('charge failed', { error: e, amount, userId });
  throw new ChargeFailedError({ cause: e });
}
```

Three rules:

- Log the error with enough context to debug.
- Either rethrow so the caller knows something failed, or take a deliberate compensating action (refund, retry, alert).
- Never `catch (e) {}` to suppress noisy errors. If the error is genuinely safe to ignore, write that in a comment and narrow the catch to the specific error type.

**Heavy `any`:** add type definitions matching the actual input shape and validate at the boundary.

```ts
import { z } from 'zod';

const WebhookSchema = z.object({
  order: z.object({
    id: z.string(),
    paid: z.boolean(),
  }),
});

function handleWebhook(payload: unknown) {
  const validated = WebhookSchema.parse(payload); // throws on bad shape
  await db.orders.update({ id: validated.order.id, paid: validated.order.paid });
}
```

Two rules:

- The handler signature takes `unknown`, not `any`. The compiler then requires you to validate before accessing fields.
- The validation happens via a schema library (Zod, Yup, valibot) that throws on shape mismatch. The validation result is fully typed.

The pattern applies the same way to body parsing in route handlers, query-string parsing, third-party API responses, and webhook payloads. Anywhere data enters the program, validate at the boundary.

## Related

- [Auth weaknesses](/learn/patterns/auth-weakness) covers `eval()` and `dangerouslySetInnerHTML`, two specific shapes that often co-locate with `any` usage.
- [Webhook validation](/learn/patterns/webhook-validation) covers the input-validation discipline for webhook handlers specifically.

## Sources

CWE-390 covers the empty-catch class. The TypeScript handbook is the authoritative reference for type-safety patterns. OWASP A04:2021 covers insecure design, which is the broader category these smells fall under.

---
title: Math.random in security-sensitive contexts
slug: weak-randomness
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Weak Randomness
sources:
  - title: OWASP A02 — Cryptographic Failures
    url: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
  - title: 'MDN — Crypto.getRandomValues'
    url: https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
  - title: 'Node.js — crypto.randomBytes / randomUUID / randomInt'
    url: https://nodejs.org/api/crypto.html
  - title: CWE-338 — Use of Cryptographically Weak Pseudo-Random Number Generator
    url: https://cwe.mitre.org/data/definitions/338.html
summary: `Math.random()` produces predictable sequences. An attacker who observes a few generated values can predict the next ones. Fine for animation jitter and shuffling; not fine for tokens, OTPs, password reset codes, session IDs, or anything that authenticates.
---

## What this is

```ts
// Predictable.
function generateResetToken() {
  return Math.random().toString(36).slice(2);
}
```

`Math.random()` is a PRNG (pseudo-random number generator) seeded from internal state the engine never claimed to make secret. The output is reproducible enough that academic and applied papers have demonstrated full-state recovery from a small number of consecutive outputs in V8, SpiderMonkey, and JavaScriptCore.

If the function above generates a password-reset token, an attacker who has observed the user receive a reset email (or a public token in a URL) can run the recovery, derive the engine's internal state, and predict the next user's reset token before that user receives the email.

## Why it matters

The class of vulnerability turns "guess the token" from an exhaustive search into a one-time math problem. Token spaces that look enormous (`36^11` for an 11-character base-36 string) shrink to essentially nothing once the PRNG state is known.

The pattern shows up in:

- Password reset codes.
- Email verification tokens.
- Magic-link URLs.
- One-time passwords / OTP codes.
- API key generation.
- CSRF tokens (in some hand-rolled implementations).
- Session IDs (rare in modern frameworks; common in custom code).
- Recovery codes.
- Invite tokens.

Anywhere a value is meant to be unguessable, `Math.random()` is the wrong primitive.

## What the failure looks like

Pre-Flight scans for `Math.random()` calls within a few lines of a name suggesting security use: `token`, `secret`, `password`, `key`, `nonce`, `csrf`, `session`, `otp`, `verification`, `reset`, `signature`, `hash`, `salt`, `recovery`, `magic`, `invite`, `verify`.

The probe excludes contexts that suggest UI / animation use: `jitter`, `delay`, `shuffle`, `animation`, `fade`, `color`, `hsl`, `rgb`, `pixel`, `particle`, `sample`, `preview`, `placeholder`, `mock`. Those uses are fine.

## What the fix looks like

Use a CSPRNG (cryptographically secure PRNG). Every modern runtime has one built in.

**Browser:**

```ts
function generateResetToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
```

**Node.js:**

```ts
import crypto from 'node:crypto';

function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Or for UUIDs:
const id = crypto.randomUUID();

// Or for a bounded integer:
const otp = crypto.randomInt(100000, 1000000).toString(); // 6-digit OTP
```

**Cross-platform via uuid library:**

```ts
import { v4 as uuidv4 } from 'uuid';
const id = uuidv4(); // backed by crypto.getRandomValues / randomBytes
```

The substitution is mechanical: same call shape, different primitive. The CSPRNG output is statistically indistinguishable from true random within any feasible computational budget.

## When Math.random is fine

The probe deliberately does not fire on these cases:

- Animation jitter: `transform: translate(${Math.random() * 2 - 1}px, 0)` for natural-feeling motion.
- Sample size: `if (Math.random() < 0.1) { logSample(); }` for 10% sampling.
- Demo data: `users[Math.floor(Math.random() * users.length)]` to pick a random user for a placeholder.
- Shuffling: most casual `Array.prototype.sort(() => Math.random() - 0.5)` shuffles (though `crypto.getRandomValues` based Fisher-Yates is a stricter shuffle for the cases that matter).

The rule of thumb: if an attacker guessing the value would cost you anything, use the CSPRNG.

## Related

- [Auth weaknesses](/learn/patterns/auth-weakness) covers the JWT-secret class. A weak JWT secret has the same shape of vulnerability as a Math.random-derived token: the space is small enough to brute-force.
- [Hardcoded secrets in source](/learn/patterns/secret-scanner) covers the related class where the value is not random at all.

## Sources

OWASP A02:2021 covers cryptographic failures. CWE-338 names the specific weak-PRNG class. MDN documents `crypto.getRandomValues` in the browser. Node's `crypto` module docs cover `randomBytes`, `randomUUID`, and `randomInt`.

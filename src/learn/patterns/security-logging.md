---
title: Missing security logging
slug: security-logging
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Security Logging
sources:
  - title: 'OWASP A09 — Security Logging and Monitoring Failures'
    url: https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
  - title: 'OWASP — Logging Cheat Sheet'
    url: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
  - title: 'CWE-778 — Insufficient Logging'
    url: https://cwe.mitre.org/data/definitions/778.html
  - title: 'NIST 800-92 — Guide to Computer Security Log Management'
    url: https://csrc.nist.gov/publications/detail/sp/800-92/final
summary: A login handler, password-reset handler, or admin action with no log call is a hole in the audit trail. The first sign of a compromise often arrives in the logs, weeks before any other indicator. No logs, no early warning.
---

## What this is

A handler that performs a security-sensitive action without emitting a log record. The action goes through; the audit trail does not.

```ts
// No log of the attempt. Not the success, not the failure, not the IP.
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await users.findOne({ email });
  if (!user || !(await verify(user.passwordHash, password))) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  const token = await signJwt({ sub: user.id });
  res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });
  res.json({ ok: true });
});
```

The handler is fine functionally. It is missing the observability layer. A credential-stuffing attack against this endpoint runs invisibly: thousands of requests per minute, each individually indistinguishable from a legitimate failed login, never aggregated, never alerted on.

Same pattern for password reset, account deletion, permission elevation, admin actions, and every other handler whose security depends on knowing who did what.

## Why it matters

The blast radius of missing logs is "we don't know what happened." Three concrete consequences:

**Incident response is impossible.** If a credential is compromised on Monday and the attacker logs in on Tuesday, the team needs to know Tuesday's login happened. Without auth logs, there's no way to confirm the breach, no way to scope the affected accounts, and no way to trigger the rotation.

**Pattern detection is blind.** Brute force, credential stuffing, password spray, account enumeration, lateral movement after takeover. Each shows up as a specific log signature. Without logs, the only signal is the user calling support to say their account has been taken over.

**Compliance and contracts depend on it.** Most security frameworks (SOC 2, ISO 27001, PCI DSS) require auth and admin action logging. Customer contracts in regulated industries often have it as a clause.

OWASP ranks A09 (Security Logging and Monitoring Failures) at #9 in the Top 10 because the failure mode is so often the difference between "incident contained in hours" and "incident discovered six months later through a news article."

## What the failure looks like

PreFlight uses a path heuristic. Files in security-sensitive paths (`auth/`, `login/`, `logout/`, `register/`, `signup/`, `password/`, `admin/`, `permission/`, `role/`, `access/`) or files containing a `DELETE` route handler are checked. If the file contains no recognizable logging call (`log.`, `logger.`, `console.error`, `audit.`, `track.`, `Sentry.captureException`, etc.), the file gets flagged.

The probe is conservative on purpose. The heuristic catches the "no logging anywhere" case; it does not flag handlers that emit logs but skip the right details. That's a different, harder-to-detect failure.

## What the fix looks like

Pick a logger and use it consistently. Every security-sensitive handler emits structured log records.

**Logger pattern:**

```ts
import pino from 'pino';
const log = pino({
  redact: ['req.headers.authorization', 'req.body.password'], // never log credentials
});
```

**Auth events:**

```ts
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const ctx = { email, ip: req.ip, userAgent: req.headers['user-agent'] };
  const user = await users.findOne({ email });

  if (!user || !(await verify(user.passwordHash, password))) {
    log.warn({ event: 'login.failed', ...ctx, reason: 'invalid_credentials' });
    return res.status(401).json({ error: 'invalid credentials' });
  }

  log.info({ event: 'login.success', userId: user.id, ...ctx });
  const token = await signJwt({ sub: user.id });
  res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });
  res.json({ ok: true });
});
```

**Sensitive state changes:**

```ts
app.post('/admin/promote', requireAdmin, async (req, res) => {
  const { targetUserId } = req.body;
  log.info({
    event: 'admin.role_change',
    actor: req.user.id,
    target: targetUserId,
    newRole: 'admin',
    ip: req.ip,
  });
  await users.update({ id: targetUserId, role: 'admin' });
  res.json({ ok: true });
});
```

**Account deletion:**

```ts
app.delete('/account', async (req, res) => {
  log.info({ event: 'account.delete', userId: req.user.id, ip: req.ip });
  await users.delete({ id: req.user.id });
  res.status(204).end();
});
```

**Things to log:**

- The event name (canonical, consistent vocabulary across the app).
- The actor (user ID, not name or email if email is sensitive).
- The target (when the action affects someone else).
- The outcome (success or failure, with the reason on failure).
- Network context (IP, user agent) when available.
- A correlation ID (request ID) so logs across services can be joined.

**Things never to log:**

- Passwords, password hashes, OTP codes, recovery codes.
- Full session tokens or JWTs.
- Credit card numbers, SSNs, government IDs.
- Anything covered by your privacy policy that says "we don't log this."

Use the logger's redaction feature (pino's `redact`, winston's filters, Datadog's scrubbers) to enforce the never-log list at the logger boundary, not by hoping every developer remembers.

## Related

- [Stack trace leaks](/learn/patterns/stack-trace-leaks) covers the parallel discipline: log richly server-side, return generic to the client.
- [API route auth](/learn/patterns/api-route-auth) covers the authorization layer that the logs document.

## Sources

OWASP A09:2021 is the authoritative ranking. The OWASP Logging Cheat Sheet covers what to log and what not to log. CWE-778 names the class. NIST 800-92 is the longer-form government reference for log management at scale.

---
title: Path traversal
slug: path-traversal
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Path Traversal
sources:
  - title: OWASP A01 — Broken Access Control
    url: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - title: OWASP — Path Traversal
    url: https://owasp.org/www-community/attacks/Path_Traversal
  - title: CWE-22 — Improper Limitation of a Pathname to a Restricted Directory
    url: https://cwe.mitre.org/data/definitions/22.html
  - title: 'Node.js path module'
    url: https://nodejs.org/api/path.html
summary: A `fs.readFile(req.body.path)` with no validation lets an attacker read any file the process can read. `../../../etc/passwd` is the textbook payload; the real targets are `.env`, `~/.ssh/id_rsa`, and your private keys.
---

## What this is

```ts
// Vulnerable.
export async function POST(req: Request) {
  const { filename } = await req.json();
  const content = await fs.readFile(path.join('/var/uploads', filename), 'utf8');
  return Response.json({ content });
}
```

`filename` is `../../../etc/passwd`. `path.join('/var/uploads', '../../../etc/passwd')` evaluates to `/etc/passwd`. The read succeeds. The contents return to the attacker.

The pattern shows up anywhere user input flows into a filesystem operation: file downloads, attachment retrieval, template loaders, log viewers, "preview this config" endpoints. Any read, write, or delete call on a user-controlled path is the same class.

## Why it matters

The attacker reads anything the process can read. On a typical Node server running as the application user, that includes:

- `~/.ssh/id_rsa` (if the process has the user's home directory).
- `.env` and other config files in the app directory.
- Cloud-provider credential caches (`~/.aws/credentials`, `~/.config/gcloud/`).
- Application source itself, which often contains secrets in comments and embedded constants.
- System files like `/etc/passwd` (account names; on modern systems password hashes are in `/etc/shadow` and unreadable by app users, but `/etc/passwd` discloses every user account).

Variants on the same pattern: `fs.writeFile(userPath, content)` becomes arbitrary file write (configuration corruption, shell startup file overwrite). `fs.unlink(userPath)` becomes arbitrary deletion. `child_process.exec(\`tar xf ${userPath}\`)` combines path traversal with command injection.

## What the failure looks like

PreFlight scans for filesystem calls (`fs.readFile`, `fs.writeFile`, `fs.createReadStream`, `path.join`, `path.resolve`, and others) where:

- A user-input-shaped variable appears in the same statement or nearby context (`req.body`, `req.query`, `req.params`, `req.headers`, `req.cookies`, `searchParams`).
- No visible normalization or guard (`path.normalize`, `path.isAbsolute`, an allowlist, a sanitizer call) appears within a few lines.

The probe is intentionally conservative; the false-positive rate is non-zero but the missed-class rate is much higher than the false-positive rate, which is the right trade for this severity.

## What the fix looks like

Two motions, often combined.

**1. Allowlist filenames.**

When the use case permits, a fixed list is the safest pattern.

```ts
const ALLOWED = new Set(['terms.md', 'privacy.md', 'about.md']);

export async function GET(req: Request) {
  const { name } = await req.json();
  if (!ALLOWED.has(name)) return new Response('not found', { status: 404 });
  return new Response(await fs.readFile(`/var/docs/${name}`, 'utf8'));
}
```

The allowlist is exhaustive. The attacker cannot invent a filename outside it. The path-traversal class is closed by construction.

**2. Resolve against a base, then verify containment.**

When the use case is "user picks from many files in this directory":

```ts
import path from 'node:path';
import fs from 'node:fs/promises';

const BASE = path.resolve('/var/uploads');

export async function GET(req: Request) {
  const { filename } = await req.json();
  const resolved = path.resolve(BASE, filename);
  if (!resolved.startsWith(BASE + path.sep)) {
    return new Response('not found', { status: 404 });
  }
  return new Response(await fs.readFile(resolved, 'utf8'));
}
```

Three checks worth keeping together:

- `path.resolve` normalizes `..` segments.
- `startsWith(BASE + path.sep)` verifies the resolved path still lives under BASE. The `+ path.sep` prevents `/var/uploads_other` from passing the `startsWith('/var/uploads')` test.
- Anything that fails the containment check returns the same generic error as "file not found." Do not differentiate "not allowed" from "missing" in the response; that distinction itself leaks information.

**3. Avoid the pattern where you can.**

The cleanest fix is often to not need user-controlled paths at all. Replace `GET /file?path=foo.txt` with `GET /file/:id` where `:id` is a database ID and the server looks up the corresponding path. The user picks an ID; the server picks the path. The attacker can pick any ID but cannot pick a path.

## Related

- [SSRF and open redirects](/learn/patterns/ssrf-open-redirect) is the same pattern for network destinations rather than filesystem destinations.
- [Auth weaknesses](/learn/patterns/auth-weakness) covers `eval` and `dangerouslySetInnerHTML`, which often co-locate with path-traversal sloppiness.

## Sources

OWASP A01:2021 covers the broken-access-control class. OWASP's path-traversal article is the canonical explainer. CWE-22 names the class. The Node.js path module docs are the authoritative reference for the normalization primitives the fix relies on.

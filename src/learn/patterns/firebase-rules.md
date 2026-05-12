---
title: Firebase Security Rules misconfigurations
slug: firebase-rules
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Firebase Rules
sources:
  - title: Firebase Docs — Security Rules
    url: https://firebase.google.com/docs/rules
  - title: Firebase Docs — Cloud Firestore Security Rules
    url: https://firebase.google.com/docs/firestore/security/get-started
  - title: CWE-285 — Improper Authorization
    url: https://cwe.mitre.org/data/definitions/285.html
  - title: OWASP A01 — Broken Access Control
    url: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
summary: Firebase rules files containing `allow read: if true` or storage rules that permit any authenticated user. The two shapes that turn a Firebase backend into a public read.
---

## What this is

Firebase Realtime Database, Firestore, and Cloud Storage all gate client access through a rules file. The rules file is the entire authorization layer. There is no per-route auth in front of it; the client SDK talks directly to the database, and the rules file decides what comes back.

The two failure shapes:

```js
// firestore.rules
match /users/{userId} {
  allow read: if true;        // public read on every user document
  allow write: if request.auth != null;  // any logged-in user can write any user
}
```

```js
// storage.rules
match /b/{bucket}/o {
  match /{allPaths=**} {
    allow read, write: if request.auth != null;  // any logged-in user can touch any file
  }
}
```

`if true` reads as "no condition, always allow." `if request.auth != null` reads as "any authenticated session is fine," which makes signup the only step between an attacker and your data.

## Why it matters

The Firebase client SDK ships with the project's API key, which is intentionally public. Access control depends entirely on the rules file. A permissive rule turns the database into a REST API that anyone with a browser can query. The blast radius is every row matched by the rule's path glob.

A `match /users/{userId}` rule with `allow read: if true` exposes every user document. That typically includes email, profile data, and any sensitive fields the app stores there. A storage rule with `allow read: if request.auth != null` plus a free signup flow turns the storage bucket into a public file share for the world.

## What the failure looks like

Pre-Flight scans `firestore.rules`, `database.rules.json`, and `storage.rules` files for:

- `allow read: if true` (or `if true` on any operation).
- `allow read, write: if request.auth != null` on storage rules without further conditions.
- Default-deny absent: rules files that omit a top-level deny block on paths that should be private.

## What the fix looks like

Tie every rule to the principal:

```js
match /users/{userId} {
  allow read, write: if request.auth.uid == userId;
}

match /posts/{postId} {
  allow read: if resource.data.public == true || request.auth.uid == resource.data.authorId;
  allow create: if request.auth.uid != null && request.resource.data.authorId == request.auth.uid;
  allow update, delete: if request.auth.uid == resource.data.authorId;
}
```

For storage, scope by path and require ownership:

```js
match /b/{bucket}/o {
  match /users/{userId}/{filename} {
    allow read, write: if request.auth.uid == userId;
  }
}
```

The pattern: every rule references `request.auth.uid` and compares it to a property of the resource. Absence of that comparison is the bug.

## Related

- [Supabase RLS](/learn/patterns/supabase-rls) covers the equivalent class on Supabase / Postgres. The mechanisms differ; the access-control discipline is identical.
- [Admin route exposure](/learn/patterns/admin-route-exposure) covers the matching pattern on application routes.

## Sources

The Firebase security-rules docs are the authoritative reference. CWE-285 names the underlying vulnerability class. OWASP A01:2021 ranks broken access control as the highest-prevalence application risk; Firebase rules misconfigurations are one of its most reproducible expressions.

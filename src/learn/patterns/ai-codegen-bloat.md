---
title: AI codegen bloat
slug: ai-codegen-bloat
type: pattern
last_updated: 2026-07-25
draft: false
related_probe_ids:
  - AI Codegen Bloat
sources:
  - title: 'CWE-1121 — Excessive McCabe Cyclomatic Complexity'
    url: https://cwe.mitre.org/data/definitions/1121.html
  - title: 'CWE-1164 — Irrelevant Code'
    url: https://cwe.mitre.org/data/definitions/1164.html
  - title: 'MDN — JavaScript modules'
    url: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Modules
  - title: 'ESLint — configuring rules and disable comments'
    url: https://eslint.org/docs/latest/use/configure/rules
summary: The maintainability tells of code that was generated and shipped without a read-through. Backup files left beside the real one, commented-out attempts, assistant narration in comments, pass-through wrappers, dead imports, oversized functions. None of these are exploits. They mark the places nobody read, which is where the real defects tend to sit.
---

## What this is

Generated code arrives finished-looking. It has comments, it has structure, it runs. What it has not had is a reader.

This probe looks for the residue that read-through would have removed. A file named `Dashboard.backup.tsx` next to `Dashboard.tsx`. Forty lines of a previous attempt commented out instead of deleted. A comment that says "Here's a robust implementation" because it was written to a person in a chat window, not to the next developer. A function that takes three arguments and passes all three, unchanged, to another function.

None of these will show up in a penetration test. They are not vulnerabilities and this probe never rates them above medium. They matter because of where they cluster.

## Why it matters

The argument is correlational and it is the whole reason this family exists.

Every item here marks a span of code that was accepted without being read. That is the same condition that produces the defects that do get exploited: the missing ownership check, the unvalidated parameter, the auth branch that was never followed to its end. The bloat is easy to detect and the missing check is hard, so the bloat is a cheap way to find the neighbourhood.

Two of these carry direct risk on their own:

**Backup and variant files.** `page-v2.tsx`, `api.old.js`, `Component.backup.tsx`. They still bundle, they can still be imported by mistake, and they hold the previous version of whatever logic was changed. When the change was "add the permission check", the old file is a copy without it. Delete them; git already remembers.

**Dead imports.** An unused binding still resolves the module, and importing a module runs it. A dependency that a file does not use is a dependency that can still execute on load.

The rest are maintainability. That is not a lesser category. Code nobody can follow is code where the next bug hides.

## What PreFlight looks for

- **Backup or variant files** in the source tree, matched by name: `.backup.`, `.old.`, `.orig.`, `-copy`, `-v2`, `_final`.
- **Commented-out code**, ten or more consecutive comment lines that parse as code rather than prose.
- **Assistant narration** left in comments. Phrases addressed to whoever ran the prompt: "Here's a complete implementation", "I've updated the function", "feel free to adjust", "let me know if".
- **Functions over 100 lines**, and functions whose cyclomatic complexity passes 10. Complexity 12 means twelve independent paths a test suite would have to cover to actually exercise the function.
- **Pass-through wrappers**, a named function whose entire body forwards its parameters unchanged to another call.
- **Dead imports**, a binding with no reference anywhere in the file, and files carrying more than 20 imported bindings.
- **Repeated string literals**, the same value appearing three or more times, skipping paths, URLs and sentence-shaped display copy.
- **`eslint-disable` with no stated reason** on the same line or the line above.
- **`TODO` and `FIXME` with no ticket reference**, no `PROJ-123`, no `#456`, no tracker link.

Two things this probe deliberately does not flag. Generic variable names like `data`, `result` and `item` are idiomatic in real code and there is no signal that separates laziness from a documented callback parameter. And file length and stray `console` calls belong to the Code Quality probe, which already reports them.

## What the fix looks like

Read the file. That is the actual fix, and everything below is what reading it produces.

Delete the variant files and the commented-out blocks. Both are recoverable from history and neither is trustworthy where it sits.

Rewrite narration comments to say why, not what. `// Here's the updated handler` teaches nothing. `// Retries twice because the upstream returns 502 on cold start` is worth keeping.

Split the long functions at the seams the generator already marked. Oversized generated functions usually carry comment headers inside them (`// validate input`, `// build the query`, `// send it`). Those headers are the extraction boundaries, and the extracted function names replace the comments.

Give the disables and the TODOs their reason:

```js
// eslint-disable-next-line no-restricted-syntax -- vendor types are wrong, see PROJ-482
```

Name the repeated literals once:

```js
const SESSION_COOKIE = 'app_session_v2';
```

Delete the pass-through wrappers unless the indirection is load-bearing. If it is a deliberate seam for testing or a planned API boundary, one comment saying so keeps it.

## What good looks like

A file where every import is used, every function fits on a screen, every disabled rule says why, and nothing is commented out. Not because those are style points, but because that file has been read end to end by someone who could have caught the missing ownership check. That is the property worth having. The tidiness is the evidence.

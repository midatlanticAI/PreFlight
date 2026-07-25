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
- **Dead imports**, a binding with no reference anywhere in the file. A binding used only as a JSX component counts as used, and so does `React` in any file containing JSX.
- **Repeated string literals**, the same value of eight characters or more appearing three or more times in executable positions. Values inside a data structure are skipped: a lookup table or a transition map repeats its own vocabulary by design. So are paths, URLs, JSX attribute values and sentence-shaped display copy.
- **`eslint-disable` with no stated reason** on the same line or the line above.
- **`TODO` and `FIXME` with no ticket reference**, no `PROJ-123`, no `#456`, no tracker link.

## Scope and the things it deliberately ignores

**Language.** The checks that need real code structure (function length, complexity, wrappers, dead imports, repeated literals) run on `.js`, `.jsx`, `.mjs` and `.cjs`. TypeScript files get the text-level checks only. The parser has no TypeScript grammar, and guessing at it produces confident nonsense: `import type { User } from './user'` reads as a plain default import named `type`, which would report an unused import on essentially every TypeScript file ever written. Structural checks wait for a parser that can actually read the language.

**Generated and minified files** are skipped entirely, on `@generated` and `do not edit` banners and on `.min.` names. Every check here asks whether a person read this code, which is the wrong question for codegen output.

**Test files and fixtures** are skipped, as they are across PreFlight. A fixture is supposed to contain the shapes being tested.

Some things are deliberately never flagged:

- **Generic variable names** like `data`, `result` and `item`. They are idiomatic in real code and no signal separates laziness from a documented callback parameter.
- **File length and stray `console` calls.** The Code Quality probe already reports both; two findings on one line is noise, not thoroughness.
- **Import counts.** A composition root legitimately imports twenty things and uses every one. Counting bindings measures a file's job, not its health. Dead imports are the version of that signal that survives contact with real code.
- **Switch arms, when scoring complexity.** Textbook complexity adds one per `case`, which scores a flat eighteen-case dispatch as unreadable. That shape is the opposite of unreadable, and it is what the advice above tells you to move toward.
- **Anything already explained.** A ticket reference or a stated reason inside a commented-out block, next to an `eslint-disable`, or in a `TODO` suppresses the finding. Documented intent is the fix, so finding the documentation means the fix is already in place.

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

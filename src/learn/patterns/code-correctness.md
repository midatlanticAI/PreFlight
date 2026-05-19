---
title: Undeclared identifiers (AST code correctness)
slug: code-correctness
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Code Correctness
sources:
  - title: 'ECMAScript Language Specification'
    url: https://tc39.es/ecma262/
  - title: 'ESLint — no-undef rule'
    url: https://eslint.org/docs/latest/rules/no-undef
  - title: 'CWE-1116 — Inaccurate Comments'
    url: https://cwe.mitre.org/data/definitions/1116.html
summary: An identifier referenced in code that is never declared, imported, or destructured anywhere in the file. The class of bug that shipped when a refactor left a dangling reference and the test suite did not exercise the affected code path.
---

## What this is

JavaScript identifiers come from one of three places:

- A binding declared in the file (`const`, `let`, `var`, `function`, `class`, function parameter, destructuring pattern, catch clause, etc.).
- An import (`import { foo } from './lib.js'`).
- A built-in or runtime-provided global (`console`, `window`, `process`, `React`, `describe`, etc.).

An identifier referenced anywhere else is undeclared. At runtime it produces a `ReferenceError`. At test time it produces a failing test if the code path is exercised. In a vibe-built app, the affected code path often is not exercised by the tests, so the bug ships.

```ts
// before refactor: useUrlHighlight was a hook in this file
export function NavLink({ href, children }) {
  const isActive = useUrlHighlight(href);
  return <a href={href} className={isActive ? 'active' : ''}>{children}</a>;
}

// after refactor: useUrlHighlight was moved to a separate file
// the import was deleted; the reference wasn't
export function NavLink({ href, children }) {
  const isActive = urlHighlight(href);  // urlHighlight is now undeclared
  return <a href={href} className={isActive ? 'active' : ''}>{children}</a>;
}
```

The component renders. The render path that touches `urlHighlight` throws. Whoever hits the route gets a crashed component.

## Why it matters

This class of bug is silent under normal testing. The test suite may not exercise every render path. ESLint catches it, but vibe coders frequently do not run ESLint. Type checkers catch it, but the same vibe coders often skip them. The bug ships to production and waits for a user.

PreFlight's Code Correctness probe is an AST-based scope check that catches the bug at scan time, before the test suite or the user. The probe is not a substitute for ESLint or `tsc`; it is the same check moved upstream into the pre-commit / pre-merge audit.

## What the failure looks like

PreFlight parses every `.js` / `.jsx` / `.mjs` / `.cjs` file with acorn + acorn-jsx and:

1. Collects every binding the file declares: imports, var/let/const, function/class declarations, params, destructuring patterns, catch clauses, re-exports.
2. Walks every identifier reference.
3. Flags any reference that is not in the bindings set and not in a curated globals allowlist (built-ins, browser globals, Node globals, test runner globals, React for JSX).

TypeScript files (`.ts`, `.tsx`) are skipped in v1; the acorn parser does not handle TS type syntax. A separate TS-aware probe is on the v0.5 roadmap.

JSX is handled: lowercase tags (`<div>`) are intrinsic HTML elements; uppercase tags (`<Foo>`) are component references and get the same scope check as any other identifier.

## What the fix looks like

For each flagged identifier, one of:

- **Add the missing import.** The identifier exists in another module; this file forgot to import it.
- **Add the missing declaration.** The identifier was supposed to be declared in this file (typo, half-renamed variable, missed paste).
- **Rename the typo.** `concole.log` should be `console.log`; the probe flags `concole` as undeclared.
- **Remove the dead reference.** The refactor left a vestige; delete the line.

In each case, the fix is local and obvious. The hard part is finding the references, which is what the probe handles.

## Worked example

PreFlight scanning PreFlight itself caught two undeclared references in `scripts/generate-og.mjs`:

```js
const __dirname = dirname(fileURLToPath(import.meta.url));
```

The probe flagged `import` and `meta` as undeclared. They aren't undeclared; they are part of the `import.meta` MetaProperty AST node, a language-level construct distinct from regular identifier references. The fix was in the probe (add a MetaProperty case to the AST walker), not in the script. The dogfood scan that produced the finding led to the probe upgrade; the test suite now includes a regression case so future probe changes can't lose the handling.

This is the loop the probe is built for: real code, real findings, real fixes.

## Related

- [AI code smells](/learn/patterns/ai-code-smells) covers patterns that co-locate with this class.
- [Code quality](/learn/patterns/code-quality) covers the broader code-quality signals that flag the same code paths from different angles.

## Sources

The ECMAScript spec covers identifier resolution rules. ESLint's `no-undef` rule is the closest analog at the linter level. CWE-1116 covers the broader class of "code that does not do what its author thought."

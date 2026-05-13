---
title: Source maps shipped to production
slug: source-map-exposure
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Source Map Exposure
sources:
  - title: 'OWASP A05 — Security Misconfiguration'
    url: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
  - title: 'CWE-540 — Inclusion of Sensitive Information in Source Code'
    url: https://cwe.mitre.org/data/definitions/540.html
  - title: 'Vite — Build options (sourcemap)'
    url: https://vitejs.dev/config/build-options.html#build-sourcemap
  - title: 'Next.js — productionBrowserSourceMaps'
    url: https://nextjs.org/docs/app/api-reference/next-config-js/productionBrowserSourceMaps
summary: A `.map` file deployed alongside a production bundle hands an attacker the original source: variable names, comments, dev-only branches, internal API paths. Use hidden source maps (uploaded to your error monitor) instead.
---

## What this is

Modern bundlers (Vite, webpack, Next.js, Rollup) can emit `.map` files alongside the minified bundle. A `.map` file contains the original source code (or enough information to reconstruct it). When the browser hits an error in production, it can resolve the minified stack trace back to the original line.

Useful for the developer. Useful for the attacker.

```js
// dist/index-abc123.js (minified, public)
function n(e) {
  return 'sk_live_' === e.slice(0, 8);
}

//# sourceMappingURL=index-abc123.js.map
```

```js
// dist/index-abc123.js.map (public next to the bundle)
{
  "sources": ["src/payments/stripe.js"],
  "sourcesContent": [
    "// Internal Stripe utilities\nfunction isLiveStripeKey(key) {\n  return key.slice(0, 8) === 'sk_live_';\n}\n..."
  ]
}
```

A request to `https://app.example.com/dist/index-abc123.js.map` returns the original source with comments, internal API paths, and any dev-mode branches. None of this was intended to be public.

## Why it matters

Three concrete consequences:

**Code-level reconnaissance.** Variable names, function names, comments, and class hierarchies all leak. The attacker reads your code like it's an open-source repo.

**Internal paths and feature flags.** Source maps often disclose paths like `src/admin/internal-debug.js`, comments like `// TODO: rotate this before launch`, and feature-flag names that hint at routes not yet released.

**Embedded constants.** A `sourcesContent` block sometimes contains constants that the minifier inlined: hardcoded staging credentials, internal hostnames, license keys, and the like. Even if the production bundle has the constants substituted, the source map carries the literal values.

The pattern is mostly about reducing recon, not preventing exploitation. Source maps don't introduce vulnerabilities; they accelerate every other attack by giving the attacker the developer's view of the codebase.

## What the failure looks like

Pre-Flight scans for:

- **Vite config** with `build.sourcemap: true` (or `'inline'` / `'hidden'` followed by no upload step).
- **Next.js config** with `productionBrowserSourceMaps: true`.
- **Webpack config** with `devtool: 'source-map'` (or similar public modes) under `mode: 'production'`.
- **Any JS/CSS file** containing a `//# sourceMappingURL=` comment pointing at a relative `.map` path.

Test files and the scanner's own dist are excluded.

## What the fix looks like

**Vite:**

```js
// vite.config.js
export default {
  build: {
    sourcemap: false,
    // OR for error-monitoring integrations:
    // sourcemap: 'hidden',  // emits maps, omits the URL comment from the bundle
  },
};
```

**Next.js:**

```js
// next.config.js
export default {
  productionBrowserSourceMaps: false, // default, but make it explicit
};
```

**Webpack:**

```js
// webpack.config.js
export default {
  mode: 'production',
  devtool: 'hidden-source-map', // or false to skip emitting entirely
};
```

**Pattern for error monitoring:** if Sentry / Datadog / similar needs source maps to symbolicate production stack traces, use the build mode that emits maps without the URL comment, then upload them to the error monitor at deploy time. The maps live with the monitoring vendor; the public origin never serves them.

```bash
# Sentry CLI example
sentry-cli sourcemaps upload --org=... --project=... ./dist
# After upload, delete the .map files from the deployed dist
find ./dist -name '*.map' -delete
```

**Audit existing builds:**

```bash
# Are .map files in your deployed dist?
find ./dist -name '*.map'

# Does any JS in dist reference a sourcemap URL?
grep -RE '//# sourceMappingURL=' ./dist
```

A non-empty result is the finding. The fix is to disable the build option and rebuild.

## Related

- [Security headers](/learn/patterns/security-headers) covers the broader production-build hardening surface.
- [Stack trace leaks](/learn/patterns/stack-trace-leaks) covers the runtime side of the same information-disclosure category.

## Sources

OWASP A05:2021 covers security misconfiguration. CWE-540 names the underlying class. Vite, Next.js, and webpack docs cover the per-bundler configuration.

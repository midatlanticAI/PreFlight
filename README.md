# Pre-Flight Audit Tool

Free, in-browser static security audit for apps built with AI coding tools (Lovable, Cursor, Bolt, Replit, Claude Code) and any other web application.

**Live:** [preflight.midatlantic.ai](https://preflight.midatlantic.ai/) _(when deployed)_

## What it does

33 probes covering:

- **OWASP Top 10 2025** — secrets, broken auth, SSRF, open redirects, CORS, missing security headers.
- **OWASP LLM Top 10 2025** — prompt injection, system-prompt leakage, excessive agency, unbounded consumption.
- **2025–2026 supply-chain incidents** — Shai-Hulud, Axios / Sapphire Sleet, Mini Shai-Hulud SAP, Bitwarden CLI compromise, and the May 11, 2026 Mini Shai-Hulud TanStack worm by TeamPCP (~170 hard-coded compromised versions).
- **Post-infection IOC detection** — `.claude/router_runtime.js`, `__DAEMONIZED` guards, Session-messenger exfil endpoints, `gh-token-monitor` dead-man-switch, spoofed Claude commit author.
- **MCP security** — shell-spawning servers, public binds, vulnerable mcp-server-git versions.
- **AI-tooling rules-file backdoors** — Cursor / Copilot / Windsurf hidden-Unicode injection.
- **Slopsquatting** — LLM-hallucinated package names.
- **AST code-correctness** — acorn-powered undeclared-identifier check. Catches the class of bug that ships when a refactor leaves a dangling reference (`return urlHighlight;` with no `urlHighlight` declared anywhere).
- **SEO + GEO + WCAG 2.2 a11y** — meta tags, JSON-LD schema drift, AI-bot allowlist, target size, focus indicators.
- **Architecture classification** — detects monolithic-SPA / static-HTML / SSR / SSG / monorepo / CLI / mobile / desktop / notebook with teaching content per type.
- **Code quality** — console.log in production, file size, unhandled promises, async without try.

All scanning runs in your browser. No upload, no signup, no data collection.

## Local dev

```bash
npm ci
npm run dev      # vite dev server on :5173
npm test         # vitest (411 tests across 19 files)
npm run build    # production build → dist/
```

## CI

GitHub Actions workflow at `.github/workflows/ci.yml`:

1. `npm ci`
2. `npm test`
3. `npm run build`
4. `npx vitest run src/test/self-audit.test.js` — the tool audits its own built dist/

If we don't pass our own audit, CI fails. Dogfooding.

## Project layout

```
src/
├── App.jsx                 ← orchestrator (~920 lines): state, scan flow, routing shell
├── ErrorBoundary.jsx       ← React class boundary with diagnostics export
├── main.jsx                ← entry point
├── components/
│   ├── HomeView.jsx        ← landing route
│   ├── AuditView.jsx       ← scan UI + results dashboard
│   ├── learn/              ← Learn route (patterns / incidents / shapes)
│   └── ...                 ← shared UI (FindingCard, IncidentMetaHeader, etc.)
├── lib/
│   ├── probes.js           ← 33-probe registry + threat-intel constants (~1,480 lines)
│   ├── probes/
│   │   └── code-correctness.js  ← AST-based undeclared-identifier probe (acorn + acorn-jsx)
│   ├── stable-id.js        ← cross-scan finding IDs + PROBE_META (confidence / autofix / learn slug)
│   ├── learn-content.js    ← markdown loader + frontmatter parser for Learn pages
│   ├── logger.js           ← structured logger with HMR-safe window listeners
│   └── analytics.js        ← privacy-preserving counter analytics (counts only, no PII)
├── learn/
│   ├── patterns/*.md       ← published pattern explainers
│   ├── incidents/*.md      ← field reports (CVE / CVSS / campaign / actor / date)
│   └── shapes/*.md         ← architectural-shape explainers
└── test/                   ← 411 tests across 19 files (vitest + jsdom)

public/
├── maai-logo.svg
├── robots.txt              ← explicit allow for GPTBot, ClaudeBot, PerplexityBot, etc.
├── sitemap.xml
└── llms.txt                ← per llmstxt.org — AI-search index of the site
```

## License

Code is **MIT licensed**. The threat-intel data manifest is **CC-BY-4.0** — use freely
with attribution to Mid-Atlantic AI / Pre-Flight. The split is intentional:

- **Code** (everything under `src/`, `public/`, `.github/`, config files, package.json)
  → MIT, see [`LICENSE`](./LICENSE). Use, fork, ship — no attribution required for
  the source code itself.
- **Threat-intel data** (`src/data/compromised-packages.js` and any future
  `src/data/*-data.{js,json}` manifests) → CC-BY-4.0, see [`LICENSE-DATA`](./LICENSE-DATA).
  Take the data, integrate it into your own scanner, but credit the source as
  "Mid-Atlantic AI / Pre-Flight Audit Tool" with a link to
  https://preflight.midatlantic.ai/ or https://github.com/midatlanticAI/PreFlight.

Publisher: Mid-Atlantic AI · [John@midatlantic.ai](mailto:John@midatlantic.ai).

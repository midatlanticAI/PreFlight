# Pre-Flight Audit Tool

Free, in-browser static security audit for apps built with AI coding tools (Lovable, Cursor, Bolt, Replit, Claude Code) and any other web application.

**Live:** [preflight.midatlantic.ai](https://preflight.midatlantic.ai/) _(when deployed)_

## What it does

29 probes covering:

- **OWASP Top 10 2025** — secrets, broken auth, SSRF, open redirects, CORS, missing security headers.
- **OWASP LLM Top 10 2025** — prompt injection, system-prompt leakage, excessive agency, unbounded consumption.
- **2025–2026 supply-chain incidents** — Shai-Hulud, Axios / Sapphire Sleet, Mini Shai-Hulud, Bitwarden CLI compromise, by exact version.
- **MCP security** — shell-spawning servers, public binds, vulnerable mcp-server-git versions.
- **AI-tooling rules-file backdoors** — Cursor / Copilot / Windsurf hidden-Unicode injection.
- **Slopsquatting** — LLM-hallucinated package names.
- **SEO + GEO + WCAG 2.2 a11y** — meta tags, JSON-LD schema drift, AI-bot allowlist, target size, focus indicators.
- **Architecture classification** — detects monolithic-SPA / static-HTML / SSR / SSG / monorepo / CLI / mobile / desktop / notebook with teaching content per type.
- **Code quality** — console.log in production, file size, unhandled promises, async without try.

All scanning runs in your browser. No upload, no signup, no data collection.

## Local dev

```bash
npm ci
npm run dev      # vite dev server on :5173
npm test         # vitest (211 unit tests + 6 self-audit tests)
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
├── App.jsx              ← main React component + helpers
├── ErrorBoundary.jsx    ← React class boundary with diagnostics export
├── main.jsx             ← entry point
├── lib/
│   ├── probes.js        ← all 29 probes + threat-intel constants + PROBES registry
│   ├── logger.js        ← structured logger with HMR-safe window listeners
│   └── analytics.js     ← privacy-preserving counter analytics (counts only, no PII)
└── test/
    ├── probes.test.js   ← 117 unit tests for probes
    ├── formatters.test.js  ← 16 tests for JSON / Markdown / agent-prompt / PR-comment exporters
    ├── history.test.js  ← 10 tests for localStorage history + diff
    ├── snippet.test.js  ← 10 tests for ±5-line code snapshot builder
    ├── scoring.test.js  ← 32 tests for severity weighting + risk tier
    ├── logger.test.js   ← 10 tests including circular-context regression
    ├── analytics.test.js  ← 10 tests for counter analytics privacy invariants
    └── self-audit.test.js  ← dogfooding: scan our own dist/

public/
├── maai-logo.svg
├── robots.txt           ← explicit allow for GPTBot, ClaudeBot, PerplexityBot, etc.
├── sitemap.xml
└── llms.txt             ← per llmstxt.org — AI-search index of the site
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

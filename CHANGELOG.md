# Changelog

All notable changes to PreFlight are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [SemVer](https://semver.org/).

The deployed site at [preflight.midatlantic.ai](https://preflight.midatlantic.ai) tracks the `main` branch — every merged commit ships through Cloudflare Pages auto-deploy within minutes.

## [Unreleased]

### Added

- Reusable `ScrollableTabs` component (`src/components/ScrollableTabs.jsx`) — horizontal-scroll tab strip with hidden scrollbar, edge-fade gradients that appear/disappear based on actual scroll position, and active-tab auto-scroll-to-centre on route change.
- `useScrollFades` hook so the Settings sidebar (column on desktop, row on mobile) can share scroll-fade logic without duplicating refs/effects.
- `CHANGELOG.md` (this file). The Settings → General tab already linked to it; the link is no longer a 404.

### Changed

- **Mobile tab navigation** — the Learn 7-tab strip and the Settings sidebar were squishing labels together on phones. Replaced flex-wrap stopgap (looked like a button grid, not nav) with single-row horizontal scrolling + edge fades. WCAG 2.5.5 AAA touch targets preserved.
- **Probe count is now dynamic everywhere reachable from React**. `AuditView`, `HomeView`, and `OwaspCoverageView` import `PROBES` from `src/lib/probes.js` and render `${PROBES.length}` instead of hardcoded strings, so this kind of drift can't recur on those surfaces.
- **Counts synchronized across all copy surfaces** to reflect actual code state (96 probes after the v0.5 phase-3 multi-language adapter merge; 921 tests across 52 files; 54 patterns / 4 field reports / 15 shapes all published). Affected files:
  - `CLAUDE.md` Counts block
  - `README.md` overview, Learn section, test-coverage section, project layout
  - `index.html` meta description + JSON-LD SoftwareApplication / FAQPage entries
  - `public/llms.txt` overview + probe inventory + architecture paragraph
  - `public/og-card.svg` "43 PROBES" pill → "96 PROBES" (PNG regeneration deferred — `sharp` native binary unavailable on Termux; CI machine can rerun `npm run og`)
  - `src/components/AuditView.jsx` hero meta line + `Updated` date
  - `src/components/HomeView.jsx` probe legend + FAQ answer + footnote date
  - `src/components/learn/OwaspCoverageView.jsx` coverage summary
  - `src/components/settings/GeneralTab.jsx` `BUILD_DATE`
  - `src/lib/personas/sam.js` and `src/lib/personas/demi.js` activation context
- **`llms.txt` voice cleanup** — removed citations to competing security platforms (Socket, Wiz, OX Security, Unit 42) per the project's voice rule against naming competing AppSec vendors in public copy. Replaced with MITRE/CWE, Microsoft Threat Intelligence, and a pointer to vendor-official advisories cited per-incident in the corresponding Field Report.
- **`index.html` JSON-LD** — `softwareVersion` bumped `0.3` → `0.5` to match visible UI; `dateModified` bumped to `2026-05-16`; both FAQ entries and the SoftwareApplication description re-synced with the visible HomeView FAQ (Google 2026 anti-schema-drift rule).
- **`README.md` Learn section** — replaced obsolete "Currently published: X. Drafts in flight: Y, Z" lists with the current state (everything published, no drafts).

### Fixed

- `index.html` JSON-LD `featureList[1]` said "26 security probes" — a count two waves stale. Now reflects the live registry.
- `CHANGELOG.md` link in Settings → General is no longer broken.
- **TanStack Mini Shai-Hulud field report sources rewritten.** The published incident report cited eight competing security-vendor blogs as `sources:` in violation of the project's sourcing convention. Replaced with whitelist-clean primary sources: TanStack's own postmortem, the TanStack hardening follow-up, TanStack/router issue #7383, GHSA-g7cv-rxg3-hmpx, The Hacker News, Microsoft Threat Intelligence, OpenAI's incident response, and Infosecurity Magazine. Body line restating the package-count figure no longer names a vendor. Same facts, primary sourcing. `src/learn/incidents/mini-shai-hulud-tanstack-2026-05.md`.
- **Stale-chunk recovery for in-app navigation across deploys.** Users keeping a tab open across a Cloudflare Pages redeploy got a "Failed to fetch dynamically imported module" trap when navigating to a lazy route — the old `index.html` referenced chunk hashes that had rotated. `lazyNamed` in `App.jsx` now performs a one-shot `sessionStorage`-guarded reload on the first chunk fetch failure, transparently pulling the fresh `index.html` + new chunk URLs. A second failure after reload surfaces to `ErrorBoundary` as before, so genuinely missing chunks still show the diagnostic screen instead of looping.
- **GitHub license detection.** `LICENSE` was rejected by GitHub's `licensee` classifier because of an appended dual-license note. `LICENSE` is now the canonical MIT text only. The dual-license split is now stated authoritatively in `README.md` §License and cross-referenced from `LICENSE-DATA`. No information loss.
- **Empty crawlable entry point.** `dist/index.html` rendered an empty `#root` because the prerender pipeline deliberately skipped `/` (the live `AuditView` reads browser globals and cannot be SSR'd). Crawlers, LLMs, and no-JavaScript visitors saw only `<title>`, `<meta description>`, and a noscript notice. The SEO and GEO probes did not catch it — they validate head and metadata hygiene, not body presence. New `HomeOverview` component is rendered server-side for `/` only via `src/entry-server.jsx`; client mounts `AuditView` over it (same prerender-for-bots / CSR-for-users contract used for Learn). All copy reused verbatim from `README.md`, `HowToView`, and the `AuditView` hero. Result: `#root` now ships about 2,300 chars of real prerendered text at the entry point.

### Probes

- **`probeEnvFiles` — preventive `.gitignore` audit added.** Previously fired only on `.env` files that were already committed. Most leaked-secret incidents in vibe-coded repos are committed `.env` because the `.gitignore` rule was never added in the first place; by the time the file appears, the secrets are already compromised. New low-severity finding fires when `.gitignore` exists in the corpus but has no `.env` / `.env.*` / `*.local` / `*.env` pattern, regardless of whether a `.env` is currently committed. Excludes projects with no `.gitignore` in the corpus to avoid cross-firing.
- **`probeMissingHeaders` — framework and host aware, per-header coverage.** Previously checked only `next.config.js headers()` and `vercel.json headers`. Missed every Vite SPA, Astro site, SvelteKit app, Remix app deployed to Cloudflare Pages, Netlify, Firebase, Fly, or Render. Now parses statically-readable host config: Cloudflare Pages / Netlify `_headers`, `netlify.toml [headers.values]` blocks, `vercel.json headers` arrays, `firebase.json hosting.headers`. Replaces the previous binary present/absent finding with up to six precise per-header findings against the canonical MDN security-header set (CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, plus clickjacking via X-Frame-Options OR CSP `frame-ancestors`). False-positive guards: GitHub Pages suppressed (no host header mechanism); Next.js `output: 'export'` flagged as ineffective `headers()` rather than missing; IaC presence (Terraform / CDK / SAM / Serverless) downgrades severity to info; reverse-proxy presence (Caddyfile / nginx / Traefik) same; opaque `next.config.js headers()` without host config suppresses per-header check (legacy compatibility preserved).
- **23 new test cases** covering both probe extensions, including positive, negative, and the FP-suppression cases.

### Self-audit

- **Crawlable entry point now asserted.** New `it('homepage dist/index.html has non-empty prerendered body content')` in `src/test/self-audit.test.js` reads `dist/index.html`, asserts the `#root` container holds more than 200 chars of text and contains the stable brand line. Closes the dogfood blind spot that let the empty homepage ship: the SEO and GEO probes only check head/metadata, so an empty `#root` previously passed the gate.

### Hardening

- **`.gitignore` now ignores `.env*`** with an `!.env.example` carveout so the placeholder template stays committable. A future `.env` an AI agent generates will no longer slip into the repo.
- **`public/_headers` now ships `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.** The five other canonical headers were already in place (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Content-Security-Policy: frame-ancestors 'none'`). PreFlight now passes its own newly-stricter `probeMissingHeaders` cleanly.
- **`CLAUDE.md` sourcing convention added.** New voice rule: prefer victim postmortem, official advisory, vendor docs, news orgs, named research orgs in that order. Security-vendor blogs are interchangeable commodities in an oversaturated market and stay unnamed even when they broke the story. Applies to Learn `incident` / `pattern` citations as well as prose.

### Removed

- **Source comments and remediation strings naming competing security platforms.** `src/lib/probes/builtin.js` Shai-Hulud remediation tail "Public IOC tracking: Aikido, Snyk, Socket, Wiz, StepSecurity (May 2026)" replaced with a pointer to the Mini Shai-Hulud field report in Learn. `src/lib/threat-intel.js` and `LICENSE-DATA` descriptive parentheticals generalized to "CISA, GHSA/CVE, affected-vendor postmortems, independent IOC tracking." No legal terms changed.
- **Four redundant artifacts from `public/`.** `googlelangugeagnostic.docx`, `groklanguageagnostic.docx`, `languageagnostic.md`, `tomdahne.jpg`. The three docs were design-process duplicates of the canonical versions in `docs/`. About 350KB removed from every deploy bundle.
- **Local design-doc scratch under `docs/`** (`.docx` exports and `claudelanguageagnostic.md`) is now in `.gitignore`. Architecture writeups and `v05-research/` stay committed normally.

### Adversarial precision pass

Five-thread campaign tightening probe precision without losing recall. Each probe got a paired recall + precision agent, fresh instance per round, strict no-implementation-reading isolation. Reusable spec at `docs/adversarial-test-agent-prompts.md`. Round counts across the pass: probeSecrets 24→10→7→1 (96% FP reduction), probeCodeCorrectness 35→0, probeAICodeSmells 1→0.

- **`probeCodeCorrectness` — 80+ new platform globals + `/* global */` directive parsing.** Service-worker globals (`caches`, `clients`, `registration`, `skipWaiting`, `importScripts`, `ExtendableEvent`, `FetchEvent`, `ServiceWorkerGlobalScope`), Deno runtime, `Intl`, `WebAssembly`, `customElements`, `ClipboardItem`, `MediaRecorder`, `RTCPeerConnection`, `OffscreenCanvas`, `setImmediate`/`clearImmediate`, build-injected `__APP_VERSION__`, and others added to `GLOBALS`. New `parseGlobalDirectives` honors the ESLint `/* global X, Y */` convention so projects declaring their host environment explicitly get no undeclared-identifier noise.
- **`probeSecrets` — multi-axis FP suppression.** `SECRET_VALUE_PLACEHOLDER_RE` catches hand-written placeholders (`x{4,}`, `REPLACE/YOUR_KEY/PLACEHOLDER/DEMO/EXAMPLE`, `<your-key-here>`). `isMatchInsideComment` skips documentation strings naming the shape rather than committing the value. `isMatchInsideTemplateLiteral` skips code-as-string snippets (PEM blocks exempted). `isPEMBodyPlaceholderOrHeaderOnly` skips framing-only PEM references. `isMatchInPlaceholderNamedAssignment` skips LHS identifiers explicitly marked sample/example/test/fake/dummy/mock/fixture (e.g. `SAMPLE_OPENAI_KEY = 'sk-proj-...'`). Generic identifiers like `API_KEY`/`AWS_SECRET` continue to fire — those are exactly what real leaked code looks like.
- **`probeSEOHygiene` + `probeGEOHygiene` — architecture-aware gating for private installable PWAs.** New `isPrivatePWAContext(files)` detects internal-tool PWAs via Web App Manifest (`manifest.json`/`manifest.webmanifest`) with installable `display` (`standalone`/`fullscreen`/`minimal-ui`) AND service worker presence (filename `sw.js`/`service-worker.js` OR file body containing `self.addEventListener('install', ...)`). When both signals are present, both probes suppress all findings — a field-tech PWA scoped to a single workplace does not need open-graph cards or `llms.txt`. Either signal alone is not enough; many public sites add one or the other independently.
- **`probeAICodeSmells` — severity reduced from `low` to `info`.** Empty catches and `:any` are smells worth surfacing but rarely security-critical. Matcher switched from per-line to whole-content masked scan via `maskCommentsAndStringsFromContent` so `// catch (e) {}` in documentation stops firing.
- **File filter — documentation markdown exempted from secret scanning.** New `isDocumentationMarkdownFile` skips `.md` in `probeSecrets`. Real secret material pasted into markdown is vanishingly rare relative to documentation references to the shape; the FP cost is higher than the FN cost.
- **Threat-intel.** GitHub Fine-Grained PAT (`github_pat_` shape) added. Private Key Block regex accepts the optional ` BLOCK` suffix for PGP. OpenAI shape floor relaxed from `{40,}` to `{20,}` per the secret-scanner pattern page.
- **Tests.** New adversarial suites: `adversarial-probeCodeCorrectness-v1.test.js` (99 recall), `adversarial-probeCodeCorrectness-precision-v1.test.jsx` (109 precision; `.jsx` because of JSX in template-literal fixtures), `adversarial-probeAICodeSmells-precision-v2/v3/v5.test.js`, `adversarial-probeSecrets-v2/v3.test.js`, `adversarial-probeSecrets-precision-v2/v3.test.js`, `adversarial-seo-geo-architecture-gating-v1.test.js` (66 gating tests with ambiguity edges), `adversarial-edges-thread2-thread5.test.js` (27 follow-on edge cases). Final: 2083 tests / 53 todo, full pass, lint clean, dogfood 7/7.

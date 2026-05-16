# Changelog

All notable changes to Pre-Flight are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [SemVer](https://semver.org/).

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

# PreFlight v0.5 Architecture

**Status:** Approved for Phase 0 implementation. All gating questions resolved.
**Date:** 2026-05-14
**Companion to:** `preflight_v05_probe_inventory.md`

This document proposes how to extend the v0.4 probe schema to support the v0.5
fields (`why_ai_v05`, `vibe_v05`, `fp_gates_v05`, `autofix_v05`, `fixtures_v05`,
`xl_ref`, `ioc_bundle_ref`, plus the new `maturity` field) without breaking
the v0.4 schema, and how to structure the XL-001 through XL-012 shared
families as reusable detector modules that language-specific probes compose.

---

## What v0.4 is today

A probe is a pure function `(files) => findings[]` registered in a flat
`PROBES` array in `src/lib/probes.js`. Per-probe metadata (`confidence`,
`autofix`, `learn_more_slug`) lives in a separate `PROBE_META` map in
`stable-id.js`. OWASP mapping lives in a parallel `PROBE_OWASP_MAP`.
Findings emit as flat objects: `{id, probe, title, severity, category, cwe,
file, line, evidence, remediation}`. There is no language axis — most probes
implicitly target JS/TS with sprinkles of Python and Go inside the regexes.
Probe names are descriptive strings ("SQL Injection", "Auth Weakness"), not
stable IDs.

## What the v0.5 schema actually demands

The new schema fields look like more columns, but they imply a structural
shift. Today's probes carry detection logic AND emit findings AND own their
metadata in one closure. The v0.5 schema separates three things that v0.4
conflates:

1. **The pattern definition** (the XL family): why_ai, vibe, fp_gates,
   autofix tier, OWASP mapping, severity floor, fixture contract.
   Language-agnostic. 12 of them.
2. **The language adapter:** detection_approach, scope glob, language-specific
   fp_gates, fixture paths. Language-specific. Up to 168 of them (14 langs ×
   12 families) at the limit, realistically <40 in v0.5.
3. **The finding:** per-emission file/line/evidence. Already at the right level.

Plus the personas (Sam / Demi / Drew / Vera) need to read fields off probes
by predictable keys, which only works if the metadata is queryable by
`probe_id` rather than human-readable name.

---

## Three architectural decisions (settled)

### Decision 1: Side-by-side schema, not replace

Keep v0.4 `PROBES` + `PROBE_META` exactly as they are during the transition.
Add a parallel `PROBE_MANIFEST_V05` keyed by `probe_id`. Findings keep the
same shape they have today, with optional new fields attached by
`attachProbeMeta()`. Tests keep passing. Personas query the v0.5 manifest by
`probe_id` when present, fall back to v0.4 `PROBE_META` by probe name when not.

Cost: two registries to keep coherent during migration. Gain: zero
regression risk, no big-bang cutover.

### Decision 2: Composition, not inheritance

XL family records are **pure metadata**: classification + canonical text +
fp_gate intent. They own no execution logic and no defaults. Adapters
explicitly reference the family via `xl_family` and independently declare
their own per-language detection, per-language fp_gates, and per-language
text fields.

The discipline matters: if execution logic lives on the family, the family
becomes a base class, and detection logic acquires a hierarchy. Hierarchies
in detection logic are how Semgrep rule maintenance becomes painful at
scale. Don't go there.

Shared helpers (test-fixture-path detection, `.example`-file detection,
allowlist-comment detection) live in a third tier — `shared-detectors/` —
that adapters import explicitly. The family record stays pure metadata.

### Decision 3: AI-authored adapters, no deterministic generator

Adapters are authored per-file with judgment: read the research spec,
choose the detection approach, write the language-specific false-positive
gates, hand-craft the positive/negative fixtures, write the Learn page.

There is no separate deterministic codegen tool (no `scripts/gen-adapter`,
no template-substitution generator) and none is planned. The "168 files is
too many to hand-write" problem that a template generator would solve does
not exist when the authoring is judgment-driven: a dumb template generator
produces worse adapters than judgment authoring (it cannot reason about a
language's false-positive quirks), and the "smart" part a good generator
would need is exactly what judgment authoring already provides. Writing a
generator to do, worse, what is already being done well is pure redundancy.

The only mechanical helper that may exist is a _scaffold_ (create the
`fixtures/<PROBE_ID>/` directory + empty stub files so the build-time
fixture/Learn contract is never tripped by a forgotten folder). That is a
chore-saver, not codegen — it generates no detection logic. Optional,
unbuilt unless explicitly requested.

---

## Probe ID format (two fields, not one)

Two separate fields, with distinct purposes:

- **`probe_id`** — human-facing. Format `LANG-CATEGORY-NNN`. Example:
  `PY-DESERIALIZE-001`, `JV-MASS-ASSIGN-001`, `RB-SQL-RAW-002`. Self-
  documenting. Stable across XL-family restructures. Used in suppression
  comments (`// preflight: ignore PY-DESERIALIZE-001`) — that comment has
  to make sense five years from now even if the XL taxonomy gets renumbered.
- **`xl_family`** — machine-facing. Format `XL-NNN`. Opaque but stable
  taxonomy reference. Null when the probe has no XL family (purely
  language-specific). Used by downstream tooling, OWASP coverage page,
  cross-language consistency checks.

Two IDs let the human-readable name evolve independently from the taxonomy
slot. Coupling them (`PY-XL001-001`) means any taxonomy restructure breaks
every suppression comment in user code. That cost is unacceptable.

## Maturity field (new)

Every adapter declares a `maturity` field:

| Value          | Meaning                                                                                                              |
| -------------- | -------------------------------------------------------------------------------------------------------------------- |
| `experimental` | New probe, may produce noise. Persona renders muted; not counted in risk score; opt-in only.                         |
| `beta`         | Production-ready but recently shipped. Persona renders normally; counted in risk score; carries a small "new" badge. |
| `stable`       | Default. Vetted on real repos. Counted in risk score, no badge.                                                      |
| `deprecated`   | On the way out. Persona renders muted with deprecation reason; not counted in risk score by default.                 |

Migrated v0.4 probes default to `stable`. New v0.5 probes declare explicitly
on first commit. The field is consumed by personas to weight finding
presentation and by the scoring layer to exclude experimental noise from
the headline risk number.

---

## Proposed module structure

```
src/lib/probes/
  v05/
    families/                          # XL-001..XL-012 pure metadata records
      xl-001-unsafe-deserialization.js
      xl-002-raw-query-interpolation.js
      ...
      xl-012-prompt-policy-leakage.js
    shared-detectors/                  # cross-cutting detection helpers
      test-fixture-path.js
      example-file-path.js
      allowlist-comment.js
      secret-pattern-bank.js           # the regex+entropy bank used by XL-006 adapters
      ...
    adapters/                          # language-specific detection
      python/
        py-deserialize-001-pickle-load.js     # xl_family: XL-001
        py-sql-raw-001-sqlalchemy-text.js     # xl_family: XL-002
        py-debug-001-django-debug-true.js     # xl_family: null
        ...
      java/
      ruby/
      ...
    manifest.js                        # aggregator: merges family records +
                                       # adapter records into PROBE_MANIFEST_V05
    fixtures/                          # canonical positive/negative per probe_id
      PY-DESERIALIZE-001/
        positive.py
        negative.py
        adversarial.py    (optional)
      ...
  legacy/                              # v0.4 probes verbatim
    secrets.js, architecture.js, web.js, etc.
  index.js                             # exports both registries
```

Two registries co-exist:

- `PROBES` (v0.4) — flat array, unchanged. Drives execution today.
- `PROBE_MANIFEST_V05` — keyed by `probe_id`, built by aggregating family
  records + adapter records at module load. Drives persona output, learn
  pages, OWASP coverage page, fixtures dogfood.

When a v0.4 probe gets migrated, it gains a `PROBE_MANIFEST_V05` entry with
a `probe_id`, `xl_family` (if applicable), and full v0.5 fields. Its
execution still goes through the v0.4 `PROBES` array until parity (see
shadow-mode below). Then the registry-build step generates `PROBES` from
the manifest instead of hand-listing it.

---

## Execution gap #1: stable finding-ID continuity during migration

v0.4 findings have stable IDs (`stableId()` in `stable-id.js`) that users
have suppressed in their code via `.preflight.yml`. The migration must not
break those IDs.

**Mechanism:** every adapter that migrates an existing v0.4 probe declares a
`legacy_finding_id_seed` field in its manifest entry. When the v0.5 adapter
emits a finding for a migrated probe, the stableId algorithm consumes the
seed (instead of the probe name) so the hash is byte-identical to what the
v0.4 probe produced.

Example: when migrating the v0.4 Secret Scanner to a set of XL-006 adapters,
each adapter declares `legacy_finding_id_seed: 'Secret Scanner'` — so the
hash input remains `'Secret Scanner|<file>|<title>|<context>'` even though
the new probe is named `PY-SECRETS-001`. The user's suppression comments
keep working without rewrites.

New probes (no v0.4 ancestor) skip the seed field and the stableId algorithm
uses the new `probe_id` as the hash input.

This is non-negotiable for migration sanity. Users will not accept a release
that silently invalidates their suppression history.

## Execution gap #2: shadow-mode for adapters during Phase 2

During Phase 2 (migrating overlapping probes), both the v0.4 probe and the
v0.5 adapter will detect the same patterns. The deduplication rule:

**During migration, the v0.4 probe is the authoritative producer.** The v0.5
adapter registers with `shadow: true` and emits findings to a separate
internal channel that is not user-visible. The scan layer compares
shadow-channel output against production output and logs deltas to the
diagnostics drawer.

The flip is a one-field config change a human makes when satisfied the
shadow output matches production output (measured by stableId equivalence):
`shadow: true` → `shadow: false` on the v0.5 adapter, and the reverse on the
v0.4 probe. There is no wall-clock dependency. All of the code — adapter,
shadow channel, comparison harness, the migration itself — is written and
shipped in one pass. Whether to soak the comparison for an hour or a week
before flipping is a deployment-confidence judgment the maintainer controls;
it is NOT a barrier to building or shipping the code. (Earlier drafts of
this doc framed the soak as a hard time-gate. It is not. It is a dial.)

Zero-downtime probe migration. No double-firing release. No noisy Phase 2.

The shadow field is part of the v0.5 schema:

- `shadow: false` (default) — adapter emits to user-visible channel.
- `shadow: true` — adapter emits to internal comparison channel only.

## Execution gap #3: fixture contract enforcement at build time

Every adapter must declare `fixtures_v05: {positive, negative, adversarial?}`
with valid filesystem paths. The manifest aggregator enforces this at build
time, not at test time:

- At module load, `manifest.js` validates every adapter declares fixture
  paths.
- For each declared path, `manifest.js` verifies the file exists on disk.
- If either check fails, manifest construction throws and the build fails.

This is a hard failure, not a CI warning. Otherwise probes ship without
fixtures and the dogfood story breaks silently — PreFlight scanning its
own fixture tree is the strongest CI signal we have, and it only works if
every adapter is reachable.

Fixture files live in `src/lib/probes/v05/fixtures/<PROBE_ID>/`. Real files,
not inline strings: the dogfood scan exercises them by scanning the fixture
tree at CI time and asserting positive fixtures produce ≥1 finding and
negative fixtures produce 0.

---

## Migration path

**Phase 0 — Infrastructure landing (this weekend).**
Land the v0.5 schema as JSDoc types + the empty directory structure + the
manifest aggregator stub with fixture-existence enforcement + the
shadow-channel comparison harness. No probes migrated. Tests assert the
aggregator produces a valid empty manifest. Zero runtime change for users.

**Gated on:** Q5 + Q6 investigations below.

**Phase 1 — Four XL families end-to-end as proof.**
Build XL-001 (deserialization), XL-002 (SQLi), XL-004 (TLS), XL-006
(secrets). Build the Python adapter for each. 4 family records + 4 adapter
records + 8+ fixture pairs. Run them in shadow mode alongside v0.4 probes.
Compare overlap on real repos (agentwasp is the obvious target).

**Phase 2 — Migrate overlapping v0.4 probes.**
The 12 v0.4 probes that overlap with an XL family. Current Secret Scanner →
adapters under XL-006. Current SQL Injection probe → JS adapter under
XL-002. Current Auth Weakness → splits across XL-001 (jwt:none) + XL-002 +
new. Originals stay in `legacy/`, drop to shadow mode, removed once the
maintainer is satisfied with parity (a config flip, no time-gate).

**Phase 3 — Build remaining priority adapters.**
The remaining languages across the same XL families plus the
language-specific probes. Driven by the 14-language research corpus.

**Phase 4 — Generate `PROBES` from manifest.**
Retire the hand-listed v0.4 array; the live PROBES set is projected from
the manifest's non-shadow adapters merged with un-migrated legacy probes.

(No Phase 5. The earlier "codegen tooling" phase was removed — see
Decision 3. Adapters are AI-authored with judgment; a deterministic
template generator would produce worse output than the authoring it
would replace.)

---

## Settled questions

| Question                                   | Resolution                                                                                                                                                  |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1: XL family execution logic?             | Pure metadata. Shared logic lives in `shared-detectors/`, imported explicitly.                                                                              |
| Q2: Probe ID format?                       | Two fields: `probe_id` (human, `PY-DESERIALIZE-001`) + `xl_family` (machine, `XL-001`).                                                                     |
| Q3: Cross-language probes → many adapters? | Yes. Verbose-and-explicit beats clever-and-implicit. Each adapter is ~10 lines if it just declares `{xl_family, scope, fp_gates, detector: detectSecrets}`. |
| Q4: Fixture format?                        | Real files in `fixtures/<PROBE_ID>/`. Dogfood scan exercises them.                                                                                          |

## Phase 0 gating questions — all resolved

Both were answered by direct investigation of existing code on 2026-05-14.
Phase 0 is no longer gated.

**Q5: Persona field consumption — RESOLVED 2026-05-14.**

Investigation of `src/lib/formatters.js#formatAgentPrompt` (the Sam SNIPPET
surface, the only persona consumer wired into runtime today) finds:

- `formatAgentPrompt` imports the persona spec (`sam.INSTRUCTIONS`) once
  for the activation contract.
- The per-finding interpolation reads **only from finding fields**:
  `f.probe`, `f.severity`, `f.cwe`, `f.file`, `f.line`, `f.snippet`,
  `f.evidence`, `f.remediation`. No reads against `PROBE_META`,
  `OWASP_BY_PROBE`, or any other metadata map.
- `attachProbeMeta()` already copies probe-level metadata onto findings at
  emission time: `confidence`, `autofix`, `learn_more_slug`, and `owasp`.
  This is the established pattern.

**Answer: emission-time copy. The pattern is already in place.**

Phase 0 work for persona-fields: extend `attachProbeMeta()` to also copy
the v0.5 fields (`probe_id`, `xl_family`, `maturity`, `why_ai_v05`,
`vibe_v05`, `autofix_v05`, `fp_gates_v05`, `legacy_finding_id_seed`) onto
findings when the probe has a `PROBE_MANIFEST_V05` entry. Behavior for
probes without a manifest entry stays exactly as today.

Net Phase 0 work for personas: ~10 lines added to `attachProbeMeta()`.
Zero changes to `formatAgentPrompt`. Zero changes to persona spec
modules (`sam.js`, `demi.js`, `drew.js`, `vera.js`). Zero changes to any
UI component.

This is the simpler of the two options the original Q5 framing
proposed and it matches the existing convention. No UI-layer migration.

**Q6: OWASP coverage page — RESOLVED 2026-05-14.**

Investigation of `src/components/learn/OwaspCoverageView.jsx`,
`src/lib/stable-id.js`, `src/components/FindingCard.jsx`, and
`src/test/probe-coverage.test.js` finds three consumers and two distinct
consumption patterns:

- **`PROBE_OWASP_MAP`** (hand-coded, keyed by OWASP code) is read directly
  by `OwaspCoverageView` to render per-category probe pills.
- **`OWASP_LABELS`** (hand-coded) is read directly by `OwaspCoverageView`
  for human labels.
- **`OWASP_BY_PROBE`** (lazy inverse of `PROBE_OWASP_MAP`, built at module
  load) is read by `attachProbeMeta()` at scan time and copied onto each
  finding as `f.owasp`.
- **`FindingCard`** reads only `finding.owasp` (the copy), never the
  master directly.
- **`probe-coverage.test.js`** asserts: every map entry references a real
  probe, every code has a label, no dead labels, `attachProbeMeta`
  populates `finding.owasp`.

**Migration shape (revised from the proposal's original wording):**

Keep `PROBE_OWASP_MAP` as the **producer interface forever**. Don't retire
it — retire only the hand-coded contributor. Reasons:

- The view iterates by category code; that shape is natural for the UI
  and is cheaper to maintain than rewriting the consumer.
- The lazy `OWASP_BY_PROBE` inversion is a useful primitive that should
  live alongside the by-category projection. Both projections, one source.

Concrete steps:

1. **Phase 0:** `stable-id.js` keeps `PROBE_OWASP_MAP` exported. Its value
   becomes `mergeOwaspMaps(handCoded, buildOwaspMapFromManifest())`.
   Manifest-derived starts empty so the output is byte-identical to today.
   `OWASP_BY_PROBE` keeps its lazy inversion unchanged. All four tests
   pass without modification.
2. **Phase 1–3:** Each migrated v0.5 adapter declares `owasp_web` and
   `owasp_llm` in its manifest entry. The aggregator's
   `buildOwaspMapFromManifest()` flattens those into the v0.4 shape
   `{A01: [probe-name], LLM01: [probe-name], ...}`. Hand-coded entries for
   migrated probes get removed in the same commit. Two producers merge;
   manifest wins on conflict.
3. **Phase 4 (parity):** Hand-coded contributor is empty. The export
   becomes a one-line build from the manifest. Both consumers still work
   without code changes.
4. **Phase 5+ (optional):** If we want to surface the `owasp_web` /
   `owasp_llm` split in the UI (v0.5 schema separates them; v0.4
   conflates), consumers migrate to read those fields off the manifest
   directly. Not required for parity.

**Net Phase 0 work for OWASP:** ~20 lines in `stable-id.js` (the merge
function + a `buildOwaspMapFromManifest()` shim). Zero changes to
`OwaspCoverageView`, `FindingCard`, or tests.

---

## What does NOT need to be relitigated

- Side-by-side schema (Decision 1)
- Composition over inheritance (Decision 2)
- AI-authored adapters, no deterministic generator (Decision 3)
- Directory structure
- Migration phase ordering

These are settled. Don't reopen them in review.

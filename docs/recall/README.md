# Bounded recall measurement, schema v1

Run `npm ci` once, then `npm run test:recall`. This invokes the same full `PROBES`
registry and file eligibility filter as `scripts/scan-dir.mjs`; it scans each
manifest case as an isolated mini-project. It reads code as text without
executing it. No network, Docker, Python packages or additional dependencies
are required. Scanner detection logic and existing precision tests are unchanged.

The default report is `.scratch/recall-scorecard.json`. To record a reviewable
baseline, use:

```sh
npm run test:recall -- --output docs/recall/scorecard-2026-10-30.json
```

The command is **measurement only**. Misses and false positives are reported,
not pass/fail gates. Invalid labels, changed fixture hashes, unscannable virtual
paths and probe exceptions fail the run before a new report is written. CI
runs it after self-audit and uploads the JSON; no recall floors are chosen.

## Manifest contract

`bench/recall/manifest.json` is the benchmark schema's concrete instance.
`scripts/recall/score.js:validateManifest` enforces the following v1 contract.
All paths are repository-relative POSIX paths: absolute paths, empty components,
backslashes, `.` and `..` components are rejected.

| Field                                  | Contract                                                                                                                     |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `schemaVersion`                        | Exactly `1`                                                                                                                  |
| `cases`                                | Nonempty list, unique nonempty string `id` per case                                                                          |
| Case `corpus`, `language`              | Nonempty strings; scorecard grouping keys                                                                                    |
| Case `provenance`                      | `independent` or `preflight-fixture`; never pooled                                                                           |
| Case `source`, `license`, `labelBasis` | Nonempty strings recording source, redistribution license, and independent/local labeling evidence, assumptions and mappings |
| Case `files`                           | Nonempty list of `{path, scanPath, sha256}`; unique `scanPath` per case; lowercase SHA-256 of exact file bytes               |
| Case `labels`                          | Nonempty list; unique nonempty string `id` within the case                                                                   |
| Label `file`                           | Exact virtual `scanPath` of a file in this case                                                                              |
| Label `cwe`                            | Canonical `CWE-` plus a positive decimal integer; the vulnerability-class grouping key                                       |
| Label `startLine`, `endLine`           | Inclusive positive integers; start ≤ end; runner rejects ranges beyond file length                                           |
| Label `kind`                           | `positive`, `negative`, or `excluded`                                                                                        |
| Label `reason`                         | Required nonempty string for `excluded`                                                                                      |

A case may contain multiple files for cross-file analysis, but v1 labels one
language per case. Mixed-language projects must be split; per-label language
support is future work. Same-file, same-CWE label ranges must not overlap,
including exclusions. Unknown extra fields are allowed for provenance extensions.
Line ranges are intentionally narrow and predeclared. Do not widen them after
seeing results just to turn misses into detections.

Physical storage paths are distinct from scanner paths: imported samples and
PreFlight fixtures are presented as `app/*.py`, preserving their content and
line numbers. This explicitly measures production-code shapes; retaining fixture
paths would trigger the scanner's deliberate test exclusions. The manifest
records both identities. Results do not measure repository ingestion or test-path
policy. Keep required project context in a case's `files`; missing context can
change full-registry findings.

## Scoring and report contract

`scoreBenchmark(manifest, observations)` is pure. Observations must contain
exactly one finding array per case, including an empty array for a completed
scan with no findings. Missing runs cannot silently become misses.

Findings normalize to `{file, line, cwe, probe, title}`. Windows separators and
one leading `./` normalize to POSIX; other path aliases, titles and CWE aliases
are not inferred. Missing/nonpositive location or missing CWE remains `null`.
A match requires exact file, exact CWE, and a finding line within the label's
inclusive range. One finding cannot satisfy two same-class labels.

- A positive with any matching finding is `detected`; otherwise `missed`.
- A negative with any matching finding is `false-positive`; otherwise `clear`.
  A negative label asserts safety only for its class and range, not the whole file.
- An excluded label stays `excluded` even if it matches. Its reason and matched
  findings remain visible, and it contributes to neither recall nor FP counts.
- Repeated findings or overlapping probes count once per labeled vulnerability
  or negative region. Extra matches count as `duplicateFindings` for scored
  labels, never extra detections. Exclusion matches remain visible but unscored.
- Findings outside all labeled regions/classes are `unadjudicated`, including
  project-level findings and findings lacking CWE or line metadata. They are
  never automatically called false positives, discarded, or credited as detections.

The JSON report contains `schemaVersion`, `scorecards`, `cases`, and
`measurement`. `cases` retain every label, status, matching normalized findings,
and unadjudicated findings. Scorecard rows group strictly by **corpus,
provenance, language, CWE** and include `detected`, `missed`, `positives`,
`falsePositives`, `clearNegatives`, `excluded`, `duplicateFindings`, and `recall`.
Recall is detected / (detected + missed), or JSON `null` when no positive labels
are eligible. There is no overall recall, accuracy, FP rate, or pooled score.
FP counts are labeled negative regions that fired, not raw warning counts.

Output ordering is deterministic, independent of finding/label/case order.
Reports contain no clock timestamps or absolute workspace paths. Measurement
metadata records Node version, source Git revision, SHA-256 of tracked `src/lib`
file paths and current bytes (including local changes), manifest bytes, harness
bytes and registry size. Run twice in the same checkout/environment for identical
JSON. A changed Git revision/Node version changes metadata even if scores do not.
Review manifest/provenance changes alongside results; hashes establish identity,
not label correctness.

## Corpus boundary and next decisions

The initial independent sample consists of two pinned Apache-2.0 upstream Python
examples. [Provenance](../../bench/recall/bandit/PROVENANCE.md) describes external
label evidence, the local line transcription, licensing and legacy API caveats.
It measures risky API patterns, not proven exploitability. No external scanner
was executed. The SQL rows use PreFlight's own existing positive/negative
fixtures and are explicitly correlated evidence, kept in a different corpus.

This is not a representative recall estimate for Python, JavaScript/TypeScript,
other languages, frameworks, taint flows, the entire CWE roster, or production
repositories. An absent row means **not evaluated**, not zero misses. Initial
exclusion counts are zero; scorer tests exercise exclusions with and without
findings. Adding an exclusion needs a specific documented scope reason, not
merely an observed miss.

Deferred prerequisites remain open: approval of large corpus selections/downloads,
Docker or other external tools and their licenses, independent adjudication of
additional cases, and acceptable per-class recall floors. No oracle-output
normalizer, mutation engine or coverage gate is claimed here. Existing
`fast-check` powers a seeded scorer invariant (finding permutation and repeated
matches preserve coverage), not a broad new scanner-property campaign.

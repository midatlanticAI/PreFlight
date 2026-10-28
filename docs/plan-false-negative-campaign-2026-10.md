# Plan: the false-negative campaign

Written 2026-10-28 against `main` at `0fc9e0b`. Companion to `docs/plan-finish-2026-10.md`.

Every precision campaign so far (May launch feedback, the September secrets campaign, today's field scan) started from a user's real repository and a finding that should not have fired. Recall has never had the same treatment. The suite has 17 `it.fails` blocks that name known misses, the adversarial prompts have a recall role, and the canaries catch a recall regression only when a finding that used to fire stops. None of that measures what PreFlight does not see.

This plan builds the measurement first, then uses it. The goal is a recall scorecard per finding class per language that is reproducible, committed, and diffed in CI the way the canary baselines are diffed by hand today, and then a loop that raises the numbers without moving precision backwards.

## Why the usual approach is not enough here

John's note of 2026-06-01 (`docs/`-bound in `project_preflight_test_validity_note`) is the constraint: tests written by the same model that wrote the probe, from the same reading of the spec, share its blind spots. A green suite says the tests that exist pass. The guards against the missing test are ones that do not come from the author:

1. Labelled corpora someone else built, with the defects already marked.
2. Independent tools run as oracles, so a finding they make and PreFlight does not is a lead.
3. Mutation testing, which attacks the probe and asks whether any test notices.
4. Property-based testing, which states invariants instead of enumerating examples.
5. Contextless adversarial agents that never see the implementation or the previous round's findings.
6. Real vulnerable-then-fixed commit pairs, where the parent must fire and the child must not.

Each is one workstream below. Outside tools appear in this document and in scorecard files under `docs/`; they never appear in product copy, README, llms.txt or commit subjects (the public-copy rule stands). Semgrep's community rule registry is LGPL-licensed; rules are read as a specification of a shape and reimplemented from the CWE, never copied.

## Workstream 1: ground truth

A corpus is useful only if it is labelled: every planted defect has a file, a line range and a CWE, so a miss is countable. Start with these, cloned under a `bench/` directory that is gitignored (they are large and not ours):

| Corpus                                                                                  | Language            | Labels                                                    | What it measures                                                               |
| --------------------------------------------------------------------------------------- | ------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------ |
| OWASP Benchmark                                                                         | Java                | ~2,700 cases, CWE-tagged, true and false halves           | Java adapters: SQL, command, path, crypto, cookies                             |
| NIST SARD Juliet                                                                        | C, C++, Java, C#    | tens of thousands, CWE-tagged, good and bad pairs         | C/C++/C#/Java adapters, with a known FP cost per case                          |
| OWASP Juice Shop                                                                        | TypeScript, Angular | challenge list maps to code                               | Core JS/TS probes on a real app shape                                          |
| OWASP NodeGoat                                                                          | Node, Express       | each OWASP Top 10 item documented to the line             | Express route auth, injection, SSRF, logging                                   |
| DVNA, Vulnerable Node                                                                   | Node                | documented                                                | Same, different idioms                                                         |
| WebGoat                                                                                 | Java, Spring        | lesson per defect                                         | Spring adapters, XL-009 mass assignment                                        |
| DVWA, DVPWA                                                                             | PHP                 | documented                                                | PHP adapters, XL-003, XL-002                                                   |
| PyGoat, django.nV, Vulnerable Flask App                                                 | Python              | documented                                                | Python adapters, pickle, subprocess, templates                                 |
| RailsGoat                                                                               | Ruby                | documented                                                | Ruby adapters, XL-009                                                          |
| govwa, go-test-bench                                                                    | Go                  | documented                                                | Go adapters                                                                    |
| CVE-fix pairs (CVEfixes, GitHub advisory commits)                                       | JS/TS, Python first | CWE from the advisory; parent is positive, child negative | Real code, real spelling, recall and precision in one pair                     |
| Secret fixtures (gitleaks and trufflehog test data; synthetic keys per provider format) | any                 | by provider                                               | Secret Scanner manifest recall per provider                                    |
| OSV malicious package list, sampled monthly                                             | npm, PyPI           | advisory ids                                              | Threat-intel manifest recall over time                                         |
| Planted-defect vibe corpus (ours)                                                       | JS/TS, Python       | our manifest                                              | The shapes vibe coders actually write (Next, Supabase, Workers, Hono, FastAPI) |

The last row is the one that looks most like PreFlight's audience and does not exist anywhere else. It is built by taking a clean app (PreFlight's own sandbox fixtures, John's own repositories that are already canaries, a fresh Lovable or Bolt export) and planting one defect per copy from a list, recording the plant in a manifest. An agent can plant; a different agent, contextless, writes the manifest entry from the diff; the two must agree before the case counts.

Benchmark corpora are not vibe-coded shape and will overstate some gaps (a Juliet case is a contrived function, not a route). The scorecard keeps corpora separate and never sums them into one number.

## Workstream 2: outside tools as oracles

Run locally, in Docker where possible so nothing is installed on the machine, against the same corpora and against John's own repositories (sixty-odd local clones; the canaries plus `~/omra`, `~/SEES`, `~/VPv1`, `~/waffhouse`, `~/scraperv2`, `~/chatagg` are the large ones). Each tool's output is normalised to `file:line|CWE|tool` and unioned.

| Tool                                                                      | Scope                                    | Role                                                         |
| ------------------------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------ |
| Semgrep OSS (`p/default`, `p/owasp-top-ten`, `p/secrets`, language packs) | 30 languages                             | Broadest oracle; shape specifications                        |
| CodeQL CLI (free for open source)                                         | JS/TS, Python, Java, Go, C#, Ruby, C/C++ | Dataflow oracle; tells us which misses need taint, not regex |
| Bandit                                                                    | Python                                   | Python-idiom oracle                                          |
| gosec                                                                     | Go                                       | Go-idiom oracle                                              |
| Brakeman                                                                  | Ruby on Rails                            | Rails oracle, XL-009                                         |
| SpotBugs with FindSecBugs                                                 | Java                                     | Java oracle                                                  |
| njsscan                                                                   | Node                                     | Node oracle                                                  |
| gitleaks, trufflehog                                                      | any                                      | Secrets oracle                                               |
| osv-scanner                                                               | manifests                                | Dependency oracle                                            |

Every union row PreFlight lacks is a candidate false negative. Adjudication is by hand or by a second contextless agent, into exactly one bucket:

- **In scope, missed.** A spelling or framework the probe should see. Goes to the fix loop.
- **Out of scope by doctrine.** Needs dataflow the engine does not have, or is a check the family roster already declines with a reason. Recorded in the family header's roster, with the oracle's case as the example.
- **Oracle false positive.** Discarded, with the reason, so the same row is not re-adjudicated next quarter.

The third bucket matters as much as the first: a tool that fires on everything is not an oracle, and the adjudication record is what keeps the next run cheap.

## Workstream 3: mutation testing of the probes

Stryker (`@stryker-mutator/core` with the Vitest runner) over `src/lib/probes/**`, one file at a time with `--mutate`, because the whole tree at once will run for hours. A mutant that drops a regex alternation, flips a guard, or returns early and still passes every test is a test nobody wrote. Target: no surviving mutant in a security probe without a written reason; a mutation score per file in the scorecard. Each survivor becomes a pin in the matching precision or recall suite, written from the mutant's diff, not from the implementation.

## Workstream 4: property-based invariants

`fast-check` is already a dev dependency with one suite (`property-probes-v1.test.js`). Extend it with the invariants the regressions of the last two months would have caught:

- Never throws, on null, empty, binary, unterminated and 400KB single-line content, for every registered probe.
- Masking is length-preserving and idempotent; a positive fixture wrapped in a comment never fires; a positive inside a string fires only for the secrets family.
- **Formatting invariance.** For every positive fixture, the Prettier-wrapped, CRLF, tab-indented, minified, `as const`, optional-chained and type-annotated spellings produce the same finding. Gate 3 showed this is where recall quietly dies: the probe matched one spelling and the formatter emitted another.
- Stable ids are deterministic across runs and across whitespace changes that do not move the line.
- Severity, category and CWE are drawn from the canonical sets; `finding.probe` byte-matches the registry.

## Workstream 5: the adversarial loop

The three-sequential-gate doctrine from the memory file, applied to recall: the same roles every round, fresh contextless agents each round, fixes between rounds, stop after three consecutive clean rounds. Roles, fixed for the whole campaign:

1. Recall by spelling: equivalent spellings of each positive fixture the probe does not match.
2. Recall by framework: the same defect in Next, Nuxt, SvelteKit, Remix, Hono, Workers, Express, FastAPI, Django, Rails, Laravel, Spring.
3. Recall by language: per adapter, the idioms the inventory names.
4. Precision guard: for every "must fire" the first three produce, a "must not fire" that looks the same.
5. Contract and performance: throws, superlinear scans, the probe contract.

Every finding is re-reproduced by a second contextless checker before anything is fixed. Agents are batched by family, never one per finding; the September session's cost record (13M tokens on verification agents answering deterministic questions) is the reason scripts answer "does this fixture fire" and agents answer "what did nobody think of".

## Workstream 6: making it permanent

A `npm run test:recall` script that runs the planted-defect corpus and the labelled benchmarks that fit in CI time, writes `docs/recall/scorecard-<date>.json` with recall per class per language and the out-of-scope count, and fails the build if any class drops below its committed floor. The scorecard is the recall equivalent of the canary baselines: a probe change that loses a case has to explain it in the CHANGELOG. The large corpora and the outside tools run locally on demand, not in CI.

## Workstream 7: what the misses will say about the engine

A share of the adjudicated misses will land in "needs dataflow". The taint engine exists and crosses files; acorn is already in the bundle. The campaign's last deliverable is a count of in-scope misses that regex cannot close and an estimate of how many the existing taint engine would, which is the evidence for or against moving the JS/TS core from regex to AST, family by family. That decision is not made in this plan; it is made with the numbers.

## Phases

1. **Harness, one session.** `scripts/scan-dir.mjs` is in. Add the normaliser for oracle output, the `bench/` layout, the scorecard writer, the Docker files for Semgrep and CodeQL. Run everything once on Juice Shop, NodeGoat and the three canaries. First scorecard committed, numbers unflattering and honest.
2. **JS/TS and Python, two sessions.** The core audience. Adjudicate the union, fix the in-scope misses family by family, each fix through the precision canaries before it lands. Mutation testing on the probes those fixes touched.
3. **Per-language, alongside Wave 3.** As each XL family lands (see the companion plan), its languages run through OWASP Benchmark or Juliet and the matching oracle before the family is called done.
4. **Mutation and properties, one session.** Stryker across the security probes; the invariants above in `fast-check`; survivors pinned.
5. **Adversarial loop, until three clean rounds.** Then, per the doctrine, document, commit, push.
6. **CI floor.** `test:recall` in `ci.yml` after `test:self-audit`.

## What it costs and what to decide

- Disk: the corpora are a few gigabytes under `bench/`, gitignored. CodeQL databases add more; they can be deleted after each run.
- Tools: Semgrep and CodeQL via Docker, the rest via Docker or `pipx`. Nothing goes into `package.json` except Stryker as a dev dependency.
- Agents: workstream 5 is the only agent spend. Batch by family; estimate before each fan-out and say the number.
- Decisions for John: Docker-based installs on this machine, which corpora to clone, whether CodeQL's open-source licence terms are acceptable for a public repo (they are written for exactly this use), and the recall floor per class once the first scorecard exists.

## What this plan refuses

- No single recall number. Per class, per language, per corpus, with the out-of-scope bucket shown beside it.
- No recall fix without a precision replay. A broadened probe that fires on more is the most direct way to fire on wrong things.
- No oracle finding copied as a rule. The oracle says where to look; the probe is written from the CWE and PreFlight's own fixtures.
- No tool named in public copy.

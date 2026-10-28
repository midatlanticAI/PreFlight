# Plan: finish what was started

Written 2026-10-28 against `main` at `0fc9e0b`. Companion to `docs/plan-false-negative-campaign-2026-10.md`. Read `docs/handoff-2026-10-28.md` first for the tree state.

This is an inventory of every piece of PreFlight work that was begun and not finished, with what "finished" means for each, the order to take them in, and the decisions that only John can make. It does not include work that was discussed and never started (the DAST suite, the showcase badge); those are separate conversations.

## The inventory

| #   | Item                                          | Where it stands                                                                                                                                                                                                               | Finished means                                                                                                                           | Size                            |
| --- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| 1   | Push state                                    | Nine local commits ahead of `origin/main` (September pair plus seven today). The live site still carries every false positive fixed today                                                                                     | John names it; rebase on origin, rerun the gate, push                                                                                    | Minutes                         |
| 2   | Two verified Wave 3 adapters never registered | `swift/sw-deserialize-001-nskeyedunarchiver.js` and `cpp/cpp-deserialize-001-binary-archive.js` are finished, fixtured and proven through `runShadow`, but untracked and absent from `adapters/index.js`                      | Registered under XL-001, phase 3 id lists updated, counts synced, gate green, canaries flat                                              | Half a session                  |
| 3   | Wave 3: eight XL families                     | Family record files exist for XL-003, 005, 007, 008, 009, 010, 011, 012 (63 to 95 lines each, untracked, unverified). 23 adapter drafts untracked, none fixtured, some with unfinished `detect()` bodies. Nothing registered  | Every family live with its language adapters, fixtures, Learn page, registration, pins, three-layer adversarial gate, canaries explained | Eight sessions, one per family  |
| 4   | v2 family severity ceiling                    | All eleven v2 families cap at medium because the class ceiling decision is parked                                                                                                                                             | John decides whether a health-axis finding may ever reach high; the cap is then lifted per family or written down as policy              | One decision, then a small edit |
| 5   | Atlan Term tab threat model                   | Parked since July; an architecture call, not a patch                                                                                                                                                                          | John decides whether the agent may drive `pty.open` at all                                                                               | One decision, Atlan repo        |
| 6   | v1.1 agent surfaces                           | Specs complete in `src/lib/personas/`; only Sam SNIPPET is wired. Apply Fix (Sam FULL), Demi Author and Grade CLIs, Drew design-rules probe and Vera engineering-rules probe are not started                                  | Each surface wired, tested, and in the Learn copy                                                                                        | Four sessions                   |
| 7   | v2 Track 2: sandbox UX                        | `/sandbox` exists (330 lines, CodeMirror editor, findings panel). The spec's dedicated scan worker, the 4ms keystroke budget and the 250ms p95 scan budget are not built. The sandbox chunk is 504KB                          | Decide whether the spec's full UX is still wanted; if yes, worker plus budgets plus tests                                                | Two sessions if wanted          |
| 8   | v2 Track 3: retention                         | Spaced retention (1/3/7/21 day), the three pedagogical arcs: not built. No code references                                                                                                                                    | Decide whether stickiness is still a goal; if yes, design the local-only mechanism (no backend) before building                          | John's call                     |
| 9   | Bundle size                                   | Main chunk is 741KB against a 500KB soft target. The July plan deferred lazy-loading acorn out of the main chunk                                                                                                              | Acorn behind a dynamic import inside Code Correctness, async probe contract, main chunk under target                                     | One session                     |
| 10  | Launch-feedback queue (May)                   | Compliance clean-state panel: shipped (the panel now distinguishes "no findings mapped" from "broken"). Auth-config hygiene probe: not built. Tor's `.env` template content false positive: never confirmed. GSC verify: John | Probe built or struck from the list; Tor's case reproduced or closed                                                                     | One session                     |
| 11  | Docs drift                                    | README still says 4,027 tests across 116 files; the architecture doc describes 33 probes; CLAUDE.md's stack section says 43 v0.5 probes                                                                                       | Every count in README, CLAUDE.md and the architecture doc reads from one place or carries a date                                         | Hours                           |
| 12  | Stale branches                                | `fix/cockpit-engine-containment` and `fix/config-title-pattern-type` are both merged into main                                                                                                                                | John approves deletion                                                                                                                   | Minutes                         |
| 13  | SEO copy                                      | Title and H1 carry no search term; meta description runs 700 characters; landing pages for the queries people type are unwritten                                                                                              | John writes or approves the voice copy; the pages are then wired like `/owasp-llm-2026`                                                  | John's copy, then hours         |

The "Pre-Flight" rename pass from the naming convention is done: zero spellings remain in `src`, `public`, `index.html` or the README.

## Wave 3 in detail

This is the bulk of the work and the reason the plan exists. The inventory in `docs/v05-research/preflight_v05_probe_inventory.md` defines the eight families. Counting the language adapters it names, and the drafts on disk:

| Family                        | Languages named                           | Adapters | Drafts on disk                         |
| ----------------------------- | ----------------------------------------- | -------- | -------------------------------------- |
| XL-009 Mass assignment        | RB, JV, PHP, CS, PY, SC, KT               | 7        | 7 (all of them)                        |
| XL-003 Shell injection        | PY, GO, JV, CS, RB, PHP, RS, C, CPP, DA   | 10       | 6 (c, go, java, kotlin, python, rust)  |
| XL-005 Missing timeouts       | PY, GO, RS, JV, CS, DA, EX, plus JS axios | 8        | 5 (go, java, javascript, python, rust) |
| XL-010 Excessive capabilities | KT, SW, RS, DA, JV                        | 5        | 3 (kotlin, rust, swift)                |
| XL-008 Install hooks          | PY, RS, RB, PHP, SW, KT/JV, GO            | 7        | 2 (python, rust)                       |
| XL-007 Dynamic versions       | PY, JV, CS, RB, PHP, RS, GO, DA, EX, SW   | 10       | 0                                      |
| XL-012 Prompt leakage         | KT, SW, DA, JV, PY, CS                    | 6        | 0                                      |
| XL-011 LLM output to sinks    | every language with an LLM SDK            | up to 15 | 0                                      |

About 68 adapters. JavaScript is absent from most rows because the core probes already own those shapes (child_process in the taint engine, npm hooks in Package Manager Hardening, lockfiles in Build & Config); each family header must say so in its "not built" roster rather than duplicate them.

The order above is deliberate: the families with the most draft material first, so the first sessions produce the most live probes per hour, and XL-011 last because its boundary with the existing LLM probes and the taint engine has to be written down before an adapter is built, or it will double-report.

Each family is one session and goes all the way through, in this order, before the next begins:

1. Read the family record draft against the inventory entry. Rewrite it; do not trust it.
2. For each language: read the adapter draft if one exists, then write the adapter fresh against `types.js`, `manifest.js` and one verified adapter in the same language. The draft is a source of ideas, never of code to keep.
3. Positive and negative fixtures under `src/lib/probes/v05/fixtures/<ID>/`, proven through `runShadow`.
4. The Learn page in Demi's register, with the family's "not built" roster and the reason for each entry.
5. Register in `families/index.js` and `adapters/index.js`; update the phase 3 id lists and `stable-id.js`; sync counts (README, CLAUDE.md, llms.txt, FAQ, OG card).
6. Full gate: `npm test`, lint, build, self-audit, format.
7. Canary replay on `~/waylou`, `~/atlan`, `~/nearbyappliancerepair` with `GIT=1 node scripts/scan-dir.mjs`, against baselines recorded before step 1; every moved row explained in the CHANGELOG.
8. The three-layer adversarial gate from `docs/adversarial-test-agent-prompts.md`: the same roles every round (recall by spelling, recall by framework, precision, probe contract and performance), fresh contextless agents each round, fixes between rounds, stop after three consecutive clean rounds. Findings verified by a second contextless checker before any fix.
9. Commit. No push.

Manifest validation throws at module load, so a half-registered family breaks the build and every test, not one test. Step 5 is done last for a reason.

## Order of work

1. **Now, half a session.** Items 1, 2, 11, 12. Push state is John's word; the two verified adapters go in; the docs stop lying about counts; the merged branches go when John says.
2. **Eight sessions.** Item 3, one family per session in the order above. After each family, the false-negative campaign's per-language benchmark (see the companion plan) runs for that family's languages, so recall is measured as the family lands rather than months later.
3. **Between families, when John has decided.** Items 4 and 5. The ceiling decision is small to apply and changes what every v2 finding is worth.
4. **One session.** Item 9, bundle size. It compounds with every family added.
5. **Four sessions, if wanted.** Item 6, the v1.1 agent surfaces, Apply Fix first because its sibling already ships.
6. **John's call before any build.** Items 7, 8, 13. Each touches either his copy or a product direction (stickiness, editor UX) that the September positioning note may have overtaken: PreFlight searches the same things on day one and day one thousand; the user grows, not the tool.

## Decisions John owes, in the order they block work

1. Push state for the nine commits.
2. The 23 adapter drafts: approve overwriting each one as its family is rebuilt. Nothing is deleted; each file is replaced by its verified version in the same session. The eight family record drafts the same way.
3. The class ceiling (item 4) and the Term tab (item 5).
4. Delete the two merged branches.
5. Whether v2 Tracks 2 and 3 (sandbox worker, retention) are still wanted.
6. SEO copy.

## What this plan does not do

It does not shorten any family to "the languages with drafts" to make the count look finished. A family is live when every language the inventory names has an adapter or a written reason in the roster. It does not register a draft to see whether it works; the manifest will tell you, by taking the suite down.

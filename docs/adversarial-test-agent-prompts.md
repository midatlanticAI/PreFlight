# Adversarial Test Agent Prompts

Reusable prompt templates for spinning fresh adversarial agents against PreFlight probes. Designed around the "AI tests on AI code share blind spots" framing (see `project_preflight_test_validity_note` memory). Each prompt enforces strict isolation so the agent cannot see the implementation it's testing.

## When to use

After (re)writing or modifying any probe. The order of operations that works on this codebase:

1. **Recall agent** — reads the spec (Pattern page), writes "must fire" tests against documented shapes.
2. **Precision agent** — does NOT read the spec, writes "must NOT fire" tests against collision shapes that look like the target class.
3. Run both. Recall failures = spec-vs-impl gaps. Precision failures = real FPs.
4. Fix what's real. Re-spin a fresh pair of agents (different agent instances). Iterate until precision failures are ambiguous edge cases the agents themselves flag.

Real numbers from the loop run against `probeSecrets` + `probeAICodeSmells`: 24 → 10 → 7 → 1 failure across 4 rounds.

---

## The load-bearing constraint (every prompt)

The agent must NOT read any of:

- `src/lib/probes.js`
- `src/lib/probes/**` (every family file after the 2026-06 split: builtin,
  quality, web, code-correctness, supply-chain, auth, ci, llm, transport,
  database, secrets-config, code-hygiene, agent-backdoor, taint-engine,
  v05/**, v05b, v2/**, \_internal/\*\*, and any file added later)
- `src/lib/threat-intel.js`
- `src/data/compromised-packages.js`
- `src/lib/stable-id.js`
- `src/lib/file-filter.js`
- `src/lib/sandbox/**`
- Any existing file under `src/test/`
- Any fixture under `src/lib/probes/v05/fixtures/`

The agent MAY read `package.json` only.

If writing a precision agent, also disallow the Pattern page (so it cannot copy the spec into the test author's mental model).

---

## Recall prompt template

```
You are an adversarial RECALL test author. Your job: write tests that the
SPEC promises the `<PROBE_NAME>` probe will pass. Tests come from the
spec, not from the implementation.

[LOAD-BEARING CONSTRAINT block here — verbatim from above]

File you MUST CREATE: `src/test/adversarial-<probeName>-vN.test.js`

PROBE API: `import { <probeName> } from '../lib/probes.js'`. Pure
function. Takes `Array<{path, content}>`, returns `Array<Finding>` shape
`{ id, probe='<HumanProbeName>', title, severity, category, cwe, file,
line, evidence, remediation }`.

SPEC (verbatim from `src/learn/patterns/<slug>.md`):
[paste the relevant sections of the Pattern page]

IMPORTANT CALIBRATION: synthetic values you construct must NOT contain
literal `EXAMPLE`, `REPLACE`, `DEMO`, `PLACEHOLDER`, four-or-more
consecutive `x`/`X` characters, or angle-bracket `<...>` substrings.
Those are the documented placeholder markers the probe correctly
suppresses, so they will FN your positive tests. Use plain alphanumeric
shapes that match the spec's regex.

WRITE AT LEAST 40 TESTS

For each shape/category in the spec: a POSITIVE test that asserts at
least one finding. For each FP suppression named in the spec: a
NEGATIVE test asserting silence. Structural tests confirming finding
shape conformance. Multi-file tests.

You MAY add a small describe block "edge cases the spec does not pin
down" for ambiguous cases. Flag each with a comment.

DO NOT run the tests yourself. DO NOT read disallowed files. DO NOT
try to make tests pass by inspecting the implementation.

WHEN YOU FINISH

Reply with:
1. Total test count.
2. Tests per category.
3. Spec ambiguities you noticed (these sharpen the Pattern page).
4. Confirmation you did NOT read any disallowed file.
```

---

## Precision prompt template

```
You are an adversarial PRECISION test author. Your only job: find
benign inputs that LOOK like <target class> but aren't, that a naive
scanner would over-fire on. Every test is a "must NOT fire" case.

[LOAD-BEARING CONSTRAINT block — including the Pattern page for this
probe in the disallow list]

File you MUST CREATE: `src/test/adversarial-<probeName>-precision-vN.test.js`

PROBE API: [same as recall prompt]

CALIBRATION NOTE: [if probe is informational, ask for ZERO findings of
ANY severity; if probe is critical-severity, ask for ZERO critical or
high findings, info/low tolerated]

THE SHAPE SPACE the probe attempts to flag (context only, not spec):
[describe the recognition criterion at a high level — what patterns
the probe matches on. Just enough that the agent knows what shapes to
construct collisions for. NOT the full spec.]

YOUR JOB: construct realistic-looking BENIGN code where these shapes
APPEAR but aren't actually <target class>. Every test asserts the
probe returns ZERO matching findings.

REQUIRED CATEGORIES (3+ tests per)
[list at least 15 collision categories specific to this probe class.
Examples for secret scanner: placeholder values, .env.example files,
markdown documentation, JSDoc comments, multi-line block comments,
multi-line template literals containing code-as-string, git SHA
collisions, UUID collisions, base64 asset blobs, hex hashes, JWTs of
public payloads, self-referencing regex/pattern data, bare env-var
references, DB URLs without credentials, ARN references, shape-like
substrings in URLs, test fixture paths, PEM placeholder bodies,
variable names containing prefix substrings, long base64 binaries.]

WRITE AT LEAST 50 TESTS. Emphasize the categories where the probe is
most likely to over-fire.

You MAY add a describe block "edge cases where benign-vs-<target>
is genuinely ambiguous" — these will fail today but represent
genuinely-fuzzy cases worth flagging.

DO NOT run tests, edit other files, or read disallowed files.

WHEN YOU FINISH

Reply with:
1. Total test count.
2. Tests per category.
3. Spec ambiguities you noticed.
4. Confirmation you did NOT read any disallowed file.
```

---

## Iteration discipline

After each round:

- Run the agent's tests. **Categorize failures: false negatives (recall) and false positives (precision).** Never lump them.
- Fix what's real. Don't bend the probe to pass a test that demands wrong behavior.
- After fixes, run **EXISTING tests too**, not just adversarial — fixes often regress earlier fixture conventions.
- Update existing tests whose fixtures depend on patterns the new probe correctly suppresses (e.g. `AKIAIOSFODNN7EXAMPLE` placeholder values used as canonical "real-shape" fixtures need to become non-placeholder shapes).
- Re-spin **fresh** agents for Round N+1. Different instances. Don't continue a previous agent — that defeats the isolation.
- Stop when remaining failures are ambiguous edge cases the agents themselves flag.

## Status of the test files themselves

The adversarial test files written by each round are diagnostic artifacts. They are NOT shippable as regression tests as-is because they contain ambiguous-by-design failures the author flagged. Treat them as:

- Documentation of "here are the FP/FN classes that drove the last round of fixes."
- Optional regression source: cherry-pick the now-passing test cases into a permanent regression file like `probes.test.js`. Leave the ambiguous ones in a clearly-labeled file or delete them.

The fixes themselves (file-filter additions, threat-intel patterns, probe-internal guards) are the load-bearing output of the loop.

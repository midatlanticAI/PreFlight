# Python detector follow-up, 2026-10-30

Scanner source: `478bbf0be8d41af7f2951c6a63586b497a3275e1`.
Benchmark/harness base: `aaa2944571b479d8768d758b69bbaa63f1fe938b` (draft PR #3).
Runtime: Node v24.22.1. Full registry: 131 probes.

The [original baseline](./baseline-2026-10-30.md) and its scorecard are unchanged.
The [new machine-readable report](./scorecard-python-fixes-2026-10-30.json)
uses exactly the same manifest, fixture bytes/hashes, labels, exclusions,
scoring logic and runner. No scoring threshold was added.

| Corpus / provenance                      | Class                   | Before detected / positives | After detected / positives | Remaining misses | FP regions before → after / negative labels |
| ---------------------------------------- | ----------------------- | --------------------------- | -------------------------- | ---------------- | ------------------------------------------- |
| Pinned upstream sample / independent     | CWE-295 TLS             | 18 / 18                     | 18 / 18                    | 0                | 0 → 0 / 18                                  |
| Pinned upstream sample / independent     | CWE-502 deserialization | 2 / 2                       | 2 / 2                      | 0                | 5 → 0 / 7                                   |
| Existing PreFlight fixtures / correlated | CWE-89 SQL injection    | 4 / 5                       | 5 / 5                      | 0                | 0 → 0 / 5                                   |

All evaluated labels are Python. Exclusions and unadjudicated findings remain
zero. SQL duplicate findings increase from one to three because the corrected
adapter now overlaps existing registry detections at additional positive lines;
they receive no extra recall credit. The report retains the matching probes.

## Traced failures and changes

The old SQL patterns stopped string content at either quote character. In the
Django `.extra(where=[f"status = '{status}'"])` positive at line 16, the inner
SQL single quote terminated the pattern before `{status}`. The full registry
masked some other adapter misses through overlapping detectors. Quote-specific
string matching now handles opposite quotes and backslash escapes for f-strings,
percent formatting, `.format()` and SQL concatenation. Literal escaped f-string
braces and comment text do not count as interpolation. The existing raw-SQL
surface requirement, same-line boundary and Python file exclusions remain.

The old YAML exemption recognized only a `Loader=SafeLoader` pattern or a
`yaml.safe_load` mention anywhere on the line. It missed `CSafeLoader` and all
positional safe loaders. A lexical argument check now recognizes exactly
`SafeLoader`, `CSafeLoader`, `yaml.SafeLoader` and `yaml.CSafeLoader` as the
second positional argument or the `Loader` keyword of that particular call.
It handles nested arguments and multiline calls, masking strings and comments.
A neighboring safe call, comment, quoted loader name, lookalike identifier,
constructor or dynamic loader cannot exempt an unsafe call. The upstream
safe calls at lines 12, 25, 26, 27 and 28 clear; unsafe calls at lines 9 and 22
still fire. Existing pickle/dill/joblib/pandas and explicit unsafe Torch
behavior is covered by regression tests and remains unchanged.

## Validation

- Full suite: 131 files passed; 4,444 tests passed, 7 skipped, 35 todo.
- Added 56 focused regression tests, split between SQL and deserialization.
- ESLint with zero warnings and Prettier checks passed.
- Production build passed; 117 routes prerendered. Existing large-chunk warnings remain.
- All 10 production self-audit checks passed.
- Recall measurement was reproduced before and after the changes. Two runs on
  the committed detector revision produced byte-identical JSON.
- No dependencies, lockfile, benchmark labels, fixture bytes, scorer or CI
  configuration changed. Node 20/22 were not run locally for these fixes.

## Limits

These are results for the existing bounded sample, not representative estimates
of scanner accuracy or Python/framework coverage. SQL evidence remains
correlated; the two independent API samples retain the original provenance and
legacy API assumptions. No external scanner or exploitability evaluation ran.

Both probes remain lexical heuristics. SQL still requires an interpolation and
raw-SQL surface on the same line, without data-flow tracking. YAML does not
resolve imports, aliases or rebinding of loader names; complex expressions and
dynamic kwargs remain conservative warnings. This work does not establish
coverage for arbitrary Python syntax, taint flows, other languages or untested
vulnerability classes. Zero remaining misses/FP regions applies only to the
unchanged labeled regions above.

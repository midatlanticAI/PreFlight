# Threat-intel review: 2026-05-12 → 2026-07-25

Record of the manifest review that bumped `_lastReviewed` in
`src/data/compromised-packages.js` to 2026-07-25, and of the adjudication
method that produced it.

Read this before the next review. The headline lesson is not about any one
package: it is that a research pass produces a **lead list**, and a lead is
not an entry until a primary source says the exact version string out loud.

## Why the bar is this high

A false entry in the manifest makes PreFlight accuse an innocent package.
That is worse than a miss. A miss is a gap we close next review; a false
accusation is the tool telling someone to rip out a dependency that was
never compromised, and it burns the credibility that makes the real
findings actionable. Detection data is held to the same bar as detection
code.

## Source order

Unchanged from the repo's editorial policy, restated here because it is
also the verification order:

1. The victim's own postmortem.
2. The official advisory: GHSA, CVE/NVD, CISA, or an OSV `MAL-` record.
3. The affected vendor's documentation.
4. Independent news organizations and named research orgs.

Commercial security-scanner vendor blogs are not cited, by name or by link.
Where a fact exists only there, it is not yet a fact for our purposes.

## What this review changed

Three entries added, each checked directly against a primary advisory:

| Package               | Versions     | Source                                        |
| --------------------- | ------------ | --------------------------------------------- |
| `supabase-javascript` | 2.98.3       | OSV `MAL-2026-3652`                           |
| `mcp-server-github`   | 0.0.1, 0.0.2 | OSV `MAL-2026-5479`                           |
| `echarts-for-react`   | 3.1.7, 3.2.7 | GitHub malware advisory, published 2026-05-19 |

`supabase-javascript` is an impersonation package, not the official
`supabase-js`. `mcp-server-github` is an unscoped squat on
`@modelcontextprotocol/server-github` that beacons host details from a
postinstall hook before any tool call runs.

## What this review rejected

**A claimed `0.10.1` marker version across the TanStack wave.** Reported as
a wave-wide worm marker published alongside each package's two malicious
releases. `GHSA-g7cv-rxg3-hmpx` — the advisory TanStack's own postmortem
points to — lists 42 packages with exactly two versions each and no
`0.10.1` anywhere. Several of those packages have live `0.x` release lines,
so importing it would have accused ~45 packages over a version number that
does not exist and could later ship legitimately.

**A claimed coverage gap in the TanStack wave.** Reported as probably
half-missing, on the reasoning that the wave published one day before the
previous review date. A programmatic diff of the shipped manifest against
the authoritative list found 42 for 42, every version string exact, no
extras. The manifest was already complete.

**A third version of `echarts-for-react` (`3.0.7`).** The advisory lists two
versions. The same +1 fabrication shape as the `0.10.1` claim.

## What remains unverified

Named in the research pass, could not be confirmed against any primary
source during this review, and therefore **not** in the manifest:

- A ~317-package `@antv/*` wave around the confirmed `echarts-for-react`
  compromise. The anchor package is real; the roster is unconfirmed.
  `size-sensor`, checked directly, has no malware advisory.
- An 89–145 package `@mastra/*` scope takeover with an `easy-day-js`
  dependency injection.
- Malicious `@asyncapi/*` and `jscrambler` releases. GitHub's advisory
  database returns no malware advisories for either name.
- A 32-package `@redhat-cloud-services` compromise. Red Hat's `RHSB-2026-006`
  **does** confirm the incident, the campaign name, and the package count,
  but publishes no per-package version list, so no entry can be written from
  it.

Unverified does not mean false. Several of these are plausibly real and the
Red Hat incident is confirmed at the bulletin level. They need per-package
advisories before they can ship.

## The reliability split, for next time

The failure was not random. Individual advisory lookups were exact every
time they were checked. The errors were concentrated entirely in aggregated
claims: marker versions, package counts, wave groupings, and "you are
missing X" warnings. Treat a research pass as a set of advisory IDs worth
fetching, and fetch them.

## A note on what the manifest can and cannot be

The live npm malware feed runs to dozens of advisories a day, dominated by
disposable spam and squat names with no downstream users. A curated manifest
of named packages cannot and should not chase that volume. Its job is the
compromises that reach real dependency trees: a popular package whose
maintainer account or CI identity was taken over. Coverage of the long tail
belongs to the behavioral probes — install hooks, agent-config writes,
name-similarity — not to this file.

## Method, reproducible

1. Run the research pass. Collect advisory IDs and package names.
2. For each candidate, fetch the primary source directly and read the exact
   version strings.
3. Diff programmatically against the shipped manifest rather than trusting
   any claim about what is missing.
4. Add only what step 2 confirmed. Record the source in the entry's note.
5. Write down what was rejected and why, so the next review does not spend
   its budget re-deriving the same negative.

# v0.5 probe infrastructure

Language-agnostic probe scaffolding per [`docs/v05-research/v05-architecture.md`](../../../../docs/v05-research/v05-architecture.md).

This directory is empty for Phase 0 by design. The aggregator, validators,
shadow channel, and schema types are wired up so that the moment the first
real adapter lands in `adapters/`, the whole system runs without further
plumbing.

## Layout

```
v05/
  families/           XL-001..XL-012 pure metadata records (empty Phase 0)
  adapters/           per-language detection modules (empty Phase 0)
    python/  java/  ruby/  go/  rust/  ...
  shared-detectors/   cross-cutting helpers (test-fixture detection etc.)
  fixtures/           canonical positive/negative test inputs per probe_id
  types.js            JSDoc typedefs for AdapterRecord, XLFamily, ManifestEntry
  manifest.js         aggregator: composes families + adapters into PROBE_MANIFEST_V05
  shadow.js           shadow-channel harness for Phase 2 dual-firing migrations
```

## Phase 0 boundaries

- The aggregator builds an empty manifest cleanly. Tests assert that.
- The validator refuses adapters missing required fields or fixture paths.
- The shadow channel exists but has no consumers yet.
- The OWASP merge function in `stable-id.js` builds `PROBE_OWASP_MAP` from
  both the v0.4 hand-coded entries and the (empty for Phase 0) manifest.
- `attachProbeMeta()` is extended to copy v0.5 fields onto findings when a
  manifest entry exists for the probe.

## Adding the first adapter (Phase 1)

1. Define the XL family record under `families/` if the adapter references one.
2. Drop fixture files under `fixtures/<PROBE_ID>/{positive, negative}`.
3. Author the adapter under `adapters/<lang>/<probe-id>.js`.
4. Register the adapter in `adapters/index.js`.
5. Add a test asserting the positive fixture produces ≥1 finding and the
   negative fixture produces 0.

The build will fail at manifest construction if step 2 is missed or
fixture paths don't exist on disk. That's the contract.

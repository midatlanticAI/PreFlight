// src/lib/cockpit-scan.js
//
// The STABLE embedding seam for host apps (e.g. the Atlan cockpit's Scan
// surface). One function: scan(files) -> { findings, score, ... }. Everything a
// host needs, nothing of the React UI.
//
// FIDELITY CONTRACT: this reproduces the EXACT scan sequence App.jsx runs for a
// dropped-in/GitHub project — not the dogfood test (which uses a different file
// selection and is only a noise-floor tracker). If you change the real scan in
// App.jsx, mirror it here, and the parity test (src/test/cockpit-scan.test.js)
// will fail loudly if the two drift. That is the whole point: a host must see
// what the browser sees.
//
// files: [{ path: string, content: string }]  (host collects them; probes are
//         pure synchronous functions over this array)
//
// Returns:
//   findings   — severity-sorted, each with .snippet (±5 lines), .stableId, and
//                probe meta attached (identical objects to what the app renders)
//   score      — computeScore(findings), security only. Null only when every
//                probe failed: zero findings from zero evidence is not a 100.
//   scores     — computeScores(findings), per-area breakdown (same null rule)
//   suppressions — repo-local .preflight.yml/json suppressions (host may apply)
//   inputFailures — [{ index, error }] for entries in `files` that are not
//                { path: string, content: string }. A bad entry is skipped so
//                the rest of the project still scans honestly, rather than
//                poisoning every file-iterating probe at once.
//   probeFailures — [{ probe, error }] for any probe that threw (scan never aborts)
//   engineFailures — [{ stage, error }] for any post-probe engine stage that
//                threw. The stage's output degrades (unsorted findings, missing
//                ids, empty suppressions); scan still returns.
//   filesScanned — how many files the probes actually saw (files.length minus
//                the inputFailures)
//
// FAILURE CONTRACT: the only throw is the TypeError below for a non-array
// `files` — that is a bug at the call site and should fail loud. Everything
// past it degrades and reports instead of throwing, because a host embeds this
// engine inside its own process (one ran scan() in a request handler and had
// the process exit when a stage threw). That includes the host's own
// opts.onProbeError / opts.onEngineError callbacks: a throwing callback is the
// error channel itself failing, so it is dropped rather than allowed to break
// the containment — the returned failure lists still carry everything. The
// browser app diverges on failure handling only: App.jsx wraps the whole scan
// and aborts with a message, a host gets a partial result plus the failure
// lists and decides for itself. On the success path the sequence and output
// match App.jsx, and the parity test replays App.jsx's stages to prove it.

import { PROBES, attachStableIds, attachProbeMeta } from './probes.js';
import { SEV_ORDER, computeScore, computeScores } from './scoring.js';
import { detectAppShape, applyAppShape } from './probes/v2/app-shape.js';
import { buildSnippet } from './snippet.js';
import {
  findPreflightConfigFile,
  parsePreflightConfig,
  configToSuppressions,
} from './preflight-config.js';

// Error text that cannot itself throw. String() on a null-prototype throw
// value raises "Cannot convert object to primitive value" — and every caller
// of this is inside a catch block, the one place a second throw would defeat
// the whole seam. Always returns a string, even for `throw { message: 42 }`.
function errText(err) {
  try {
    if (typeof err?.message === 'string' && err.message) return err.message;
    return String(err?.message ?? err);
  } catch {
    return 'unstringifiable error';
  }
}

export function scan(files, opts = {}) {
  if (!Array.isArray(files)) {
    throw new TypeError('scan(files): files must be an array of { path, content }');
  }
  // A default parameter does not catch an explicit null, and opts fields are
  // read on the FAILURE paths — the worst possible place to throw.
  if (!opts || typeof opts !== 'object') opts = {};

  // Host callbacks are a reporting channel, not a control channel: if one
  // throws, that report is dropped (the returned failure lists still carry
  // everything), because the alternative is the escape this seam exists to
  // prevent.
  const tell = (fn, a, b) => {
    if (typeof fn !== 'function') return;
    try {
      fn(a, b);
    } catch {
      /* the error channel failed; there is nowhere left to report */
    }
  };

  // 0) input hygiene: hosts collect `files` by walking real repos, and one
  // unreadable entry must not poison the good ones. Pre-containment a null
  // entry failed every file-iterating probe one at a time and then crashed the
  // snippet stage; contained naively, the same input yields zero findings and
  // a perfect score — the most misleading result a security scanner can
  // return. Skip and record instead, so the rest of the project scans
  // honestly. (Indexed loop, not forEach: forEach skips sparse-array holes and
  // a hole is exactly the kind of entry this exists to record.)
  const inputFailures = [];
  const scanFiles = [];
  for (let index = 0; index < files.length; index++) {
    const f = files[index];
    if (f && typeof f === 'object' && typeof f.path === 'string' && typeof f.content === 'string') {
      scanFiles.push(f);
    } else {
      inputFailures.push({ index, error: 'not a { path: string, content: string } object' });
    }
  }

  // Containment for the engine plumbing below (sort, snippets, ids, config,
  // shape, score). Probes already degrade one at a time; these stages used to
  // run bare, so a throw out of any one of them escaped to the host — a
  // wrong-typed config field was the live case. Same contract as
  // probeFailures: degrade, record, keep going.
  const engineFailures = [];
  const contained = (stage, fn, fallback) => {
    try {
      return fn();
    } catch (err) {
      engineFailures.push({ stage, error: errText(err) });
      tell(opts.onEngineError, stage, err);
      return fallback;
    }
  };

  // 1) run every probe (pure, synchronous) — one bad probe never aborts the scan
  const findings = [];
  const probeFailures = [];
  for (const probe of PROBES) {
    try {
      const found = probe.fn(scanFiles);
      if (!Array.isArray(found)) throw new Error(`probe returned non-array: ${typeof found}`);
      findings.push(...found);
    } catch (err) {
      // PROBES is exported mutable; even the catch must not trust the entry.
      const name = typeof probe?.name === 'string' ? probe.name : 'unknown probe';
      probeFailures.push({ probe: name, error: errText(err) });
      tell(opts.onProbeError, name, err);
    }
  }

  // 2) severity sort (App.jsx order)
  contained('severity-sort', () => {
    findings.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  });

  // 3) ±5-line code snapshot per finding (reports + agent prompts want context)
  contained('snippets', () => {
    const fileMap = new Map(scanFiles.map((f) => [f.path, f.content]));
    for (const f of findings) {
      try {
        const content = fileMap.get(f.file);
        if (content && f.line) f.snippet = buildSnippet(content, f.line, 5);
      } catch {
        /* snippet is best-effort, never fatal */
      }
    }
  });

  // 4) stable ids (NOTE: 2-arg — hashes probe+file+context from the FILES) + probe meta.
  //    Both MUTATE `findings` in place (they return nothing) — mirror App.jsx exactly.
  //    Contained separately: meta can still attach when the id hash fails.
  contained('stable-ids', () => attachStableIds(findings, scanFiles));
  contained('probe-meta', () => attachProbeMeta(findings));

  // 5) repo-local .preflight.yml/json suppressions (host applies over its own prefs).
  //    The config layer degrades wrong-typed fields itself now, but a repo
  //    config is untrusted input and this stage stays contained regardless.
  const suppressions = contained(
    'config-suppressions',
    () => {
      const configFile = findPreflightConfigFile(scanFiles);
      if (!configFile) return {};
      const cfg = parsePreflightConfig(configFile.path, configFile.content);
      return cfg.error ? {} : configToSuppressions(cfg, findings);
    },
    {}
  );

  // 5b) app shape: re-weight exposure-dependent findings for a
  // single-user local tool rather than dropping them.
  // Fallback is the unshaped findings: shown at full exposure weight, never dropped.
  const shaped = contained(
    'app-shape',
    () => applyAppShape(findings, detectAppShape(scanFiles)),
    findings
  );

  // 6) score. `score` is the headline security number; `scores` breaks it out
  // by area (security / health / accessibility / discoverability) so a host
  // can show where the outstanding work actually is. A wholesale probe
  // collapse nulls both instead: computeScore is total over garbage input, so
  // without this guard a scan where nothing ran would report a perfect 100.
  const probesCollapsed = PROBES.length > 0 && probeFailures.length >= PROBES.length;
  if (probesCollapsed) {
    engineFailures.push({ stage: 'score', error: 'every probe failed; no findings to score' });
  }
  const score = probesCollapsed ? null : contained('score', () => computeScore(shaped), null);
  const scores = probesCollapsed ? null : contained('scores', () => computeScores(shaped), null);

  return {
    findings: shaped,
    score,
    scores,
    suppressions,
    inputFailures,
    probeFailures,
    engineFailures,
    filesScanned: scanFiles.length,
  };
}

// Host-friendly engine metadata without importing the React tree.
// The engine's actual runtime dependencies, declared rather than inferred.
//
// Consumers vendor `src/lib` and `src/data` and then need to know what to
// install. Parsing import statements out of the vendored files looks like the
// obvious way to find out, and it is a trap: `src/lib/probes/v05/fixtures/`
// holds deliberately-vulnerable sample code that the probes parse as INPUT, and
// those samples contain real import statements. JS-AUTH-001's negative case
// imports `jsonwebtoken` purely as bait for the auth probe.
//
// That is not hypothetical. A downstream cockpit traced imports across the
// vendored tree and installed `jsonwebtoken` into its own dependency tree,
// where nothing ever ran it (found by an outside review, 2026-07-26). The
// failure is benign in that instance and would not stay benign: a fixture is
// exactly the place an attacker-shaped package name belongs, and this repo
// ships 100+ of them on purpose.
//
// So the engine states its own dependencies. Anything not listed here is a
// fixture, a sample, or scan input, and installing it is a mistake.
export const ENGINE_RUNTIME_DEPS = Object.freeze(['acorn', 'acorn-jsx', 'acorn-loose']);

export function engineInfo() {
  return {
    probeCount: PROBES.length,
    // PROBES is exported mutable; stay total even over a corrupted registry.
    probes: PROBES.map((p) => (typeof p?.name === 'string' ? p.name : null)),
    runtimeDeps: [...ENGINE_RUNTIME_DEPS],
  };
}

export { PROBES } from './probes.js';

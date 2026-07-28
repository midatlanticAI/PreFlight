// src/lib/sandbox/runner.js
//
// Pure scan runner for the sandbox surface. Takes a string of code, returns
// an array of findings shaped like every other probe's output so the existing
// FindingsPanel and (eventually) the live-probe UI can render them without a
// new contract.
//
// The first cut ran three probes and hardcoded the filename `sandbox.jsx`.
// Both turned out to be load-bearing rather than incidental. Three probes meant
// only 3 of 56 published Learn patterns had a probe the sandbox could execute,
// so fifty-three pages had nothing to link to; and a fixed extension meant
// every language-scoped check was unreachable no matter what you typed, because
// a probe that only reads `.py` never sees a buffer named `sandbox.jsx`.
//
// Both are open now: the probe set below, and a `filename` argument a shape can
// set so a Python shape is scanned as Python.
//
// The 156 v2 probes from preflight-v2-spec.md are still not plugged in. They
// will run through this same entry point when they ship, likely on a Web Worker
// so the main thread stays responsive on large files. This file's contract does
// not change when that move happens.

import {
  probeAICodeSmells,
  probeAPIRouteAuth,
  probeAuthWeakness,
  probeClientAuthStorage,
  probeCodeQuality,
  probeCookieFlags,
  probeCORS,
  probeIframeSandbox,
  probeLLMSecurity,
  probePathTraversal,
  probePythonSecurity,
  probeReflectedXSS,
  probeSecrets,
  probeSQLInjectionTemplateLiterals,
  probeStackTraceLeaks,
  probeTaintFlow,
  probeWeakCryptography,
  probeWeakRandomness,
} from '../probes.js';

// The default virtual filename. `.jsx` because most of what people paste is a
// React component, and several probes enable JSX-aware paths on the extension.
export const DEFAULT_SANDBOX_FILENAME = 'sandbox.jsx';

// The probes the sandbox runs, and the reasoning for the boundary.
//
// INCLUDED: every probe that can decide from ONE file. The sandbox holds a
// single buffer, so a probe that reads one file and answers about that file
// gives an honest answer here.
//
// EXCLUDED, deliberately, each for a reason a reader can check:
//
//   - Code Correctness reports references to undeclared identifiers. Correct
//     for a whole project, wrong for a snippet: a pasted handler legitimately
//     refers to `app`, `db` and `router` that live elsewhere. It would put a
//     finding on almost every buffer for the crime of being an excerpt.
//   - Corpus-level probes — Architecture, SEO, GEO, Host Detection, Security
//     Headers, Package.json, Env File Hygiene, Compromised Packages, Supabase
//     RLS, Firebase Rules. Each answers a question about a PROJECT: what shape
//     is it, what does it depend on, what did the host config say. One buffer
//     cannot answer any of those, and a confident answer from a single file
//     would be a guess wearing a finding's clothes.
//   - AI Codegen Bloat measures file length and cyclomatic complexity. On a
//     deliberately short teaching buffer that measures the exercise, not the
//     code.
const SANDBOX_PROBES = [
  probeCodeQuality,
  probeAICodeSmells,
  probeAuthWeakness,
  probeAPIRouteAuth,
  probeClientAuthStorage,
  probeCookieFlags,
  probeCORS,
  probeIframeSandbox,
  probeLLMSecurity,
  probePathTraversal,
  probePythonSecurity,
  probeReflectedXSS,
  probeSecrets,
  probeSQLInjectionTemplateLiterals,
  probeStackTraceLeaks,
  probeTaintFlow,
  probeWeakCryptography,
  probeWeakRandomness,
];

/**
 * Scan one buffer.
 *
 * @param {string} code
 * @param {string} [filename] the virtual path the probes see. The extension
 *   decides which language-scoped probes engage, so a Python shape passes a
 *   `.py` name and gets the Python checks.
 * @returns {Array} findings, each carrying a stable `id`
 */
export function runSandboxScan(code, filename = DEFAULT_SANDBOX_FILENAME) {
  if (typeof code !== 'string' || code.length === 0) return [];
  const path = typeof filename === 'string' && filename ? filename : DEFAULT_SANDBOX_FILENAME;
  const files = [{ path, content: code }];
  const findings = [];
  for (const probe of SANDBOX_PROBES) {
    // One probe throwing must not blank the panel. The editor re-scans on every
    // keystroke, so it is routinely handed half-typed code, and a parse failure
    // in one probe should cost that probe's findings and nothing else.
    try {
      const found = probe(files);
      if (found) findings.push(...found);
    } catch {
      // Deliberately quiet. Mid-keystroke input is not a defect to report.
    }
  }
  // Stable React keys for the panel. The probe-emitted `id` is preferred when
  // present; otherwise we derive one from the position in the merged array.
  return findings.map((f, i) => ({
    ...f,
    id: f.id || `sb-${i}-${f.probe || 'unknown'}`,
  }));
}

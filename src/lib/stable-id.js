// src/lib/stable-id.js
// Deterministic per-finding identifiers that survive line shifts and reformats, plus the
// per-probe confidence / autofix metadata that the UI surfaces alongside severity.
//
// Why the stableId hash exists: a finding's default uid=197610(jviru) gid=197610 groups=197610 field uses byte offsets, so any
// edit above a vulnerability invents a new id. That makes suppression and "have I seen
// this before" comparisons impossible. stableId() hashes (probe + file + title + ±3-line
// whitespace-normalized context) instead, so trivial reformats don't perturb the ID.

// --- Stable cross-scan finding ID ---
// The existing `id` field on each finding uses byte offsets, so adding a line above the
// vulnerability creates a new `id`. That makes suppression / "you've seen this before" impossible.
//
// stableId() returns a deterministic hash from {probe, file, title, ±3-line normalized context}.
// The context is whitespace-normalized so trivial reformats don't perturb the ID. The hash itself
// is a 32-bit FNV-1a → base36 (8 chars), fast in JS, collision rate is fine at this scale.

function fnv1a(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(36);
}

export function stableId(finding, fileContent) {
  const file = (finding.file || '').replace(/\\/g, '/');
  const lines = (fileContent || '').split('\n');
  const ln = finding.line || 0;
  const ctxStart = Math.max(0, ln - 4);
  const ctxEnd = Math.min(lines.length, ln + 3);
  const ctx = lines
    .slice(ctxStart, ctxEnd)
    .map((s) => s.replace(/\s+/g, ' ').trim())
    .filter(Boolean)
    .join('|');
  const key = `${finding.probe}|${file}|${finding.title}|${ctx}`;
  return fnv1a(key);
}

// Apply stableId to every finding. Pure helper — call from handleScan after probes run.
export function attachStableIds(findings, files) {
  const fileMap = new Map(files.map((f) => [f.path, f.content]));
  findings.forEach((f) => {
    f.stableId = stableId(f, fileMap.get(f.file));
  });
  return findings;
}

// --- Probe metadata: confidence + fixability ---
// Each probe declares two attributes the UI surfaces alongside severity:
//
//   confidence:
//     'high'      — deterministic pattern match. Almost no false positives in practice.
//     'medium'    — regex matches that need a glance of context to validate.
//     'heuristic' — path / structural inference; real but warrants manual review.
//
//   autofix:
//     'mechanical'    — a one-or-two-line drop-in patch fixes it cleanly.
//     'review-needed' — clear remediation path but requires reading the surrounding code.
//     'manual'        — architectural / scope-dependent; no canned fix.
//
// These aren't severity. A 'critical' + 'heuristic' finding still demands attention; the
// tag just tells the user "look at this twice before acting." A 'low' + 'mechanical' finding
// is the 30-second win that's worth doing before merge.
// `learn_more_slug` (optional) — when set, FindingCard renders a "Learn more about
// this pattern →" link to /learn/patterns/<slug> IF the markdown file exists AND
// is not a draft. Graceful fallback: missing or draft file = link hidden.
export const PROBE_META = {
  // Deterministic + mechanical: drop-in patches
  'Env File Hygiene': { confidence: 'high', autofix: 'mechanical' },
  'AI Rules Files': { confidence: 'high', autofix: 'mechanical' },
  'Trojan Source': { confidence: 'high', autofix: 'mechanical' },
  'Package Manager Hardening': { confidence: 'high', autofix: 'mechanical' },
  'Slopsquat / Typosquat': { confidence: 'high', autofix: 'mechanical' },

  // Deterministic + needs-review: clear fix but requires looking around
  'Secret Scanner': {
    confidence: 'high',
    autofix: 'review-needed',
    learn_more_slug: 'secret-scanner',
  },
  'NEXT_PUBLIC_ Misuse': {
    confidence: 'high',
    autofix: 'review-needed',
    learn_more_slug: 'next-public-misuse',
  },
  'Compromised Packages': {
    confidence: 'high',
    autofix: 'review-needed',
    learn_more_slug: 'package-json-supply-chain',
  },
  'Malicious Artifacts': { confidence: 'high', autofix: 'manual' },

  // Pattern matches: regex + light context
  CORS: { confidence: 'medium', autofix: 'mechanical' },
  'Cookie Security': { confidence: 'medium', autofix: 'mechanical' },
  'HTML Hygiene': { confidence: 'medium', autofix: 'mechanical' },
  'A11y Landmarks': { confidence: 'medium', autofix: 'mechanical' },
  'SEO Hygiene': { confidence: 'medium', autofix: 'mechanical' },
  'GEO Hygiene': { confidence: 'medium', autofix: 'mechanical' },

  // Pattern matches that need real fix work
  'Supabase RLS': {
    confidence: 'medium',
    autofix: 'review-needed',
    learn_more_slug: 'supabase-rls',
  },
  'Firebase Rules': { confidence: 'medium', autofix: 'review-needed' },
  'Auth Weakness': {
    confidence: 'medium',
    autofix: 'review-needed',
    learn_more_slug: 'auth-weakness',
  },
  'Webhook Validation': { confidence: 'medium', autofix: 'review-needed' },
  'GitHub Actions': { confidence: 'medium', autofix: 'review-needed' },
  'Client Auth Storage': { confidence: 'medium', autofix: 'review-needed' },
  'SSRF / Open Redirect': { confidence: 'medium', autofix: 'review-needed' },
  'MCP Security': { confidence: 'medium', autofix: 'review-needed' },
  'URL Reputation': { confidence: 'medium', autofix: 'manual' },
  'AI Code Smells': { confidence: 'medium', autofix: 'review-needed' },
  'Code Correctness': { confidence: 'high', autofix: 'mechanical' },

  // Heuristics that benefit from manual scrutiny
  'Admin Route Exposure': { confidence: 'heuristic', autofix: 'manual' },
  'API Route Auth': { confidence: 'heuristic', autofix: 'manual' },
  'Security Headers': { confidence: 'medium', autofix: 'review-needed' },
  'LLM Security': { confidence: 'heuristic', autofix: 'review-needed' },
  'Code Quality': { confidence: 'medium', autofix: 'manual' },

  // Architectural classification — informational, no autofix
  Architecture: { confidence: 'heuristic', autofix: 'manual' },

  // Package.json supply-chain hooks (catch-all)
  'Package.json': { confidence: 'medium', autofix: 'mechanical' },
  'Supply Chain': { confidence: 'medium', autofix: 'mechanical' },
  'Code Injection': { confidence: 'medium', autofix: 'review-needed' },
};

// Attach probe-level confidence and autofix metadata to each finding.
export function attachProbeMeta(findings) {
  findings.forEach((f) => {
    const meta = PROBE_META[f.probe];
    if (meta) {
      f.confidence = meta.confidence;
      f.autofix = meta.autofix;
      if (meta.learn_more_slug) f.learn_more_slug = meta.learn_more_slug;
    } else {
      // Default: treat as medium / manual when we haven't classified a probe yet.
      f.confidence = 'medium';
      f.autofix = 'manual';
    }
  });
  return findings;
}

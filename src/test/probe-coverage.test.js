// Probe-coverage test: every probe in PROBES has either a published Learn
// pattern wired through PROBE_META.learn_more_slug, or is explicitly listed
// as exempt with a documented reason.
//
// Why this test exists: when the user clicks "Learn more" on a finding, they
// expect the link to resolve. A draft pattern, a missing slug, or a typo'd
// slug breaks the UX silently. The test asserts the bridge end-to-end.

import { describe, it, expect } from 'vitest';
import { PROBES } from '../lib/probes.js';
import {
  PROBE_META,
  PROBE_OWASP_MAP,
  OWASP_LABELS,
  OWASP_BY_PROBE,
  attachProbeMeta,
} from '../lib/stable-id.js';
import { LEARN_ENTRIES, resolvePatternForProbe } from '../lib/learn-content.js';

// Probes that intentionally have no dedicated pattern page. Each must carry a
// brief reason here so a future contributor reading the test understands why
// the exemption exists.
const EXEMPT = new Map([
  [
    'Architecture',
    'Architecture is a classifier emitting shape-aware informational findings. The natural Learn destination is the matching /learn/shapes/ page rather than a single pattern slug.',
  ],
]);

describe('probe coverage', () => {
  it('every registered probe has a PROBE_META entry', () => {
    const missing = PROBES.filter((p) => !PROBE_META[p.name]).map((p) => p.name);
    expect(missing).toEqual([]);
  });

  it('every probe is either wired to a learn_more_slug or explicitly exempt', () => {
    const unwired = PROBES.filter((p) => {
      const meta = PROBE_META[p.name];
      return !meta?.learn_more_slug && !EXEMPT.has(p.name);
    }).map((p) => p.name);
    expect(unwired).toEqual([]);
  });

  it('every learn_more_slug resolves to an existing Learn entry', () => {
    const unresolved = [];
    for (const probe of PROBES) {
      const slug = PROBE_META[probe.name]?.learn_more_slug;
      if (!slug) continue;
      const entry = LEARN_ENTRIES.find((e) => e.slug === slug);
      if (!entry) unresolved.push(`${probe.name} → ${slug}`);
    }
    expect(unresolved).toEqual([]);
  });

  it('every learn_more_slug resolves to a non-draft pattern (so the in-app link works)', () => {
    const failures = [];
    for (const probe of PROBES) {
      const slug = PROBE_META[probe.name]?.learn_more_slug;
      if (!slug) continue;
      const resolved = resolvePatternForProbe(slug);
      if (!resolved) {
        failures.push(
          `${probe.name} → ${slug} (entry exists but is draft, wrong type, or missing)`
        );
      }
    }
    expect(failures).toEqual([]);
  });

  it('every probe (except the exempt ones) has a corresponding pattern entry of type "pattern"', () => {
    const missing = [];
    for (const probe of PROBES) {
      if (EXEMPT.has(probe.name)) continue;
      const slug = PROBE_META[probe.name]?.learn_more_slug;
      const entry = LEARN_ENTRIES.find((e) => e.slug === slug && e.type === 'pattern');
      if (!entry) missing.push(`${probe.name} → ${slug ?? '<no slug>'}`);
    }
    expect(missing).toEqual([]);
  });

  it('the EXEMPT list has a documented reason for each entry', () => {
    for (const [name, reason] of EXEMPT.entries()) {
      expect(typeof reason).toBe('string');
      expect(reason.length).toBeGreaterThan(40);
      const stillRegistered = PROBES.some((p) => p.name === name);
      expect(stillRegistered).toBe(true);
    }
  });
});

// ---- OWASP coverage contract ----
//
// Every probe named inside PROBE_OWASP_MAP must be a registered probe. Every
// OWASP code that has probes mapped to it must have a human-readable label.
// attachProbeMeta() must attach the owasp array to a finding whose probe name
// appears in the mapping.

describe('OWASP coverage mapping', () => {
  it('every PROBE_OWASP_MAP entry references a registered probe', () => {
    const registered = new Set(PROBES.map((p) => p.name));
    const unknown = [];
    for (const [code, probes] of Object.entries(PROBE_OWASP_MAP)) {
      for (const probe of probes) {
        if (!registered.has(probe)) {
          unknown.push(`${code} -> ${probe}`);
        }
      }
    }
    expect(unknown).toEqual([]);
  });

  it('every OWASP code in PROBE_OWASP_MAP has a label in OWASP_LABELS', () => {
    const missing = Object.keys(PROBE_OWASP_MAP).filter((code) => !OWASP_LABELS[code]);
    expect(missing).toEqual([]);
  });

  it('every label in OWASP_LABELS is used (no dead entries)', () => {
    const used = new Set(Object.keys(PROBE_OWASP_MAP));
    const unused = Object.keys(OWASP_LABELS).filter((code) => !used.has(code));
    expect(unused).toEqual([]);
  });

  it('attachProbeMeta attaches the owasp array to findings whose probe maps', () => {
    const findings = [
      { probe: 'SQL Injection', severity: 'critical', title: 't', file: 'a.js' },
      { probe: 'Path Traversal', severity: 'high', title: 't', file: 'a.js' },
      { probe: 'Architecture', severity: 'info', title: 't', file: 'a.js' },
    ];
    attachProbeMeta(findings);
    expect(findings[0].owasp).toContain('A03');
    expect(findings[1].owasp).toContain('A01');
    // Architecture is intentionally not OWASP-mapped (it's a classifier).
    expect(findings[2].owasp).toBeUndefined();
  });

  it('every security-class probe has at least one OWASP mapping (or is in EXEMPT)', () => {
    // Probes that are intentionally not OWASP-mapped: discoverability (SEO,
    // GEO), accessibility (A11y), or pure classifiers (Architecture).
    const NON_OWASP_PROBES = new Set([
      'SEO Hygiene',
      'GEO Hygiene',
      'A11y Landmarks',
      'Architecture',
    ]);
    const unmapped = PROBES.filter((p) => {
      if (NON_OWASP_PROBES.has(p.name)) return false;
      return !OWASP_BY_PROBE[p.name] || OWASP_BY_PROBE[p.name].length === 0;
    }).map((p) => p.name);
    expect(unmapped).toEqual([]);
  });
});

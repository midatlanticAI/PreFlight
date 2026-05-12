// Probe-coverage test: every probe in PROBES has either a published Learn
// pattern wired through PROBE_META.learn_more_slug, or is explicitly listed
// as exempt with a documented reason.
//
// Why this test exists: when the user clicks "Learn more" on a finding, they
// expect the link to resolve. A draft pattern, a missing slug, or a typo'd
// slug breaks the UX silently. The test asserts the bridge end-to-end.

import { describe, it, expect } from 'vitest';
import { PROBES } from '../lib/probes.js';
import { PROBE_META } from '../lib/stable-id.js';
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
        failures.push(`${probe.name} → ${slug} (entry exists but is draft, wrong type, or missing)`);
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

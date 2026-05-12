// Tests for src/lib/learn-content.js — the markdown frontmatter parser + content registry
// that drives the /learn route. Guards: every shipped .md file parses, the entry shape
// matches the expected schema, type filters work, draft-aware resolution gates the
// FindingCard cross-link correctly.

import { describe, it, expect } from 'vitest';
import {
  LEARN_ENTRIES,
  getManifesto,
  getByType,
  getBySlug,
  resolvePatternForProbe,
} from '../lib/learn-content.js';

describe('LEARN_ENTRIES', () => {
  it('parses at least one entry per content type', () => {
    expect(LEARN_ENTRIES.length).toBeGreaterThan(0);
    expect(LEARN_ENTRIES.some((e) => e.type === 'manifesto')).toBe(true);
    expect(LEARN_ENTRIES.some((e) => e.type === 'pattern')).toBe(true);
    expect(LEARN_ENTRIES.some((e) => e.type === 'incident')).toBe(true);
    expect(LEARN_ENTRIES.some((e) => e.type === 'shape')).toBe(true);
  });

  it('every entry has the required frontmatter shape', () => {
    for (const e of LEARN_ENTRIES) {
      expect(typeof e.slug).toBe('string');
      expect(e.slug.length).toBeGreaterThan(0);
      expect(typeof e.title).toBe('string');
      expect(e.title.length).toBeGreaterThan(0);
      expect(['manifesto', 'pattern', 'incident', 'shape']).toContain(e.type);
      expect(typeof e.draft).toBe('boolean');
      expect(Array.isArray(e.related_probe_ids)).toBe(true);
      expect(Array.isArray(e.related_incident_slugs)).toBe(true);
      expect(Array.isArray(e.sources)).toBe(true);
      expect(typeof e.body).toBe('string');
      // Incident-specific structured fields — all optional, but must be either the
      // correct primitive type or null. The parser guards against bad-shape values.
      expect(e.cve === null || typeof e.cve === 'string').toBe(true);
      expect(e.cvss === null || typeof e.cvss === 'number').toBe(true);
      expect(e.campaign === null || typeof e.campaign === 'string').toBe(true);
      expect(e.threat_actor === null || typeof e.threat_actor === 'string').toBe(true);
      expect(e.attack_date === null || typeof e.attack_date === 'string').toBe(true);
    }
  });

  it('the published TanStack field report populates the incident metadata fields', () => {
    // Guards against schema drift — if any of these get silently dropped by the parser,
    // the EntryView's incident-metadata header stops rendering them.
    const tanstack = LEARN_ENTRIES.find((e) => e.slug === 'mini-shai-hulud-tanstack-2026-05');
    expect(tanstack).toBeDefined();
    expect(tanstack.cve).toBe('CVE-2026-45321');
    expect(tanstack.cvss).toBe(9.6);
    expect(tanstack.campaign).toBe('Mini Shai-Hulud');
    expect(tanstack.threat_actor).toBe('TeamPCP');
    expect(tanstack.attack_date).toBe('2026-05-11');
  });

  it('slugs are unique across the whole registry', () => {
    const slugs = LEARN_ENTRIES.map((e) => e.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
  });
});

describe('getManifesto', () => {
  it('returns the manifesto entry', () => {
    const m = getManifesto();
    expect(m).toBeDefined();
    expect(m.type).toBe('manifesto');
    expect(m.slug).toBe('manifesto');
  });
});

describe('getByType', () => {
  it('returns all entries of a given type, alphabetically by title', () => {
    const patterns = getByType('pattern');
    expect(patterns.length).toBeGreaterThan(0);
    expect(patterns.every((e) => e.type === 'pattern')).toBe(true);
    // Confirm sort: titles ascending
    for (let i = 1; i < patterns.length; i++) {
      expect(patterns[i - 1].title.localeCompare(patterns[i].title)).toBeLessThanOrEqual(0);
    }
  });

  it('returns [] for unknown type', () => {
    expect(getByType('not-a-real-type')).toEqual([]);
  });
});

describe('getBySlug', () => {
  it('returns the entry with the given slug', () => {
    // Use a slug we know ships in the repo
    const entry = getBySlug('manifesto');
    expect(entry).toBeDefined();
    expect(entry.slug).toBe('manifesto');
  });

  it('returns undefined for a non-existent slug', () => {
    expect(getBySlug('never-going-to-exist-xyz123')).toBeUndefined();
  });
});

describe('resolvePatternForProbe', () => {
  // FindingCard uses this to decide whether to surface a "Learn more →" link.
  // Three failure modes the function must handle without exploding:
  //   - slug is null / undefined / empty
  //   - slug refers to a non-existent entry
  //   - slug refers to a draft entry (link must NOT be shown)
  //   - slug refers to a non-pattern type (link must NOT be shown)
  it('returns null when slug is falsy', () => {
    expect(resolvePatternForProbe(null)).toBeNull();
    expect(resolvePatternForProbe(undefined)).toBeNull();
    expect(resolvePatternForProbe('')).toBeNull();
  });

  it('returns null when slug does not resolve to any entry', () => {
    expect(resolvePatternForProbe('definitely-not-a-real-slug')).toBeNull();
  });

  it('returns null when the entry is a draft (graceful fallback)', () => {
    // All current pattern files are drafts — pick one we know ships as draft
    const draftPattern = getByType('pattern').find((p) => p.draft === true);
    if (draftPattern) {
      expect(resolvePatternForProbe(draftPattern.slug)).toBeNull();
    }
  });

  it('returns null when the slug points at a non-pattern type', () => {
    // manifesto is a real entry but type is "manifesto", not "pattern"
    expect(resolvePatternForProbe('manifesto')).toBeNull();
  });

  // The "happy path" test fires once we publish a non-draft pattern. Until then,
  // the resolvePatternForProbe('secret-scanner') call returns null because the
  // .md file ships with draft: true. When we promote secret-scanner.md to
  // draft: false, this test will start passing automatically — leaving it here
  // as a forward-looking guard.
  it('returns the entry when a pattern is published (FUTURE — currently expected null)', () => {
    const result = resolvePatternForProbe('secret-scanner');
    const pattern = getBySlug('secret-scanner');
    if (pattern && !pattern.draft) {
      expect(result).toBe(pattern);
    } else {
      // Currently a draft, so resolver returns null — that's the graceful fallback.
      expect(result).toBeNull();
    }
  });
});

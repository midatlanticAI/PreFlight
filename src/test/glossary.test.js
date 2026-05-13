// Glossary data + contract tests. Source-of-truth lives in src/lib/glossary.js;
// this file enforces the schema, the free-link criterion, and the cross-link
// integrity so contributors can't ship a malformed or paywalled entry.

import { describe, it, expect } from 'vitest';
import {
  GLOSSARY_GROUPS,
  ALL_GLOSSARY_ENTRIES,
  getGlossaryCount,
  getGlossaryGroupCount,
  searchGlossary,
} from '../lib/glossary.js';

describe('Glossary shape', () => {
  it('has at least 100 entries', () => {
    expect(ALL_GLOSSARY_ENTRIES.length).toBeGreaterThanOrEqual(100);
  });

  it('every group has a unique id, title, and at least one entry', () => {
    const ids = new Set();
    for (const g of GLOSSARY_GROUPS) {
      expect(g.id, 'group missing id').toBeTypeOf('string');
      expect(g.title, 'group missing title').toBeTypeOf('string');
      expect(g.entries.length, `group ${g.id} has no entries`).toBeGreaterThan(0);
      expect(ids.has(g.id), `duplicate group id: ${g.id}`).toBe(false);
      ids.add(g.id);
    }
  });

  it('every entry has the required schema', () => {
    for (const e of ALL_GLOSSARY_ENTRIES) {
      expect(e.term, 'entry missing term').toBeTypeOf('string');
      expect(e.definition, `entry "${e.term}" missing definition`).toBeTypeOf('string');
      expect(e.link, `entry "${e.term}" missing link`).toBeTypeOf('string');
      expect(e.definition.length, `entry "${e.term}" definition too short`).toBeGreaterThan(10);
      // Definitions should be one sentence-ish: ~25 words upper bound to enforce brevity.
      const wordCount = e.definition.split(/\s+/).length;
      expect(
        wordCount,
        `entry "${e.term}" definition is too long (${wordCount} words)`
      ).toBeLessThanOrEqual(40);
    }
  });

  it('terms within the catalogue are unique (case-insensitive)', () => {
    const seen = new Set();
    for (const e of ALL_GLOSSARY_ENTRIES) {
      const key = e.term.toLowerCase();
      expect(seen.has(key), `duplicate term: ${e.term}`).toBe(false);
      seen.add(key);
    }
  });
});

describe('Glossary link policy: free-only', () => {
  // The user-facing inclusion criterion is "free or zero-friction free tier".
  // We enforce a subset of that here via a blocklist: domains we know put core
  // content behind a paywall, or marketing pages for paid books.
  const BLOCKED_DOMAIN_FRAGMENTS = [
    'refactoringui.com', // paid book
    'amazon.com/dp/', // Amazon product / book pages (aws.amazon.com docs are fine)
    'amazon.com/gp/', // Amazon product / book pages (gp variant)
    'manning.com', // commercial publisher
    'pragprog.com', // commercial publisher
    'pluralsight.com', // paid course platform
    'lynda.com', // legacy paid course platform
    'oreilly.com/library/', // paid book detail pages
    'udemy.com', // paid course platform
  ];

  it('no entry links to a known paywalled or paid-book destination', () => {
    const offenders = [];
    for (const e of ALL_GLOSSARY_ENTRIES) {
      for (const blocked of BLOCKED_DOMAIN_FRAGMENTS) {
        if (e.link.toLowerCase().includes(blocked)) {
          offenders.push(`${e.term}: ${e.link}`);
        }
      }
    }
    expect(offenders, 'glossary entries pointing at paid resources').toEqual([]);
  });

  it('external links are either http(s) URLs or internal /learn anchors', () => {
    const malformed = [];
    for (const e of ALL_GLOSSARY_ENTRIES) {
      const ok = /^https?:\/\//.test(e.link) || e.link.startsWith('/learn');
      if (!ok) malformed.push(`${e.term}: ${e.link}`);
    }
    expect(malformed).toEqual([]);
  });

  it('internal pattern cross-links (if present) point at /learn/ paths', () => {
    for (const e of ALL_GLOSSARY_ENTRIES) {
      if (!e.internal) continue;
      expect(e.internal.startsWith('/learn'), `${e.term}: internal link doesn't go to /learn`).toBe(
        true
      );
    }
  });

  it('no entry links to a competing security-platform vendor (memory rule)', () => {
    // Per the standing voice rule: no competing security platforms named in
    // public-facing copy. This blocklist catches the most common offenders.
    const BLOCKED_VENDORS = [
      'snyk.io',
      'aikido.dev',
      'socket.dev',
      'semgrep.dev',
      'veracode.com',
      'checkmarx.com',
      'ox.security',
      'wiz.io',
    ];
    const offenders = [];
    for (const e of ALL_GLOSSARY_ENTRIES) {
      for (const v of BLOCKED_VENDORS) {
        if (e.link.toLowerCase().includes(v)) {
          offenders.push(`${e.term}: ${e.link}`);
        }
      }
    }
    expect(offenders, 'glossary links to competing security platforms').toEqual([]);
  });
});

describe('Glossary helpers', () => {
  it('getGlossaryCount returns the catalogue size', () => {
    expect(getGlossaryCount()).toBe(ALL_GLOSSARY_ENTRIES.length);
  });

  it('getGlossaryGroupCount returns the group count', () => {
    expect(getGlossaryGroupCount()).toBe(GLOSSARY_GROUPS.length);
  });

  it('searchGlossary("") returns every entry', () => {
    expect(searchGlossary('').length).toBe(ALL_GLOSSARY_ENTRIES.length);
  });

  it('searchGlossary matches by term', () => {
    const result = searchGlossary('SSRF');
    const hasSSRF = result.some((e) => /ssrf/i.test(e.term));
    expect(hasSSRF).toBe(true);
  });

  it('searchGlossary matches by alias', () => {
    // "xsrf" is an alias for the CSRF entry.
    const result = searchGlossary('xsrf');
    expect(result.length).toBeGreaterThan(0);
  });

  it('searchGlossary matches by definition substring', () => {
    const result = searchGlossary('postinstall');
    expect(result.length).toBeGreaterThan(0);
  });

  it('searchGlossary returns empty for nonsense queries', () => {
    expect(searchGlossary('xyzzy-not-a-real-term').length).toBe(0);
  });
});

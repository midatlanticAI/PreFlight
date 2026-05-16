// v1 step B — educational-material uniformity.
//
// learn-content.test.js already enforces the generic frontmatter shape and
// probe-coverage proves every probe resolves a published page. This suite
// enforces VOICE + STRUCTURE uniformity across the cohesive content this
// v0.5 + compliance work added (5 XL family pages + 9 compliance pages),
// so the set stays consistent and a future addition cannot quietly drift:
//   - frontmatter: slug matches filename, type pattern, not draft, a
//     non-empty summary, >=1 primary-source {title,url}
//   - body voice (CLAUDE.md): no em-dashes, none of the banned marketing
//     words. (Frontmatter source titles quote external pages verbatim and
//     are intentionally not voice-checked.)
//   - body structure: real section headings; compliance pages must carry
//     the scan-vs-teach statement AND a not-legal-advice disclaimer.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { getBySlug, LEARN_ENTRIES } from '../lib/learn-content.js';

// Shapes is teaching content: it covers the architecture taxonomy the
// classifier recognizes, not only the shapes that emit a finding. Every
// page carries a "Scanner behavior" line differentiating "flags" from
// "classifies". The four FINDING-emitting shapes (FLAG_SHAPES) must be a
// subset of the pages (ecosystem-complete, like probe-coverage); the
// rest are classify/teach-only.
const FLAG_SHAPES = ['monolithic-spa', 'monorepo', 'static-html-build', 'ssr'];
const SHAPE_PAGES = [
  ...FLAG_SHAPES,
  'modular-spa',
  'ssg',
  'mobile',
  'desktop-tauri',
  'desktop-electron',
  'cli',
  'cli-ink',
  'backend-api',
  'library',
  'python-project',
  'notebook',
];
const XL_PAGES = [
  'xl-unsafe-deserialization',
  'xl-raw-query-interpolation',
  'xl-tls-verification-disabled',
  'xl-hardcoded-secrets',
  'xl-auth-token-verification',
];
const SCAN_PAGES = ['compliance-hipaa', 'compliance-pci-dss', 'compliance-gdpr', 'compliance-soc2'];
const EDU_PAGES = [
  'compliance-ferpa',
  'compliance-sox',
  'compliance-fda',
  'compliance-ftc',
  'compliance-eu-ai-act',
];
const ALL = [...XL_PAGES, ...SCAN_PAGES, ...EDU_PAGES];

// Curated AI-slop lexicon (CLAUDE.md voice rules + the corpus-study tells).
// High-signal, low-false-positive only: words that almost never appear in
// the manifesto's plain register and reliably mark inflated AI diction.
// Deliberately NOT banned: "ecosystem" (the manifesto uses it), "navigate"
// / "intricate" (legitimate technical senses), and common fillers like
// "just"/"very" (too FP-prone for a hard lint).
const BANNED =
  /\b(comprehensive|best-in-class|powerful|robust|enterprise-grade|unlock|leverage|seamless|delve|utilize|harness|foster|elevate|unveil|embark|garner|bolster|underscore|tapestry|realm|testament|beacon|treasure trove|synergy|multifaceted|meticulous|commendable|transformative|unparalleled|unwavering|groundbreaking|cutting-edge|pivotal|paramount)\b/i;
// Performative-gravitas phrases (Pattern 1.1.2 / 1.2.1 / 1.3.1).
const SLOP_PHRASES =
  /it'?s (important|worth) (to )?note|in the realm of|fast-paced|ever-evolving|in a world where|stands? as a testament|shed light on|when it comes to|in essence,|in conclusion|ultimately,|navigate the complexit/i;

const raw = (slug) => readFileSync(join(process.cwd(), 'src/learn/patterns', `${slug}.md`), 'utf8');
const rawShape = (slug) =>
  readFileSync(join(process.cwd(), 'src/learn/shapes', `${slug}.md`), 'utf8');
const bodyOf = (text) => {
  // strip the leading --- frontmatter --- block
  const m = text.match(/^---\n[\s\S]*?\n---\n([\s\S]*)$/);
  return m ? m[1] : text;
};

describe('learn uniformity: frontmatter is complete and consistent', () => {
  for (const slug of ALL) {
    it(`${slug} has a published, well-formed pattern entry`, () => {
      const e = getBySlug(slug);
      expect(e, `${slug} not in registry`).toBeDefined();
      expect(e.slug).toBe(slug);
      expect(e.type).toBe('pattern');
      expect(e.draft).toBe(false);
      expect(typeof e.title).toBe('string');
      expect(e.title.length).toBeGreaterThan(0);
      expect(typeof e.summary).toBe('string');
      expect(e.summary.trim().length).toBeGreaterThan(20);
      expect(Array.isArray(e.sources)).toBe(true);
      expect(e.sources.length).toBeGreaterThan(0);
      for (const s of e.sources) {
        expect(typeof s.title).toBe('string');
        expect(s.url).toMatch(/^https?:\/\//);
      }
    });
  }
});

describe('learn uniformity: body voice (CLAUDE.md rules)', () => {
  for (const slug of ALL) {
    it(`${slug} body has no em-dash, slop word, or gravitas phrase`, () => {
      const body = bodyOf(raw(slug));
      expect(body.includes('—'), `${slug}: em-dash in body`).toBe(false);
      const w = body.match(BANNED);
      expect(w, `${slug}: AI-slop word "${w && w[0]}"`).toBe(null);
      const p = body.match(SLOP_PHRASES);
      expect(p, `${slug}: performative-gravitas phrase "${p && p[0]}"`).toBe(null);
    });

    it(`${slug} has real section headings`, () => {
      const body = bodyOf(raw(slug));
      const headings = (body.match(/^##\s+\S/gm) || []).length;
      expect(headings, `${slug}: needs >=2 section headings`).toBeGreaterThanOrEqual(2);
    });
  }
});

describe('learn uniformity: compliance pages state scope + disclaimer', () => {
  for (const slug of [...SCAN_PAGES, ...EDU_PAGES]) {
    it(`${slug} carries a not-legal-advice disclaimer`, () => {
      const body = bodyOf(raw(slug)).toLowerCase();
      expect(body).toMatch(/not legal advice|not .*attestation|not .*advice/);
    });
  }
  for (const slug of SCAN_PAGES) {
    it(`${slug} states it IS in scan scope`, () => {
      expect(bodyOf(raw(slug))).toMatch(/in scan scope/i);
    });
  }
  for (const slug of EDU_PAGES) {
    it(`${slug} states Pre-Flight does NOT scan for it`, () => {
      expect(bodyOf(raw(slug))).toMatch(/does not scan for/i);
    });
  }
});

describe('learn uniformity: Shapes are comprehensive, published, on-voice', () => {
  for (const slug of SHAPE_PAGES) {
    it(`${slug} is a published shape with complete frontmatter`, () => {
      const e = getBySlug(slug);
      expect(e, `${slug} not in registry`).toBeDefined();
      expect(e.slug).toBe(slug);
      expect(e.type).toBe('shape');
      expect(e.draft).toBe(false);
      expect(typeof e.title).toBe('string');
      expect(e.summary.trim().length).toBeGreaterThan(20);
      expect(Array.isArray(e.sources)).toBe(true);
      expect(e.sources.length).toBeGreaterThan(0);
    });

    it(`${slug} is comprehensive (not a stub) and on-voice`, () => {
      const body = bodyOf(rawShape(slug));
      // a real page, not the old "content coming soon" placeholder
      expect(body).not.toMatch(/content coming soon|_Draft/i);
      expect(body.length).toBeGreaterThan(1200);
      expect((body.match(/^##\s+\S/gm) || []).length).toBeGreaterThanOrEqual(4);
      expect(body.includes('—'), `${slug}: em-dash in body`).toBe(false);
      const w = body.match(BANNED);
      expect(w, `${slug}: AI-slop word "${w && w[0]}"`).toBe(null);
      const p = body.match(SLOP_PHRASES);
      expect(p, `${slug}: gravitas phrase "${p && p[0]}"`).toBe(null);
    });
  }
});

describe('learn uniformity: Shapes differentiate flag vs classify', () => {
  for (const slug of SHAPE_PAGES) {
    it(`${slug} has a Scanner behavior section that says flags or classifies`, () => {
      const body = bodyOf(rawShape(slug));
      expect(body).toMatch(/##\s+Scanner behavior/);
      expect(body).toMatch(/Pre-Flight (flags|classifies) this shape/);
    });
  }

  it('flag-emitting shapes say "flags"; teach-only shapes say "classifies"', () => {
    for (const slug of SHAPE_PAGES) {
      const body = bodyOf(rawShape(slug));
      if (FLAG_SHAPES.includes(slug)) {
        expect(body, `${slug} should flag`).toMatch(/Pre-Flight flags this shape/);
      } else {
        expect(body, `${slug} should classify`).toMatch(/Pre-Flight classifies this shape/);
      }
    }
  });

  it('every FINDING-emitting shape has a page (ecosystem-complete)', () => {
    for (const s of FLAG_SHAPES) expect(SHAPE_PAGES).toContain(s);
  });
});

describe('learn uniformity: no draft ever ships', () => {
  it('every Learn entry in the registry is published (no draft:true)', () => {
    const drafts = LEARN_ENTRIES.filter((e) => e.draft === true).map((e) => e.slug);
    expect(drafts, `draft Learn entries: ${drafts.join(', ')}`).toEqual([]);
  });
});

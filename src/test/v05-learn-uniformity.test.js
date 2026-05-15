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
import { getBySlug } from '../lib/learn-content.js';

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
const BANNED =
  /\b(comprehensive|best-in-class|powerful|robust|enterprise-grade|unlock|leverage|seamless)\b/i;

const raw = (slug) => readFileSync(join(process.cwd(), 'src/learn/patterns', `${slug}.md`), 'utf8');
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
    it(`${slug} body has no em-dash and no marketing words`, () => {
      const body = bodyOf(raw(slug));
      expect(body.includes('—'), `${slug}: em-dash in body`).toBe(false);
      const hit = body.match(BANNED);
      expect(hit, `${slug}: banned marketing word "${hit && hit[0]}"`).toBe(null);
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

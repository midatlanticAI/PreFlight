// Compliance phase. The locked /goal's final layer: a scan-scope
// regulatory interpretation mapping (HIPAA / PCI-DSS / GDPR / SOC2)
// attached at the XL-family level and inherited by adapters, plus
// education-scope Learn pages for the frameworks Pre-Flight teaches but
// does NOT scan (FERPA / SOX / FDA / FTC / EU-AI-Act).
//
// Load-bearing legal constraints under test:
//   - scan scope is narrow: only the four code-detectable frameworks may
//     appear in compliance_refs; the education-only five are rejected
//   - compliance is an interpretation layer (relationship direct|
//     indicative) with auditable provenance (ISO last_reviewed), never a
//     certification
//   - every framework gets a Learn page that states plainly whether
//     Pre-Flight scans for it or only teaches it
//
// Reference: docs/v05-research/v05-architecture.md; locked /goal
//            (scan scope vs education scope).

import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PROBE_MANIFEST_V05, validateComplianceRefs } from '../lib/probes/v05/manifest.js';
import { COMPLIANCE_FRAMEWORKS, COMPLIANCE_RELATIONSHIPS } from '../lib/probes/v05/types.js';
import { getBySlug } from '../lib/learn-content.js';
import { attachProbeMeta } from '../lib/stable-id.js';

const ENTRIES = Object.values(PROBE_MANIFEST_V05);
const SCAN_FAMILIES = ['XL-001', 'XL-002', 'XL-004', 'XL-006', 'XL-013'];
const EDU_ONLY = ['FERPA', 'SOX', 'FDA', 'FTC', 'EU-AI-Act'];

describe('compliance: family-level mapping is inherited by adapters', () => {
  it('every adapter under a scan-scope family inherits non-null compliance_refs', () => {
    for (const e of ENTRIES) {
      if (SCAN_FAMILIES.includes(e.xl_family)) {
        expect(Array.isArray(e.compliance_refs), `${e.probe_id} compliance_refs`).toBe(true);
        expect(e.compliance_refs.length).toBeGreaterThan(0);
      }
    }
  });

  it('Python and Dart adapters inherit the SAME refs as their XL family (composition)', () => {
    const py = PROBE_MANIFEST_V05['PY-DESERIALIZE-001']; // XL-001
    const da = PROBE_MANIFEST_V05['DA-SECRETS-001']; // XL-006
    expect(py.compliance_refs.some((r) => r.framework === 'PCI-DSS')).toBe(true);
    expect(da.compliance_refs.some((r) => r.framework === 'SOC2')).toBe(true);
    // Same family => same mapping object shape across languages.
    const rs = PROBE_MANIFEST_V05['RS-DESERIALIZE-001']; // XL-001
    expect(rs.compliance_refs).toEqual(py.compliance_refs);
  });
});

describe('compliance: every ref in the manifest is well-formed + scan-scope', () => {
  it('framework is one of the four scan-scope frameworks (never education-only)', () => {
    for (const e of ENTRIES) {
      for (const ref of e.compliance_refs || []) {
        expect(COMPLIANCE_FRAMEWORKS).toContain(ref.framework);
        expect(EDU_ONLY).not.toContain(ref.framework);
      }
    }
  });

  it('relationship is direct|indicative; url is http(s); last_reviewed is ISO', () => {
    for (const e of ENTRIES) {
      for (const ref of e.compliance_refs || []) {
        expect(COMPLIANCE_RELATIONSHIPS).toContain(ref.relationship);
        expect(ref.url).toMatch(/^https?:\/\//);
        expect(ref.clause.length).toBeGreaterThan(0);
        expect(ref.last_reviewed).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      }
    }
  });

  it('validateComplianceRefs rejects an education-scope framework with a scan-scope message', () => {
    expect(() =>
      validateComplianceRefs(
        [
          {
            framework: 'FERPA',
            clause: '34 CFR 99',
            url: 'https://example.gov',
            relationship: 'indicative',
            last_reviewed: '2026-05-15',
          },
        ],
        'family XL-TEST'
      )
    ).toThrow(/scan-scope/);
  });

  it('absent / null compliance_refs is valid (compliance is optional)', () => {
    expect(() => validateComplianceRefs(undefined, 'x')).not.toThrow();
    expect(() => validateComplianceRefs(null, 'x')).not.toThrow();
  });
});

describe('compliance: the nine Learn pages exist and are framed correctly', () => {
  const SCAN_PAGES = [
    'compliance-hipaa',
    'compliance-pci-dss',
    'compliance-gdpr',
    'compliance-soc2',
  ];
  const EDU_PAGES = [
    'compliance-ferpa',
    'compliance-sox',
    'compliance-fda',
    'compliance-ftc',
    'compliance-eu-ai-act',
  ];
  const pagePath = (slug) => join(process.cwd(), 'src/learn/patterns', `${slug}.md`);

  it('all nine pages are published patterns', () => {
    for (const slug of [...SCAN_PAGES, ...EDU_PAGES]) {
      const entry = getBySlug(slug);
      expect(entry, `${slug} missing`).toBeDefined();
      expect(entry.draft).toBe(false);
      expect(entry.type).toBe('pattern');
    }
  });

  it('scan-scope pages state they are in scan scope', () => {
    for (const slug of SCAN_PAGES) {
      const body = readFileSync(pagePath(slug), 'utf8');
      expect(body, slug).toMatch(/in scan scope/i);
      expect(body, slug).toMatch(/not (a )?(legal advice|.*attestation)/i);
    }
  });

  it('education-only pages state Pre-Flight does NOT scan for them', () => {
    for (const slug of EDU_PAGES) {
      const body = readFileSync(pagePath(slug), 'utf8');
      expect(body, slug).toMatch(/does not scan for/i);
    }
  });

  it('every page file is on disk (build-time content contract)', () => {
    for (const slug of [...SCAN_PAGES, ...EDU_PAGES]) {
      expect(existsSync(pagePath(slug)), slug).toBe(true);
    }
  });
});

describe('compliance: attachProbeMeta surfaces refs onto a live finding (UI wiring)', () => {
  it('a live XL-006 finding gets compliance_refs + learn slug from the manifest', () => {
    const findings = [
      {
        probe: 'Rust Hardcoded Secret', // RS-SECRETS-001, XL-006, live
        file: 'a.rs',
        line: 1,
        title: 'Hardcoded provider key / secret in Rust source',
        severity: 'critical',
      },
    ];
    attachProbeMeta(findings);
    const f = findings[0];
    expect(Array.isArray(f.compliance_refs)).toBe(true);
    expect(f.compliance_refs.length).toBeGreaterThan(0);
    expect(f.compliance_refs.some((r) => r.framework === 'PCI-DSS')).toBe(true);
    for (const r of f.compliance_refs) {
      expect(COMPLIANCE_FRAMEWORKS).toContain(r.framework);
      expect(COMPLIANCE_RELATIONSHIPS).toContain(r.relationship);
    }
    // v0.5 probes have no v0.4 PROBE_META; the Learn link must come from
    // the manifest or the in-app "Learn more" silently breaks.
    expect(f.learn_more_slug).toBe('xl-hardcoded-secrets');
  });

  it('a v0.4-only finding gets NO compliance_refs (compliance is opt-in)', () => {
    const findings = [{ probe: 'Env File Hygiene', file: '.env', line: 1, title: 't' }];
    attachProbeMeta(findings);
    expect(findings[0].compliance_refs).toBeUndefined();
  });
});

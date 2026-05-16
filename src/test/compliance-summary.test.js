// Unit: the pure compliance roll-up. No React.

import { describe, it, expect } from 'vitest';
import {
  summarizeCompliance,
  formatComplianceExport,
  COMPLIANCE_DISCLAIMER,
} from '../lib/compliance-summary.js';

const ref = (framework, clause, relationship, url = 'https://example.gov/x') => ({
  framework,
  clause,
  relationship,
  url,
});

describe('summarizeCompliance', () => {
  it('returns an empty shape when no finding carries refs', () => {
    const s = summarizeCompliance([{ probe: 'x' }, { compliance_refs: [] }, null]);
    expect(s.mappedFindingCount).toBe(0);
    expect(s.frameworks).toEqual([]);
    expect(s.hasDirect).toBe(false);
    expect(s.hasIndicative).toBe(false);
  });

  it('groups by framework then clause and counts', () => {
    const findings = [
      {
        compliance_refs: [
          ref('PCI-DSS', 'Req 6.2.4', 'direct'),
          ref('GDPR', 'Art.32', 'indicative'),
        ],
      },
      { compliance_refs: [ref('PCI-DSS', 'Req 6.2.4', 'direct')] },
      { compliance_refs: [ref('HIPAA', '164.312(e)(1)', 'direct')] },
    ];
    const s = summarizeCompliance(findings);
    expect(s.mappedFindingCount).toBe(3);
    expect(s.frameworkCount).toBe(3);
    const pci = s.frameworks.find((f) => f.framework === 'PCI-DSS');
    expect(pci.findingCount).toBe(2);
    expect(pci.clauses[0]).toMatchObject({ clause: 'Req 6.2.4', relationship: 'direct', count: 2 });
    expect(s.hasDirect).toBe(true);
    expect(s.hasIndicative).toBe(true);
    // most-referenced framework sorts first
    expect(s.frameworks[0].framework).toBe('PCI-DSS');
  });

  it("'direct' dominates a clause that also appears as indicative", () => {
    const s = summarizeCompliance([
      { compliance_refs: [ref('HIPAA', '164.312(d)', 'indicative')] },
      { compliance_refs: [ref('HIPAA', '164.312(d)', 'direct')] },
    ]);
    expect(s.frameworks[0].clauses[0].relationship).toBe('direct');
  });
});

describe('formatComplianceExport', () => {
  it('produces a deterministic markdown handoff with the disclaimer', () => {
    const s = summarizeCompliance([
      { compliance_refs: [ref('PCI-DSS', 'Req 4.2.1', 'direct', 'https://pci.example/4')] },
    ]);
    const md = formatComplianceExport(s, '2026-05-15T00:00:00Z');
    expect(md).toContain('# Pre-Flight regulatory mapping');
    expect(md).toContain('2026-05-15T00:00:00Z');
    expect(md).toContain('## PCI-DSS');
    expect(md).toContain('Req 4.2.1 [direct]');
    expect(md).toContain('https://pci.example/4');
    expect(md).toContain(COMPLIANCE_DISCLAIMER);
  });

  it('the disclaimer names the education-only frameworks as not scanned', () => {
    expect(COMPLIANCE_DISCLAIMER).toMatch(/FERPA/);
    expect(COMPLIANCE_DISCLAIMER).toMatch(/not .*detect|not scan/i);
  });
});

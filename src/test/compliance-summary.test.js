// Unit: the pure compliance roll-up. Compliance is opt-in and
// scope-filtered — declare nothing, get nothing.

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
const FULL = ['HIPAA', 'PCI-DSS', 'GDPR', 'SOC2'];

describe('summarizeCompliance: scope gating', () => {
  it('NO declared scope => empty, even when findings carry refs (the email-app fix)', () => {
    const findings = [{ compliance_refs: [ref('PCI-DSS', 'Req 6.2.4', 'direct')] }];
    for (const scope of [undefined, null, [], new Set()]) {
      const s = summarizeCompliance(findings, scope);
      expect(s.mappedFindingCount).toBe(0);
      expect(s.frameworks).toEqual([]);
    }
  });

  it('only refs in the declared scope are counted', () => {
    const findings = [
      {
        compliance_refs: [
          ref('PCI-DSS', 'Req 6.2.4', 'direct'),
          ref('HIPAA', '164.312(c)', 'indicative'),
        ],
      },
    ];
    const s = summarizeCompliance(findings, ['HIPAA']);
    expect(s.frameworkCount).toBe(1);
    expect(s.frameworks[0].framework).toBe('HIPAA');
    expect(s.declaredScope).toEqual(['HIPAA']);
  });
});

describe('summarizeCompliance: direct/indicative split', () => {
  it('separates direct from indicative and ranks direct-heavy frameworks first', () => {
    const findings = [
      { compliance_refs: [ref('PCI-DSS', 'Req 4.2.1', 'direct')] },
      { compliance_refs: [ref('GDPR', 'Art.32', 'indicative')] },
      { compliance_refs: [ref('PCI-DSS', 'Req 4.2.1', 'direct')] },
    ];
    const s = summarizeCompliance(findings, FULL);
    expect(s.frameworks[0].framework).toBe('PCI-DSS');
    const pci = s.frameworks.find((f) => f.framework === 'PCI-DSS');
    expect(pci.direct[0]).toMatchObject({ clause: 'Req 4.2.1', count: 2 });
    expect(pci.indicative).toEqual([]);
    const gdpr = s.frameworks.find((f) => f.framework === 'GDPR');
    expect(gdpr.direct).toEqual([]);
    expect(gdpr.indicative[0].clause).toBe('Art.32');
    expect(s.hasDirect).toBe(true);
    expect(s.hasIndicative).toBe(true);
  });

  it("'direct' anywhere promotes a clause out of indicative", () => {
    const s = summarizeCompliance(
      [
        { compliance_refs: [ref('HIPAA', '164.312(d)', 'indicative')] },
        { compliance_refs: [ref('HIPAA', '164.312(d)', 'direct')] },
      ],
      ['HIPAA']
    );
    expect(s.frameworks[0].direct[0].clause).toBe('164.312(d)');
    expect(s.frameworks[0].indicative).toEqual([]);
  });
});

describe('formatComplianceExport', () => {
  it('records the declared scope and splits direct/indicative', () => {
    const s = summarizeCompliance(
      [
        { compliance_refs: [ref('PCI-DSS', 'Req 4.2.1', 'direct', 'https://pci.example/4')] },
        { compliance_refs: [ref('PCI-DSS', 'Req 8.3.1', 'indicative', 'https://pci.example/8')] },
      ],
      ['PCI-DSS']
    );
    const md = formatComplianceExport(s, '2026-05-15T00:00:00Z');
    expect(md).toContain('Declared regulatory scope: PCI-DSS');
    expect(md).toContain('Direct (the pattern is itself the clause failure):');
    expect(md).toContain('Req 4.2.1');
    expect(md).toContain('Indicative (needs human judgement in context):');
    expect(md).toContain('Req 8.3.1');
    expect(md).toContain(COMPLIANCE_DISCLAIMER);
  });

  it('the disclaimer states the user declared scope + names un-scanned frameworks', () => {
    expect(COMPLIANCE_DISCLAIMER).toMatch(/You declared the regulatory scope/);
    expect(COMPLIANCE_DISCLAIMER).toMatch(/FERPA/);
  });
});

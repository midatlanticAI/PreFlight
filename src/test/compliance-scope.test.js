// The declared regulatory scope: empty by default, persisted, sanitized.

import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadComplianceScope,
  saveComplianceScope,
  SELECTABLE_FRAMEWORKS,
  COMPLIANCE_SCOPE_KEY,
} from '../lib/compliance-scope.js';

beforeEach(() => {
  globalThis.localStorage?.removeItem(COMPLIANCE_SCOPE_KEY);
});

describe('compliance scope persistence', () => {
  it('defaults to empty (un-regulated is the default)', () => {
    expect(loadComplianceScope()).toEqual([]);
  });

  it('the selectable set is exactly the four scan-scope frameworks', () => {
    expect([...SELECTABLE_FRAMEWORKS].sort()).toEqual(['GDPR', 'HIPAA', 'PCI-DSS', 'SOC2'].sort());
  });

  it('round-trips a declared scope', () => {
    const saved = saveComplianceScope(['HIPAA', 'PCI-DSS']);
    expect(saved).toEqual(['HIPAA', 'PCI-DSS']);
    expect(loadComplianceScope()).toEqual(['HIPAA', 'PCI-DSS']);
  });

  it('drops unknown / education-scope frameworks on save and load', () => {
    const saved = saveComplianceScope(['HIPAA', 'FERPA', 'SOX', 'garbage']);
    expect(saved).toEqual(['HIPAA']);
    expect(loadComplianceScope()).toEqual(['HIPAA']);
  });

  it('a corrupt stored value loads as empty, not a crash', () => {
    globalThis.localStorage?.setItem(COMPLIANCE_SCOPE_KEY, '{not json');
    expect(loadComplianceScope()).toEqual([]);
  });
});

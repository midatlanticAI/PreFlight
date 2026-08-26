// Reachability guard for the regulatory mapping layer.
//
// The compliance panel is an interpretation layer keyed by PROBE NAME. That
// makes it silently breakable in a way no other test caught: a mapped family
// can carry perfectly valid compliance_refs while the name those refs are
// filed under matches nothing that ever fires. Findings then arrive with no
// refs, summarizeCompliance() sees nothing in scope, and a user who declared
// SOC2 gets an EMPTY compliance report rendered directly above six criticals.
// Every unit here passed while that was true, because each half was correct on
// its own — the refs were well-formed, the roll-up aggregated correctly, and
// nothing asserted the two halves met.
//
// The failure is worse than a missing feature: an empty regulatory report
// reads as "clean", which is the most misleading output a compliance view can
// produce. These tests assert the join, not the halves.

import { describe, it, expect } from 'vitest';
import {
  PROBE_MANIFEST_V05,
  buildComplianceRefsByProbeName,
  isLiveAdapter,
} from '../lib/probes/v05/manifest.js';
import { PROBES } from '../lib/probes.js';
import { attachProbeMeta } from '../lib/stable-id.js';
import { summarizeCompliance } from '../lib/compliance-summary.js';

const PRODUCTION_PROBE_NAMES = new Set(PROBES.map((p) => p.name));
const COMPLIANCE_INDEX = buildComplianceRefsByProbeName(PROBE_MANIFEST_V05);

const mappedEntries = Object.values(PROBE_MANIFEST_V05).filter(
  (e) => Array.isArray(e.compliance_refs) && e.compliance_refs.length > 0
);

describe('compliance mapping reachability', () => {
  it('the mapped set is non-empty (guards against the index silently emptying)', () => {
    expect(mappedEntries.length).toBeGreaterThan(0);
    expect(Object.keys(COMPLIANCE_INDEX).length).toBeGreaterThan(0);
  });

  it('every compliance-mapped manifest entry is reachable under a name that fires', () => {
    // A mapped entry reaches findings one of two ways: it is LIVE and emits
    // under its own name, or it is a HELD migration whose v0.4 probe fires
    // under legacy_finding_id_seed. Anything else is a dead mapping.
    const unreachable = [];
    for (const entry of mappedEntries) {
      const firingName = isLiveAdapter(entry) ? entry.name : entry.legacy_finding_id_seed;
      if (!firingName) {
        unreachable.push(`${entry.probe_id}: not live and no legacy_finding_id_seed`);
        continue;
      }
      if (!COMPLIANCE_INDEX[firingName]) {
        unreachable.push(`${entry.probe_id}: "${firingName}" absent from the compliance index`);
      }
    }
    expect(unreachable).toEqual([]);
  });

  it('a held migration maps under the v0.4 probe name, not the adapter name', () => {
    // This is the exact regression: JS-SECRET-001 carries the XL-006 refs but
    // is held out of the live set, so "Secret Scanner" is what actually fires.
    const held = mappedEntries.filter((e) => !isLiveAdapter(e) && e.legacy_finding_id_seed != null);
    expect(held.length).toBeGreaterThan(0);
    for (const entry of held) {
      expect(COMPLIANCE_INDEX[entry.legacy_finding_id_seed]?.probe_id).toBe(entry.probe_id);
      // The adapter's own name must NOT be indexed — it never fires, and
      // indexing it would hide a future promotion bug behind a passing test.
      expect(COMPLIANCE_INDEX[entry.name]).toBeUndefined();
      // ...and the name it maps under must be a real production probe.
      expect(PRODUCTION_PROBE_NAMES.has(entry.legacy_finding_id_seed)).toBe(true);
    }
  });

  it('no indexed compliance name is orphaned from the production probe set', () => {
    // Every key in the index must be a name a scan can actually emit. A key
    // that matches nothing is a mapping that will never fire.
    const liveNames = new Set(
      Object.values(PROBE_MANIFEST_V05)
        .filter(isLiveAdapter)
        .map((e) => e.name)
    );
    const orphans = Object.keys(COMPLIANCE_INDEX).filter(
      (name) => !PRODUCTION_PROBE_NAMES.has(name) && !liveNames.has(name)
    );
    expect(orphans).toEqual([]);
  });

  it('rejects two adapters claiming compliance mapping for one probe name', () => {
    // Ambiguity here means a finding gets an arbitrary one of two regulatory
    // readings. The build must fail rather than pick.
    const collide = {
      'AA-001': {
        probe_id: 'AA-001',
        name: 'Alpha',
        shadow: false,
        legacy_finding_id_seed: 'Shared Legacy Name',
        compliance_refs: [{ framework: 'SOC2', clause: 'CC6.1', relationship: 'indicative' }],
      },
      'BB-001': {
        probe_id: 'BB-001',
        name: 'Beta',
        shadow: false,
        legacy_finding_id_seed: 'Shared Legacy Name',
        compliance_refs: [{ framework: 'HIPAA', clause: '164.312(d)', relationship: 'direct' }],
      },
    };
    expect(() => buildComplianceRefsByProbeName(collide)).toThrow(/claimed for compliance mapping/);
  });
});

describe('compliance mapping: end-to-end through a scan-shaped finding set', () => {
  // The join under test is attachProbeMeta -> summarizeCompliance. Findings are
  // built in the shape the v0.4 pipeline emits (probe name only, no v0.5
  // fields), because that is the shape that exposed the gap.
  const findingsFor = (probeNames) =>
    attachProbeMeta(
      probeNames.map((probe, i) => ({
        probe,
        title: `${probe} finding`,
        file: `src/app-${i}.js`,
        line: i + 1,
        severity: 'critical',
      }))
    );

  it('a hardcoded secret under the v0.4 probe name maps to SOC2 CC6.1', () => {
    const findings = findingsFor(['Secret Scanner']);
    expect(findings[0].compliance_refs?.length).toBeGreaterThan(0);

    const summary = summarizeCompliance(findings, ['SOC2']);
    expect(summary.mappedFindingCount).toBe(1);
    expect(summary.frameworks[0].framework).toBe('SOC2');
    expect(summary.frameworks[0].indicative.some((c) => /CC6\.1/.test(c.clause))).toBe(true);
  });

  it('the declared-scope gate still holds after the fallback (declare nothing, get nothing)', () => {
    // The fallback attaches more refs than before; it must not leak output for
    // an un-regulated app. This is the property the whole layer rests on.
    const findings = findingsFor(['Secret Scanner', 'Auth Weakness', 'SQL Injection']);
    expect(summarizeCompliance(findings, []).mappedFindingCount).toBe(0);
    expect(summarizeCompliance(findings, []).frameworks).toEqual([]);
  });

  it('scope filtering still excludes undeclared regimes', () => {
    const findings = findingsFor(['Secret Scanner']);
    const summary = summarizeCompliance(findings, ['GDPR']);
    expect(summary.frameworkCount).toBe(1);
    expect(summary.frameworks[0].framework).toBe('GDPR');
  });

  it('an unmapped probe stays a plain security finding', () => {
    // Not every probe should map. Security Headers has no regulatory mapping
    // yet, and inventing one would be false authority.
    const findings = findingsFor(['Security Headers']);
    expect(findings[0].compliance_refs).toBeUndefined();
    expect(summarizeCompliance(findings, ['SOC2']).mappedFindingCount).toBe(0);
  });

  it('the fallback never overrides refs the manifest record already supplied', () => {
    // A live v0.5 probe's own refs win; the seed-keyed index is gap-fill only.
    const findings = findingsFor(['JavaScript TLS Verification Disabled']);
    const entry = Object.values(PROBE_MANIFEST_V05).find(
      (e) => e.name === 'JavaScript TLS Verification Disabled'
    );
    expect(findings[0].compliance_refs).toEqual(entry.compliance_refs);
  });
});

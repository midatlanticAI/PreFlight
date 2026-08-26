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
import fs from 'node:fs';
import path from 'node:path';
import {
  PROBE_MANIFEST_V05,
  buildComplianceRefsByProbeName,
  isLiveAdapter,
} from '../lib/probes/v05/manifest.js';
import { PROBES } from '../lib/probes.js';
import { attachProbeMeta } from '../lib/stable-id.js';
import { summarizeCompliance } from '../lib/compliance-summary.js';
import { PROBE_COMPLIANCE_REFS_V04, CLAUSES } from '../lib/compliance-refs-v04.js';

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

  it('a deliberately unmapped probe stays a plain security finding', () => {
    // Not every probe should map, and the refusals are decisions rather than
    // gaps. Code Quality counts console call sites and measures file length; it
    // cannot see whether anything sensitive is logged, so an audit-controls
    // clause on it would assert a finding the detector never made.
    const findings = findingsFor(['Code Quality']);
    expect(findings[0].compliance_refs).toBeUndefined();
    expect(summarizeCompliance(findings, ['SOC2']).mappedFindingCount).toBe(0);
  });

  it('the discoverability and accessibility probes are never mapped', () => {
    // SEO, GEO and A11y are governed by regimes outside scan scope, or by no
    // regime at all. A clause here would be pure false authority.
    for (const probe of ['SEO Hygiene', 'GEO Hygiene', 'A11y Landmarks', 'Architecture']) {
      expect(PROBE_COMPLIANCE_REFS_V04[probe]).toBeUndefined();
      expect(findingsFor([probe])[0].compliance_refs).toBeUndefined();
    }
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

describe('clause catalogue consistency', () => {
  // One requirement must render one way. The auditor export groups by clause
  // STRING, so two spellings of PCI Req 6.2.4 became two separate rows citing
  // the same requirement with different parentheticals. A reviewer reading that
  // export cannot tell whether they are looking at one control or two.
  //
  // The identifier is the stable part of a citation ("CC6.1", "164.312(e)(1)",
  // "Req 6.2.4", "Art.32(1)(a)"); the parenthetical gloss is the part that
  // drifts. This asserts the gloss is a function of the identifier.
  //
  // One citation legitimately splits: GDPR Art.32(1)(b) covers "confidentiality,
  // integrity, availability and resilience" in a single lettered point, and the
  // families cite the specific property at risk rather than the whole list. That
  // distinction is worth keeping, so the aspect word counts as part of the
  // identifier. Two spellings of the SAME aspect are still drift.
  const ASPECTS = ['confidentiality', 'integrity', 'availability', 'resilience'];
  const identifierOf = (clause) => {
    const m =
      clause.match(/^Trust Services Criteria (CC[\d.]+)/) ||
      clause.match(/^45 CFR ([\d.]+(?:\([A-Za-z0-9]+\))+)/) ||
      clause.match(/^(Req [\d.]+)/) ||
      clause.match(/^(Art\.[\d]+(?:\(\d+\)\([a-z]\))?)/);
    if (!m) return null;
    const aspect = ASPECTS.find((a) => clause.toLowerCase().includes(a));
    return aspect ? `${m[1]} ${aspect}` : m[1];
  };

  const allRefs = [
    ...Object.values(PROBE_MANIFEST_V05).flatMap((e) =>
      (e.compliance_refs || []).map((r) => ({ ...r, from: e.probe_id }))
    ),
    ...Object.entries(PROBE_COMPLIANCE_REFS_V04).flatMap(([name, refs]) =>
      (refs || []).map((r) => ({ ...r, from: `v0.4 ${name}` }))
    ),
    ...Object.values(CLAUSES).map((c) => ({ ...c, from: 'catalogue' })),
  ];

  it('a given framework + requirement identifier has exactly one clause string', () => {
    const byIdentifier = {};
    for (const r of allRefs) {
      const id = identifierOf(r.clause);
      if (!id) continue;
      const key = `${r.framework}|${id}`;
      (byIdentifier[key] ||= new Map()).set(r.clause, r.from);
    }
    const drifted = Object.entries(byIdentifier)
      .filter(([, spellings]) => spellings.size > 1)
      .map(
        ([key, spellings]) =>
          `${key}: ${[...spellings].map(([c, f]) => `"${c}" (${f})`).join(' vs ')}`
      );
    expect(drifted).toEqual([]);
  });

  it('a given framework + requirement identifier has exactly one source URL', () => {
    const byIdentifier = {};
    for (const r of allRefs) {
      const id = identifierOf(r.clause);
      if (!id || !r.url) continue;
      (byIdentifier[`${r.framework}|${id}`] ||= new Set()).add(r.url);
    }
    const drifted = Object.entries(byIdentifier)
      .filter(([, urls]) => urls.size > 1)
      .map(([key, urls]) => `${key}: ${[...urls].join(' vs ')}`);
    expect(drifted).toEqual([]);
  });

  it('every clause string in the catalogue parses to a recognised identifier', () => {
    // A citation the parser cannot read is a citation the drift guard silently
    // skips, which would let the next inconsistency through unnoticed.
    const unparsed = Object.entries(CLAUSES)
      .filter(([, c]) => identifierOf(c.clause) === null)
      .map(([k, c]) => `${k}: "${c.clause}"`);
    expect(unparsed).toEqual([]);
  });

  it('every v0.4 mapping passes the same ref validation as a manifest ref', () => {
    // The v0.4 map is hand-maintained and has no adapter to validate it, so the
    // build-time validator is the only thing standing between a typo and the
    // auditor export.
    expect(() => buildComplianceRefsByProbeName({}, PROBE_COMPLIANCE_REFS_V04)).not.toThrow();
  });

  it('a v0.4 mapping cannot shadow a manifest-derived mapping', () => {
    // "Secret Scanner" already resolves through JS-SECRET-001's legacy seed.
    // A v0.4 entry for the same name would mean two regulatory readings of one
    // finding, decided by iteration order.
    expect(() =>
      buildComplianceRefsByProbeName(PROBE_MANIFEST_V05, {
        'Secret Scanner': [
          {
            framework: 'SOC2',
            clause: 'Trust Services Criteria CC6.1 (logical access controls)',
            url: 'https://example.gov/x',
            relationship: 'indicative',
            last_reviewed: '2026-08-25',
          },
        ],
      })
    ).toThrow(/claimed for compliance mapping/);
  });
});

describe('v0.4 mappings are keyed by the name a finding actually carries', () => {
  // The registry name and the emitted name are not the same string for every
  // probe. PROBES calls it "CORS"; findings say "CORS Check". "Env File
  // Hygiene" emits "Env Hygiene". "SSRF / Open Redirect" emits two names,
  // neither of them the registry one. A map keyed from the registry would look
  // completely correct and match nothing, which is the failure this file exists
  // to prevent, reintroduced one layer down.
  //
  // Source of truth is the probe implementations: every `probe: '...'` literal
  // they can emit. Read from disk, so a rename in a probe breaks this test
  // rather than silently orphaning a regulatory mapping.
  const collectEmittedNames = () => {
    const names = new Set();
    const scan = (file) => {
      const src = fs.readFileSync(file, 'utf8');
      for (const m of src.matchAll(/probe:\s*'([^']+)'/g)) names.add(m[1]);
    };
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.name.endsWith('.js')) scan(full);
      }
    };
    walk('src/lib/probes');
    scan('src/lib/probes.js');
    return names;
  };
  const EMITTED = collectEmittedNames();

  it('found a plausible set of emitted probe names', () => {
    expect(EMITTED.size).toBeGreaterThan(30);
    expect(EMITTED.has('Secret Scanner')).toBe(true);
  });

  it('every v0.4 mapping key is a name some probe actually emits', () => {
    const orphans = Object.keys(PROBE_COMPLIANCE_REFS_V04).filter((n) => !EMITTED.has(n));
    expect(orphans).toEqual([]);
  });

  it('the known registry-vs-emitted mismatches are keyed the emitted way', () => {
    // Pinned explicitly: these six are the ones that differ today, and a future
    // rename that "fixes" the registry must not silently re-break the mapping.
    for (const registryOnly of [
      'CORS',
      'Supabase RLS',
      'Firebase Rules',
      'Env File Hygiene',
      'SSRF / Open Redirect',
    ]) {
      expect(PROBE_COMPLIANCE_REFS_V04[registryOnly]).toBeUndefined();
    }
    for (const emitted of [
      'CORS Check',
      'Supabase RLS Check',
      'Firebase Rules Check',
      'SSRF',
      'Open Redirect',
    ]) {
      expect(EMITTED.has(emitted)).toBe(true);
    }
  });
});

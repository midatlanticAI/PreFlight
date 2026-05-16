// Persona journey tests ("our own playwright-lite"): render the real
// result-surface components to static markup and assert each user type
// sees what they should, end to end, using REAL pipeline data
// (attachProbeMeta populates compliance_refs / xl_family exactly as a
// live scan does).
//
//   - Compliance / GRC: a scan with mapped findings shows the
//     ComplianceSummary lens with the right frameworks + no live script.
//   - Vibe coder: a scan whose findings carry no scan-scope mapping
//     shows NO compliance lens (zero noise for the primary audience).
//   - Security reviewer: a v0.5 SQLi finding resolves the SQL-injection
//     Breakers via the xl_family bridge (depth path works for all 14
//     languages, not just v0.4 names).

import { describe, it, expect } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { ComplianceSummary } from '../components/ComplianceSummary.jsx';
import { attachProbeMeta } from '../lib/stable-id.js';
import { getBreakers } from '../lib/breakers.js';
import { PROBE_MANIFEST_V05 } from '../lib/probes/v05/manifest.js';

const render = (el) => renderToStaticMarkup(React.createElement(MemoryRouter, null, el));

describe('journey: compliance / GRC persona', () => {
  it('a scan with mapped findings shows the regulatory lens + frameworks', () => {
    // A live v0.5 secret finding, meta-attached exactly as handleScan does.
    const findings = [
      {
        probe: 'Rust Hardcoded Secret',
        file: 'src/main.rs',
        line: 4,
        title: 'Hardcoded provider key / secret in Rust source',
        severity: 'critical',
      },
    ];
    attachProbeMeta(findings);
    expect(Array.isArray(findings[0].compliance_refs)).toBe(true);

    // GRC user declared HIPAA + PCI scope.
    const html = render(
      React.createElement(ComplianceSummary, {
        findings,
        scope: ['HIPAA', 'PCI-DSS'],
        scannedAt: '2026-05-15',
      })
    );
    expect(html).toContain('Regulatory mapping');
    expect(html).toMatch(/PCI-DSS|HIPAA/);
    expect(html).not.toMatch(/<script\b/i);
  });
});

describe('journey: vibe coder / un-regulated app — zero compliance noise', () => {
  it('a MAPPED finding but NO declared scope renders NOTHING (the email-app fix)', () => {
    // Exactly the user's scenario: a plain app with a hardcoded key. The
    // finding carries XL-006 refs, but the user never declared a regime,
    // so the app is NOT told it fails HIPAA/PCI/SOC2.
    const findings = [
      {
        probe: 'Rust Hardcoded Secret',
        file: 'src/main.rs',
        line: 4,
        title: 'Hardcoded provider key / secret in Rust source',
        severity: 'critical',
      },
    ];
    attachProbeMeta(findings);
    expect(Array.isArray(findings[0].compliance_refs)).toBe(true); // data is present
    const html = render(React.createElement(ComplianceSummary, { findings, scope: [] }));
    expect(html).toBe(''); // ...but the lens stays silent
  });

  it('findings with no scan-scope mapping render NO lens even if scope declared', () => {
    const findings = [
      { probe: 'Env File Hygiene', file: '.env', line: 1, title: 't', severity: 'low' },
    ];
    attachProbeMeta(findings);
    const html = render(React.createElement(ComplianceSummary, { findings, scope: ['HIPAA'] }));
    expect(html).toBe('');
  });

  it('an empty scan renders no lens', () => {
    expect(render(React.createElement(ComplianceSummary, { findings: [], scope: ['HIPAA'] }))).toBe(
      ''
    );
  });
});

describe('journey: security reviewer — Breakers depth works for v0.5', () => {
  it('a v0.5 SQLi finding resolves the SQL-injection adversarial inputs', () => {
    const a = PROBE_MANIFEST_V05['PHP-SQL-RAW-001']; // live, XL-002
    const breakers = getBreakers(a.name, a.xl_family);
    expect(breakers.length).toBeGreaterThan(0);
    // the canonical SQLi payload is reachable for a PHP (non-v0.4) finding
    expect(breakers.some((b) => /OR 1=1|UNION SELECT/.test(b.payload))).toBe(true);
  });
});

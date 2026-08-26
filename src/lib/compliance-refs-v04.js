// src/lib/compliance-refs-v04.js
//
// Scan-scope regulatory mapping for the v0.4 probes.
//
// The v0.5 manifest carries compliance_refs on its XL families, so a migrated
// probe inherits its mapping from the family record. The v0.4 probes have no
// manifest entry at all, which left the entire web / cloud / supply-chain half
// of the scanner unmappable: an app could produce an unauthenticated admin
// route and a service-role key in the client bundle and still render an empty
// regulatory report, because nothing those probes emit had anywhere to hang a
// clause. This module is that missing half, keyed by the probe name the v0.4
// pipeline actually puts on a finding.
//
// CLAUSE CATALOGUE, not inline strings. Forty-plus probes repeating clause text
// by hand would drift within a release, and a regulatory citation that differs
// by a word between two findings is the kind of detail a reviewer notices. Each
// clause is written once here and referenced by symbol. A test asserts these
// strings stay identical to the ones the v0.5 families use for the same clause.
//
// Every entry below survived three independent adversarial reviews (an audit
// lens, a false-authority lens, and a detector-accuracy lens) before it shipped.
// Anything a single lens rejected is absent, deliberately. A missing mapping is
// a small gap; a wrong one is a defect an auditor finds, and it discredits the
// layer that carries it. Probes that detect quality, accessibility,
// discoverability, maintainability or classification concerns are not mapped at
// all, because a code-quality signal is not a security control and dressing one
// up as a clause failure would be exactly the false authority this layer exists
// to avoid.

const AICPA_URL =
  'https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services';
const HIPAA_URL = 'https://www.ecfr.gov/current/title-45/section-164.312';
const PCI_URL = 'https://www.pcisecuritystandards.org/document_library/';
const GDPR_URL = 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679';

// The date the clause wording and its applicability were last checked against
// the published standard. Carried onto every ref for auditable provenance.
const REVIEWED = '2026-08-25';

/**
 * Clause catalogue. Keys are internal symbols; the `clause` strings are the
 * user-visible citations and must match the v0.5 family wording exactly.
 */
export const CLAUSES = Object.freeze({
  // --- SOC 2 / AICPA Trust Services Criteria (Common Criteria) ---
  SOC2_CC6_1: {
    framework: 'SOC2',
    clause: 'Trust Services Criteria CC6.1 (logical access controls)',
    url: AICPA_URL,
  },
  SOC2_CC6_6: {
    framework: 'SOC2',
    clause:
      'Trust Services Criteria CC6.6 (measures against threats from outside the system boundaries)',
    url: AICPA_URL,
  },
  SOC2_CC6_7: {
    framework: 'SOC2',
    clause: 'Trust Services Criteria CC6.7 (transmission of data)',
    url: AICPA_URL,
  },
  SOC2_CC6_8: {
    framework: 'SOC2',
    clause: 'Trust Services Criteria CC6.8 (unauthorized or malicious software)',
    url: AICPA_URL,
  },
  SOC2_CC7_2: {
    framework: 'SOC2',
    clause: 'Trust Services Criteria CC7.2 (monitoring for anomalies indicative of malicious acts)',
    url: AICPA_URL,
  },
  SOC2_CC8_1: {
    framework: 'SOC2',
    clause: 'Trust Services Criteria CC8.1 (authorized, tested and approved changes)',
    url: AICPA_URL,
  },

  // --- HIPAA Security Rule ---
  // 164.312 is the technical-safeguards section. 164.308(a)(5)(ii)(B) is an
  // administrative safeguard whose implementation is a technical control, and
  // it is the only clause outside 164.312 mapped here. The scan-scope wording
  // in COMPLIANCE_DISCLAIMER names it explicitly for that reason.
  HIPAA_308_A_5_II_B: {
    framework: 'HIPAA',
    clause: '45 CFR 164.308(a)(5)(ii)(B) Protection from malicious software',
    url: 'https://www.ecfr.gov/current/title-45/section-164.308',
  },
  HIPAA_312_A_1: {
    framework: 'HIPAA',
    clause: '45 CFR 164.312(a)(1) Access control',
    url: HIPAA_URL,
  },
  HIPAA_312_A_2_IV: {
    framework: 'HIPAA',
    clause: '45 CFR 164.312(a)(2)(iv) Encryption and decryption',
    url: HIPAA_URL,
  },
  HIPAA_312_B: {
    framework: 'HIPAA',
    clause: '45 CFR 164.312(b) Audit controls',
    url: HIPAA_URL,
  },
  HIPAA_312_C_1: {
    framework: 'HIPAA',
    clause: '45 CFR 164.312(c)(1) Integrity',
    url: HIPAA_URL,
  },
  HIPAA_312_D: {
    framework: 'HIPAA',
    clause: '45 CFR 164.312(d) Person or entity authentication',
    url: HIPAA_URL,
  },
  HIPAA_312_E_1: {
    framework: 'HIPAA',
    clause: '45 CFR 164.312(e)(1) Transmission security',
    url: HIPAA_URL,
  },

  // --- PCI DSS v4 ---
  PCI_4_2_1: {
    framework: 'PCI-DSS',
    clause: 'Req 4.2.1 (strong cryptography for PAN in transit over open networks)',
    url: PCI_URL,
  },
  PCI_5_2_1: {
    framework: 'PCI-DSS',
    clause: 'Req 5.2.1 (anti-malware deployed on system components at risk)',
    url: PCI_URL,
  },
  PCI_6_2_3: {
    framework: 'PCI-DSS',
    clause: 'Req 6.2.3 (bespoke and custom software reviewed prior to release)',
    url: PCI_URL,
  },
  PCI_6_2_4: {
    framework: 'PCI-DSS',
    clause: 'Req 6.2.4 (software engineering techniques to prevent common software attacks)',
    url: PCI_URL,
  },
  PCI_6_3_1: {
    framework: 'PCI-DSS',
    clause: 'Req 6.3.1 (security vulnerabilities in software components identified and managed)',
    url: PCI_URL,
  },
  PCI_6_4_3: {
    framework: 'PCI-DSS',
    clause: 'Req 6.4.3 (payment page scripts authorized and integrity-assured)',
    url: PCI_URL,
  },
  PCI_7_2_1: {
    framework: 'PCI-DSS',
    clause: 'Req 7.2.1 (access control model granting least privilege and need to know)',
    url: PCI_URL,
  },
  PCI_8_3: {
    framework: 'PCI-DSS',
    clause: 'Req 8.3 (strong authentication for users and administrators)',
    url: PCI_URL,
  },
  PCI_8_3_1: {
    framework: 'PCI-DSS',
    clause: 'Req 8.3.1 / 8.6.2 (do not hard-code authentication credentials)',
    url: PCI_URL,
  },
  PCI_8_3_2: {
    framework: 'PCI-DSS',
    clause: 'Req 8.3.2 (authentication factors unreadable in transmission and storage)',
    url: PCI_URL,
  },
  PCI_8_6_2: {
    framework: 'PCI-DSS',
    clause: 'Req 8.6.2 (passwords not hard-coded in scripts or configuration files)',
    url: PCI_URL,
  },
  PCI_10_2_1: {
    framework: 'PCI-DSS',
    clause: 'Req 10.2.1 (audit logs enabled and active for all system components)',
    url: PCI_URL,
  },

  // --- GDPR ---
  // Art.32(1)(b) names confidentiality, integrity, availability and resilience
  // in one lettered point. The property actually at risk is the useful part of
  // the citation, so it is carried in the clause text and treated as part of
  // the identifier by the drift guard.
  GDPR_32_1_A: {
    framework: 'GDPR',
    clause: 'Art.32(1)(a) encryption of personal data',
    url: GDPR_URL,
  },
  GDPR_32_1_B_CONF: {
    framework: 'GDPR',
    clause: 'Art.32(1)(b) confidentiality of processing systems',
    url: GDPR_URL,
  },
  GDPR_32_1_B_INTEG: {
    framework: 'GDPR',
    clause: 'Art.32(1)(b) integrity of processing systems',
    url: GDPR_URL,
  },
  GDPR_32: {
    framework: 'GDPR',
    clause: 'Art.32 security of processing',
    url: GDPR_URL,
  },
});

/**
 * Build a ref from a catalogue entry.
 * @param {{framework: string, clause: string, url: string}} clause
 * @param {'direct'|'indicative'} relationship
 * @returns {object} a well-formed ComplianceRef
 */
function ref(clause, relationship) {
  return Object.freeze({
    framework: clause.framework,
    clause: clause.clause,
    url: clause.url,
    relationship,
    last_reviewed: REVIEWED,
  });
}

export { ref as buildComplianceRef };

/**
 * Scan-scope regulatory mapping for v0.4 probes.
 *
 * Keyed by the probe name a FINDING carries, which is not always the name in
 * the PROBES registry: the registry calls it "CORS" and findings say "CORS
 * Check", the registry says "Env File Hygiene" and findings say "Env Hygiene",
 * and "SSRF / Open Redirect" emits under two separate names. Keying this map
 * from the registry would have produced mappings that match nothing, which is
 * the exact failure this whole layer was just repaired for. A test pins every
 * key here to a name the probe sources actually emit.
 *
 * Every relationship below is "indicative". Nothing in this set is a clause
 * failure on the pattern alone: each of these detectors reasons from the
 * absence of evidence in one file, or from a path or filename heuristic, and
 * none can see a gateway, a framework guard, or an infrastructure policy. They
 * also cannot know the app is in the regime the user declared. Human judgement
 * is required for every one of them, which is what "indicative" says.
 *
 * @type {Object<string, object[]>}
 */
export const PROBE_COMPLIANCE_REFS_V04 = Object.freeze({
  'API Route Auth': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_A_1, 'indicative'),
    ref(CLAUSES.PCI_6_2_4, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Admin Route Exposure': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_A_1, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Agent Config Backdoor': [ref(CLAUSES.SOC2_CC6_8, 'indicative')],
  'CORS Check': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_A_1, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Client Auth Storage': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_D, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Compromised Packages': [
    ref(CLAUSES.GDPR_32_1_B_INTEG, 'indicative'),
    ref(CLAUSES.HIPAA_308_A_5_II_B, 'indicative'),
    ref(CLAUSES.PCI_6_3_1, 'indicative'),
    ref(CLAUSES.SOC2_CC6_8, 'indicative'),
  ],
  'Cookie Security': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_A_1, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Firebase Rules Check': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_A_1, 'indicative'),
    ref(CLAUSES.PCI_7_2_1, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'GitHub Actions': [ref(CLAUSES.SOC2_CC6_1, 'indicative'), ref(CLAUSES.SOC2_CC8_1, 'indicative')],
  'HTML Hygiene': [ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative')],
  'Iframe Sandbox': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.SOC2_CC6_6, 'indicative'),
  ],
  'LLM Security': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.PCI_6_2_4, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Malicious Artifacts': [
    ref(CLAUSES.GDPR_32_1_B_INTEG, 'indicative'),
    ref(CLAUSES.HIPAA_308_A_5_II_B, 'indicative'),
    ref(CLAUSES.PCI_5_2_1, 'indicative'),
    ref(CLAUSES.SOC2_CC6_8, 'indicative'),
  ],
  'NEXT_PUBLIC_ Misuse': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_A_1, 'indicative'),
    ref(CLAUSES.PCI_8_6_2, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Open Redirect': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_A_1, 'indicative'),
    ref(CLAUSES.PCI_6_2_4, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Path Traversal': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_A_1, 'indicative'),
    ref(CLAUSES.PCI_6_2_4, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Python Security': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_A_1, 'indicative'),
    ref(CLAUSES.PCI_6_2_4, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'RAG Ingestion': [ref(CLAUSES.GDPR_32_1_B_INTEG, 'indicative')],
  'Reflected XSS': [
    ref(CLAUSES.GDPR_32_1_B_INTEG, 'indicative'),
    ref(CLAUSES.HIPAA_312_C_1, 'indicative'),
    ref(CLAUSES.PCI_6_2_4, 'indicative'),
  ],
  SSRF: [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_A_1, 'indicative'),
    ref(CLAUSES.PCI_6_2_4, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Security Headers': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.SOC2_CC6_6, 'indicative'),
  ],
  'Security Logging': [
    ref(CLAUSES.HIPAA_312_B, 'indicative'),
    ref(CLAUSES.PCI_10_2_1, 'indicative'),
    ref(CLAUSES.SOC2_CC7_2, 'indicative'),
  ],
  'Stack Trace Leaks': [ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative')],
  'Subresource Integrity': [
    ref(CLAUSES.GDPR_32_1_B_INTEG, 'indicative'),
    ref(CLAUSES.PCI_6_4_3, 'indicative'),
    ref(CLAUSES.SOC2_CC6_8, 'indicative'),
  ],
  'Supabase RLS Check': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_A_1, 'indicative'),
    ref(CLAUSES.PCI_7_2_1, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Taint Flow': [
    ref(CLAUSES.GDPR_32_1_B_INTEG, 'indicative'),
    ref(CLAUSES.HIPAA_312_C_1, 'indicative'),
    ref(CLAUSES.PCI_6_2_4, 'indicative'),
  ],
  'Trojan Source': [ref(CLAUSES.PCI_6_2_3, 'indicative'), ref(CLAUSES.SOC2_CC8_1, 'indicative')],
  'Vector Embedding Weaknesses': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_A_1, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Weak Cryptography': [
    ref(CLAUSES.GDPR_32_1_A, 'indicative'),
    ref(CLAUSES.HIPAA_312_A_2_IV, 'indicative'),
    ref(CLAUSES.PCI_6_2_4, 'indicative'),
    ref(CLAUSES.PCI_8_3_2, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Weak Randomness': [
    ref(CLAUSES.GDPR_32_1_B_CONF, 'indicative'),
    ref(CLAUSES.HIPAA_312_D, 'indicative'),
    ref(CLAUSES.PCI_6_2_4, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
  'Webhook Validation': [
    ref(CLAUSES.HIPAA_312_D, 'indicative'),
    ref(CLAUSES.SOC2_CC6_1, 'indicative'),
  ],
});

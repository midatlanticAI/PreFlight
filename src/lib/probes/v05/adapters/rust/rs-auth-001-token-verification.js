// src/lib/probes/v05/adapters/rust/rs-auth-001-token-verification.js
//
// XL-013 adapter for Rust. rust-jwt Token::parse_unverified, which returns a fully typed token whose signature has never been checked.
//
// Every pattern here was narrowed by an adversarial false-positive pass that
// wrote correct Rust designed to match the first draft. The naive versions
// fired on documentation, guard-rail constants and unrelated APIs that share a
// keyword; what survived is what could not be broken that way.
//
// Inherits the XL-013 Learn page (xl-auth-token-verification) from the family.

import { rustFiles, isRustCommentLine } from '../../shared-detectors/rust-scope.js';

const PROBE_NAME = 'Rust JWT Signature Not Verified (XL-013)';
// One CWE per adapter, matching the manifest record: the phase tests assert
// finding.cwe === adapter.cwe so the OWASP projection and the UI agree. The
// specific weakness (alg none, no expiry, timing) is carried by each finding's
// title and remediation, which is the text a reader actually acts on.
const PROBE_CWE = 'CWE-347';

// rust-jwt: the explicitly unverified parse, with or without a turbofish.
const RS_PARSE_UNVERIFIED_RE = /\bToken::parse_unverified\s*(?:::<[^\n]{0,80}>)?\s*\(/;

export const RS_AUTH_001 = {
  probe_id: 'RS-AUTH-001',
  xl_family: 'XL-013',
  language: 'rust',
  name: PROBE_NAME,
  category: 'access',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-347',
  owasp_web: 'A07',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.rs',
  what_it_catches:
    'rust-jwt Token::parse_unverified, which returns a fully typed token whose signature has never been checked.',
  why_ai_v05:
    'The type system makes the result look safe. parse_unverified hands back the same Token type a verified parse would, so nothing downstream can tell the difference and the compiler has no complaint.',
  vibe_v05:
    '"It compiled and the claims are typed, so this is fine." The function name is the only warning, and it is easy to read as a performance option.',
  detection_approach:
    'Per line, comments skipped: Token::parse_unverified, including its turbofish form.',
  fp_gates_v05: [
    'comment lines and doc comments (isRustCommentLine)',
    'verify_with_key / decode called with a DecodingKey and a Validation',
    '#[cfg(test)] modules / tests trees / scanner self-source / fixture tree (rustFiles())',
  ],
  remediation:
    'Verify against a key: token.verify_with_key(&key), or jsonwebtoken::decode(&token, &DecodingKey::from_secret(secret), &Validation::new(Algorithm::HS256)).',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/RS-AUTH-001/positive.rs',
    negative: 'src/lib/probes/v05/fixtures/RS-AUTH-001/negative.rs',
  },
  known_incidents: 'CWE-347 (missing signature verification); CWE-327 (alg none); OWASP A07',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of rustFiles(files)) {
      const lines = f.content.split('\n');
      const push = (kind, i, line, meta) => {
        findings.push({
          id: `${kind}-${f.path}-${i}`,
          probe: PROBE_NAME,
          title: meta.title,
          severity: meta.severity,
          category: 'Auth & Access',
          cwe: PROBE_CWE,
          file: f.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation: meta.remediation,
        });
      };
      lines.forEach((line, i) => {
        if (isRustCommentLine(line)) return;
        if (RS_PARSE_UNVERIFIED_RE.test(line)) {
          push('rs_parse_unverified_re', i, line, {
            title: 'JWT parsed without verifying the signature',
            severity: 'critical',
            remediation:
              'Use verify_with_key with the signing key, or jsonwebtoken::decode with a DecodingKey and a Validation. parse_unverified returns the same type a verified parse does, so nothing downstream can tell it apart.',
          });
        }
      });
    }
    return findings;
  },
};

// src/lib/probes/v05/adapters/java/jv-auth-001-token-verification.js
//
// XL-013 adapter for Java. jjwt parsers that opt in to unsecured tokens with .unsecured(), signing with SignatureAlgorithm.NONE or Jwts.SIG.NONE, or the explicitly unsigned parseClaimsJwt / parseUnsecuredClaims family.
//
// Every pattern here was narrowed by an adversarial false-positive pass that
// wrote correct Java designed to match the first draft. The naive versions
// fired on documentation, guard-rail constants and unrelated APIs that share a
// keyword; what survived is what could not be broken that way.
//
// Inherits the XL-013 Learn page (xl-auth-token-verification) from the family.

import { javaFiles, isJavaCommentLine } from '../../shared-detectors/java-scope.js';

const PROBE_NAME = 'Java JWT Signature Not Verified (XL-013)';
// One CWE per adapter, matching the manifest record: the phase tests assert
// finding.cwe === adapter.cwe so the OWASP projection and the UI agree. The
// specific weakness (alg none, no expiry, timing) is carried by each finding's
// title and remediation, which is the text a reader actually acts on.
const PROBE_CWE = 'CWE-347';

// jjwt 0.12+: the parser explicitly opts in to alg=none tokens.
const JV_UNSECURED_RE = /\bJwts\b[^;]*?\.\s*unsecured\s*\(\s*\)/;
// Signing with the none algorithm, both the old and new constant spellings.
const JV_SIGN_NONE_RE =
  /\bsignWith\s*\(\s*[^)]*(?:\bSignatureAlgorithm\s*\.\s*NONE\b|\bJwts\s*\.\s*SIG\s*\.\s*NONE\b)/;
// The explicitly UNSIGNED parse methods. JWE decrypt calls are excluded.
const JV_PARSE_UNSIGNED_RE =
  /\.\s*(?:parseClaimsJwt|parseContentJwt|parseUnsecuredClaims|parseUnsecuredContent)\s*\((?![^)]*(?:[Jj][Ww][Ee]|ecrypt))/;

export const JV_AUTH_001 = {
  probe_id: 'JV-AUTH-001',
  xl_family: 'XL-013',
  language: 'java',
  name: PROBE_NAME,
  category: 'access',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-347',
  owasp_web: 'A07',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.java',
  what_it_catches:
    'jjwt parsers that opt in to unsecured tokens with .unsecured(), signing with SignatureAlgorithm.NONE or Jwts.SIG.NONE, or the explicitly unsigned parseClaimsJwt / parseUnsecuredClaims family.',
  why_ai_v05:
    'parseClaimsJwt and parseClaimsJws differ by one character and only one of them checks a signature. The unsigned one works in a demo because the demo never sends a forged token.',
  vibe_v05:
    '"The claims object is populated, so the token is valid." The library will happily populate it from a token nobody signed.',
  detection_approach:
    'Per line, comments skipped: a Jwts chain calling .unsecured(); signWith carrying SignatureAlgorithm.NONE or Jwts.SIG.NONE; and the unsecured parse methods, with JWE decrypt calls excluded by lookahead.',
  fp_gates_v05: [
    'comment lines (isJavaCommentLine)',
    'parseSignedClaims / parseClaimsJws with verifyWith or setSigningKey',
    'JWE decryption calls, which legitimately parse without a JWS signature',
    '*Test.java / src/test / scanner self-source / fixture tree (javaFiles())',
  ],
  remediation:
    'Jwts.parser().verifyWith(key).build().parseSignedClaims(token). Never .unsecured() on a trust path, never SignatureAlgorithm.NONE.',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/JV-AUTH-001/positive.java',
    negative: 'src/lib/probes/v05/fixtures/JV-AUTH-001/negative.java',
  },
  known_incidents: 'CWE-347 (missing signature verification); CWE-327 (alg none); OWASP A07',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of javaFiles(files)) {
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
        if (isJavaCommentLine(line)) return;
        if (JV_UNSECURED_RE.test(line)) {
          push('jv_unsecured_re', i, line, {
            title: 'JWT parser accepts unsecured (alg=none) tokens',
            severity: 'critical',
            remediation:
              'Drop .unsecured() and verify: Jwts.parser().verifyWith(key).build().parseSignedClaims(token).',
          });
        }
        if (JV_SIGN_NONE_RE.test(line)) {
          push('jv_sign_none_re', i, line, {
            title: 'JWT signed with algorithm NONE',
            severity: 'critical',
            remediation:
              'Sign with Jwts.SIG.HS256 and a strong key, or an RSA/EC key pair. NONE means unsigned.',
          });
        }
        if (JV_PARSE_UNSIGNED_RE.test(line)) {
          push('jv_parse_unsigned_re', i, line, {
            title: 'JWT parsed without signature verification',
            severity: 'critical',
            remediation:
              'parseClaimsJwt parses an unsigned token. Use parseSignedClaims with verifyWith(key) whenever the claims decide anything.',
          });
        }
      });
    }
    return findings;
  },
};

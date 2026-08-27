// src/lib/probes/v05/adapters/dart/da-auth-001-token-verification.js
//
// XL-013 adapter for Dart. dart_jsonwebtoken verify calls with expiry or not-before checking turned off, tokens signed with no expiry, and hand-built JOSE headers declaring alg none.
//
// Every pattern here was narrowed by an adversarial false-positive pass that
// wrote correct Dart designed to match the first draft. The naive versions
// fired on documentation, guard-rail constants and unrelated APIs that share a
// keyword; what survived is what could not be broken that way.
//
// Inherits the XL-013 Learn page (xl-auth-token-verification) from the family.

import { dartFiles, isDartCommentLine } from '../../shared-detectors/dart-scope.js';

const PROBE_NAME = 'Dart JWT Signature Not Verified (XL-013)';
// One CWE per adapter, matching the manifest record: the phase tests assert
// finding.cwe === adapter.cwe so the OWASP projection and the UI agree. The
// specific weakness (alg none, no expiry, timing) is carried by each finding's
// title and remediation, which is the text a reader actually acts on.
const PROBE_CWE = 'CWE-347';

// Expiry or not-before validation explicitly disabled.
const DA_CHECKS_OFF_RE = /\bcheck(?:ExpiresIn|NotBefore)\s*:\s*false\b/;
// A token signed with no expiry on the line.
const DA_NO_EXPIRY_RE =
  /^(?!.*(?:expiresIn|['"]exp['"])).*\.sign\(\s*(?:SecretKey|RSAPrivateKey|ECPrivateKey|EdDSAPrivateKey)(?:\.[A-Za-z]+)?\s*\(.*;/;
// A hand-built header declaring alg none, excluding rejection checks.
const DA_HEADER_ALG_NONE_RE =
  /^(?!.*(?:[!=]=|throw|reject|denie|deny|disallow|forbid|assert|banned|blocked|unsupported|invalid|exception)).*["']alg["']\s*:\s*["']none["']/;

export const DA_AUTH_001 = {
  probe_id: 'DA-AUTH-001',
  xl_family: 'XL-013',
  language: 'dart',
  name: PROBE_NAME,
  category: 'access',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-347',
  owasp_web: 'A07',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.dart',
  what_it_catches:
    'dart_jsonwebtoken verify calls with expiry or not-before checking turned off, tokens signed with no expiry, and hand-built JOSE headers declaring alg none.',
  why_ai_v05:
    'checkExpiresIn: false is the fastest way to stop a demo failing after fifteen minutes, and it survives into production because nothing visibly breaks.',
  vibe_v05: '"The token kept expiring while I was testing." It is supposed to.',
  detection_approach:
    'Per line, comments skipped: checkExpiresIn / checkNotBefore set to false; a .sign( with a key type and no expiresIn or exp on the line; and an "alg": "none" pair on a line that is not a rejection check.',
  fp_gates_v05: [
    'comment lines (isDartCommentLine)',
    'lines that reject alg none rather than configuring it',
    'a sign call that does pass expiresIn',
    '*_test.dart / test trees / scanner self-source / fixture tree (dartFiles())',
  ],
  remediation:
    'Leave checkExpiresIn and checkNotBefore on, and pass expiresIn when signing so tokens stop working on their own.',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/DA-AUTH-001/positive.dart',
    negative: 'src/lib/probes/v05/fixtures/DA-AUTH-001/negative.dart',
  },
  known_incidents: 'CWE-347 (missing signature verification); CWE-327 (alg none); OWASP A07',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of dartFiles(files)) {
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
        if (isDartCommentLine(line)) return;
        if (DA_CHECKS_OFF_RE.test(line)) {
          push('da_checks_off_re', i, line, {
            title: 'JWT expiry or not-before validation disabled',
            severity: 'high',
            remediation:
              'Remove the flag. With expiry checking off a stolen token never stops working.',
          });
        }
        if (DA_NO_EXPIRY_RE.test(line)) {
          push('da_no_expiry_re', i, line, {
            title: 'JWT minted without an expiry',
            severity: 'medium',
            remediation:
              'Pass expiresIn: Duration(minutes: 15) and issue refresh tokens separately.',
          });
        }
        if (DA_HEADER_ALG_NONE_RE.test(line)) {
          push('da_header_alg_none_re', i, line, {
            title: 'JOSE header declares algorithm "none"',
            severity: 'critical',
            remediation: 'Declare a real algorithm and sign the token.',
          });
        }
      });
    }
    return findings;
  },
};

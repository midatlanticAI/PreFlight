// src/lib/probes/v05/adapters/swift/sw-auth-001-token-verification.js
//
// XL-013 adapter for Swift. JWTKit configured with the unsecured none algorithm, SwiftJWT signing or verifying with .none, kylef JWT decode with verify: false, and hand-built JOSE headers declaring alg none.
//
// Every pattern here was narrowed by an adversarial false-positive pass that
// wrote correct Swift designed to match the first draft. The naive versions
// fired on documentation, guard-rail constants and unrelated APIs that share a
// keyword; what survived is what could not be broken that way.
//
// Inherits the XL-013 Learn page (xl-auth-token-verification) from the family.

import { swiftFiles, isSwiftCommentLine } from '../../shared-detectors/swift-scope.js';

const PROBE_NAME = 'Swift JWT Signature Not Verified (XL-013)';
// One CWE per adapter, matching the manifest record: the phase tests assert
// finding.cwe === adapter.cwe so the OWASP projection and the UI agree. The
// specific weakness (alg none, no expiry, timing) is carried by each finding's
// title and remediation, which is the text a reader actually acts on.
const PROBE_CWE = 'CWE-347';

// JWTKit: the unsecured none signer.
const SW_UNSECURED_NONE_RE = /\.unsecuredNone\b|\baddUnsecuredNone\s*\(/;
// SwiftJWT: signing or verifying with the none algorithm.
const SW_SIGN_NONE_RE = /\b(?:sign|verify)\s*\(\s*[^()]*\busing\s*:\s*\.none\b/;
// kylef: verification switched off on decode.
const SW_DECODE_NOVERIFY_RE = /\bdecode\s*\([^;]*\balgorithms?\s*:[^;]*\bverify\s*:\s*false\b/;
// kylef: the none algorithm passed to encode or decode.
const SW_ALG_NONE_CALL_RE =
  /\bJWT\s*\.\s*(?:encode|decode)\s*\([^;()]*\balgorithms?\s*:\s*\.none\b|\bencode\s*\(\s*claims\s*:[^;()]*\balgorithm\s*:\s*\.none\b/;
// A hand-built header declaring alg none, excluding lines that reject it.
const SW_HEADER_ALG_NONE_RE =
  /^(?!.*(?:[!=]=|throw|reject|denie|deny|disallow|forbid|assert|banned|blocked|unsupported|invalid|exception)).*["']alg["']\s*:\s*["']none["']/;

export const SW_AUTH_001 = {
  probe_id: 'SW-AUTH-001',
  xl_family: 'XL-013',
  language: 'swift',
  name: PROBE_NAME,
  category: 'access',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-347',
  owasp_web: 'A07',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.swift',
  what_it_catches:
    'JWTKit configured with the unsecured none algorithm, SwiftJWT signing or verifying with .none, kylef JWT decode with verify: false, and hand-built JOSE headers declaring alg none.',
  why_ai_v05:
    'A mobile client that only needs to read its own token invites "just decode it", and every Swift JWT library offers a way to do that which looks like an ordinary option.',
  vibe_v05:
    '"It is our own token, we issued it." The app cannot tell its own token from one an attacker wrote unless it checks.',
  detection_approach:
    'Per line, comments skipped: .unsecuredNone / addUnsecuredNone; sign/verify using: .none; a decode carrying verify: false; JWT.encode/decode with algorithm .none; and an "alg": "none" pair on a line that is not a rejection check.',
  fp_gates_v05: [
    'comment lines (isSwiftCommentLine)',
    'lines that compare, throw, reject or otherwise refuse alg none rather than configuring it',
    'a real algorithm (.hs256, .rs256) with a key',
    '*Tests.swift / Tests trees / scanner self-source / fixture tree (swiftFiles())',
  ],
  remediation:
    'Sign and verify with a real algorithm and key. On a client, treat a token as a bearer credential to send, not as a source of truth to read.',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/SW-AUTH-001/positive.swift',
    negative: 'src/lib/probes/v05/fixtures/SW-AUTH-001/negative.swift',
  },
  known_incidents: 'CWE-347 (missing signature verification); CWE-327 (alg none); OWASP A07',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of swiftFiles(files)) {
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
        if (isSwiftCommentLine(line)) return;
        if (SW_UNSECURED_NONE_RE.test(line)) {
          push('sw_unsecured_none_re', i, line, {
            title: 'JWT signer configured with unsecured "none"',
            severity: 'critical',
            remediation: 'Add a real signer: addHMAC(key:digestAlgorithm:) or an RSA/ECDSA key.',
          });
        }
        if (SW_SIGN_NONE_RE.test(line)) {
          push('sw_sign_none_re', i, line, {
            title: 'JWT signed or verified with algorithm .none',
            severity: 'critical',
            remediation:
              'Use .hs256(key:) or .rs256(privateKey:). .none produces and accepts unsigned tokens.',
          });
        }
        if (SW_DECODE_NOVERIFY_RE.test(line)) {
          push('sw_decode_noverify_re', i, line, {
            title: 'JWT decoded with verification disabled',
            severity: 'critical',
            remediation: 'Remove verify: false and pass the secret.',
          });
        }
        if (SW_ALG_NONE_CALL_RE.test(line)) {
          push('sw_alg_none_call_re', i, line, {
            title: 'JWT encoded or decoded with algorithm .none',
            severity: 'critical',
            remediation: 'Name a real algorithm with a secret: .hs256(secret).',
          });
        }
        if (SW_HEADER_ALG_NONE_RE.test(line)) {
          push('sw_header_alg_none_re', i, line, {
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

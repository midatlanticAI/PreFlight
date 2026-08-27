// src/lib/probes/v05/adapters/scala/sc-auth-001-token-verification.js
//
// XL-013 adapter for Scala. jwt-scala decode / isValid / validate called with only a token and no key, or jjwt used from Scala with SignatureAlgorithm.NONE or an unsecured parse.
//
// Every pattern here was narrowed by an adversarial false-positive pass that
// wrote correct Scala designed to match the first draft. The naive versions
// fired on documentation, guard-rail constants and unrelated APIs that share a
// keyword; what survived is what could not be broken that way.
//
// Inherits the XL-013 Learn page (xl-auth-token-verification) from the family.

import { scalaFiles, isScalaCommentLine } from '../../shared-detectors/scala-scope.js';

const PROBE_NAME = 'Scala JWT Signature Not Verified (XL-013)';
// One CWE per adapter, matching the manifest record: the phase tests assert
// finding.cwe === adapter.cwe so the OWASP projection and the UI agree. The
// specific weakness (alg none, no expiry, timing) is carried by each finding's
// title and remediation, which is the text a reader actually acts on.
const PROBE_CWE = 'CWE-347';

// jwt-scala: the single-argument overload, which does not verify.
const SC_DECODE_NOKEY_RE =
  /\bJwt(?:Json4sNative|Json4sJackson|Json4s|Circe|Json|Upickle|Argonaut|ZIOJson|SprayJson)?\s*\.\s*(?:decodeRaw|decodeJson|decode|isValid|validate)\s*\(\s*[A-Za-z_][A-Za-z0-9_.]*\s*\)/;
// jjwt from Scala: signing with none.
const SC_SIGN_NONE_RE =
  /\bsignWith\s*\(\s*[^)]*(?:\bSignatureAlgorithm\s*\.\s*NONE\b|\bJwts\s*\.\s*SIG\s*\.\s*NONE\b)/;
// jjwt from Scala: the unsigned parse.
const SC_PARSE_UNSIGNED_RE =
  /\.\s*(?:parseClaimsJwt|parseUnsecuredClaims)\s*\((?![^)]*(?:[Jj][Ww][Ee]|ecrypt))/;

export const SC_AUTH_001 = {
  probe_id: 'SC-AUTH-001',
  xl_family: 'XL-013',
  language: 'scala',
  name: PROBE_NAME,
  category: 'access',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-347',
  owasp_web: 'A07',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.scala',
  what_it_catches:
    'jwt-scala decode / isValid / validate called with only a token and no key, or jjwt used from Scala with SignatureAlgorithm.NONE or an unsecured parse.',
  why_ai_v05:
    'jwt-scala overloads decode so the one-argument form compiles and returns a Success. The signature is simply not part of that overload, and nothing in the type tells you.',
  vibe_v05: '"decode returned Success, so it is a valid token." Success means it was well formed.',
  detection_approach:
    'Per line, comments skipped: a Jwt* object calling decode/decodeRaw/decodeJson/isValid/validate with a single identifier argument; plus the jjwt none-signing and unsecured-parse shapes.',
  fp_gates_v05: [
    'comment lines (isScalaCommentLine)',
    'decode / isValid called with a key and an algorithm list (more than one argument)',
    'JWE decryption calls',
    '*Spec.scala / src/test / scanner self-source / fixture tree (scalaFiles())',
  ],
  remediation:
    'Pass the key and the permitted algorithms: Jwt.decode(token, key, Seq(JwtAlgorithm.HS256)). The single-argument overload does not verify anything.',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/SC-AUTH-001/positive.scala',
    negative: 'src/lib/probes/v05/fixtures/SC-AUTH-001/negative.scala',
  },
  known_incidents: 'CWE-347 (missing signature verification); CWE-327 (alg none); OWASP A07',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of scalaFiles(files)) {
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
        if (isScalaCommentLine(line)) return;
        if (SC_DECODE_NOKEY_RE.test(line)) {
          push('sc_decode_nokey_re', i, line, {
            title: 'JWT decoded without a key (signature not verified)',
            severity: 'critical',
            remediation:
              'Use the overload that takes the key and the algorithm list: Jwt.decode(token, key, Seq(JwtAlgorithm.HS256)).',
          });
        }
        if (SC_SIGN_NONE_RE.test(line)) {
          push('sc_sign_none_re', i, line, {
            title: 'JWT signed with algorithm NONE',
            severity: 'critical',
            remediation:
              'Sign with a real algorithm and key. NONE means the token carries no proof.',
          });
        }
        if (SC_PARSE_UNSIGNED_RE.test(line)) {
          push('sc_parse_unsigned_re', i, line, {
            title: 'JWT parsed without signature verification',
            severity: 'critical',
            remediation: 'Use parseSignedClaims with verifyWith(key).',
          });
        }
      });
    }
    return findings;
  },
};

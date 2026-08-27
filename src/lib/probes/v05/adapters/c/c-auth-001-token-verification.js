// src/lib/probes/v05/adapters/c/c-auth-001-token-verification.js
//
// XL-013 adapter for C. libjwt decoding with a NULL key, a libjwt v3 checker
// keyed with JWT_ALG_NONE, l8w8jwt's explicitly unvalidated decode, and the
// OpenSSL / mbedTLS layer underneath: a verification result compared against
// the wrong value, discarded entirely, or a signature compared with memcmp.
//
// Verified against primary sources rather than memory: libjwt's own header
// documents that jwt_decode with a NULL key performs "no validation ... other
// than formatting", l8w8jwt's decode.h documents
// l8w8jwt_decode_raw_no_validation as "no validation!", and the OpenSSL manual
// for EVP_DigestVerifyInit states that EVP_DigestVerifyFinal returns 1 for
// success and any other value for failure.
//
// Inherits the XL-013 Learn page (xl-auth-token-verification) from the family.

import { cFiles } from '../../shared-detectors/c-family-scope.js';
import {
  forEachCFamilyCodeLine,
  isContinuationOf,
  C_VERIFY_WRONG_COMPARE_RE,
  C_VERIFY_DISCARDED_RE,
  C_TIMING_COMPARE_RE,
} from '../../shared-detectors/c-family-auth.js';

const PROBE_NAME = 'C JWT Signature Not Verified (XL-013)';
// One CWE per adapter, matching the manifest record: the phase tests assert
// finding.cwe === adapter.cwe so the OWASP projection and the UI agree. The
// specific weakness (alg none, no expiry, timing) is carried by each finding's
// title and remediation, which is the text a reader actually acts on.
const PROBE_CWE = 'CWE-347';

// libjwt: a NULL key with zero length means the token is decoded but never
// verified. The argument list is bounded so it cannot run past this call.
const C_JWT_DECODE_NULL_RE = /\bjwt_decode\s*\((?:[^;()]|\([^;()]*\))*,\s*NULL\s*,\s*0\s*\)/;

// libjwt v3: the checker is told to expect an unsigned token.
const C_CHECKER_ALG_NONE_RE =
  /\bjwt_checker_setkey\s*\((?:[^;()]|\([^;()]*\))*,\s*JWT_ALG_NONE\s*,\s*NULL\s*\)/;

// l8w8jwt: the function whose own documentation says it validates nothing.
const C_L8W8JWT_NO_VALIDATION_RE = /\bl8w8jwt_decode_raw_no_validation\s*\(/;

export const C_AUTH_001 = {
  probe_id: 'CC-AUTH-001',
  xl_family: 'XL-013',
  language: 'c',
  name: PROBE_NAME,
  category: 'access',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-347',
  owasp_web: 'A07',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.{c,h}',
  what_it_catches:
    'libjwt jwt_decode called with a NULL key, a libjwt v3 checker keyed with JWT_ALG_NONE, l8w8jwt_decode_raw_no_validation, an OpenSSL verification result compared against the wrong value or discarded, and a signature or HMAC compared with memcmp / strcmp.',
  why_ai_v05:
    'C has no exceptions, so a verification failure is a return value somebody has to check. The generated code that "works" is the code that calls the function; the check is a separate line that is easy never to write.',
  vibe_v05: '"I called the verify function." Calling it is not the same as acting on what it said.',
  detection_approach:
    'Per line with block-comment state carried across lines, and a previous-line check so a clang-format-wrapped call is not read as a discarded result. Argument lists are bounded so a pattern cannot run past its own closing paren into an unrelated comparison.',
  fp_gates_v05: [
    'line and block comments, tracked with state rather than per-line shape',
    'clang-format continuation lines, where the return value is used on the line above',
    'function prototypes in headers, rejected by a type-name lookahead',
    'ordering comparators and file-format magic checks, which memcmp signature fields legitimately',
    'vendored trees (third_party, 3rdparty, external, deps) via the file filter',
    'test files / scanner self-source / fixture tree (cFiles())',
  ],
  remediation:
    'Pass the key to jwt_decode and check its return. Test EVP_DigestVerifyFinal against 1 and nothing else. Compare signatures with a constant-time function such as CRYPTO_memcmp, never memcmp.',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/CC-AUTH-001/positive.c',
    negative: 'src/lib/probes/v05/fixtures/CC-AUTH-001/negative.c',
  },
  known_incidents: 'CWE-347; CWE-327 (alg none); CWE-208 (timing); OWASP A07',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of cFiles(files)) {
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

      forEachCFamilyCodeLine(f.content, (line, i, prevCodeLine) => {
        if (C_JWT_DECODE_NULL_RE.test(line)) {
          push('c-auth-nullkey', i, line, {
            title: 'JWT decoded with a NULL key (no signature verification)',
            severity: 'critical',
            remediation:
              'libjwt performs no validation beyond formatting when the key is NULL. Pass the key and its length, and check the return value.',
          });
        }
        if (C_CHECKER_ALG_NONE_RE.test(line)) {
          push('c-auth-algnone', i, line, {
            title: 'JWT checker configured for unsigned tokens (JWT_ALG_NONE)',
            severity: 'critical',
            remediation:
              'Key the checker with a real algorithm and a secret. JWT_ALG_NONE with a NULL key accepts any token whose header says alg=none.',
          });
        }
        if (C_L8W8JWT_NO_VALIDATION_RE.test(line)) {
          push('c-auth-novalidation', i, line, {
            title: 'JWT decoded with validation explicitly skipped',
            severity: 'critical',
            remediation:
              'l8w8jwt_decode_raw_no_validation checks neither claims nor signature, by its own documentation. Use l8w8jwt_decode with a verification key.',
          });
        }
        if (C_VERIFY_WRONG_COMPARE_RE.test(line)) {
          push('c-auth-wrongcompare', i, line, {
            title: 'Signature verification result compared against the wrong value',
            severity: 'critical',
            remediation:
              'EVP_DigestVerifyFinal returns 1 for success and any other value for failure, so a forged signature can return 0 or a negative error code. Test == 1.',
          });
        }
        if (!isContinuationOf(prevCodeLine) && C_VERIFY_DISCARDED_RE.test(line)) {
          push('c-auth-discarded', i, line, {
            title: 'Signature verification return value discarded',
            severity: 'critical',
            remediation:
              'The return value IS the verification result. Capture it and act on it; a call whose result is thrown away verifies nothing.',
          });
        }
        if (C_TIMING_COMPARE_RE.test(line)) {
          push('c-auth-timing', i, line, {
            title: 'Signature or HMAC compared with a non-constant-time function',
            severity: 'high',
            remediation:
              'memcmp returns as soon as bytes differ, which leaks how much of a guess was correct. Use CRYPTO_memcmp or another constant-time comparison.',
          });
        }
      });
    }
    return findings;
  },
};

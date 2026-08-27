// src/lib/probes/v05/adapters/cpp/cpp-auth-001-token-verification.js
//
// XL-013 adapter for C++. cpp-jwt / jwt-cpp decode calls that accept the
// "none" algorithm or turn verification off, plus the same OpenSSL and
// mbedTLS layer the C adapter covers.
//
// cFiles() and cppFiles() partition the extensions between them (.h belongs to
// C, .hpp / .hxx / .hh / .cpp / .cc / .cxx to C++), so the shared OpenSSL rules
// cannot double-report one file.
//
// Inherits the XL-013 Learn page (xl-auth-token-verification) from the family.

import { cppFiles } from '../../shared-detectors/c-family-scope.js';
import {
  forEachCFamilyCodeLine,
  isContinuationOf,
  C_VERIFY_WRONG_COMPARE_RE,
  C_VERIFY_DISCARDED_RE,
  C_TIMING_COMPARE_RE,
} from '../../shared-detectors/c-family-auth.js';

const PROBE_NAME = 'C++ JWT Signature Not Verified (XL-013)';
// One CWE per adapter, matching the manifest record: the phase tests assert
// finding.cwe === adapter.cwe so the OWASP projection and the UI agree. The
// specific weakness (alg none, no expiry, timing) is carried by each finding's
// title and remediation, which is the text a reader actually acts on.
const PROBE_CWE = 'CWE-347';

// cpp-jwt: the decode call lists "none" among the algorithms it will accept.
const CPP_DECODE_ALG_NONE_RE =
  /\bjwt\s*::\s*decode\s*\((?:[^;()]|\([^;()]*\))*?\balgorithms\s*\(\s*\{[^}]*"(?:none|None|NONE)"/;

// cpp-jwt: verification switched off on the decode call itself.
const CPP_DECODE_NOVERIFY_RE =
  /\bjwt\s*::\s*decode\s*\((?:[^;()]|\([^;()]*\))*?\bverify\s*\(\s*false\s*\)/;

// jwt-cpp: the verifier is told the none algorithm is acceptable.
const CPP_ALLOW_NONE_RE = /\ballow_algorithm\s*\(\s*jwt\s*::\s*algorithm\s*::\s*none\b/;

export const CPP_AUTH_001 = {
  probe_id: 'CPP-AUTH-001',
  xl_family: 'XL-013',
  language: 'cpp',
  name: PROBE_NAME,
  category: 'access',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-347',
  owasp_web: 'A07',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.{cpp,cc,cxx,hpp,hh,hxx}',
  what_it_catches:
    'cpp-jwt decode accepting the "none" algorithm or with verify(false), jwt-cpp verifiers allowing algorithm::none, an OpenSSL verification result compared against the wrong value or discarded, and a signature or HMAC compared with memcmp / strcmp.',
  why_ai_v05:
    'Both libraries expose the none algorithm as an ordinary enumeration value sitting beside the real ones, so allowing it looks like configuration rather than a decision to stop checking.',
  vibe_v05: '"I added the algorithms it should accept." One of them accepts everything.',
  detection_approach:
    'Per line with block-comment state carried across lines, a previous-line continuation check, and bounded argument lists so a pattern cannot run past its own closing paren.',
  fp_gates_v05: [
    'line and block comments, tracked with state rather than per-line shape',
    'clang-format continuation lines, where the return value is used on the line above',
    'function prototypes in headers, rejected by a type-name lookahead',
    'ordering comparators and file-format magic checks that memcmp a field named signature',
    'vendored trees (third_party, 3rdparty, external, deps) via the file filter, which is what keeps jwt-cpp own examples out',
    'test files / scanner self-source / fixture tree (cppFiles())',
  ],
  remediation:
    'List only real algorithms on the verifier, leave verify on, test EVP_DigestVerifyFinal against 1, and compare signatures with CRYPTO_memcmp.',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/CPP-AUTH-001/positive.cpp',
    negative: 'src/lib/probes/v05/fixtures/CPP-AUTH-001/negative.cpp',
  },
  known_incidents: 'CWE-347; CWE-327 (alg none); CWE-208 (timing); OWASP A07',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of cppFiles(files)) {
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
        if (CPP_DECODE_ALG_NONE_RE.test(line) || CPP_ALLOW_NONE_RE.test(line)) {
          push('cpp-auth-algnone', i, line, {
            title: 'JWT verifier accepts the "none" algorithm',
            severity: 'critical',
            remediation:
              'Remove none from the accepted algorithms. A token whose header says alg=none carries no signature, so anyone can write one.',
          });
        }
        if (CPP_DECODE_NOVERIFY_RE.test(line)) {
          push('cpp-auth-noverify', i, line, {
            title: 'JWT decoded with verification disabled',
            severity: 'critical',
            remediation:
              'Drop verify(false) and supply the key. With verification off the claims are attacker-controlled input.',
          });
        }
        if (C_VERIFY_WRONG_COMPARE_RE.test(line)) {
          push('cpp-auth-wrongcompare', i, line, {
            title: 'Signature verification result compared against the wrong value',
            severity: 'critical',
            remediation:
              'EVP_DigestVerifyFinal returns 1 for success and any other value for failure. Test == 1.',
          });
        }
        if (!isContinuationOf(prevCodeLine) && C_VERIFY_DISCARDED_RE.test(line)) {
          push('cpp-auth-discarded', i, line, {
            title: 'Signature verification return value discarded',
            severity: 'critical',
            remediation: 'The return value IS the verification result. Capture it and act on it.',
          });
        }
        if (C_TIMING_COMPARE_RE.test(line)) {
          push('cpp-auth-timing', i, line, {
            title: 'Signature or HMAC compared with a non-constant-time function',
            severity: 'high',
            remediation:
              'Use CRYPTO_memcmp or another constant-time comparison. memcmp returns early and leaks how much of a guess matched.',
          });
        }
      });
    }
    return findings;
  },
};

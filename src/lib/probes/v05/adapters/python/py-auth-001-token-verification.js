// src/lib/probes/v05/adapters/python/py-auth-001-token-verification.js
//
// XL-013 adapter for Python. PyJWT decode with options={"verify_signature": False}, an algorithms list that accepts "none", a jwt.encode/jws.sign that mints with algorithm "none", or python-jose get_unverified_claims used as if it returned trusted data.
//
// Every pattern here was narrowed by an adversarial false-positive pass that
// wrote correct Python designed to match the first draft. The naive versions
// fired on documentation, guard-rail constants and unrelated APIs that share a
// keyword; what survived is what could not be broken that way.
//
// Inherits the XL-013 Learn page (xl-auth-token-verification) from the family.

import { pythonFiles } from '../../shared-detectors/python-scope.js';
import {
  forEachPythonCodeLine,
  isInsideStringLiteral,
} from '../../shared-detectors/python-strings.js';

const PROBE_NAME = 'Python JWT Signature Not Verified (XL-013)';
// One CWE per adapter, matching the manifest record: the phase tests assert
// finding.cwe === adapter.cwe so the OWASP projection and the UI agree. The
// specific weakness (alg none, no expiry, timing) is carried by each finding's
// title and remediation, which is the text a reader actually acts on.
const PROBE_CWE = 'CWE-347';

// verify_signature disabled, and only inside an options= dict literal on this line.
const PY_VERIFY_OFF_RE = /\boptions\s*=\s*\{[^}]*["']verify_signature["']\s*:\s*False\b/;
// An algorithms list that accepts "none". Plural + list literal is a JWT shape.
const PY_ALG_NONE_LIST_RE = /\balgorithms\s*=\s*\[[^\]]*["']none["']/;
// Minting an unsigned token. Requires the jwt/jws call, so codec kwargs cannot match.
const PY_ALG_NONE_SIGN_RE =
  /\b(?:jwt|jws)\.(?:encode|sign)\s*\(.*\balgorithms?\s*=\s*(?:["']none["']|[\w.]*ALGORITHMS\.NONE\b)/;
// Reading claims without verification. Leading dot so wrapper definitions do not match.
const PY_UNVERIFIED_CLAIMS_RE = /\.get_unverified_claims\s*\(/;

export const PY_AUTH_001 = {
  probe_id: 'PY-AUTH-001',
  xl_family: 'XL-013',
  language: 'python',
  name: PROBE_NAME,
  category: 'access',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-347',
  owasp_web: 'A07',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.py',
  what_it_catches:
    'PyJWT decode with options={"verify_signature": False}, an algorithms list that accepts "none", a jwt.encode/jws.sign that mints with algorithm "none", or python-jose get_unverified_claims used as if it returned trusted data.',
  why_ai_v05:
    'Signature verification is the first thing that breaks a demo, and turning it off is the shortest edit that makes the token decode. PyJWT raises on a bad signature, so a model that has never had a valid key reaches for options={"verify_signature": False} and the endpoint starts working.',
  vibe_v05:
    '"The claims came back, so the token is good." Decoding is base64. Verification is the part that was switched off.',
  detection_approach:
    'Per line, comments stripped, CASE SENSITIVE (an /i flag starts matching embedded JSON config). Four rules: verify_signature:False inside an options= dict literal; algorithms=[...] containing "none"; a jwt/jws encode/sign call carrying algorithm none or ALGORITHMS.NONE; and a qualified .get_unverified_claims( call.',
  fp_gates_v05: [
    'comment lines (isPythonCommentLine)',
    'the options= dict must be on the line, so guard-rail denylists and pytest parametrize lists do not match',
    'algorithm="none" on a codec or compression kwarg (the rule needs the plural list form or a jwt/jws call)',
    'test files / scanner self-source / fixture tree (pythonFiles())',
  ],
  remediation:
    'Verify the signature: jwt.decode(token, key, algorithms=["RS256"]). Never accept "none" in the algorithms list, and never pass verify_signature: False on a trust path. get_unverified_claims is for reading the issuer to pick a key, not for authorising anyone.',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/PY-AUTH-001/positive.py',
    negative: 'src/lib/probes/v05/fixtures/PY-AUTH-001/negative.py',
  },
  known_incidents: 'CWE-347 (missing signature verification); CWE-327 (alg none); OWASP A07',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of pythonFiles(files)) {
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
      forEachPythonCodeLine(f.content, (line, i) => {
        // A rule only counts when its match is CODE. A docstring warning
        // against options={"verify_signature": False} is byte-identical to the
        // call, and help='...' strings carry the same text as an argument.
        const asCode = (re) => {
          const m = re.exec(line);
          return m ? !isInsideStringLiteral(line, m.index) : false;
        };
        if (asCode(PY_VERIFY_OFF_RE)) {
          push('py_verify_off_re', i, line, {
            title: 'JWT signature verification disabled (verify_signature: False)',
            severity: 'critical',
            remediation:
              'Remove the option and pass the key: jwt.decode(token, key, algorithms=["RS256"]). If this token really did arrive over TLS straight from the token endpoint, say so in a comment, because the next reader cannot tell.',
          });
        }
        if (asCode(PY_ALG_NONE_LIST_RE)) {
          push('py_alg_none_list_re', i, line, {
            title: 'JWT decode accepts the "none" algorithm',
            severity: 'critical',
            remediation:
              'Drop "none" from the algorithms list. An unsigned token can be forged by anyone who can reach the endpoint.',
          });
        }
        if (asCode(PY_ALG_NONE_SIGN_RE)) {
          push('py_alg_none_sign_re', i, line, {
            title: 'JWT minted with algorithm "none"',
            severity: 'critical',
            remediation:
              'Sign with HS256 and a strong secret, or RS256 and a key pair. A token signed with "none" carries no proof of anything.',
          });
        }
        if (asCode(PY_UNVERIFIED_CLAIMS_RE)) {
          push('py_unverified_claims_re', i, line, {
            title: 'JWT claims read without verifying the signature',
            severity: 'medium',
            remediation:
              'Legitimate for reading the issuer to choose a key. If any value from here decides who the caller is or what they may do, verify the token first.',
          });
        }
      });
    }
    return findings;
  },
};

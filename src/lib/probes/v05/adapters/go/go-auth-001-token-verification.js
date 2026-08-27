// src/lib/probes/v05/adapters/go/go-auth-001-token-verification.js
//
// XL-013 adapter for Go. golang-jwt tokens created with SigningMethodNone, jwx verification or validation switched off with jwt.WithVerify(false) / jwt.WithValidate(false), or claim validation waived with WithoutClaimsValidation().
//
// Every pattern here was narrowed by an adversarial false-positive pass that
// wrote correct Go designed to match the first draft. The naive versions
// fired on documentation, guard-rail constants and unrelated APIs that share a
// keyword; what survived is what could not be broken that way.
//
// Inherits the XL-013 Learn page (xl-auth-token-verification) from the family.

import { goFiles, isGoCommentLine } from '../../shared-detectors/go-scope.js';

const PROBE_NAME = 'Go JWT Signature Not Verified (XL-013)';
// One CWE per adapter, matching the manifest record: the phase tests assert
// finding.cwe === adapter.cwe so the OWASP projection and the UI agree. The
// specific weakness (alg none, no expiry, timing) is carried by each finding's
// title and remediation, which is the text a reader actually acts on.
const PROBE_CWE = 'CWE-347';

// golang-jwt: the unsigned signing method, in constructor or struct-field form.
const GO_SIGNING_NONE_RE =
  /\bNew(?:WithClaims)?\s*\(\s*(?:[\w.]+\.)?SigningMethodNone\b|\bMethod\s*:\s*(?:[\w.]+\.)?SigningMethodNone\b/;
// jwx: signature verification explicitly disabled.
const GO_JWX_NOVERIFY_RE = /\bjwt\.WithVerify\s*\(\s*false\s*\)/;
// golang-jwt: exp / nbf / aud checks waived.
const GO_NO_CLAIMS_VALIDATION_RE = /\.WithoutClaimsValidation\s*\(\s*\)/;
// jwx: the same waiver.
const GO_JWX_NOVALIDATE_RE = /\bjwt\.WithValidate\s*\(\s*false\s*\)/;

export const GO_AUTH_001 = {
  probe_id: 'GO-AUTH-001',
  xl_family: 'XL-013',
  language: 'go',
  name: PROBE_NAME,
  category: 'access',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-347',
  owasp_web: 'A07',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.go',
  what_it_catches:
    'golang-jwt tokens created with SigningMethodNone, jwx verification or validation switched off with jwt.WithVerify(false) / jwt.WithValidate(false), or claim validation waived with WithoutClaimsValidation().',
  why_ai_v05:
    'SigningMethodNone exists so the library can round-trip an unsigned token, and it is the one signing method that needs no key material. A model with no key to hand reaches for the option that compiles.',
  vibe_v05:
    '"It parses and I get claims back." Parsing is not verifying, and Go will not tell you the difference.',
  detection_approach:
    'Per line, comments skipped: jwt.New / NewWithClaims taking SigningMethodNone or a Method: SigningMethodNone field; jwt.WithVerify(false); jwt.WithValidate(false); .WithoutClaimsValidation().',
  fp_gates_v05: [
    'comment lines (isGoCommentLine)',
    'a real signing method (SigningMethodHS256 / RS256) on the same call',
    'WithVerify / WithValidate passed true',
    '*_test.go / scanner self-source / fixture tree (goFiles())',
  ],
  remediation:
    'Parse with a key and an expected method: jwt.Parse(tok, keyFunc, jwt.WithValidMethods([]string{"RS256"})). Never SigningMethodNone outside a test, and leave jwx verification and validation on.',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/GO-AUTH-001/positive.go',
    negative: 'src/lib/probes/v05/fixtures/GO-AUTH-001/negative.go',
  },
  known_incidents: 'CWE-347 (missing signature verification); CWE-327 (alg none); OWASP A07',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of goFiles(files)) {
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
        if (isGoCommentLine(line)) return;
        if (GO_SIGNING_NONE_RE.test(line)) {
          push('go_signing_none_re', i, line, {
            title: 'JWT signed with SigningMethodNone',
            severity: 'critical',
            remediation:
              'Use jwt.SigningMethodHS256 with a strong secret or jwt.SigningMethodRS256 with a key pair. SigningMethodNone produces a token anyone can rewrite.',
          });
        }
        if (GO_JWX_NOVERIFY_RE.test(line)) {
          push('go_jwx_noverify_re', i, line, {
            title: 'JWT signature verification disabled (jwt.WithVerify(false))',
            severity: 'critical',
            remediation:
              'Remove the option, or pass the key set: jwt.Parse(buf, jwt.WithKeySet(keys)). With verification off the token is untrusted input wearing a claims struct.',
          });
        }
        if (GO_NO_CLAIMS_VALIDATION_RE.test(line)) {
          push('go_no_claims_validation_re', i, line, {
            title: 'JWT claim validation disabled (WithoutClaimsValidation)',
            severity: 'high',
            remediation:
              'Leave claim validation on so an expired token stops working. Waiving it means a stolen token is valid until the key rotates.',
          });
        }
        if (GO_JWX_NOVALIDATE_RE.test(line)) {
          push('go_jwx_novalidate_re', i, line, {
            title: 'JWT claim validation disabled (jwt.WithValidate(false))',
            severity: 'high',
            remediation: 'Leave validation on. Without it exp and nbf are decoration.',
          });
        }
      });
    }
    return findings;
  },
};

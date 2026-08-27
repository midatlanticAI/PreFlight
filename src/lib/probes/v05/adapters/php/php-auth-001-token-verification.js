// src/lib/probes/v05/adapters/php/php-auth-001-token-verification.js
//
// XL-013 adapter for PHP. lcobucci/jwt configured with forUnsecuredSigner() or the Signer\None class, a hand-written JOSE header declaring alg none, or a payload read by base64-decoding the middle segment directly.
//
// Every pattern here was narrowed by an adversarial false-positive pass that
// wrote correct PHP designed to match the first draft. The naive versions
// fired on documentation, guard-rail constants and unrelated APIs that share a
// keyword; what survived is what could not be broken that way.
//
// Inherits the XL-013 Learn page (xl-auth-token-verification) from the family.

import { phpFiles, isPhpCommentLine } from '../../shared-detectors/php-scope.js';

const PROBE_NAME = 'PHP JWT Signature Not Verified (XL-013)';
// One CWE per adapter, matching the manifest record: the phase tests assert
// finding.cwe === adapter.cwe so the OWASP projection and the UI agree. The
// specific weakness (alg none, no expiry, timing) is carried by each finding's
// title and remediation, which is the text a reader actually acts on.
const PROBE_CWE = 'CWE-347';

// lcobucci/jwt: the unsecured configuration.
const PHP_UNSECURED_SIGNER_RE = /(?:::|->)\s*forUnsecuredSigner\s*\(/;
// The None signer class itself.
const PHP_SIGNER_NONE_RE =
  /\bnew\s+\\?(?:[\w\\]+\\)?Signer\\None\b|^\s*use\s+[\w\\]*Signer\\None\s*;/;
// A hand-built header declaring alg none.
const PHP_ALG_NONE_RE = /['"]alg['"]\s*=>\s*['"]none['"]/;
// Reading the payload segment directly, which skips verification entirely.
const PHP_MANUAL_DECODE_RE =
  /json_decode\s*\([^;]{0,60}base64_decode\s*\([^;]{0,60}explode\s*\(\s*['"]\.['"]\s*,\s*[^;()]{1,60}\)\s*\[\s*1\s*\]/;

export const PHP_AUTH_001 = {
  probe_id: 'PHP-AUTH-001',
  xl_family: 'XL-013',
  language: 'php',
  name: PROBE_NAME,
  category: 'access',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-347',
  owasp_web: 'A07',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.php',
  what_it_catches:
    'lcobucci/jwt configured with forUnsecuredSigner() or the Signer\\None class, a hand-written JOSE header declaring alg none, or a payload read by base64-decoding the middle segment directly.',
  why_ai_v05:
    'Splitting on dots and base64-decoding segment one is the obvious way to "read a JWT" if you have never been told what the third segment is for. It works, and it skips the only part that mattered.',
  vibe_v05:
    '"I just need the user id out of the token." The signature is the reason the user id can be believed.',
  detection_approach:
    'Per line, comments skipped: forUnsecuredSigner(); a Signer\\None import or instantiation; an "alg" => "none" header pair; and the explode / base64_decode / json_decode chain that reads a payload directly.',
  fp_gates_v05: [
    'comment lines (isPhpCommentLine)',
    'a real signer (Signer\\Hmac\\Sha256) with a key',
    'vendor/ trees, which carry these shapes legitimately',
    '*Test.php / tests / scanner self-source / fixture tree (phpFiles())',
  ],
  remediation:
    'Configuration::forSymmetricSigner(new Sha256(), $key) and validate with a SignedWith constraint. Never read claims by base64-decoding the payload segment.',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/PHP-AUTH-001/positive.php',
    negative: 'src/lib/probes/v05/fixtures/PHP-AUTH-001/negative.php',
  },
  known_incidents: 'CWE-347 (missing signature verification); CWE-327 (alg none); OWASP A07',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of phpFiles(files)) {
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
        if (isPhpCommentLine(line)) return;
        if (PHP_UNSECURED_SIGNER_RE.test(line)) {
          push('php_unsecured_signer_re', i, line, {
            title: 'JWT configuration built with the unsecured signer',
            severity: 'critical',
            remediation:
              'Use Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText($key)) and add a SignedWith constraint.',
          });
        }
        if (PHP_SIGNER_NONE_RE.test(line)) {
          push('php_signer_none_re', i, line, {
            title: 'JWT None signer in use',
            severity: 'critical',
            remediation:
              'Replace Signer\\None with Signer\\Hmac\\Sha256 or an RSA signer, and supply a key.',
          });
        }
        if (PHP_ALG_NONE_RE.test(line)) {
          push('php_alg_none_re', i, line, {
            title: 'JOSE header declares algorithm "none"',
            severity: 'critical',
            remediation: 'Name a real algorithm in the header and sign the token.',
          });
        }
        if (PHP_MANUAL_DECODE_RE.test(line)) {
          push('php_manual_decode_re', i, line, {
            title: 'JWT payload read by manual base64 decode',
            severity: 'high',
            remediation:
              'Parse and validate with a library. Decoding the middle segment yourself reads attacker-supplied JSON and calls it a user.',
          });
        }
      });
    }
    return findings;
  },
};

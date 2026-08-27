// src/lib/probes/v05/adapters/ruby/rb-auth-001-token-verification.js
//
// XL-013 adapter for Ruby. ruby-jwt JWT.decode called with its verify argument false, an options hash accepting the "none" algorithm, or JWT.encode minting an unsigned token.
//
// Every pattern here was narrowed by an adversarial false-positive pass that
// wrote correct Ruby designed to match the first draft. The naive versions
// fired on documentation, guard-rail constants and unrelated APIs that share a
// keyword; what survived is what could not be broken that way.
//
// Inherits the XL-013 Learn page (xl-auth-token-verification) from the family.

import { rubyFiles, isRubyCommentLine } from '../../shared-detectors/ruby-scope.js';

const PROBE_NAME = 'Ruby JWT Signature Not Verified (XL-013)';
// One CWE per adapter, matching the manifest record: the phase tests assert
// finding.cwe === adapter.cwe so the OWASP projection and the UI agree. The
// specific weakness (alg none, no expiry, timing) is carried by each finding's
// title and remediation, which is the text a reader actually acts on.
const PROBE_CWE = 'CWE-347';

// The verify argument passed false.
const RB_DECODE_NOVERIFY_RE =
  /(?<!\w)(?<![A-Za-z_]::)JWT(?:\.|::)decode\s*\(\s*[^,()]+,\s*[^,()]*,\s*false\b/;
// An algorithm option of "none", on a line that is about JWT.
const RB_ALG_NONE_RE =
  /^(?=.*[Jj][Ww][Tt])(?:.*[\s{(,:'"])?algorithms?\s*['"]?\s*(?:=>|:)\s*\[?\s*['"]none['"]/;
// Minting an unsigned token.
const RB_ENCODE_NONE_RE =
  /(?<!\w)(?<![A-Za-z_]::)JWT(?:\.|::)encode\s*\([^)(]*,\s*['"]none['"]\s*(?:\)|,\s*\{)/;

export const RB_AUTH_001 = {
  probe_id: 'RB-AUTH-001',
  xl_family: 'XL-013',
  language: 'ruby',
  name: PROBE_NAME,
  category: 'access',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-347',
  owasp_web: 'A07',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.rb',
  what_it_catches:
    'ruby-jwt JWT.decode called with its verify argument false, an options hash accepting the "none" algorithm, or JWT.encode minting an unsigned token.',
  why_ai_v05:
    'JWT.decode(token, nil, false) is the shortest call that returns a payload, and it is what a model writes when it has no key in hand. Nothing raises.',
  vibe_v05:
    '"decode gave me the payload hash, so the user is who they say." The third argument decided that, and it was false.',
  detection_approach:
    'Per line, comments skipped: JWT.decode with a literal false in the verify position; an algorithm option set to "none" on a line mentioning JWT; and JWT.encode with "none" as the algorithm.',
  fp_gates_v05: [
    'comment lines (isRubyCommentLine)',
    'JWT.decode passed true with a key and an algorithm option',
    'a constant path such as Some::JWT.decode, excluded by lookbehind',
    '*_spec.rb / spec / test trees / scanner self-source / fixture tree (rubyFiles())',
  ],
  remediation:
    'JWT.decode(token, key, true, { algorithm: "HS256" }). The third argument is verify; false means the signature is ignored.',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/RB-AUTH-001/positive.rb',
    negative: 'src/lib/probes/v05/fixtures/RB-AUTH-001/negative.rb',
  },
  known_incidents: 'CWE-347 (missing signature verification); CWE-327 (alg none); OWASP A07',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of rubyFiles(files)) {
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
        if (isRubyCommentLine(line)) return;
        if (RB_DECODE_NOVERIFY_RE.test(line)) {
          push('rb_decode_noverify_re', i, line, {
            title: 'JWT.decode called with verification disabled',
            severity: 'critical',
            remediation:
              'Pass true and supply the key and algorithm: JWT.decode(token, key, true, { algorithm: "HS256" }).',
          });
        }
        if (RB_ALG_NONE_RE.test(line)) {
          push('rb_alg_none_re', i, line, {
            title: 'JWT configured to accept the "none" algorithm',
            severity: 'critical',
            remediation:
              'Name a real algorithm. "none" means unsigned, and an unsigned token can be written by anyone.',
          });
        }
        if (RB_ENCODE_NONE_RE.test(line)) {
          push('rb_encode_none_re', i, line, {
            title: 'JWT minted with algorithm "none"',
            severity: 'critical',
            remediation:
              'JWT.encode(payload, secret, "HS256"). A token signed with "none" proves nothing.',
          });
        }
      });
    }
    return findings;
  },
};

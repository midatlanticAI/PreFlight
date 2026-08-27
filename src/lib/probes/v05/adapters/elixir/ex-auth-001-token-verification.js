// src/lib/probes/v05/adapters/elixir/ex-auth-001-token-verification.js
//
// XL-013 adapter for Elixir. erlang-jose configured to accept unsigned tokens through unsecured_signing, in config or at runtime, and Joken token configs that skip the exp claim without adding one back.
//
// Every pattern here was narrowed by an adversarial false-positive pass that
// wrote correct Elixir designed to match the first draft. The naive versions
// fired on documentation, guard-rail constants and unrelated APIs that share a
// keyword; what survived is what could not be broken that way.
//
// Inherits the XL-013 Learn page (xl-auth-token-verification) from the family.

import { elixirFiles, isElixirCommentLine } from '../../shared-detectors/elixir-scope.js';

const PROBE_NAME = 'Elixir JWT Signature Not Verified (XL-013)';
// One CWE per adapter, matching the manifest record: the phase tests assert
// finding.cwe === adapter.cwe so the OWASP projection and the UI agree. The
// specific weakness (alg none, no expiry, timing) is carried by each finding's
// title and remediation, which is the text a reader actually acts on.
const PROBE_CWE = 'CWE-347';

// erlang-jose: unsigned tokens enabled in config.
const EX_UNSECURED_CONFIG_RE = /^[^\x60\n]*\bunsecured_signing:\s*true\b/;
// The same switch flipped at runtime.
const EX_UNSECURED_RUNTIME_RE = /^[^\x60\n]*\bunsecured_signing\s*\(\s*true\s*\)/;
// Joken: the exp claim skipped with nothing put back.
const EX_NO_EXP_RE =
  /\bdefault_claims\s*\([^\n)]*skip:\s*\[[^\]\n]*:exp\b(?![^\n]*add_claim\s*\(\s*["']exp)/;

export const EX_AUTH_001 = {
  probe_id: 'EX-AUTH-001',
  xl_family: 'XL-013',
  language: 'elixir',
  name: PROBE_NAME,
  category: 'access',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-347',
  owasp_web: 'A07',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.{ex,exs}',
  what_it_catches:
    'erlang-jose configured to accept unsigned tokens through unsecured_signing, in config or at runtime, and Joken token configs that skip the exp claim without adding one back.',
  why_ai_v05:
    'unsecured_signing is a single boolean in config that makes an entire class of forged token acceptable, and it reads like a compatibility switch rather than a security one.',
  vibe_v05: '"I turned that on to get the tests passing." It stayed on.',
  detection_approach:
    'Per line, comments skipped, with backtick-quoted lines excluded so documentation does not match: unsecured_signing: true in config, JOSE.unsecured_signing(true) at runtime, and default_claims with :exp skipped and no compensating add_claim.',
  fp_gates_v05: [
    'comment lines (isElixirCommentLine)',
    'lines containing backticks, which are documentation rather than configuration',
    'a default_claims skip that adds its own exp claim back',
    '*_test.exs / test trees / scanner self-source / fixture tree (elixirFiles())',
  ],
  remediation:
    'Leave unsecured_signing off so alg=none tokens are rejected. If you skip the default exp claim, add one with add_claim so tokens still expire.',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/EX-AUTH-001/positive.ex',
    negative: 'src/lib/probes/v05/fixtures/EX-AUTH-001/negative.ex',
  },
  known_incidents: 'CWE-347 (missing signature verification); CWE-327 (alg none); OWASP A07',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of elixirFiles(files)) {
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
        if (isElixirCommentLine(line)) return;
        if (EX_UNSECURED_CONFIG_RE.test(line)) {
          push('ex_unsecured_config_re', i, line, {
            title: 'Unsigned JWTs enabled (unsecured_signing: true)',
            severity: 'critical',
            remediation:
              'Remove the setting. With it on, a token signed with alg=none is accepted as genuine.',
          });
        }
        if (EX_UNSECURED_RUNTIME_RE.test(line)) {
          push('ex_unsecured_runtime_re', i, line, {
            title: 'Unsigned JWTs enabled at runtime',
            severity: 'critical',
            remediation: 'Drop the call. Unsigned tokens should never validate outside a test.',
          });
        }
        if (EX_NO_EXP_RE.test(line)) {
          push('ex_no_exp_re', i, line, {
            title: 'JWT minted without an expiry claim',
            severity: 'medium',
            remediation:
              'Add an exp claim back with add_claim, or stop skipping it. A token with no expiry is valid until the key rotates.',
          });
        }
      });
    }
    return findings;
  },
};

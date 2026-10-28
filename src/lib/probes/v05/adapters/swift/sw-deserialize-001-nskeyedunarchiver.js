// src/lib/probes/v05/adapters/swift/sw-deserialize-001-nskeyedunarchiver.js
//
// XL-001 adapter for Swift. RX-based. The legacy NSKeyedUnarchiver entry
// points that instantiate arbitrary classes from bytes: the deprecated
// class methods unarchiveObject(with:) / unarchiveObject(withFile:) /
// unarchiveTopLevelObjectWithData(_:), and the legacy init(forReadingWith:)
// whose requiresSecureCoding defaults to false. Corpus: docs/v05-research/
// preflight_v05_probe_inventory.md XL-001 "SW (NSKeyedUnarchiver without
// secure coding)".
//
// The init form is gated on a nearby-line check: an unarchiver built with
// forReadingWith: and then given requiresSecureCoding = true within the
// following lines is the mitigated spelling, so it stays silent. The modern
// API — unarchivedObject(ofClass:from:) / unarchivedObject(ofClasses:from:)
// and init(forReadingFrom:) — is a different token and never matches.

import { swiftFiles, isSwiftCommentLine } from '../../shared-detectors/swift-scope.js';

const PROBE_NAME = 'Swift Unsafe Deserialization';

// Deprecated class methods. Plain "unarchiveObject" cannot bind the secure
// "unarchivedObject" spelling: the tokens differ at the d.
const LEGACY_UNARCHIVE_RE = /\bNSKeyedUnarchiver\s*\.\s*unarchiveObject\s*\(\s*with(?:File)?\s*:/;
const TOP_LEVEL_RE = /\bunarchiveTopLevelObjectWithData\s*\(/;

// Legacy initializer: requiresSecureCoding defaults to false here. The modern
// init(forReadingFrom:) defaults it to true and does not match this token.
const INIT_LEGACY_RE = /\bNSKeyedUnarchiver\s*\(\s*forReadingWith\s*:/;
const SECURE_FLAG_RE = /\brequiresSecureCoding\s*=\s*true\b/;

// How far around the init line the requiresSecureCoding = true assignment may
// sit and still count as configuring this unarchiver.
const SECURE_WINDOW_BEFORE = 2;
const SECURE_WINDOW_AFTER = 8;

export const SW_DESERIALIZE_001 = {
  probe_id: 'SW-DESERIALIZE-001',
  xl_family: 'XL-001',
  language: 'swift',
  name: PROBE_NAME,
  category: 'security',
  severity: 'critical',
  confidence: 'medium',
  cwe: 'CWE-502',
  owasp_web: 'A08',
  owasp_llm: null,
  detector: 'rx',
  scope: '**/*.swift',
  what_it_catches:
    'Legacy NSKeyedUnarchiver spellings: unarchiveObject(with:) / unarchiveObject(withFile:), unarchiveTopLevelObjectWithData, or NSKeyedUnarchiver(forReadingWith:) without requiresSecureCoding = true nearby. Each can instantiate any NSCoding class named in the archive bytes.',
  why_ai_v05:
    'Years of iOS tutorials round-trip objects through the pre-iOS-12 NSKeyedUnarchiver class methods, so the assistant reaches for them on any Data value, including bytes that arrived over the network.',
  vibe_v05:
    '"Archive the object, unarchive it later." No model of the archive naming the class to instantiate, so attacker bytes choose the class.',
  detection_approach:
    'RX per line: the deprecated class methods flag unconditionally; NSKeyedUnarchiver(forReadingWith:) flags only when no requiresSecureCoding = true appears within a few surrounding lines.',
  fp_gates_v05: [
    'comment lines',
    'the secure API unarchivedObject(ofClass:from:) / unarchivedObject(ofClasses:from:) and init(forReadingFrom:) — different tokens, never matched',
    'NSKeyedUnarchiver(forReadingWith:) with requiresSecureCoding = true set on a nearby line (the mitigated legacy spelling)',
    '*Tests.swift / src/test / scanner self-source / fixture tree (swiftFiles())',
  ],
  remediation:
    'Use try NSKeyedUnarchiver.unarchivedObject(ofClass:from:) or unarchivedObject(ofClasses:from:) so only the classes you list can be instantiated. If you must keep an unarchiver instance, use NSKeyedUnarchiver(forReadingFrom:) and leave requiresSecureCoding on.',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/SW-DESERIALIZE-001/positive.swift',
    negative: 'src/lib/probes/v05/fixtures/SW-DESERIALIZE-001/negative.swift',
  },
  known_incidents:
    'CWE-502; OWASP A08; Apple deprecated the class-method unarchive API in the iOS 12 era in favor of NSSecureCoding-checked unarchivedObject(ofClass:from:)',
  ioc_bundle_ref: null,
  maturity: 'experimental',
  shadow: false,
  legacy_finding_id_seed: null,
  detect(files) {
    const findings = [];
    for (const f of swiftFiles(files)) {
      const lines = String(f.content || '').split('\n');
      const secureNearby = (i) => {
        const from = Math.max(0, i - SECURE_WINDOW_BEFORE);
        const to = Math.min(lines.length - 1, i + SECURE_WINDOW_AFTER);
        for (let j = from; j <= to; j++) {
          if (isSwiftCommentLine(lines[j])) continue;
          if (SECURE_FLAG_RE.test(lines[j])) return true;
        }
        return false;
      };
      lines.forEach((line, i) => {
        if (isSwiftCommentLine(line)) return;
        let hit = null;
        if (LEGACY_UNARCHIVE_RE.test(line)) {
          hit = 'NSKeyedUnarchiver.unarchiveObject(with:/withFile:)';
        } else if (TOP_LEVEL_RE.test(line)) {
          hit = 'unarchiveTopLevelObjectWithData';
        } else if (INIT_LEGACY_RE.test(line) && !secureNearby(i)) {
          hit = 'NSKeyedUnarchiver(forReadingWith:) without requiresSecureCoding';
        }
        if (!hit) return;
        findings.push({
          id: `sw-deser-${f.path}-${i}`,
          probe: PROBE_NAME,
          title: `Unsafe deserialization: ${hit}`,
          severity: 'critical',
          category: 'Security',
          cwe: 'CWE-502',
          file: f.path,
          line: i + 1,
          evidence: line.trim().slice(0, 200),
          remediation:
            'Use NSKeyedUnarchiver.unarchivedObject(ofClass:from:) / unarchivedObject(ofClasses:from:). The legacy API lets the archive bytes pick the class to instantiate.',
        });
      });
    }
    return findings;
  },
};

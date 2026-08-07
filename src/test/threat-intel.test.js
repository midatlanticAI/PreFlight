// Sanity tests for the threat-intel constants. Specific incidents are exercised through
// the probe tests; these tests guard the shapes + a few load-bearing entries we depend on
// elsewhere (e.g. cloudflareinsights.com being safe-listed so the CSP allowlist doesn't
// trip URL Reputation against ourselves).

import { describe, it, expect } from 'vitest';
import {
  SECRET_PATTERNS,
  COMPROMISED_PACKAGES,
  TYPOSQUATS,
  SLOPSQUAT_GENERIC_RE,
  BIDI_CONTROL_RE,
  NEXT_PUBLIC_DANGER_NAMES,
  NEXT_PUBLIC_DANGER_VALUES,
  URL_PLACEHOLDER_HOSTS,
  URL_PLACEHOLDER_IP_RE,
  URL_SAFE_HOSTS,
  URL_SUSPICIOUS_TLD_RE,
  URL_RAW_IP_RE,
  URL_SHORTENERS,
  isHostInSafeList,
  AI_CRAWLER_BOTS,
  FILE_SIZE_WARN_LINES,
  FILE_SIZE_MED_LINES,
  FILE_SIZE_HIGH_LINES,
  FILE_SIZE_CRIT_LINES,
  FILE_SIZE_FAIL_LINES,
} from '../lib/threat-intel.js';

describe('SECRET_PATTERNS', () => {
  it('is a non-empty array of { name, regex, severity, category, cwe } objects', () => {
    expect(Array.isArray(SECRET_PATTERNS)).toBe(true);
    expect(SECRET_PATTERNS.length).toBeGreaterThan(5);
    for (const p of SECRET_PATTERNS) {
      expect(typeof p.name).toBe('string');
      expect(p.regex instanceof RegExp).toBe(true);
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(p.severity);
      expect(typeof p.category).toBe('string');
      expect(typeof p.cwe).toBe('string');
    }
  });

  it('detects an AWS Access Key shape via the AKIA pattern', () => {
    const aws = SECRET_PATTERNS.find((p) => p.name.includes('AWS Access Key'));
    expect(aws).toBeDefined();
    expect(aws.regex.test('AKIA' + 'IOSFODNN7' + 'EXAMPLE')).toBe(true);
  });
});

describe('COMPROMISED_PACKAGES', () => {
  it('strips meta-keys (_schema / _note / _lastReviewed) from the manifest', () => {
    expect(Object.keys(COMPROMISED_PACKAGES)).not.toContain('_schema');
    expect(Object.keys(COMPROMISED_PACKAGES)).not.toContain('_note');
    expect(Object.keys(COMPROMISED_PACKAGES)).not.toContain('_lastReviewed');
  });

  it('includes the headline @tanstack/react-router Mini Shai-Hulud versions', () => {
    expect(COMPROMISED_PACKAGES['@tanstack/react-router']).toBeDefined();
    expect(COMPROMISED_PACKAGES['@tanstack/react-router'].versions).toContain('1.169.5');
    expect(COMPROMISED_PACKAGES['@tanstack/react-router'].versions).toContain('1.169.8');
  });

  it('includes the August 2026 keyv wave, and only advisory-listed versions', () => {
    expect(COMPROMISED_PACKAGES['keyv'].versions).toEqual(['6.0.0']);
    expect(COMPROMISED_PACKAGES['@keyv/redis'].versions).toEqual(['6.0.0']);
    expect(COMPROMISED_PACKAGES['flat-cache'].versions).toEqual(['6.1.24']);
    expect(COMPROMISED_PACKAGES['cacheable'].versions).toEqual(['2.5.1']);
    // Secondary reporting named file-entry-cache 11.1.7; the advisory
    // (MAL-2026-11970) lists 11.1.6 only. The manifest ships the advisory,
    // not the reporting — this pin fails if 11.1.7 ever sneaks in.
    expect(COMPROMISED_PACKAGES['file-entry-cache'].versions).toEqual(['11.1.6']);
    expect(COMPROMISED_PACKAGES['@thiennq/docs-viewer'].versions).toEqual([
      '1.6.2',
      '1.6.3',
      '1.6.4',
    ]);
  });

  it('every entry has the { versions: string[], note: string } shape', () => {
    for (const [name, entry] of Object.entries(COMPROMISED_PACKAGES)) {
      expect(Array.isArray(entry.versions), `versions for ${name}`).toBe(true);
      expect(entry.versions.length).toBeGreaterThan(0);
      expect(typeof entry.note).toBe('string');
    }
  });
});

describe('TYPOSQUATS', () => {
  it('maps common misspellings to the real package name', () => {
    expect(TYPOSQUATS.lodahs).toBe('lodash');
    expect(TYPOSQUATS.expreess).toBe('express');
    expect(TYPOSQUATS.reactt).toBe('react');
  });
});

describe('SLOPSQUAT_GENERIC_RE', () => {
  it('matches LLM-shaped generic package names like auth-tool / api-helper', () => {
    expect(SLOPSQUAT_GENERIC_RE.test('auth-tool')).toBe(true);
    expect(SLOPSQUAT_GENERIC_RE.test('api-helper')).toBe(true);
    expect(SLOPSQUAT_GENERIC_RE.test('user-manager')).toBe(true);
  });

  it('does NOT match real package names', () => {
    expect(SLOPSQUAT_GENERIC_RE.test('react')).toBe(false);
    expect(SLOPSQUAT_GENERIC_RE.test('vite')).toBe(false);
    expect(SLOPSQUAT_GENERIC_RE.test('jsonwebtoken')).toBe(false);
  });
});

describe('BIDI_CONTROL_RE', () => {
  it('matches the LRE control character (Trojan Source CVE-2021-42574)', () => {
    expect(BIDI_CONTROL_RE.test('‪')).toBe(true); // LRE
    expect(BIDI_CONTROL_RE.test('‮')).toBe(true); // RLO
    expect(BIDI_CONTROL_RE.test('⁦')).toBe(true); // LRI
    expect(BIDI_CONTROL_RE.test('⁩')).toBe(true); // PDI
  });

  it('does NOT match ordinary ASCII', () => {
    expect(BIDI_CONTROL_RE.test('hello world 123')).toBe(false);
  });
});

describe('NEXT_PUBLIC_DANGER_* patterns', () => {
  it('NAMES regex flags secret-shaped env-var identifiers', () => {
    expect(NEXT_PUBLIC_DANGER_NAMES.test('NEXT_PUBLIC_API_SECRET')).toBe(true);
    expect(NEXT_PUBLIC_DANGER_NAMES.test('NEXT_PUBLIC_DB_PASSWORD')).toBe(true);
    expect(NEXT_PUBLIC_DANGER_NAMES.test('NEXT_PUBLIC_SERVICE_ROLE')).toBe(true);
    expect(NEXT_PUBLIC_DANGER_NAMES.test('NEXT_PUBLIC_API_URL')).toBe(false);
  });

  it('VALUES regex flags secret-shaped env-var values', () => {
    expect(NEXT_PUBLIC_DANGER_VALUES.test('sk_live_xxx')).toBe(true);
    expect(NEXT_PUBLIC_DANGER_VALUES.test('sk-ant-xxx')).toBe(true);
    expect(NEXT_PUBLIC_DANGER_VALUES.test('https://example.com')).toBe(false);
  });
});

describe('URL host classification', () => {
  it('URL_PLACEHOLDER_HOSTS contains every documentation example domain we depend on', () => {
    expect(URL_PLACEHOLDER_HOSTS.has('example.com')).toBe(true);
    expect(URL_PLACEHOLDER_HOSTS.has('localhost')).toBe(true);
    expect(URL_PLACEHOLDER_HOSTS.has('yourdomain.com')).toBe(true);
  });

  it('URL_PLACEHOLDER_IP_RE matches RFC 5737 reserved ranges', () => {
    expect(URL_PLACEHOLDER_IP_RE.test('192.0.2.5')).toBe(true);
    expect(URL_PLACEHOLDER_IP_RE.test('198.51.100.10')).toBe(true);
    expect(URL_PLACEHOLDER_IP_RE.test('203.0.113.7')).toBe(true);
    expect(URL_PLACEHOLDER_IP_RE.test('1.2.3.4')).toBe(false);
  });

  it('URL_SAFE_HOSTS includes well-known hosts we never want to flag', () => {
    expect(URL_SAFE_HOSTS.has('github.com')).toBe(true);
    expect(URL_SAFE_HOSTS.has('npmjs.com')).toBe(true);
    expect(URL_SAFE_HOSTS.has('openai.com')).toBe(true);
    expect(URL_SAFE_HOSTS.has('anthropic.com')).toBe(true);
  });

  it('URL_SAFE_HOSTS allowlists Cloudflare Pages Analytics (consequence of our CSP)', () => {
    expect(URL_SAFE_HOSTS.has('cloudflareinsights.com')).toBe(true);
  });

  it('URL_SUSPICIOUS_TLD_RE catches common malware TLDs', () => {
    expect(URL_SUSPICIOUS_TLD_RE.test('evil.tk')).toBe(true);
    expect(URL_SUSPICIOUS_TLD_RE.test('phish.xyz')).toBe(true);
    expect(URL_SUSPICIOUS_TLD_RE.test('google.com')).toBe(false);
  });

  it('URL_RAW_IP_RE matches dotted-quad IPv4', () => {
    expect(URL_RAW_IP_RE.test('1.2.3.4')).toBe(true);
    expect(URL_RAW_IP_RE.test('255.255.255.255')).toBe(true);
    expect(URL_RAW_IP_RE.test('example.com')).toBe(false);
  });

  it('URL_SHORTENERS contains the obvious offenders', () => {
    expect(URL_SHORTENERS.has('bit.ly')).toBe(true);
    expect(URL_SHORTENERS.has('tinyurl.com')).toBe(true);
    expect(URL_SHORTENERS.has('t.co')).toBe(true);
  });

  it('isHostInSafeList matches exact entries AND subdomains', () => {
    expect(isHostInSafeList('github.com')).toBe(true);
    expect(isHostInSafeList('raw.githubusercontent.com')).toBe(true);
    expect(isHostInSafeList('cdn.cloudflare.com')).toBe(true);
    expect(isHostInSafeList('evil-github.com')).toBe(false);
  });
});

describe('AI_CRAWLER_BOTS', () => {
  it('lists the major AI crawler user-agents (for GEO Hygiene)', () => {
    expect(AI_CRAWLER_BOTS).toContain('GPTBot');
    expect(Array.isArray(AI_CRAWLER_BOTS)).toBe(true);
    expect(AI_CRAWLER_BOTS.length).toBeGreaterThan(3);
  });
});

describe('FILE_SIZE thresholds', () => {
  it('the four-band ladder is monotonic and non-zero', () => {
    expect(FILE_SIZE_WARN_LINES).toBeGreaterThan(0);
    expect(FILE_SIZE_WARN_LINES).toBeLessThan(FILE_SIZE_MED_LINES);
    expect(FILE_SIZE_MED_LINES).toBeLessThan(FILE_SIZE_HIGH_LINES);
    expect(FILE_SIZE_HIGH_LINES).toBeLessThan(FILE_SIZE_CRIT_LINES);
  });
  it('FILE_SIZE_FAIL_LINES is aliased to HIGH (gating threshold)', () => {
    expect(FILE_SIZE_FAIL_LINES).toBe(FILE_SIZE_HIGH_LINES);
  });
  it('HIGH band catches the 3000-3500 monolith range (the prior blind)', () => {
    // Pre-2026-06 the gate fired only at 5000+ LOC, so a 3554-line
    // builtin.js capped at "info" and slipped past the dogfood gate.
    // This regression guard fixes the band boundary in place.
    expect(FILE_SIZE_HIGH_LINES).toBeLessThanOrEqual(3000);
  });
});

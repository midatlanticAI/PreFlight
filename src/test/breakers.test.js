// Breakers v1 data + contract tests. The data lives in src/lib/breakers.js;
// each entry must conform to the schema documented at the top of that file.
// The shape is enforced here so a future contributor can't ship a malformed
// or unsafe-looking entry.

import { describe, it, expect } from 'vitest';
import { BREAKERS, getBreakers, getBreakersCount, getBreakersProbeCount } from '../lib/breakers.js';
import { PROBES } from '../lib/probes.js';

describe('BREAKERS catalogue shape', () => {
  it('exports at least one entry per probe in the catalogue', () => {
    for (const [, entries] of Object.entries(BREAKERS)) {
      expect(entries.length).toBeGreaterThan(0);
      expect(Array.isArray(entries)).toBe(true);
    }
  });

  it('every entry has the required fields', () => {
    for (const [probeName, entries] of Object.entries(BREAKERS)) {
      for (const entry of entries) {
        expect(entry.name, `${probeName}: name missing`).toBeTypeOf('string');
        expect(entry.payload, `${probeName}: payload missing`).toBeTypeOf('string');
        expect(entry.where, `${probeName}: where missing`).toBeTypeOf('string');
        expect(entry.effect, `${probeName}: effect missing`).toBeTypeOf('string');
      }
    }
  });

  it('every entry has a non-trivial payload, where, and effect', () => {
    for (const [probeName, entries] of Object.entries(BREAKERS)) {
      for (const entry of entries) {
        expect(entry.payload.length, `${probeName}: ${entry.name} payload too short`).toBeGreaterThan(0);
        expect(entry.where.length, `${probeName}: ${entry.name} where too short`).toBeGreaterThan(20);
        expect(entry.effect.length, `${probeName}: ${entry.name} effect too short`).toBeGreaterThan(20);
      }
    }
  });

  it('every catalogue key matches a registered probe', () => {
    const registered = new Set(PROBES.map((p) => p.name));
    const unknown = Object.keys(BREAKERS).filter((name) => !registered.has(name));
    expect(unknown).toEqual([]);
  });
});

describe('Breakers safety contract', () => {
  it('no payload references a real-looking production hostname', () => {
    // The safety contract says payloads must use anonymized hosts only.
    // Approved placeholder hosts: example.com / example.org / example.net /
    // attacker.example / *.example. Plus internal-ish addresses that are
    // illustrative (localhost, 169.254.169.254 metadata endpoint).
    const ALLOWED_HOSTS = [
      'example.com',
      'example.org',
      'example.net',
      '.example/',
      '.example"',
      "'.example",
      'attacker.example',
      'attacker-phishing.example',
      'cdn.example',
      'victim.example',
      'localhost',
      '127.0.0.1',
      '169.254.169.254',
      'metadata.google.internal',
    ];
    for (const [probeName, entries] of Object.entries(BREAKERS)) {
      for (const entry of entries) {
        // Extract every hostname-looking token from the payload.
        const hosts = entry.payload.match(/https?:\/\/[a-zA-Z0-9_\-.:]+/g) || [];
        for (const url of hosts) {
          const okay = ALLOWED_HOSTS.some((h) => url.includes(h));
          if (!okay) {
            expect.fail(
              `${probeName} > ${entry.name}: payload contains non-anonymized URL ${url}`
            );
          }
        }
      }
    }
  });

  it('no payload contains real-looking secrets', () => {
    // The safety contract says no real credentials, tokens, or exploit chains.
    // The JWT alg-none example in Auth Weakness is a known exception (it's
    // structurally a JWT but the payload encodes the placeholder {sub:admin}).
    for (const [probeName, entries] of Object.entries(BREAKERS)) {
      for (const entry of entries) {
        // Skip the documented JWT alg-none structural example.
        if (entry.name === 'JWT alg-none forgery') continue;
        const looksLikeKey =
          /\bAKIA[A-Z0-9]{16}\b/.test(entry.payload) || // AWS
          /\bsk_live_[a-zA-Z0-9]{24,}\b/.test(entry.payload) || // Stripe live
          /\bsk-ant-[a-zA-Z0-9_-]{20,}\b/.test(entry.payload); // Anthropic
        if (looksLikeKey) {
          expect.fail(`${probeName} > ${entry.name}: payload looks like a real credential`);
        }
      }
    }
  });
});

describe('Breakers helpers', () => {
  it('getBreakers returns the catalogue for a known probe', () => {
    const entries = getBreakers('SQL Injection');
    expect(entries.length).toBeGreaterThan(0);
  });

  it('getBreakers returns [] for an unknown probe', () => {
    expect(getBreakers('NonexistentProbe')).toEqual([]);
  });

  it('getBreakersCount returns the total catalogue size', () => {
    const total = getBreakersCount();
    expect(total).toBeGreaterThan(10);
  });

  it('getBreakersProbeCount returns the number of probes with at least one Breaker', () => {
    const probeCount = getBreakersProbeCount();
    expect(probeCount).toBeGreaterThanOrEqual(10);
    expect(probeCount).toBeLessThanOrEqual(PROBES.length);
  });
});

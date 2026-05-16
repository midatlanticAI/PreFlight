// Post-merge (integration/v1): the Breakers panel must work for the
// promoted v0.5 language adapters, not just v0.4 probe names. Breakers
// are a property of the vulnerability CLASS (xl_family), not the
// language, so a Rust/PHP/etc SQLi finding must surface the same SQL
// injection payloads as the v0.4 "SQL Injection" probe.

import { describe, it, expect } from 'vitest';
import { getBreakers } from '../lib/breakers.js';
import { PROBE_MANIFEST_V05 } from '../lib/probes/v05/manifest.js';

describe('v0.5 -> Breakers bridge (xl_family fallback)', () => {
  it('v0.4 probe-name lookup still works (back-compat)', () => {
    expect(getBreakers('SQL Injection').length).toBeGreaterThan(0);
    expect(getBreakers('Auth Weakness').length).toBeGreaterThan(0);
  });

  it('a v0.5 SQLi finding (any language) resolves the SQL Injection breakers', () => {
    const sql = getBreakers('SQL Injection');
    for (const id of ['RS-SQL-RAW-001', 'PHP-SQL-RAW-001', 'GO-SQL-RAW-001', 'KT-SQL-RAW-001']) {
      const a = PROBE_MANIFEST_V05[id];
      expect(getBreakers(a.name, a.xl_family)).toEqual(sql);
    }
  });

  it('a v0.5 token-verification finding resolves the Auth Weakness breakers', () => {
    const auth = getBreakers('Auth Weakness');
    const a = PROBE_MANIFEST_V05['CS-AUTH-001'];
    expect(getBreakers(a.name, a.xl_family)).toEqual(auth);
  });

  it('TLS-disabled / hardcoded-secret families correctly have NO breaker', () => {
    // No "adversarial input you type" exists for a config/credential issue.
    for (const id of ['RS-TLS-VERIFY-001', 'GO-SECRETS-001', 'PHP-DESERIALIZE-001']) {
      const a = PROBE_MANIFEST_V05[id];
      expect(getBreakers(a.name, a.xl_family)).toEqual([]);
    }
  });

  it('unknown probe + no family => empty (no crash)', () => {
    expect(getBreakers('Nonexistent Probe')).toEqual([]);
    expect(getBreakers(undefined, undefined)).toEqual([]);
  });
});

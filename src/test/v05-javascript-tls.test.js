/**
 * JS-TLS-VERIFY-001 — the XL-004 adapter for JavaScript.
 *
 * Fourteen languages carried a TLS-verification adapter and JavaScript was not
 * one of them. `requests.get(url, verify=False)` fired at high severity while
 * `new https.Agent({ rejectUnauthorized: false })` was silent, in the language
 * most of the scanned corpus is written in.
 *
 * The precision half is the adapter's own remediation: a CA bundle, a
 * NODE_EXTRA_CA_CERTS path, rejectUnauthorized left true. Each of those has to
 * stay silent, or the finding argues against its own fix.
 */

import { describe, it, expect } from 'vitest';
import { JS_TLS_VERIFY_001 } from '../lib/probes/v05/adapters/javascript/js-tls-verify-001-disabled.js';
import { PROBE_MANIFEST_V05 } from '../lib/probes/v05/manifest.js';

const scan = (content, path = 'server/client.js') =>
  JS_TLS_VERIFY_001.detect([{ path, content }]) || [];

describe('JS-TLS-VERIFY-001 — manifest wiring', () => {
  it('is registered in the v0.5 manifest under XL-004', () => {
    const entry = PROBE_MANIFEST_V05['JS-TLS-VERIFY-001'];
    expect(entry).toBeDefined();
    expect(entry.xl_family).toBe('XL-004');
    expect(entry.language).toBe('javascript');
    expect(entry.cwe).toBe('CWE-295');
    expect(entry.owasp_web).toBe('A02');
  });

  it('inherits the XL-004 Learn page and compliance mapping', () => {
    const entry = PROBE_MANIFEST_V05['JS-TLS-VERIFY-001'];
    expect(entry.learn_more_slug).toBe('xl-tls-verification-disabled');
    expect(Array.isArray(entry.compliance_refs)).toBe(true);
    expect(entry.compliance_refs.length).toBeGreaterThan(0);
  });

  it('is live rather than shadow, so it runs in a real scan', () => {
    expect(JS_TLS_VERIFY_001.shadow).toBe(false);
    expect(JS_TLS_VERIFY_001.legacy_finding_id_seed).toBeNull();
  });
});

describe('JS-TLS-VERIFY-001 — recall', () => {
  const shapes = [
    ['new https.Agent', 'const agent = new https.Agent({ rejectUnauthorized: false });\n'],
    [
      'axios.create with an insecure httpsAgent',
      'const client = axios.create({ httpsAgent: new https.Agent({ rejectUnauthorized: false }) });\n',
    ],
    ['NODE_TLS_REJECT_UNAUTHORIZED set to 0', "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n"],
    [
      'fetch with an insecure agent',
      'const r = await fetch(url, { agent: new https.Agent({ rejectUnauthorized: false }) });\n',
    ],
    [
      'bracket access to the environment flag',
      "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';\n",
    ],
    ['tls.connect option', 'tls.connect({ port, rejectUnauthorized: false });\n'],
    [
      'strictSSL: false on a legacy client',
      "request({ url: 'https://x', strictSSL: false }, cb);\n",
    ],
    [
      'the option on its own line in a multi-line literal',
      'const agent = new https.Agent({\n  keepAlive: true,\n  rejectUnauthorized: false,\n});\n',
    ],
  ];
  for (const [name, src] of shapes) {
    it(`${name} fires CWE-295`, () => {
      const found = scan(src);
      expect(found.length).toBeGreaterThan(0);
      expect(found[0].cwe).toBe('CWE-295');
    });
  }

  it('rates the process-wide environment override above the per-agent option', () => {
    expect(scan("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n")[0].severity).toBe('critical');
    expect(scan('new https.Agent({ rejectUnauthorized: false });\n')[0].severity).toBe('high');
  });

  it('is in scope for TypeScript', () => {
    expect(
      scan('const agent = new https.Agent({ rejectUnauthorized: false });\n', 'src/http.ts').length
    ).toBeGreaterThan(0);
  });
});

describe('JS-TLS-VERIFY-001 — precision', () => {
  const safe = [
    ['rejectUnauthorized: true', 'const a = new https.Agent({ rejectUnauthorized: true });\n'],
    ['an https.Agent with no options', 'const a = new https.Agent();\n'],
    [
      'an https.Agent given a CA bundle',
      "const a = new https.Agent({ ca: fs.readFileSync('/etc/ssl/corp-ca.pem') });\n",
    ],
    ['NODE_TLS_REJECT_UNAUTHORIZED left at 1', "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';\n"],
    [
      'the flag read from configuration rather than the literal false',
      'const a = new https.Agent({ rejectUnauthorized: config.verifyTls });\n',
    ],
    ['strictSSL: true', 'request({ strictSSL: true }, cb);\n'],
    [
      'NODE_EXTRA_CA_CERTS, which is the fix',
      "process.env.NODE_EXTRA_CA_CERTS = '/etc/ssl/corp-ca.pem';\n",
    ],
    ['a variable that merely names the flag', "const flagName = 'NODE_TLS_REJECT_UNAUTHORIZED';\n"],
  ];
  for (const [name, src] of safe) {
    it(`${name} is silent`, () => {
      expect(scan(src)).toHaveLength(0);
    });
  }

  it('a Python file is out of scope (PY-TLS-VERIFY-001 owns it)', () => {
    expect(scan('requests.get(url, verify=False)\n', 'app/main.py')).toHaveLength(0);
  });

  it('a test file is out of scope', () => {
    expect(
      scan(
        'const a = new https.Agent({ rejectUnauthorized: false });\n',
        'server/__tests__/agent.test.js'
      )
    ).toHaveLength(0);
  });
});

describe('JS-TLS-VERIFY-001 — the comment-blind view', () => {
  it('a line comment naming the flag is not the flag', () => {
    expect(
      scan(
        '// Never ship new https.Agent({ rejectUnauthorized: false }) in production.\nexport const x = 1;\n'
      )
    ).toHaveLength(0);
  });

  it('a block comment contrasting the bug with its fix is not the bug', () => {
    expect(
      scan(
        '/*\n * Bad:  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\n * Good: process.env.NODE_EXTRA_CA_CERTS = "/etc/ssl/ca.pem";\n */\nexport const y = 2;\n'
      )
    ).toHaveLength(0);
  });

  it('remediation prose in a lint-rule config is not a finding', () => {
    expect(
      scan('// message: "replace strictSSL: false with a ca bundle"\nexport const z = 3;\n')
    ).toHaveLength(0);
  });
});

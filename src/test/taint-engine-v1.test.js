/**
 * Taint Engine v1 — proves the intra-procedural dataflow analyzer catches
 * shapes the regex-list probes would miss.
 *
 * The taint engine is the first piece of TRUE dataflow analysis in PreFlight.
 * Source -> sink propagation is tracked across assignments, returns, template
 * literals, concatenation, conditional / logical / await expressions, all
 * inside ONE function body. The engine complements (does not replace) the
 * regex probes.
 */

import { describe, it, expect } from 'vitest';
import { probeTaintFlow } from '../lib/probes.js';

const f = (path, content) => ({ path, content });

describe('Taint engine — emailassist canonical case', () => {
  it('canonical emailassist server.js: req.url -> path.join -> fs.readFile fires', () => {
    const findings = probeTaintFlow([
      f(
        'server.js',
        `const http = require('http');
const path = require('path');
const fs = require('fs');
http.createServer((req, res) => {
  let filePath = req.url === '/' ? '/index.html' : req.url;
  filePath = path.join(__dirname, filePath);
  fs.readFile(filePath, (err, data) => { res.end(data); });
}).listen(3000);
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
    const fsCall = findings.find((x) => x.cwe === 'CWE-22');
    expect(fsCall).toBeTruthy();
    // The taint engine's distinguishing claim: it reports the SOURCE and SINK
    // lines, not just a single hit line.
    expect(fsCall.taintPath).toBeTruthy();
    expect(fsCall.taintPath.sourceLine).toBeLessThan(fsCall.taintPath.sinkLine);
  });

  it('Express req.body.path -> fs.createReadStream fires', () => {
    const findings = probeTaintFlow([
      f(
        'src/routes/file.js',
        `app.post('/file', (req, res) => {
  const target = req.body.path;
  const stream = fs.createReadStream(target);
  stream.pipe(res);
});
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('req.body -> eval fires (RCE class)', () => {
    const findings = probeTaintFlow([
      f(
        'src/eval.js',
        `function handler(req, res) {
  const code = req.body.code;
  eval(code);
}
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((x) => x.cwe === 'CWE-95')).toBe(true);
  });

  it('req.query.cmd -> child_process.exec fires (CWE-78)', () => {
    const findings = probeTaintFlow([
      f(
        'src/run.js',
        `const child_process = require('child_process');
function handler(req, res) {
  const cmd = req.query.cmd;
  child_process.exec(cmd, (err, stdout) => res.end(stdout));
}
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((x) => x.cwe === 'CWE-78')).toBe(true);
  });
});

describe('Taint engine — propagation forms', () => {
  it('intermediate assignment: req.url -> tmp -> filePath -> fs.readFile fires', () => {
    const findings = probeTaintFlow([
      f(
        'src/chain.js',
        `function handler(req, res) {
  const tmp = req.url;
  const filePath = tmp;
  fs.readFile(filePath, () => {});
}
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('template literal interpolation propagates taint', () => {
    const findings = probeTaintFlow([
      f(
        'src/tpl.js',
        `function handler(req, res) {
  const target = \`/var/data/\${req.body.name}\`;
  fs.readFile(target, () => {});
}
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('concatenation propagates taint', () => {
    const findings = probeTaintFlow([
      f(
        'src/concat.js',
        `function handler(req, res) {
  const target = '/var/data/' + req.body.name;
  fs.readFile(target, () => {});
}
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('conditional propagates taint from either branch', () => {
    const findings = probeTaintFlow([
      f(
        'src/cond.js',
        `function handler(req, res) {
  const target = req.body.alt || req.query.fallback;
  fs.readFile(target, () => {});
}
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('await unwraps taint through promises', () => {
    const findings = probeTaintFlow([
      f(
        'src/aw.js',
        `async function handler(req, res) {
  const data = await req.json();
  fs.readFile(data.path, () => {});
}
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('Taint engine — sanitizers clear taint', () => {
  it('path.normalize() clears taint', () => {
    const findings = probeTaintFlow([
      f(
        'src/safe.js',
        `function handler(req, res) {
  const dirty = req.url;
  const clean = path.normalize(dirty);
  fs.readFile(clean, () => {});
}
`
      ),
    ]);
    expect(findings.length).toBe(0);
  });

  it('path.resolve(BASE, x) with literal BASE clears taint', () => {
    const findings = probeTaintFlow([
      f(
        'src/safe2.js',
        `function handler(req, res) {
  const dirty = req.url;
  const safe = path.resolve('/var/data', dirty);
  fs.readFile(safe, () => {});
}
`
      ),
    ]);
    expect(findings.length).toBe(0);
  });
});

describe('Taint engine — negatives, must NOT fire', () => {
  it('literal path -> fs.readFile does not fire', () => {
    const findings = probeTaintFlow([
      f('src/lit.js', `function handler(req, res) { fs.readFile('/etc/hostname', () => {}); }`),
    ]);
    expect(findings.length).toBe(0);
  });

  it('env-loaded path -> fs.readFile does not fire', () => {
    const findings = probeTaintFlow([
      f(
        'src/env.js',
        `function handler(req, res) {
  const target = process.env.CONFIG_PATH;
  fs.readFile(target, () => {});
}
`
      ),
    ]);
    expect(findings.length).toBe(0);
  });

  it('handler that never reads request input does not fire', () => {
    const findings = probeTaintFlow([
      f('src/clean.js', `function handler(req, res) { res.json({ ok: true }); }`),
    ]);
    expect(findings.length).toBe(0);
  });

  it('test files are skipped', () => {
    const findings = probeTaintFlow([
      f(
        'src/test/handler.test.js',
        `function handler(req, res) { fs.readFile(req.url, () => {}); }`
      ),
    ]);
    expect(findings.length).toBe(0);
  });
});

describe('Taint engine — browser storage sources', () => {
  it('localStorage.getItem -> eval fires', () => {
    const findings = probeTaintFlow([
      f(
        'src/client.js',
        `function handler() {
  const code = localStorage.getItem('script');
  eval(code);
}
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('location.hash -> new Function fires', () => {
    const findings = probeTaintFlow([
      f(
        'src/hash.js',
        `function handler() {
  const code = location.hash.slice(1);
  new Function(code)();
}
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });
});

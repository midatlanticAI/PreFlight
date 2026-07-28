/**
 * Server-side reflected XSS.
 *
 * PreFlight covered the browser half of XSS from the first release and none of
 * the server half, so this exact four-line Express handler — a request value
 * concatenated into an <h1> and written with res.send — came back with ZERO
 * findings of any severity, and so did the same shape written with res.end,
 * res.write, and Fastify's reply.type('text/html').send.
 *
 * The precision half matters as much: every safe idiom below is the FIX this
 * probe's remediation recommends. res.json, a template engine, escapeHtml, and
 * DOMPurify all have to stay silent, because recommending a fix that then gets
 * flagged is how a tool loses a user for good.
 */

import { describe, it, expect } from 'vitest';
import { probeReflectedXSS } from '../lib/probes/server-xss.js';

const scan = (content, path = 'server/routes/app.js') =>
  probeReflectedXSS([{ path, content }]) || [];

const VULNERABLE_EXPRESS = `const express = require('express');
const app = express();

app.get('/greet', (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

app.post('/comment', (req, res) => {
  res.end("<p>" + req.body.comment + "</p>");
});

app.get('/item/:id', (req, res) => {
  res.write(\`<span>\${req.params.id}</span>\`);
  res.end();
});

app.get('/search', (req, res) => {
  const { q } = req.query;
  res.send(\`<div>Results for \${q}</div>\`);
});

module.exports = app;
`;

describe('probeReflectedXSS — recall', () => {
  it('the realistic vulnerable Express app is no longer silent', () => {
    const found = scan(VULNERABLE_EXPRESS);
    expect(found.length).toBeGreaterThanOrEqual(4);
    for (const f of found) {
      expect(f.cwe).toBe('CWE-79');
      expect(f.severity).toBe('high');
      expect(f.probe).toBe('Reflected XSS');
    }
  });

  const shapes = [
    [
      'res.send with string concatenation',
      'app.get("/g", (req, res) => {\n  res.send("<h1>Hello " + req.query.name + "</h1>");\n});\n',
    ],
    [
      'res.send with a template literal',
      'app.get("/s", (req, res) => {\n  res.send(`<div>${req.query.q}</div>`);\n});\n',
    ],
    [
      'res.end with req.body',
      'app.post("/c", (req, res) => {\n  res.end("<p>" + req.body.comment + "</p>");\n});\n',
    ],
    [
      'res.write with req.params',
      'app.get("/i/:id", (req, res) => {\n  res.write(`<span>${req.params.id}</span>`);\n});\n',
    ],
    [
      'fastify reply.type("text/html").send',
      'fastify.get("/x", (request, reply) => {\n  reply.type("text/html").send(`<b>${request.query.x}</b>`);\n});\n',
    ],
    [
      'res.status(404).send',
      'app.use((req, res) => {\n  res.status(404).send(`<h1>No route ${req.path}</h1>`);\n});\n',
    ],
    [
      'one hop through a const',
      'app.get("/x", (req, res) => {\n  const name = req.query.name;\n  res.send("<h1>Hi " + name + "</h1>");\n});\n',
    ],
    [
      'one hop through destructuring',
      'app.get("/x", (req, res) => {\n  const { q } = req.query;\n  res.send(`<div>${q}</div>`);\n});\n',
    ],
    [
      'raw node http with searchParams',
      'http.createServer((req, res) => {\n  const u = new URL(req.url, "http://x");\n  const term = u.searchParams.get("term");\n  res.end("<p>Results for " + term + "</p>");\n});\n',
    ],
    [
      'a template argument spanning several lines',
      'app.get("/p", (req, res) => {\n  res.send(`\n    <html><body>\n      <h1>${req.query.title}</h1>\n    </body></html>\n  `);\n});\n',
    ],
  ];
  for (const [name, src] of shapes) {
    it(`${name} fires`, () => {
      expect(scan(src).length).toBeGreaterThan(0);
    });
  }

  it('a TypeScript route file is in scope', () => {
    expect(
      scan(
        'router.get("/g", (req: Request, res: Response) => {\n  res.send(`<h2>${req.query.name}</h2>`);\n});\n',
        'server/routes.ts'
      ).length
    ).toBeGreaterThan(0);
  });

  it('reports the line of the response write', () => {
    const found = scan(
      'app.get("/g", (req, res) => {\n  res.send("<h1>" + req.query.name + "</h1>");\n});\n'
    );
    expect(found[0].line).toBe(2);
    expect(found[0].evidence).toContain('res.send');
  });
});

describe('probeReflectedXSS — precision', () => {
  const safe = [
    [
      'res.json with request data',
      'app.get("/u", (req, res) => {\n  res.json({ name: req.query.name });\n});\n',
    ],
    [
      'res.send of a plain string with request data',
      'app.get("/e", (req, res) => {\n  res.send("You asked for " + req.query.q);\n});\n',
    ],
    [
      'an escaped template',
      'app.get("/s", (req, res) => {\n  res.send(`<div>${escapeHtml(req.query.q)}</div>`);\n});\n',
    ],
    [
      'DOMPurify.sanitize',
      'app.post("/s", (req, res) => {\n  res.send(`<div>${DOMPurify.sanitize(req.body.html)}</div>`);\n});\n',
    ],
    [
      'he.encode',
      'app.get("/s", (req, res) => {\n  res.send("<p>" + he.encode(req.query.q) + "</p>");\n});\n',
    ],
    [
      'a hand-rolled entity replace',
      'app.get("/s", (req, res) => {\n  res.end(`<p>${req.query.q.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</p>`);\n});\n',
    ],
    [
      'a templating engine render call',
      'app.get("/p", (req, res) => {\n  res.render("profile", { name: req.query.name });\n});\n',
    ],
    [
      'a constant HTML page',
      'app.get("/ok", (req, res) => {\n  res.send("<html><body><h1>All good</h1></body></html>");\n});\n',
    ],
    [
      'interpolated HTML with no request value',
      'app.get("/v", (req, res) => {\n  res.send(`<h1>Version ${pkg.version}</h1>`);\n});\n',
    ],
    [
      'an explicitly declared JSON content type',
      'app.get("/j", (req, res) => {\n  res.type("application/json").send(JSON.stringify({ q: req.query.q }));\n});\n',
    ],
    [
      'an explicitly declared plain-text content type',
      'app.get("/t", (req, res) => {\n  res.status(403).type("text/plain").send("bad origin " + req.query.o);\n});\n',
    ],
    [
      'a server-sent-events stream with no markup',
      'app.get("/e", (req, res) => {\n  res.write(`event: ping\\ndata: ${req.query.id}\\n\\n`);\n});\n',
    ],
    [
      'a numeric comparison inside the argument',
      'app.get("/c", (req, res) => {\n  res.send(String(req.query.a < req.query.b) + " " + String(a > b));\n});\n',
    ],
    [
      'a browser fetch response that happens to be named res',
      'async function load(q) {\n  const res = await fetch("/api?q=" + q);\n  return res.json();\n}\n',
    ],
  ];
  for (const [name, src] of safe) {
    it(`${name} is silent`, () => {
      expect(scan(src)).toHaveLength(0);
    });
  }

  it('a Python file is out of scope', () => {
    expect(
      scan('def view():\n    return "<h1>" + request.args.get("n") + "</h1>"\n', 'app/main.py')
    ).toHaveLength(0);
  });

  it('a test file is out of scope', () => {
    expect(
      scan(
        'app.get("/g", (req, res) => {\n  res.send("<h1>" + req.query.name + "</h1>");\n});\n',
        'server/__tests__/route.test.js'
      )
    ).toHaveLength(0);
  });
});

describe('probeReflectedXSS — the comment-blind view', () => {
  it('a line comment demonstrating the vulnerable call is not the call', () => {
    expect(
      scan(
        'app.get("/x", (req, res) => {\n  // never write res.send("<h1>" + req.query.name + "</h1>")\n  res.json({ ok: true });\n});\n'
      )
    ).toHaveLength(0);
  });

  it('a block comment contrasting the bug with its fix is not the bug', () => {
    expect(
      scan(
        '/*\n * Bad:  res.send(`<div>${req.query.q}</div>`)\n * Good: res.send(`<div>${escapeHtml(req.query.q)}</div>`)\n */\nexport const note = 1;\n'
      )
    ).toHaveLength(0);
  });

  it('a JSDoc @example carrying the shape is not the shape', () => {
    expect(
      scan(
        '/**\n * @example res.end("<p>" + req.body.comment + "</p>")\n */\nexport function h() {}\n'
      )
    ).toHaveLength(0);
  });
});

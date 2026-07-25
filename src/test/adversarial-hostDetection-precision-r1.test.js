// Adversarial PRECISION suite for probeHostDetection (round 1).
//
// Every test in the main describe blocks constructs a BENIGN project layout
// containing lookalike signals (prose mentions, near-miss filenames,
// similarly named dependencies, marker strings in non-marker file types)
// and asserts the detector produces ZERO findings. A failure here is a
// false positive: the detector claimed "built with <Tool>" about a project
// that carries no real host marker.
//
// The final describe block ("genuinely ambiguous host signals") holds cases
// the author believes SHOULD detect, or that are legitimately fuzzy. Each is
// flagged with a comment and may fail in either direction without indicating
// a precision bug.
//
// Authored without reading the probe implementation, by design: assertions
// encode the documented contract (marker files, lovable-tagger dependency,
// HTML content markers, v0.dev mentions in md/js/ts), not the code.

import { describe, it, expect } from 'vitest';
import { probeHostDetection } from '../lib/probes.js';

const f = (path, content = '') => ({ path, content });

const pkg = (obj) => f('package.json', JSON.stringify(obj, null, 2));

const plainPkg = (extra = {}) =>
  pkg({
    name: 'benign-app',
    version: '1.0.0',
    scripts: { start: 'node index.js' },
    dependencies: { express: '^4.19.0' },
    ...extra,
  });

describe('probeHostDetection precision: prose mentions of tools by name', () => {
  it('README comparing editors that names Cursor does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'README.md',
        [
          '# Benign App',
          '',
          'I wrote this by hand in Vim. My teammate prefers Cursor as her editor',
          'and another uses plain VS Code. The choice of editor does not change',
          'the code in this repository.',
        ].join('\n')
      ),
      f('index.js', 'const express = require("express")\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('README discussing Replit and Bolt as hosting options does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'README.md',
        [
          '# Deployment notes',
          '',
          'We evaluated Replit for quick demos and Bolt for scaffolding, then',
          'rejected both and deployed to a plain VPS with systemd. Neither tool',
          'generated any part of this codebase.',
        ].join('\n')
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('README mentioning Lovable by name (no URL) does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'README.md',
        [
          '# Craft app',
          '',
          'A friend suggested I try Lovable to prototype the UI. I declined and',
          'built the components manually. This paragraph is the only place the',
          'word Lovable appears in the project.',
        ].join('\n')
      ),
      f('src/app.js', 'export const app = () => "hello"\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('CONTRIBUTING.md naming Windsurf, Claude, and Gemini as chat tools does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'CONTRIBUTING.md',
        [
          '# Contributing',
          '',
          'Feel free to draft PR descriptions with Claude or Gemini, and some of',
          'us pair with Windsurf, but every diff must be reviewed line by line',
          'by a human before merge. Do not commit tool configuration files.',
        ].join('\n')
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('blog-style md mentioning v0 by Vercel WITHOUT the v0.dev domain does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'posts/2026-01-generators.md',
        'A roundup of UI generators: v0 from Vercel, plus a dozen open-source clones. We use none of them here.\n'
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });
});

describe('probeHostDetection precision: lookalike filenames (near-miss names)', () => {
  it('docs/claude.md (lowercase basename) does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'docs/claude.md',
        '# Claude Shannon\n\nBiography notes for a docs site about information theory.\n'
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('src/agents.md (lowercase, in src) does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'src/agents.md',
        '# Insurance agents\n\nDomain notes on the agents table in our CRM schema.\n'
      ),
      f('src/agents.js', 'export const listAgents = () => []\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('notes/GEMINI.markdown (different extension) does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'notes/GEMINI.markdown',
        '# GEMINI\n\nNotes on the Gemini North telescope observation run.\n'
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('.cursorrules.bak and replit.nix.example (suffixed marker names) do not detect', () => {
    const files = [
      plainPkg(),
      f('.cursorrules.bak', 'stale backup a colleague committed from another repo template\n'),
      f('replit.nix.example', '# example nix expression from a tutorial, never used\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('my.replit.js (marker string embedded mid-filename) does not detect', () => {
    const files = [
      plainPkg(),
      f('my.replit.js', '// a module named after my dog, Replit the corgi\nmodule.exports = {}\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('src/bolt/index.js (source dir named bolt, no leading dot) does not detect', () => {
    const files = [
      plainPkg(),
      f('src/bolt/index.js', '// lightning-bolt icon helpers\nexport const bolt = "\\u26A1"\n'),
      f('src/bolt/render.js', 'export const render = () => null\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('windsurf-shop/products.js and cursor.js (domain-vocabulary names) do not detect', () => {
    const files = [
      plainPkg(),
      f('windsurf-shop/products.js', 'export const boards = ["wave", "freeride", "slalom"]\n'),
      f(
        'src/cursor.js',
        '// mouse cursor position tracking for the canvas layer\nexport const cursorAt = (e) => [e.clientX, e.clientY]\n'
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });
});

describe('probeHostDetection precision: similarly named dependencies', () => {
  it('cursor-position dependency does not detect', () => {
    const files = [
      pkg({
        name: 'editor-widget',
        version: '2.0.0',
        dependencies: { 'cursor-position': '^1.0.0', react: '^18.3.1' },
      }),
      f('src/index.js', 'import getCursor from "cursor-position"\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('bolt-connect and bolt11 dependencies do not detect', () => {
    const files = [
      pkg({
        name: 'lightning-pay',
        version: '0.3.0',
        dependencies: { 'bolt-connect': '^2.1.0', bolt11: '^1.4.1' },
      }),
      f('src/invoice.js', 'import { decode } from "bolt11"\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('replit-client style dependency name does not detect', () => {
    const files = [
      pkg({
        name: 'ide-bridge',
        version: '1.1.0',
        dependencies: { 'replit-client': '^0.9.0' },
      }),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('gemini-api (crypto exchange SDK) and windsurfing-api do not detect', () => {
    const files = [
      pkg({
        name: 'trading-bot',
        version: '4.2.0',
        dependencies: { 'gemini-api': '^2.0.5', 'windsurfing-api': '^1.0.0' },
      }),
      f('src/exchange.js', 'import GeminiAPI from "gemini-api"\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('lovable-quotes (near-miss on lovable-tagger) does not detect', () => {
    const files = [
      pkg({
        name: 'greeting-cards',
        version: '1.0.0',
        dependencies: { 'lovable-quotes': '^3.0.0' },
      }),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });
});

describe('probeHostDetection precision: content markers in NON-HTML files', () => {
  it('a .js blocklist string containing gptengineer.js does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'src/security/blocklist.js',
        [
          '// Third-party script names our CSP report tooling watches for.',
          'export const WATCHED_SCRIPTS = [',
          '  "gptengineer.js",',
          '  "tracker.min.js",',
          ']',
        ].join('\n')
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('a JSON allowlist containing lovable.dev does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'config/link-preview-allowlist.json',
        JSON.stringify(
          { allowedPreviewDomains: ['github.com', 'lovable.dev', 'vercel.com'] },
          null,
          2
        )
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('a .js CSP audit constant containing cdn.gpteng.co does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'scripts/csp-audit.js',
        '// Domains we explicitly refuse in script-src:\nconst DENIED = ["cdn.gpteng.co", "evil.example.com"]\nmodule.exports = { DENIED }\n'
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('a plain .txt security note listing all three HTML markers does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'notes/security-notes.txt',
        'Strings scanners look for: gptengineer.js, cdn.gpteng.co, lovable.dev. None are used by this app.\n'
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });
});

describe('probeHostDetection precision: URLs in package.json fields', () => {
  it('homepage pointing at lovable.dev/showcase does not detect', () => {
    const files = [
      pkg({
        name: 'portfolio-piece',
        version: '1.0.0',
        homepage: 'https://lovable.dev/showcase',
        dependencies: { react: '^18.3.1' },
      }),
      f('src/App.jsx', 'export default function App() { return null }\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('repository and bugs URLs mentioning replit.com and cursor.sh do not detect', () => {
    const files = [
      pkg({
        name: 'mirror-repo',
        version: '0.1.0',
        repository: { type: 'git', url: 'https://replit.com/@someone/old-mirror' },
        bugs: { url: 'https://cursor.sh/community/issue-tracker-migration' },
      }),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('description field naming Bolt and Lovable as comparisons does not detect', () => {
    const files = [
      pkg({
        name: 'scaffolder-bench',
        version: '1.0.0',
        description:
          'Benchmark harness comparing output quality of Bolt, Lovable, and hand-written scaffolds.',
        dependencies: { commander: '^12.0.0' },
      }),
      f('bin/bench.js', '#!/usr/bin/env node\nconsole.log("bench")\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });
});

describe('probeHostDetection precision: near-miss dot-directories', () => {
  it('src/.claude-work/notes.js (dot-dir with suffix after marker) does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'src/.claude-work/notes.js',
        '// scratch notes dir named after a coworker, Claude Dubois\nexport const notes = []\n'
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('.claudette/config.yml does not detect', () => {
    const files = [plainPkg(), f('.claudette/config.yml', 'theme: mauve\nlocale: fr-FR\n')];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('.geminiv2/model.json and .boltless/index.js do not detect', () => {
    const files = [
      plainPkg(),
      f('.geminiv2/model.json', '{ "constellation": "gemini", "epoch": 2 }'),
      f('.boltless/index.js', '// fastener-free furniture catalog\nexport default {}\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('.cursors/theme.json and .windsurfer/profile.json (plural/agent-noun dirs) do not detect', () => {
    const files = [
      plainPkg(),
      f('.cursors/theme.json', '{ "pointer": "crosshair" }'),
      f('.windsurfer/profile.json', '{ "sailSize": 5.2 }'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });
});

describe('probeHostDetection precision: empty input and generic projects', () => {
  it('empty file array yields zero findings', () => {
    expect(probeHostDetection([])).toEqual([]);
  });

  it('plain node app yields zero findings', () => {
    const files = [
      plainPkg(),
      f(
        'index.js',
        'const http = require("http")\nhttp.createServer((q, s) => s.end("ok")).listen(3000)\n'
      ),
      f('README.md', '# Plain node app\n\nA tiny HTTP server. Written by hand.\n'),
      f('.gitignore', 'node_modules\n.env\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('plain react + vite app yields zero findings', () => {
    const files = [
      pkg({
        name: 'react-starter',
        version: '0.0.1',
        dependencies: { react: '^18.3.1', 'react-dom': '^18.3.1' },
        devDependencies: { vite: '^5.4.11' },
      }),
      f('index.html', '<div id="root"></div><script type="module" src="/src/main.jsx"></script>'),
      f(
        'src/main.jsx',
        'import { createRoot } from "react-dom/client"\ncreateRoot(document.getElementById("root")).render("hi")\n'
      ),
      f('src/App.jsx', 'export default function App() { return <p>hi</p> }\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('files with empty content and unusual-but-benign paths yield zero findings', () => {
    const files = [
      f('src/utils/empty.js', ''),
      f('assets/deep/nested/dir/logo.svg', '<svg xmlns="http://www.w3.org/2000/svg"></svg>'),
      f('LICENSE', 'MIT License\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });
});

describe('probeHostDetection precision: extension-suffixed marker basenames', () => {
  it('CLAUDE.md.txt does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'CLAUDE.md.txt',
        'A pasted copy of some other repo\u2019s agent notes, kept as reference text only.\n'
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('AGENTS.md.old and backup/CLAUDE.md.bak do not detect', () => {
    const files = [
      plainPkg(),
      f('AGENTS.md.old', 'retired draft, superseded by human-written docs\n'),
      f('backup/CLAUDE.md.bak', 'archived snapshot from a template repo we abandoned\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('GEMINI.md5 (checksum file) does not detect', () => {
    const files = [
      plainPkg(),
      f('dist-artifacts/GEMINI.md5', 'd41d8cd98f00b204e9800998ecf8427e  GEMINI.tar.gz\n'),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });
});

describe('probeHostDetection precision: v0.dev outside md/js/ts', () => {
  it('a CSS comment mentioning v0.dev does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'src/styles/buttons.css',
        '/* gradient inspired by a screenshot from v0.dev, rebuilt from scratch */\n.btn { background: linear-gradient(#111, #333); }\n'
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('a CSS url() with v0.dev in an image path does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'src/styles/hero.css',
        '.hero { background-image: url("/assets/comparisons/v0.dev-screenshot.png"); }\n'
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('an HTML img path containing v0.dev does not detect (v0.dev is not an HTML marker)', () => {
    const files = [
      plainPkg(),
      f(
        'blog/generator-roundup.html',
        '<h1>Generator roundup</h1><img src="/assets/v0.dev-badge.png" alt="comparison shot">'
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });
});

describe('probeHostDetection precision: lovable-tagger only as a lockfile transitive', () => {
  it('package-lock.json transitive entry without a package.json dependency does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'package-lock.json',
        JSON.stringify(
          {
            name: 'benign-app',
            lockfileVersion: 3,
            packages: {
              '': { name: 'benign-app', dependencies: { express: '^4.19.0' } },
              'node_modules/express': { version: '4.19.0' },
              'node_modules/some-audit-corpus/node_modules/lovable-tagger': {
                version: '1.0.0',
                dev: true,
                extraneous: true,
              },
            },
          },
          null,
          2
        )
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('yarn.lock resolution mentioning lovable-tagger does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'yarn.lock',
        [
          '# THIS IS AN AUTOGENERATED FILE.',
          '',
          'express@^4.19.0:',
          '  version "4.19.0"',
          '',
          'lovable-tagger@^1.0.0:',
          '  version "1.0.0"',
          '  resolved "https://registry.yarnpkg.com/lovable-tagger/-/lovable-tagger-1.0.0.tgz"',
        ].join('\n')
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  it('pnpm-lock.yaml transitive mentioning lovable-tagger does not detect', () => {
    const files = [
      plainPkg(),
      f(
        'pnpm-lock.yaml',
        [
          'lockfileVersion: "9.0"',
          'packages:',
          '  lovable-tagger@1.0.0:',
          '    resolution: {integrity: sha512-deadbeef}',
        ].join('\n')
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });
});

describe('genuinely ambiguous host signals', () => {
  // AMBIGUOUS: a real .cursorrules with real content, but nested under a
  // monorepo workspace instead of the repo root. The author believes this
  // SHOULD detect (the workspace really was built with Cursor). If the
  // detector is root-only it will return []. May fail either way.
  it('real .cursorrules inside apps/web/ (monorepo workspace)', () => {
    const files = [
      plainPkg(),
      f('apps/web/.cursorrules', 'Always use TypeScript. Prefer functional components.\n'),
      f('apps/web/src/App.tsx', 'export default function App() { return null }\n'),
    ];
    const findings = probeHostDetection(files);
    expect(findings.length).toBeGreaterThan(0);
  });

  // AMBIGUOUS: a real CLAUDE.md nested in a workspace. Claude Code genuinely
  // reads nested CLAUDE.md files, so the author believes this SHOULD detect.
  // A root-only basename check will return []. May fail either way.
  it('real CLAUDE.md inside packages/api/', () => {
    const files = [
      plainPkg(),
      f(
        'packages/api/CLAUDE.md',
        '# API package\n\nRun `npm test` before committing. Use zod for validation.\n'
      ),
      f('packages/api/src/index.js', 'export const handler = () => {}\n'),
    ];
    const findings = probeHostDetection(files);
    expect(findings.length).toBeGreaterThan(0);
  });

  // AMBIGUOUS: the canonical GPT Engineer script tag, but commented out in
  // HTML ("we removed this"). A substring scan detects; a DOM-aware scan
  // would not. The author leans "should NOT detect" (the live page no longer
  // loads it), but a shipped commented-out marker is strong provenance
  // evidence. Asserting zero per the benign reading. May fail either way.
  // ADJUDICATED round 1: kept firing. The content marker is a substring scan
  // and the finding is info-only inventory; masking HTML comments for an
  // inventory signal is not worth the parser. Revisit if it misroutes copy.
  it.skip('cdn.gpteng.co script tag present only inside an HTML comment', () => {
    const files = [
      plainPkg(),
      f(
        'index.html',
        '<div id="root"></div>\n<!-- removed after migrating off the generator:\n<script src="https://cdn.gpteng.co/gptengineer.js" type="module"></script>\n-->\n'
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  // AMBIGUOUS: a v0.dev project URL in package.json homepage. package.json is
  // .json, so the documented md/js/ts content rule does not cover it, and the
  // suite asserts zero. But a homepage pointing at a v0.dev chat/project link
  // is strong real-world evidence the app came from v0. May fail either way.
  it('package.json homepage pointing at a v0.dev project link', () => {
    const files = [
      pkg({
        name: 'landing-page',
        version: '1.0.0',
        homepage: 'https://v0.dev/chat/projects/abc123',
        dependencies: { react: '^18.3.1' },
      }),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });

  // AMBIGUOUS: the literal string "lovable.dev" in README.md. The documented
  // contract scopes lovable.dev to HTML content, so the suite asserts zero.
  // But real Lovable exports commonly ship a README linking lovable.dev, so
  // an md-scoped check would be defensible. May fail either way.
  it('README.md containing a lovable.dev project URL', () => {
    const files = [
      plainPkg(),
      f(
        'README.md',
        '# App\n\nOriginally prototyped at https://lovable.dev/projects/xyz then rewritten by hand.\n'
      ),
    ];
    expect(probeHostDetection(files)).toEqual([]);
  });
});

// scripts/prerender.mjs
//
// Runs after `vite build`. Renders every indexable route to static HTML so
// crawlers get real content plus a correct per-route <head>, instead of the
// homepage shell for all 85 pages. The client bundle is unchanged; browsers
// still boot the full SPA and mount over this markup. No new dependency:
// Vite is already in the toolchain, react-dom/server ships with react-dom.
//
// Strategy: Vite middleware-mode SSR resolves import.meta.glob (eager Learn
// registry) and JSX, so entry-server.jsx and seo.js load with zero extra
// build steps.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { createServer } from 'vite';
import { ROOT, allRoutePaths } from './lib/routes.mjs';

const DIST = join(ROOT, 'dist');
const TEMPLATE = readFileSync(join(DIST, 'index.html'), 'utf8');

const escAttr = (s) =>
  String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

function applyHead(html, meta) {
  return html
    .replace(/<title>[\s\S]*?<\/title>/, `<title>${escAttr(meta.title)}</title>`)
    .replace(
      /<meta\s+name="description"\s+content="[\s\S]*?"\s*\/>/,
      `<meta name="description" content="${escAttr(meta.description)}" />`
    )
    .replace(
      /<link rel="canonical" href="[^"]*"\s*\/>/,
      `<link rel="canonical" href="${meta.canonical}" />`
    )
    .replace(
      /<link rel="alternate" hreflang="en" href="[^"]*"\s*\/>/,
      `<link rel="alternate" hreflang="en" href="${meta.canonical}" />`
    )
    .replace(
      /<link rel="alternate" hreflang="x-default" href="[^"]*"\s*\/>/,
      `<link rel="alternate" hreflang="x-default" href="${meta.canonical}" />`
    )
    .replace(
      /<meta\s+property="og:title"\s+content="[\s\S]*?"\s*\/>/,
      `<meta property="og:title" content="${escAttr(meta.ogTitle)}" />`
    )
    .replace(
      /<meta\s+property="og:description"\s+content="[\s\S]*?"\s*\/>/,
      `<meta property="og:description" content="${escAttr(meta.ogDescription)}" />`
    )
    .replace(
      /<meta property="og:url" content="[^"]*"\s*\/>/,
      `<meta property="og:url" content="${meta.canonical}" />`
    );
}

const ROOT_DIV = '<div id="root" role="presentation"></div>';

const vite = await createServer({
  server: { middlewareMode: true },
  appType: 'custom',
  logLevel: 'warn',
});

let written = 0;
try {
  const { render } = await vite.ssrLoadModule('/src/entry-server.jsx');
  const { getRouteMeta } = await vite.ssrLoadModule('/src/lib/seo.js');

  for (const path of allRoutePaths()) {
    const appHtml = render(path);
    const meta = getRouteMeta(path);

    let html = applyHead(TEMPLATE, meta);
    html = html.replace(ROOT_DIV, `<div id="root" role="presentation">${appHtml}</div>`);

    const outPath = path === '/' ? join(DIST, 'index.html') : join(DIST, path, 'index.html');
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, html, 'utf8');
    written += 1;
  }
} finally {
  await vite.close();
}

console.log(`prerender: ${written} route(s) written to dist/`);

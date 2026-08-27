// scripts/gen-sitemap.mjs
//
// Generates public/sitemap.xml from the shared route surface (scripts/lib/
// routes.mjs) so Google and the AI crawlers we allow can discover every
// page, not just the homepage. Runs in the "prebuild" script, so the
// sitemap regenerates on every build and cannot drift behind the Learn
// library. Zero external deps.

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, STATIC_ROUTES, contentRoutes } from './lib/routes.mjs';

const BASE = 'https://preflight.midatlantic.ai';
const TODAY = new Date().toISOString().slice(0, 10);

const xmlEscape = (s) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function urlBlock({ path, priority, changefreq, lastmod, alternates }) {
  // Trailing slash for non-root, to match the url Cloudflare Pages actually
  // serves 200 for (and the canonical in seo.js). A sitemap loc that 308s is a
  // wasted crawl and a canonical mismatch.
  const loc = `${BASE}${path === '/' ? '/' : path.replace(/\/$/, '') + '/'}`;
  const alt = alternates
    ? `\n    <xhtml:link rel="alternate" hreflang="en" href="${loc}" />` +
      `\n    <xhtml:link rel="alternate" hreflang="x-default" href="${loc}" />`
    : '';
  return `  <url>
    <loc>${xmlEscape(loc)}</loc>
    <lastmod>${lastmod || TODAY}</lastmod>
    <changefreq>${changefreq}</changefreq>
    <priority>${priority}</priority>${alt}
  </url>`;
}

const records = [...STATIC_ROUTES, ...contentRoutes()];
const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
${records.map(urlBlock).join('\n')}
</urlset>
`;

writeFileSync(join(ROOT, 'public', 'sitemap.xml'), xml, 'utf8');
console.log(
  `sitemap.xml: ${records.length} urls (${STATIC_ROUTES.length} static + ${records.length - STATIC_ROUTES.length} content)`
);
